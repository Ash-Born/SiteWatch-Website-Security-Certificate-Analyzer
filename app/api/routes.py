"""
Vulnerability Scanner API - Routes / Endpoints module.
Defines HTTP routes and delegates request handling to the Service Layer.
"""

from typing import List, Optional
from datetime import datetime, timedelta, timezone
import ipaddress
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException, Query, Depends, status, Response, Header, UploadFile, File, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import requests

from app.services import ScannerService, AssetService, CveService, AuthService, DEFAULT_PORTS
from app.auth import (decode_access_token, verify_password, hash_password,
                      create_password_reset_token, hash_password_reset_token)
import os
import hmac
import io
import re
import uuid
from pathlib import Path
from PIL import Image, UnidentifiedImageError
from app import database as db_ops
from app.scanner.website_analyzer import analyze_website, validate_public_website_target
from app.services.notifications import validate_webhook_url, dispatch_scan_notifications

router = APIRouter()
_API_STARTED_AT = time.monotonic()

# Auth Security Helper
security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """Dependency to retrieve the current authenticated user from JWT."""
    jwt_token = None
    if credentials:
        jwt_token = credentials.credentials

    if not jwt_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(jwt_token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = int(payload["sub"]) if str(payload["sub"]).isdigit() else payload["sub"]
    user = db_ops.get_user_by_id(user_id)
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Account is suspended or unavailable")
    return {"id": user_id, "username": user["username"], "role": user.get("role", "user")}


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") not in {"admin", "company_admin"}:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return current_user


def require_scan_key(x_scan_key: Optional[str] = Header(None, alias="X-Scan-Key")) -> None:
    configured_key = os.getenv("SCAN_ACCESS_KEY")
    if not configured_key:
        raise HTTPException(status_code=503, detail="Scanning is disabled: SCAN_ACCESS_KEY is not configured")
    if not x_scan_key or not hmac.compare_digest(x_scan_key, configured_key):
        raise HTTPException(status_code=403, detail="A valid X-Scan-Key is required")


# Request/Response Schemas

class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=254, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=128)


class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=120)
    username: str = Field(..., min_length=3, max_length=30, description="Unique username")
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128, description="Password (minimum 8 characters)")


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=200)
    new_password: str = Field(..., min_length=8, max_length=128)


class UserProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, max_length=120)
    email: Optional[str] = Field(None, max_length=254)
    webhook_url: Optional[str] = Field(None, max_length=2048)


class ScheduledScanCreateRequest(BaseModel):
    target_url: str = Field(..., min_length=3, max_length=2048)
    frequency_hours: int = Field(..., ge=1, le=720)


class ScheduledScanResponse(BaseModel):
    id: int
    user_id: int
    target_url: str
    frequency_hours: int
    last_run: Optional[str] = None
    next_run: str
    is_active: bool
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)


class UserAuthResponse(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    role: str
    is_verified: bool = False


class AssetCreateRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=100, description="Friendly hostname (e.g., WEB01)")
    ip_address: str = Field(..., min_length=1, max_length=255, description="Target IP or hostname")
    operating_system: Optional[str] = Field(None, max_length=100, description="Optional OS description")
    criticality: str = Field("Medium", description="Low / Medium / High / Critical")
    owner: Optional[str] = Field(None, max_length=100, description="Team or person responsible")
    description: Optional[str] = Field(None, description="Optional notes")


class AssetUpdateRequest(BaseModel):
    hostname: Optional[str] = Field(None, min_length=1, max_length=100)
    ip_address: Optional[str] = Field(None, min_length=1, max_length=255)
    operating_system: Optional[str] = Field(None, max_length=100)
    criticality: Optional[str] = Field(None)
    owner: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None)


class AssetResponse(BaseModel):
    id: int
    hostname: str
    ip_address: str
    operating_system: Optional[str] = None
    criticality: str
    owner: Optional[str] = None
    description: Optional[str] = None
    created_at: str
    updated_at: str
    user_id: int
    scans: Optional[List[dict]] = None


class ScanRequest(BaseModel):
    asset_id: int = Field(..., description="ID of registered asset to scan")
    scan_profile: str = Field("Quick", description="Selected scan profile (e.g., Quick, Full TCP, Service Detection, Vulnerability)")
    threads: int = Field(10, ge=1, le=100, description="Number of threads for concurrent scanning")
    timeout: float = Field(10.0, gt=0.0, le=10.0, description="Socket timeout in seconds")
    use_threaded: bool = Field(True, description="Whether to use the threaded scanner for performance")
    grab_banners: bool = Field(False, description="Whether to grab service banners for open ports")


class WebsiteAnalyzeRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=2048, description="Public website hostname or HTTP(S) URL")


class BulkWebsiteAnalyzeRequest(BaseModel):
    urls: List[str] = Field(..., description="Between 1 and 20 public website URLs or hostnames")


class AdminUserStatusRequest(BaseModel):
    is_active: bool


class AdminUserResponse(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[str] = None
    scan_count: int = 0


class AdminStatsResponse(BaseModel):
    total_users: Optional[int] = None
    total_scans: Optional[int] = None
    api_status: str
    uptime_seconds: int
    uptime_human: str
    database_status: str


class AdminThreatResponse(BaseModel):
    scan_id: int
    target: str
    title: str
    severity: str
    evidence: Optional[str] = None
    created_at: Optional[str] = None


class AdminMapPoint(BaseModel):
    ip: str
    target: str
    scan_id: int
    latitude: float
    longitude: float
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    organization: Optional[str] = None


class AdminThreatMapResponse(BaseModel):
    points: List[AdminMapPoint]
    source: str


class CVEInfo(BaseModel):
    cve_id: str = Field(..., description="CVE ID, e.g., CVE-2024-6387")
    software: str = Field(..., description="Affected software name")
    description: str = Field(..., description="Vulnerability description")
    severity: str = Field(..., description="Severity level (e.g. LOW, MEDIUM, HIGH, CRITICAL)")
    cvss_score: float = Field(..., description="CVSS version 3 score")
    remediation: Optional[str] = Field(None, description="Remediation steps or recommendations")


class ScanResultItem(BaseModel):
    port: int
    status: str
    service: str
    message: Optional[str] = None
    banner: Optional[str] = None
    software: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: Optional[List[CVEInfo]] = Field(default=[], description="List of matched CVE vulnerabilities")
    http_assessment: Optional[dict] = Field(default=None, description="HTTP assessment details for web port")
    findings: Optional[List[dict]] = Field(default=[], description="List of unified findings for port")


class RiskSummary(BaseModel):
    max_cvss_score: float = Field(..., description="Highest CVSS score found on the target")
    weighted_risk_score: float = Field(..., description="Weighted cumulative risk score capped at 10.0")
    host_severity: str = Field(..., description="Overall severity level for the host")
    severity_counts: dict = Field(..., description="Counts of vulnerabilities at each severity level")


class ScanResponse(BaseModel):
    id: Optional[int] = None
    target: Optional[str] = None
    asset_id: int
    scan_profile: str
    status: str
    ports_scanned: int
    use_threaded: bool
    results: List[ScanResultItem]
    risk_summary: RiskSummary = Field(..., description="Overall risk scoring and summary for the host")
    http_assessment: Optional[dict] = Field(default=None, description="Host-wide HTTP security assessment summary")
    findings: Optional[List[dict]] = Field(default=[], description="Merged findings list across the target host")


class SavedScanSummary(BaseModel):
    id: int
    target: Optional[str] = None
    timestamp: str
    duration: Optional[float] = None
    status: str
    scan_profile: Optional[str] = None
    ports_scanned: int
    max_cvss_score: float
    weighted_risk_score: float
    score: Optional[int] = None
    grade: Optional[str] = None
    severity_counts: Optional[dict] = None
    critical_count: int = 0
    host_severity: str
    asset_id: Optional[int] = None
    asset_hostname: Optional[str] = None
    num_findings: int = 0
    compliance_signals: Optional[List[dict]] = None


class SavedScanResponse(BaseModel):
    id: int
    target: Optional[str] = None
    timestamp: str
    duration: Optional[float] = None
    status: str
    scan_profile: Optional[str] = None
    ports_scanned: int
    max_cvss_score: float
    weighted_risk_score: float
    score: Optional[int] = None
    grade: Optional[str] = None
    host_severity: str
    num_findings: int = 0
    asset_id: Optional[int] = None
    asset_hostname: Optional[str] = None
    results: List[ScanResultItem]
    risk_summary: RiskSummary
    http_assessment: Optional[dict] = Field(default=None, description="Host-wide HTTP security assessment summary")
    findings: Optional[List[dict]] = Field(default=[], description="Merged findings list across the target host")
    details: Optional[dict] = None


# Public Root Endpoint
@router.get("/")
def read_root():
    return {
        "message": "Website Security & Certificate Analyzer",
        "version": "2.0.0",
        "auth_endpoints": {
            "POST /api/v1/auth/register": "Register a new user",
            "POST /api/v1/auth/login": "Authenticate user and get access token"
        },
        "endpoints": {
            "GET /api/v1/assets": "List registered assets (Requires JWT)",
            "POST /api/v1/assets": "Create a new asset (Requires JWT)",
            "GET /api/v1/assets/{id}": "Get asset details (Requires JWT)",
            "PUT /api/v1/assets/{id}": "Update asset (Requires JWT)",
            "DELETE /api/v1/assets/{id}": "Delete asset (Requires JWT)",
            "POST /api/v1/analyze": "Run live TLS, DNS and HTTP analysis (JWT + X-Scan-Key)",
            "POST /api/v1/analyze/bulk": "Queue up to 20 live website assessments (JWT + X-Scan-Key)",
            "GET /api/v1/analyze/bulk/{job_id}": "Poll bulk assessment progress and results (JWT)",
            "GET /api/v1/scans": "Retrieve user scan history (Requires JWT)",
            "GET /api/v1/scans/{scan_id}": "Retrieve a specific scan report (Requires JWT)",
            "GET /api/v1/scans/{scan_id}/report": "Get HTML report for stored scan (Requires JWT)",
            "GET /api/v1/scans/{scan_id}/pdf": "Get PDF report for stored scan (Requires JWT)",
            "GET /api/v1/common-ports": "Retrieve common ports list",
            "GET /api/v1/cve/lookup": "Look up CVEs for software and version",
            "GET /api/v1/cve/search": "Search CVEs by keyword"
        }
    }


@router.get("/api/v1/health")
def api_health():
    return {"status": "online", "service": "website-security-analyzer"}


# Registration & Authentication Endpoints

@router.post("/api/v1/auth/register", response_model=UserAuthResponse, status_code=201)
def register_user(request: UserRegisterRequest):
    """Register a new user account."""
    res = AuthService.register_user(request.username, request.password, request.full_name, request.email)
    db_ops.log_activity(res["id"], "registration", "Account created")
    return UserAuthResponse(**res)


@router.post("/api/v1/auth/login", response_model=TokenResponse)
def login_user(request: UserLoginRequest):
    """Authenticate with username or email and return a JWT access token."""
    res = AuthService.authenticate_user(request.username, request.password)
    db_ops.log_activity(res["user_id"], "login", "Successful login")
    return TokenResponse(**res)


@router.post("/api/v1/auth/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    """Create a one-time reset link; always return a generic response to prevent account discovery."""
    email = request.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    raw_token, token_hash = create_password_reset_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=20)
    if db_ops.save_password_reset_token(email, token_hash, expires_at):
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
        reset_link = f"{frontend_url}/reset-password?token={raw_token}"
        print(f"[PASSWORD RESET LINK] {reset_link}", flush=True)
    return {"message": "If an account exists for that email, a password reset link has been created."}


@router.post("/api/v1/auth/reset-password")
def reset_password(request: ResetPasswordRequest):
    """Consume a single-use, expiring reset token and replace the password hash."""
    password = request.new_password
    if len(password) < 8 or not re.search(r"[0-9]|[^A-Za-z0-9]", password):
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters and include a number or special character")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=422, detail="Password must be at most 72 UTF-8 bytes")
    token_hash = hash_password_reset_token(request.token)
    if not db_ops.reset_password_by_token(token_hash, hash_password(password)):
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired. Request a new link.")
    return {"message": "Password reset successfully. You can now sign in."}


@router.get("/api/v1/auth/me", response_model=dict)
def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Retrieve details of the currently logged in user."""
    db_ops.log_activity(current_user["id"], "profile_view", "Account profile viewed")
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "is_verified": bool(db_ops.get_user_by_id(current_user["id"]).get("is_verified", False))
    }


@router.get("/api/v1/users/me")
def read_my_profile(current_user: dict = Depends(get_current_user)):
    profile = db_ops.get_user_by_id(current_user["id"])
    if not profile:
        raise HTTPException(status_code=404, detail="Account not found")
    db_ops.log_activity(current_user["id"], "profile_view", "Profile viewed")
    return {"id": profile["id"], "username": profile["username"], "role": profile["role"],
            "full_name": profile.get("full_name"), "email": profile.get("email"),
            "is_verified": profile.get("is_verified", False),
            "webhook_url": profile.get("webhook_url"),
            "avatar_url": f"/api/v1/users/me/avatar?v={profile['avatar_filename']}" if profile.get("avatar_filename") else None,
            "created_at": profile.get("created_at")}


@router.put("/api/v1/users/me")
def update_my_profile(request: UserProfileUpdateRequest, current_user: dict = Depends(get_current_user)):
    email = request.email.strip() if request.email else None
    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    webhook_url = None
    if "webhook_url" in request.model_fields_set:
        try:
            webhook_url = validate_webhook_url(request.webhook_url) or ""
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    try:
        result = db_ops.update_user_profile(current_user["id"], request.full_name, email, webhook_url)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    db_ops.log_activity(current_user["id"], "profile_updated", "Profile details and notification settings updated")
    return result


_AVATAR_DIR = Path(os.getenv("AVATAR_STORAGE_DIR", "uploads/avatars")).resolve()
_AVATAR_MIME = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}


@router.post("/api/v1/users/me/avatar")
async def upload_my_avatar(request: Request, file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > 6 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Avatar request must be smaller than 6 MB")
    if file.content_type not in _AVATAR_MIME:
        raise HTTPException(status_code=415, detail="Use a JPEG, PNG, or WebP image")
    payload = await file.read(5 * 1024 * 1024 + 1)
    if not payload or len(payload) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Avatar must be smaller than 5 MB")
    try:
        with Image.open(io.BytesIO(payload)) as source:
            if source.format not in {"JPEG", "PNG", "WEBP"}:
                raise HTTPException(status_code=415, detail="Unsupported image format")
            if source.width * source.height > 20_000_000:
                raise HTTPException(status_code=413, detail="Image dimensions exceed the 20 megapixel limit")
            source.verify()
        with Image.open(io.BytesIO(payload)) as source:
            source = source.convert("RGB")
            source.thumbnail((512, 512))
            output = io.BytesIO()
            source.save(output, format="WEBP", quality=86, method=6)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid image")
    _AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.webp"
    (_AVATAR_DIR / filename).write_bytes(output.getvalue())
    previous = db_ops.set_user_avatar(current_user["id"], filename)
    if previous is None:
        (_AVATAR_DIR / filename).unlink(missing_ok=True)
        raise HTTPException(status_code=404, detail="Account not found")
    if previous:
        (_AVATAR_DIR / previous).unlink(missing_ok=True)
    db_ops.log_activity(current_user["id"], "avatar_updated", "Profile picture changed")
    return {"avatar_url": f"/api/v1/users/me/avatar?v={filename}"}


@router.get("/api/v1/users/me/avatar")
def read_my_avatar(current_user: dict = Depends(get_current_user)):
    profile = db_ops.get_user_by_id(current_user["id"])
    filename = profile.get("avatar_filename") if profile else None
    if not filename:
        raise HTTPException(status_code=404, detail="No profile picture uploaded")
    path = (_AVATAR_DIR / filename).resolve()
    if path.parent != _AVATAR_DIR or not path.is_file():
        raise HTTPException(status_code=404, detail="Profile picture not found")
    return FileResponse(path, media_type="image/webp", headers={"Cache-Control": "private, max-age=300"})


@router.put("/api/v1/users/me/password")
def change_my_password(request: PasswordChangeRequest, current_user: dict = Depends(get_current_user)):
    user = db_ops.get_user_by_username(current_user["username"])
    if not user or not verify_password(request.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if request.current_password == request.new_password:
        raise HTTPException(status_code=400, detail="New password must be different")
    db_ops.set_user_password_hash(current_user["id"], hash_password(request.new_password))
    db_ops.log_activity(current_user["id"], "password_changed", "Account password changed")
    return {"ok": True, "message": "Password changed successfully."}


@router.get("/api/v1/admin/overview")
def admin_overview(current_user: dict = Depends(require_admin)):
    db_ops.log_activity(current_user["id"], "admin_overview_view", "User and activity dashboard viewed")
    return db_ops.admin_overview()


@router.get("/api/v1/admin/stats", response_model=AdminStatsResponse)
def get_admin_stats(current_user: dict = Depends(require_admin)):
    stats = db_ops.admin_stats()
    uptime = max(0, int(time.monotonic() - _API_STARTED_AT))
    hours, remainder = divmod(uptime, 3600)
    minutes, seconds = divmod(remainder, 60)
    return {
        **stats,
        "api_status": "healthy",
        "uptime_seconds": uptime,
        "uptime_human": f"{hours}h {minutes}m {seconds}s",
        "database_status": stats.get("database_status", "unavailable"),
    }


@router.get("/api/v1/admin/users", response_model=List[AdminUserResponse])
def list_admin_users(current_user: dict = Depends(require_admin)):
    return db_ops.admin_users()


@router.put("/api/v1/admin/users/{user_id}/status")
def update_admin_user_status(user_id: int, request: AdminUserStatusRequest,
                             current_user: dict = Depends(require_admin)):
    if user_id == current_user["id"] and not request.is_active:
        raise HTTPException(status_code=400, detail="You cannot suspend your own administrator account")
    if not db_ops.set_user_active(user_id, request.is_active):
        raise HTTPException(status_code=404, detail="User not found or privileged administrator accounts cannot be changed here")
    state = "reactivated" if request.is_active else "suspended"
    db_ops.log_activity(current_user["id"], f"user_{state}", f"user_id={user_id}")
    return {"ok": True, "user_id": user_id, "is_active": request.is_active}


@router.get("/api/v1/admin/recent-vulnerabilities", response_model=List[AdminThreatResponse])
def get_recent_admin_vulnerabilities(current_user: dict = Depends(require_admin)):
    return db_ops.admin_recent_vulnerabilities(limit=5)


@lru_cache(maxsize=512)
def _geolocate_public_ip(ip: str) -> Optional[dict]:
    """Resolve coarse public-IP location for the admin-only aggregate map."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/",
                                headers={"User-Agent": "SiteWatch-Admin-Map/1.0"}, timeout=(1.5, 3.0))
        response.raise_for_status()
        data = response.json()
        latitude, longitude = data.get("latitude"), data.get("longitude")
        if latitude is None or longitude is None:
            return None
        return {"latitude": float(latitude), "longitude": float(longitude),
                "city": data.get("city"), "region": data.get("region"),
                "country": data.get("country_name") or data.get("country"),
                "organization": data.get("org")}
    except (requests.RequestException, ValueError, TypeError):
        return None


@router.get("/api/v1/admin/threat-map", response_model=AdminThreatMapResponse)
def get_admin_threat_map(current_user: dict = Depends(require_admin)):
    observed = db_ops.admin_recent_scan_ips(limit=100)
    safe_items = []
    for item in observed:
        try:
            if ipaddress.ip_address(item["ip"]).is_global:
                safe_items.append(item)
        except (ValueError, KeyError):
            continue
    with ThreadPoolExecutor(max_workers=6) as pool:
        locations = list(pool.map(lambda item: _geolocate_public_ip(item["ip"]), safe_items[:18]))
    points = []
    for item, location in zip(safe_items[:18], locations):
        if location:
            points.append({**item, **location})
    return {"points": points, "source": "Coarse IP geolocation for public IPs from saved scan DNS observations"}


@router.post("/api/v1/admin/users/{user_id}/suspend")
def suspend_user(user_id: int, current_user: dict = Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="You cannot suspend your own admin account")
    if not db_ops.set_user_active(user_id, False):
        raise HTTPException(status_code=404, detail="User not found or is an administrator")
    db_ops.log_activity(current_user["id"], "user_suspended", f"user_id={user_id}")
    return {"ok": True, "user_id": user_id, "is_active": False}


@router.post("/api/v1/admin/users/{user_id}/activate")
def activate_user(user_id: int, current_user: dict = Depends(require_admin)):
    if not db_ops.set_user_active(user_id, True):
        raise HTTPException(status_code=404, detail="User not found or is an administrator")
    db_ops.log_activity(current_user["id"], "user_activated", f"user_id={user_id}")
    return {"ok": True, "user_id": user_id, "is_active": True}


# Asset Management Endpoints (CRUD)

@router.get("/api/v1/assets", response_model=List[AssetResponse])
def list_assets(current_user: dict = Depends(get_current_user)):
    """Retrieve all assets owned by the authenticated user."""
    db_ops.log_activity(current_user["id"], "asset_list_view", "Asset inventory viewed")
    return AssetService.list_assets(current_user["id"])


@router.post("/api/v1/assets", response_model=AssetResponse, status_code=201)
def create_asset(request: AssetCreateRequest, current_user: dict = Depends(get_current_user)):
    """Create a new asset for the authenticated user."""
    asset = AssetService.create_asset(current_user["id"], request.model_dump())
    db_ops.log_activity(current_user["id"], "asset_created", asset.get("hostname", ""))
    return asset


@router.get("/api/v1/assets/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, current_user: dict = Depends(get_current_user)):
    """Retrieve a specific asset owned by the authenticated user."""
    db_ops.log_activity(current_user["id"], "asset_view", f"asset_id={asset_id}")
    return AssetService.get_asset(asset_id, current_user["id"])


@router.put("/api/v1/assets/{asset_id}", response_model=AssetResponse)
def update_asset(asset_id: int, request: AssetUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update an existing asset owned by the authenticated user."""
    asset = AssetService.update_asset(asset_id, current_user["id"], request.model_dump(exclude_unset=True))
    db_ops.log_activity(current_user["id"], "asset_updated", f"asset_id={asset_id}")
    return asset


@router.delete("/api/v1/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, current_user: dict = Depends(get_current_user)):
    """Delete an asset owned by the authenticated user."""
    AssetService.delete_asset(asset_id, current_user["id"])
    db_ops.log_activity(current_user["id"], "asset_deleted", f"asset_id={asset_id}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Protected Scanner & Scan History Endpoints

@router.get("/api/v1/cve/lookup", response_model=List[CVEInfo])
def lookup_cve(
    software: str = Query(..., description="Software name to look up"),
    version: str = Query(..., description="Version of the software")
):
    """Look up CVEs for a specific software and version from the local database."""
    return CveService.lookup(software, version)


@router.get("/api/v1/cve/search", response_model=List[CVEInfo])
def search_cve(
    query: str = Query(..., description="Search query term")
):
    """Search for CVEs in the local database using a keyword."""
    return CveService.search(query)


@router.get("/api/v1/scans", response_model=List[SavedScanSummary])
def list_scans(current_user: dict = Depends(get_current_user)):
    """Retrieve all previously stored scan summaries belonging to the authenticated user."""
    db_ops.log_activity(current_user["id"], "scan_history_view", "Scan history viewed")
    return ScannerService.list_user_scans(current_user["id"])


@router.post("/api/v1/scans/schedule", response_model=ScheduledScanResponse, status_code=201)
def create_scan_schedule(request: ScheduledScanCreateRequest,
                         current_user: dict = Depends(get_current_user),
                         _scan_key: None = Depends(require_scan_key)):
    try:
        target_url = validate_public_website_target(request.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    schedule = db_ops.create_scheduled_scan(current_user["id"], target_url, request.frequency_hours)
    db_ops.log_activity(current_user["id"], "scan_schedule_created",
                        f"schedule_id={schedule['id']}; frequency_hours={request.frequency_hours}")
    return schedule


@router.get("/api/v1/scans/scheduled", response_model=List[ScheduledScanResponse])
def list_my_scan_schedules(current_user: dict = Depends(get_current_user)):
    return db_ops.list_scheduled_scans(current_user["id"])


@router.delete("/api/v1/scans/scheduled/{schedule_id}", status_code=204)
def delete_my_scan_schedule(schedule_id: int, current_user: dict = Depends(get_current_user)):
    if not db_ops.delete_scheduled_scan(schedule_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    db_ops.log_activity(current_user["id"], "scan_schedule_deleted", f"schedule_id={schedule_id}")
    return Response(status_code=204)


@router.get("/api/v1/scans/{scan_id}", response_model=SavedScanResponse)
def get_single_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Retrieve a detailed scan report belonging to the user."""
    scan = ScannerService.get_user_scan(scan_id, current_user["id"])
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found or access denied"
        )
    db_ops.log_activity(current_user["id"], "scan_report_view", f"scan_id={scan_id}")
    return scan


@router.get("/api/v1/scans/{scan_id}/report", response_class=HTMLResponse)
def get_single_scan_report(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Generate and return the HTML report for a stored scan ID."""
    scan = ScannerService.get_user_scan(scan_id, current_user["id"])
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found or access denied"
        )

    db_ops.log_activity(current_user["id"], "html_report_view", f"scan_id={scan_id}")
    html_content = ScannerService.generate_html_report(scan)
    return HTMLResponse(content=html_content)


@router.get("/api/v1/scans/{scan_id}/pdf")
def get_single_scan_pdf(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Generate and return the PDF report for a stored scan ID."""
    scan = ScannerService.get_user_scan(scan_id, current_user["id"])
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan with ID {scan_id} not found or access denied"
        )
    db_ops.log_activity(current_user["id"], "pdf_report_download", f"scan_id={scan_id}")
    try:
        pdf_bytes = ScannerService.generate_pdf_report(scan)
        safe_target = "".join(c for c in scan.get("target", "unknown") if c.isalnum() or c in ".-_")
        filename = f"scan_{safe_target}_{scan_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"inline; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {str(e)}"
        )


@router.get("/api/v1/scans/{scan_id}/report/pdf")
def download_scan_pdf(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Download a PDF report for a scan owned by the authenticated user."""
    scan = ScannerService.get_user_scan(scan_id, current_user["id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    try:
        pdf_bytes = ScannerService.generate_pdf_report(scan)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report") from exc
    db_ops.log_activity(current_user["id"], "pdf_report_download", f"scan_id={scan_id}")
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{scan_id}.pdf"'},
    )


@router.get("/api/v1/scans/{scan_id}/report/json")
def download_scan_json(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Download the stored scan report as JSON, scoped to its owner."""
    scan = ScannerService.get_user_scan(scan_id, current_user["id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    db_ops.log_activity(current_user["id"], "json_report_download", f"scan_id={scan_id}")
    return JSONResponse(
        content=jsonable_encoder(scan),
        headers={"Content-Disposition": f'attachment; filename="report_{scan_id}.json"'},
    )


def _run_bulk_website_analysis(job_id: int, user_id: int, targets: List[str]) -> None:
    """Run targets sequentially in a background worker and persist progress after each target."""
    results = [{"target": target, "status": "queued"} for target in targets]
    db_ops.update_bulk_scan_job(job_id, user_id, "running", results)
    for index, target in enumerate(targets):
        results[index] = {"target": target, "status": "running"}
        db_ops.update_bulk_scan_job(job_id, user_id, "running", results)
        try:
            report = analyze_website(target)
            scan_id = db_ops.save_scan({
                "target": report["target"], "status": "Completed", "scan_profile": "Website posture",
                "ports_scanned": 0, "findings": report.get("findings", []),
                "http_assessment": {"checks": report.get("checks", {}), "score": report.get("score"),
                                    "grade": report.get("grade"), "data_source": report.get("data_source")},
                "details": report,
                "risk_summary": {"max_cvss_score": 0, "weighted_risk_score": 0, "host_severity": "N/A"},
            }, user_id=user_id)
            account = db_ops.get_user_by_id(user_id) or {}
            dispatch_scan_notifications(
                user_id, scan_id, report,
                email_report=account.get("role") in {"admin", "company_admin"},
            )
            levels = {}
            for finding in report.get("findings", []):
                severity = str(finding.get("severity", "INFO")).upper()
                levels[severity] = levels.get(severity, 0) + 1
            results[index] = {
                "id": scan_id, "target": report.get("target", target), "status": "completed",
                "score": report.get("score"), "grade": report.get("grade"),
                "num_findings": len(report.get("findings", [])), "timestamp": report.get("observed_at"),
                "severity_counts": levels,
            }
            db_ops.log_activity(user_id, "website_analysis_bulk", report.get("target", target))
        except ValueError as exc:
            results[index] = {"target": target, "status": "failed", "error": str(exc)[:400]}
        except Exception as exc:
            results[index] = {"target": target, "status": "failed", "error": f"Live analysis failed ({type(exc).__name__})"}

        final_status = "running"
        if index == len(targets) - 1:
            final_status = "partial" if any(item.get("status") == "failed" for item in results) else "completed"
        db_ops.update_bulk_scan_job(job_id, user_id, final_status, results)


@router.post("/api/v1/analyze/bulk", status_code=202)
def start_bulk_website_analysis(
    request: BulkWebsiteAnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    _scan_key: None = Depends(require_scan_key),
):
    """Queue a persisted bulk scan job; poll its status endpoint for progress and results."""
    targets = [url.strip() for url in request.urls if isinstance(url, str) and url.strip()]
    if not targets:
        raise HTTPException(status_code=422, detail="Provide at least one non-empty URL")
    if len(targets) > 20:
        raise HTTPException(status_code=422, detail="Bulk scans are limited to 20 targets per job")
    if any(len(target) > 2048 for target in targets):
        raise HTTPException(status_code=422, detail="Each target must be at most 2048 characters")
    job = db_ops.create_bulk_scan_job(current_user["id"], targets)
    db_ops.log_activity(current_user["id"], "bulk_scan_started", f"job_id={job['job_id']}; targets={len(targets)}")
    background_tasks.add_task(_run_bulk_website_analysis, job["job_id"], current_user["id"], targets)
    return {**job, "poll_url": f"/api/v1/analyze/bulk/{job['job_id']}"}


@router.get("/api/v1/analyze/bulk/{job_id}")
def get_bulk_website_analysis(job_id: int, current_user: dict = Depends(get_current_user)):
    """Return progress and completed scan summaries for a user's bulk job."""
    job = db_ops.get_bulk_scan_job(job_id, current_user["id"])
    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan job not found")
    return job


@router.post("/api/v1/analyze", status_code=201)
def analyze_public_website(request: WebsiteAnalyzeRequest, background_tasks: BackgroundTasks,
                           current_user: dict = Depends(get_current_user),
                           _scan_key: None = Depends(require_scan_key)):
    """Run live TLS, DNS and HTTP checks against an authorized public website."""
    try:
        report = analyze_website(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Live analysis could not complete: {type(exc).__name__}")
    scan_id = db_ops.save_scan({
        "target": report["target"], "status": "Completed", "scan_profile": "Website posture",
        "ports_scanned": 1, "findings": report["findings"],
        "http_assessment": {"checks": report["checks"], "score": report["score"], "grade": report["grade"], "data_source": report["data_source"]},
        "details": report,
        "risk_summary": {"max_cvss_score": 0, "weighted_risk_score": 0, "host_severity": "N/A"}
    }, user_id=current_user["id"])
    db_ops.log_activity(current_user["id"], "website_analysis", report["target"])
    report["id"] = scan_id
    background_tasks.add_task(
        dispatch_scan_notifications, current_user["id"], scan_id, report,
        current_user.get("role") in {"admin", "company_admin"},
    )
    return report


