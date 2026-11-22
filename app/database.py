import json
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text, func

from app.db_config import SessionLocal, engine, Base
from app.models import User, Scan, Asset, ActivityLog, BulkScanJob, ScheduledScan
from app.scanner.risk_scorer import RiskScorer

def init_db():
    """Require a reachable, migrated MySQL database; schema changes use Alembic."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

def log_activity(user_id: int, action: str, details: Optional[str] = None) -> None:
    db = SessionLocal()
    try:
        db.add(ActivityLog(user_id=user_id, action=action, details=details))
        db.commit()
    finally:
        db.close()

def bootstrap_admin(username: str, password_hash: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            user = User(username=username, password_hash=password_hash, role="admin", is_active=1)
            db.add(user)
        else:
            user.role = "admin"
            user.is_active = 1
            user.password_hash = password_hash
        db.commit()
    finally:
        db.close()

def admin_overview() -> Dict[str, Any]:
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        events = db.query(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(500).all()
        return {
            "users": [{"id": u.id, "username": u.username, "role": u.role, "is_active": bool(u.is_active),
                       "created_at": u.created_at.isoformat() if u.created_at else None,
                       "scan_count": len(u.scans)} for u in users],
            "activity": [{"id": e.id, "user_id": e.user_id, "username": e.user.username,
                          "action": e.action, "details": e.details,
                          "created_at": e.created_at.isoformat()} for e in events],
        }
    finally:
        db.close()

def set_user_active(user_id: int, active: bool) -> bool:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id, ~User.role.in_(["admin", "company_admin"])).first()
        if not user:
            return False
        user.is_active = 1 if active else 0
        db.commit()
        return True
    finally:
        db.close()


def admin_stats() -> Dict[str, Any]:
    """Return live user/scan counts and database health for the admin console."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {
            "total_users": int(db.query(func.count(User.id)).scalar() or 0),
            "total_scans": int(db.query(func.count(Scan.id)).scalar() or 0),
            "database_status": "healthy",
        }
    except Exception:
        db.rollback()
        return {"total_users": None, "total_scans": None, "database_status": "unavailable"}
    finally:
        db.close()


def admin_users() -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        scan_counts = dict(db.query(Scan.user_id, func.count(Scan.id))
                           .filter(Scan.user_id.isnot(None)).group_by(Scan.user_id).all())
        return [{
            "id": user.id, "username": user.username, "full_name": user.full_name,
            "email": user.email, "role": user.role, "is_active": bool(user.is_active),
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "scan_count": int(scan_counts.get(user.id, 0)),
        } for user in users]
    finally:
        db.close()


def admin_recent_vulnerabilities(limit: int = 5) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.started_at.desc(), Scan.id.desc()).limit(500).all()
        recent = []
        for scan in scans:
            try:
                payload = json.loads(scan.results_json or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            details = payload.get("details") or {}
            if not isinstance(details, dict):
                details = {}
            findings = payload.get("findings") or details.get("findings") or []
            if not isinstance(findings, list):
                findings = []
            if not findings:
                findings = [finding for item in payload.get("results", []) if isinstance(item, dict)
                            for finding in (item.get("vulnerabilities", []) + item.get("findings", []))]
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity", "INFO")).upper()
                if severity not in {"HIGH", "CRITICAL"}:
                    continue
                recent.append({
                    "scan_id": scan.id, "target": scan.target or "Unknown target",
                    "title": finding.get("title") or finding.get("check_id") or finding.get("cve_id") or "Security finding",
                    "severity": severity, "evidence": finding.get("evidence"),
                    "created_at": (scan.started_at or scan.timestamp).isoformat() if (scan.started_at or scan.timestamp) else None,
                })
                if len(recent) >= limit:
                    return recent
        return recent
    finally:
        db.close()


def admin_recent_scan_ips(limit: int = 100) -> List[Dict[str, Any]]:
    """Return unique public IPs observed in recent stored DNS results."""
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.started_at.desc(), Scan.id.desc()).limit(limit).all()
        points, seen = [], set()
        for scan in scans:
            try:
                payload = json.loads(scan.results_json or "{}")
                details = payload.get("details") or {}
                addresses = (details.get("checks") or {}).get("dns", {}).get("addresses", [])
            except (TypeError, ValueError, AttributeError):
                continue
            for address in addresses:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if parsed.is_global and str(parsed) not in seen:
                    seen.add(str(parsed))
                    points.append({"ip": str(parsed), "target": scan.target or "Unknown target", "scan_id": scan.id})
        return points[:30]
    finally:
        db.close()

# User Management Database Functions

def create_user(username: str, password_hash: str, full_name: Optional[str] = None, email: Optional[str] = None) -> int:
    """Insert a new user into the database using SQLAlchemy."""
    db: Session = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise ValueError("Username already exists")
        if email and db.query(User).filter(User.email == email.lower()).first():
            raise ValueError("Email address is already registered")
        user = User(
            username=username,
            password_hash=password_hash,
            full_name=(full_name or "").strip(),
            email=email.lower() if email else None,
            is_verified=0,
            created_at=datetime.now(timezone.utc)
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    finally:
        db.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve a user record by username."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        return {
            "id": user.id,
            "username": user.username,
            "password_hash": user.password_hash,
            "role": user.role,
            "is_active": bool(user.is_active),
            "full_name": user.full_name,
            "email": user.email,
            "is_verified": bool(user.is_verified),
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else ""
        }
    finally:
        db.close()

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve user info by database ID."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "is_active": bool(user.is_active),
            "full_name": user.full_name,
            "email": user.email,
            "is_verified": bool(user.is_verified),
            "avatar_filename": user.avatar_filename,
            "webhook_url": user.webhook_url,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else ""
        }
    finally:
        db.close()

def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve an account by case-insensitive username or email for login/reset flows."""
    db: Session = SessionLocal()
    try:
        normalized = identifier.strip().casefold()
        user = db.query(User).filter(
            (func.lower(User.username) == normalized) | (func.lower(User.email) == normalized)
        ).first()
        if not user:
            return None
        return {"id": user.id, "username": user.username, "email": user.email,
                "full_name": user.full_name, "password_hash": user.password_hash,
                "role": user.role, "is_active": bool(user.is_active),
                "is_verified": bool(user.is_verified)}
    finally:
        db.close()

def save_password_reset_token(email: str, token_hash: str, expires_at: datetime) -> bool:
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email.strip().lower(), User.is_active == 1).first()
        if not user:
            return False
        user.password_reset_token_hash = token_hash
        user.password_reset_expires_at = expires_at.replace(tzinfo=None)
        db.commit()
        return True
    finally:
        db.close()

def reset_password_by_token(token_hash: str, password_hash: str) -> bool:
    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        user = db.query(User).filter(
            User.password_reset_token_hash == token_hash,
            User.password_reset_expires_at > now,
            User.is_active == 1,
        ).first()
        if not user:
            return False
        user.password_hash = password_hash
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        db.commit()
        return True
    finally:
        db.close()

def update_user_profile(user_id: int, full_name: Optional[str], email: Optional[str], webhook_url: Optional[str] = None) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise LookupError("Account not found")
        normalized_email = email.strip().lower() if email else None
        if normalized_email:
            duplicate = db.query(User).filter(User.email == normalized_email, User.id != user_id).first()
            if duplicate:
                raise ValueError("Email address is already used by another account")
        if user.email != normalized_email:
            user.is_verified = 0
            user.password_reset_token_hash = None
            user.password_reset_expires_at = None
        user.full_name = full_name.strip() if full_name and full_name.strip() else None
        user.email = normalized_email
        if webhook_url is not None:
            user.webhook_url = webhook_url.strip() or None
        db.commit()
        return {"id": user.id, "username": user.username, "role": user.role,
                "full_name": user.full_name, "email": user.email,
                "is_verified": bool(user.is_verified),
                "webhook_url": user.webhook_url,
                "avatar_url": f"/api/v1/users/me/avatar?v={user.avatar_filename}" if user.avatar_filename else None}
    finally:
        db.close()

def set_user_avatar(user_id: int, filename: str) -> Optional[str]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            return None
        previous = user.avatar_filename
        user.avatar_filename = filename
        db.commit()
        return previous
    finally:
        db.close()

def set_user_password_hash(user_id: int, password_hash: str) -> bool:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            return False
        user.password_hash = password_hash
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        db.commit()
        return True
    finally:
        db.close()


def _format_scheduled_scan(job: ScheduledScan) -> Dict[str, Any]:
    def iso(value):
        return value.replace(tzinfo=timezone.utc).isoformat() if value and value.tzinfo is None else value.isoformat() if value else None
    return {
        "id": job.id, "user_id": job.user_id, "target_url": job.target_url,
        "frequency_hours": job.frequency_hours, "last_run": iso(job.last_run),
        "next_run": iso(job.next_run), "is_active": bool(job.is_active),
        "last_status": job.last_status, "last_error": job.last_error,
        "created_at": iso(job.created_at),
    }


def create_scheduled_scan(user_id: int, target_url: str, frequency_hours: int) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        job = ScheduledScan(user_id=user_id, target_url=target_url,
                            frequency_hours=frequency_hours,
                            next_run=now + timedelta(hours=frequency_hours), is_active=1)
        db.add(job)
        db.commit()
        db.refresh(job)
        return _format_scheduled_scan(job)
    finally:
        db.close()


def list_scheduled_scans(user_id: int) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        jobs = db.query(ScheduledScan).filter(ScheduledScan.user_id == user_id).order_by(ScheduledScan.created_at.desc()).all()
        return [_format_scheduled_scan(job) for job in jobs]
    finally:
        db.close()


def delete_scheduled_scan(job_id: int, user_id: int) -> bool:
    db = SessionLocal()
    try:
        job = db.query(ScheduledScan).filter(ScheduledScan.id == job_id, ScheduledScan.user_id == user_id).first()
        if not job:
            return False
        db.delete(job)
        db.commit()
        return True
    finally:
        db.close()


def claim_due_scheduled_scans(limit: int = 5) -> List[Dict[str, Any]]:
    """Atomically claim due rows so only one scheduler process runs each due scan."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        jobs = (db.query(ScheduledScan)
                .filter(ScheduledScan.is_active == 1, ScheduledScan.next_run <= now,
                        ScheduledScan.owner.has(User.is_active == 1))
                .order_by(ScheduledScan.next_run.asc(), ScheduledScan.id.asc())
                .with_for_update(skip_locked=True).limit(limit).all())
        claimed = []
        for job in jobs:
            job.last_run = now
            job.next_run = now + timedelta(hours=job.frequency_hours)
            job.last_status = "running"
            job.last_error = None
            claimed.append({"id": job.id, "user_id": job.user_id, "target_url": job.target_url,
                            "frequency_hours": job.frequency_hours})
        db.commit()
        return claimed
    finally:
        db.close()


def finish_scheduled_scan(job_id: int, status: str, error: Optional[str] = None) -> None:
    db = SessionLocal()
    try:
        job = db.query(ScheduledScan).filter(ScheduledScan.id == job_id).first()
        if job:
            job.last_status = status[:20]
            job.last_error = error[:1000] if error else None
            db.commit()
    finally:
        db.close()


# Asset Management Database Functions

def create_asset(
    user_id: int,
    hostname: str,
    ip_address: str,
    operating_system: Optional[str] = None,
    criticality: str = "Medium",
    owner_team: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new asset for a given user."""
    db: Session = SessionLocal()
    try:
        # Check duplicate ip_address or hostname for the same user
        existing = db.query(Asset).filter(
            Asset.user_id == user_id,
            (Asset.hostname == hostname) | (Asset.ip_address == ip_address)
        ).first()
        if existing:
            raise ValueError("An asset with this hostname or IP address already exists.")

        asset = Asset(
            hostname=hostname,
            ip_address=ip_address,
            operating_system=operating_system,
            criticality=criticality,
            owner_team=owner_team,
            description=description,
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return format_asset(asset)
    finally:
        db.close()

def get_all_assets(user_id: int) -> List[Dict[str, Any]]:
    """Get all assets for a given user."""
    db: Session = SessionLocal()
    try:
        assets = db.query(Asset).filter(Asset.user_id == user_id).order_by(Asset.id.desc()).all()
        return [format_asset(a) for a in assets]
    finally:
        db.close()

def get_asset_by_id(asset_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Get a single asset by ID for a given user."""
    db: Session = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == user_id).first()
        if not asset:
            return None
        return format_asset(asset, include_scans=True)
    finally:
        db.close()

def update_asset(
    asset_id: int,
    user_id: int,
    hostname: Optional[str] = None,
    ip_address: Optional[str] = None,
    operating_system: Optional[str] = None,
    criticality: Optional[str] = None,
    owner_team: Optional[str] = None,
    description: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Update an existing asset."""
    db: Session = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == user_id).first()
        if not asset:
            return None

        if hostname and hostname != asset.hostname:
            existing = db.query(Asset).filter(Asset.user_id == user_id, Asset.hostname == hostname, Asset.id != asset_id).first()
            if existing:
                raise ValueError("An asset with this hostname already exists.")
            asset.hostname = hostname

        if ip_address and ip_address != asset.ip_address:
            existing = db.query(Asset).filter(Asset.user_id == user_id, Asset.ip_address == ip_address, Asset.id != asset_id).first()
            if existing:
                raise ValueError("An asset with this IP address already exists.")
            asset.ip_address = ip_address

        if operating_system is not None:
            asset.operating_system = operating_system
        if criticality is not None:
            asset.criticality = criticality
        if owner_team is not None:
            asset.owner_team = owner_team
        if description is not None:
            asset.description = description

        asset.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(asset)
        return format_asset(asset)
    finally:
        db.close()

def delete_asset(asset_id: int, user_id: int) -> bool:
    """Delete an asset for a given user."""
    db: Session = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == user_id).first()
        if not asset:
            return False
        db.delete(asset)
        db.commit()
        return True
    finally:
        db.close()

def format_asset(asset: Asset, include_scans: bool = False) -> Dict[str, Any]:
    """Helper to convert Asset model to dict."""
    res = {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "operating_system": asset.operating_system,
        "criticality": asset.criticality,
        "owner": asset.owner_team,
        "description": asset.description,
        "created_at": asset.created_at.strftime("%Y-%m-%d %H:%M:%S") if asset.created_at else "",
        "updated_at": asset.updated_at.strftime("%Y-%m-%d %H:%M:%S") if asset.updated_at else "",
        "user_id": asset.user_id
    }
    if include_scans and asset.scans:
        res["scans"] = [
            {
                "id": s.id,
                "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.timestamp else "",
                "ports_scanned": s.ports_scanned,
                "max_cvss_score": s.max_cvss_score,
                "weighted_risk_score": s.weighted_risk_score,
                "host_severity": s.host_severity,
            }
            for s in sorted(asset.scans, key=lambda x: x.id, reverse=True)
        ]
    elif include_scans:
        res["scans"] = []
    return res


# Scan Management Database Functions

def save_scan(scan_data: Dict[str, Any], user_id: Optional[int] = None, asset_id: Optional[int] = None) -> int:
    """Save a scan result to PostgreSQL database linked to user_id and optionally asset_id."""
    db: Session = SessionLocal()
    try:
        target = scan_data.get("target")
        results = scan_data.get("results", [])
        ports_scanned = scan_data.get("ports_scanned", 0)

        risk_summary = scan_data.get("risk_summary", {})
        max_cvss = risk_summary.get("max_cvss_score", 0.0)
        weighted_risk = risk_summary.get("weighted_risk_score", 0.0)
        host_severity = risk_summary.get("host_severity", "NONE")

        # Save structured container holding results, http_assessment, and findings
        container = {
            "results": results,
            "http_assessment": scan_data.get("http_assessment"),
            "findings": scan_data.get("findings", []),
            "details": scan_data.get("details", {})
        }
        results_json = json.dumps(container)

        scan_profile = scan_data.get("scan_profile")
        status = scan_data.get("status", "Completed")
        duration = scan_data.get("duration")

        scan_record = Scan(
            target=target,
            timestamp=datetime.now(timezone.utc),
            ports_scanned=ports_scanned,
            max_cvss_score=max_cvss,
            weighted_risk_score=weighted_risk,
            host_severity=host_severity,
            results_json=results_json,
            user_id=user_id,
            asset_id=asset_id,
            scan_profile=scan_profile,
            status=status,
            duration=duration,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc) if status == "Completed" else None
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        return scan_record.id
    finally:
        db.close()


def create_bulk_scan_job(user_id: int, targets: List[str]) -> Dict[str, Any]:
    db: Session = SessionLocal()
    try:
        initial_results = [{"target": target, "status": "queued"} for target in targets]
        job = BulkScanJob(user_id=user_id, status="queued", total_targets=len(targets), completed_targets=0,
                          targets_json=json.dumps(targets), results_json=json.dumps(initial_results))
        db.add(job)
        db.commit()
        db.refresh(job)
        return _format_bulk_scan_job(job)
    finally:
        db.close()


def update_bulk_scan_job(job_id: int, user_id: int, status: str, results: List[Dict[str, Any]]) -> bool:
    db: Session = SessionLocal()
    try:
        job = db.query(BulkScanJob).filter(BulkScanJob.id == job_id, BulkScanJob.user_id == user_id).first()
        if not job:
            return False
        job.status = status
        job.results_json = json.dumps(results)
        job.completed_targets = sum(1 for item in results if item.get("status") in {"completed", "failed"})
        job.updated_at = datetime.now(timezone.utc)
        db.commit()
        return True
    finally:
        db.close()


def get_bulk_scan_job(job_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    db: Session = SessionLocal()
    try:
        job = db.query(BulkScanJob).filter(BulkScanJob.id == job_id, BulkScanJob.user_id == user_id).first()
        return _format_bulk_scan_job(job) if job else None
    finally:
        db.close()


def _format_bulk_scan_job(job: BulkScanJob) -> Dict[str, Any]:
    try:
        results = json.loads(job.results_json or "[]")
    except (TypeError, ValueError):
        results = []
    return {"job_id": job.id, "status": job.status, "total_targets": job.total_targets,
            "completed_targets": job.completed_targets, "results": results,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "updated_at": job.updated_at.isoformat() if job.updated_at else None}

def _parse_scan_payload(raw_json: Optional[str]) -> tuple[List[dict], Optional[dict], List[dict], int]:
    """Helper to parse results_json for list vs dict format."""
    if not raw_json:
        return [], None, [], 0
    try:
        data = json.loads(raw_json)
        if isinstance(data, list):
            results = data
            all_vulns = []
            for r in results:
                all_vulns.extend(r.get("vulnerabilities", []))
            return results, None, [], len(all_vulns)
        elif isinstance(data, dict):
            results = data.get("results", [])
            http_assessment = data.get("http_assessment")
            findings = data.get("findings", [])
            
            # Count findings
            num = len(findings)
            if num == 0:
                num = sum(len(r.get("vulnerabilities", [])) + len(r.get("findings", [])) for r in results)
            return results, http_assessment, findings, num
    except Exception:
        pass
    return [], None, [], 0


def _posture_score(details: Dict[str, Any], http_assessment: Optional[dict], findings: List[dict]) -> tuple[Optional[int], Optional[str]]:
    score = details.get("score")
    grade = details.get("grade")
    if score is None and isinstance(http_assessment, dict):
        score = http_assessment.get("score")
        grade = grade or http_assessment.get("grade")
    if score is None:
        checks = details.get("checks") or (http_assessment.get("checks", {}) if isinstance(http_assessment, dict) else {})
        dns_observed = bool(checks.get("dns", {}).get("addresses"))
        tls = checks.get("tls", {})
        tls_observed = bool(tls.get("supported_protocols") or tls.get("certificate_chain") or tls.get("issuer"))
        if not (dns_observed and tls_observed):
            return None, grade
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        breakdown = details.get("score_breakdown") or []
        if breakdown:
            deductions = sum(int(item.get("deduction", 0)) for item in breakdown)
        else:
            unique = {}
            for index, finding in enumerate(findings):
                key = finding.get("check_id") or finding.get("cve_id") or finding.get("id") or finding.get("title") or index
                unique[str(key)] = (str(finding.get("severity", "INFO")).upper(), finding.get("confidence", "high"))
            deductions = sum(weights.get(severity, 0) for severity, confidence in unique.values() if confidence == "high")
        score = max(0, 100 - min(100, deductions))
    try:
        score = int(score)
    except (TypeError, ValueError):
        return None, grade
    if not grade or grade == "INCOMPLETE":
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade

def get_all_scans(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieve scan summaries from PostgreSQL, optionally filtered by user_id."""
    db: Session = SessionLocal()
    try:
        query = db.query(Scan)
        if user_id is not None:
            query = query.filter(Scan.user_id == user_id)
        scans = query.order_by(Scan.id.desc()).all()

        res_list = []
        for s in scans:
            results, http_assessment, findings, num_findings = _parse_scan_payload(s.results_json)
            details = (json.loads(s.results_json or "{}").get("details") or {})
            observed_findings = list(findings)
            for result in results:
                observed_findings.extend(result.get("vulnerabilities", []))
                observed_findings.extend(result.get("findings", []))
            severity_by_finding = {}
            for index, finding in enumerate(observed_findings):
                key = finding.get("check_id") or finding.get("cve_id") or finding.get("id") or finding.get("title") or f"finding-{index}"
                severity_by_finding[str(key)] = str(finding.get("severity", "INFO")).upper()
            severity_counts = {level: sum(1 for value in severity_by_finding.values() if value == level)
                               for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
            posture_score, posture_grade = _posture_score(details, http_assessment, observed_findings)
            res_list.append({
                "id": s.id,
                "target": s.target,
                "timestamp": s.started_at.strftime("%Y-%m-%d %H:%M:%S") if s.started_at else (s.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.timestamp else ""),
                "duration": s.duration,
                "status": s.status,
                "scan_profile": s.scan_profile,
                "ports_scanned": s.ports_scanned,
                "max_cvss_score": s.max_cvss_score,
                "weighted_risk_score": s.weighted_risk_score,
                "score": posture_score,
                "grade": posture_grade,
                "severity_counts": severity_counts,
                "critical_count": severity_counts["CRITICAL"],
                "host_severity": s.host_severity,
                "num_findings": num_findings,
                "user_id": s.user_id,
                "asset_id": s.asset_id,
                "asset_hostname": s.asset.hostname if s.asset else None,
                "compliance_signals": details.get("compliance_signals")
            })
        return res_list
    finally:
        db.close()

def get_scan(scan_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a specific scan record from PostgreSQL."""
    db: Session = SessionLocal()
    try:
        query = db.query(Scan).filter(Scan.id == scan_id)
        if user_id is not None:
            query = query.filter(Scan.user_id == user_id)
        s = query.first()

        if not s:
            return None

        results, http_assessment, findings, num_findings = _parse_scan_payload(s.results_json)
        
        all_vulns = []
        for res in results:
            all_vulns.extend(res.get("vulnerabilities", []))

        risk_summary = RiskScorer.calculate_host_risk(all_vulns)

        # If HTTP findings exist and no explicit findings array was stored, compile them
        if not findings:
            findings = []
            for res in results:
                for v in res.get("vulnerabilities", []):
                    findings.append({
                        "id": v.get("cve_id"),
                        "type": "CVE",
                        "title": f"{v.get('cve_id')} - {v.get('software')}",
                        "severity": v.get("severity", "MEDIUM"),
                        "cvss_score": v.get("cvss_score", 0.0),
                        "port": res.get("port"),
                        "service": res.get("service"),
                        "description": v.get("description"),
                        "recommendation": v.get("remediation")
                    })
                for hf in res.get("findings", []):
                    if hf not in findings:
                        findings.append(hf)

        details = (json.loads(s.results_json or "{}").get("details") or {})
        posture_score, posture_grade = _posture_score(details, http_assessment, findings)
        if posture_score is not None:
            details["score"] = posture_score
            details["grade"] = posture_grade
            if isinstance(http_assessment, dict):
                http_assessment["score"] = posture_score
                http_assessment["grade"] = posture_grade

        return {
            "id": s.id,
            "target": s.target,
            "timestamp": s.started_at.strftime("%Y-%m-%d %H:%M:%S") if s.started_at else (s.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.timestamp else ""),
            "duration": s.duration,
            "status": s.status,
            "scan_profile": s.scan_profile,
            "ports_scanned": s.ports_scanned,
            "max_cvss_score": s.max_cvss_score,
            "weighted_risk_score": s.weighted_risk_score,
            "score": posture_score,
            "grade": posture_grade,
            "host_severity": s.host_severity,
            "num_findings": num_findings,
            "results_json": s.results_json,
            "user_id": s.user_id,
            "asset_id": s.asset_id,
            "asset_hostname": s.asset.hostname if s.asset else None,
            "results": results,
            "risk_summary": risk_summary,
            "http_assessment": http_assessment,
            "findings": findings,
            "details": details
        }
    finally:
        db.close()
