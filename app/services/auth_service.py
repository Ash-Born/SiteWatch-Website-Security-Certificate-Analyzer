"""
Service layer for Authentication and User management.
"""

from typing import Optional, Dict, Any
import re
from fastapi import HTTPException, status

from app.auth import hash_password, verify_password, create_access_token
import app.database as database


class AuthService:
    """Service class for user registration and authentication."""

    @staticmethod
    def register_user(username: str, password: str, full_name: str, email: str) -> Dict[str, Any]:
        username = username.strip()
        full_name = full_name.strip()
        email = email.strip().lower()
        if username.strip().casefold() == "admin":
            raise HTTPException(status_code=400, detail="This username is reserved")
        if not full_name:
            raise HTTPException(status_code=422, detail="Full name is required")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise HTTPException(status_code=422, detail="Enter a valid email address")
        domain = email.rsplit("@", 1)[-1].casefold()
        blocked_domains = {"example.com", "test.com", "mailinator.com"}
        if domain in blocked_domains or any(domain.endswith("." + blocked) for blocked in blocked_domains):
            raise HTTPException(status_code=422, detail="Use a non-disposable email address")
        if len(password) < 8 or not re.search(r"[0-9]|[^A-Za-z0-9]", password):
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters and include a number or special character")
        if len(password.encode("utf-8")) > 72:
            raise HTTPException(status_code=422, detail="Password must be at most 72 UTF-8 bytes")
        existing_user = database.get_user_by_username(username)
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Username already taken"
            )
        if database.get_user_by_identifier(email):
            raise HTTPException(status_code=400, detail="Email address is already registered")
        try:
            p_hash = hash_password(password)
            user_id = database.create_user(username, p_hash, full_name=full_name, email=email)
            return {
                "id": user_id,
                "username": username,
                "full_name": full_name,
                "email": email,
                "message": "User registered successfully"
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error occurred")

    @staticmethod
    def authenticate_user(username: str, password: str) -> Dict[str, Any]:
        user = database.get_user_by_identifier(username)
        if not user or not user.get("is_active", True) or not verify_password(password, user["password_hash"]):
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )

        token_data = {"sub": str(user["id"]), "username": user["username"], "role": user.get("role", "user")}
        access_token = create_access_token(token_data)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user["id"],
            "username": user["username"],
            "role": user.get("role", "user"),
            "is_verified": bool(user.get("is_verified", False))
        }
