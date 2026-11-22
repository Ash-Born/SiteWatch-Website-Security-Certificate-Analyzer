from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.db_config import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user", index=True)
    is_active = Column(Integer, nullable=False, default=1, index=True)
    full_name = Column(String(120), nullable=True)
    email = Column(String(254), nullable=True, unique=True, index=True)
    is_verified = Column(Integer, nullable=False, default=0, index=True)
    password_reset_token_hash = Column(String(64), nullable=True, unique=True)
    password_reset_expires_at = Column(DateTime, nullable=True)
    avatar_filename = Column(String(80), nullable=True)
    webhook_url = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    assets = relationship("Asset", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    activity = relationship("ActivityLog", back_populates="user", cascade="all, delete-orphan")
    scheduled_scans = relationship("ScheduledScan", back_populates="owner", cascade="all, delete-orphan")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(80), nullable=False, index=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    user = relationship("User", back_populates="activity")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False)
    ip_address = Column(String(255), nullable=False)
    operating_system = Column(String(100), nullable=True)
    criticality = Column(String(20), nullable=False, default="Medium")
    owner_team = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    owner = relationship("User", back_populates="assets")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=True)  # Made nullable since asset_id is preferred
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    ports_scanned = Column(Integer, nullable=True, default=0)
    max_cvss_score = Column(Float, nullable=True, default=0.0)
    weighted_risk_score = Column(Float, nullable=True, default=0.0)
    host_severity = Column(String(50), nullable=True, default="NONE")
    results_json = Column(Text, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)

    # Scan metadata fields
    scan_type = Column(String(50), nullable=True)
    status = Column(String(50), default="Pending")
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    scanner_version = Column(String(50), default="1.2.0")
    scan_profile = Column(String(50), nullable=True)

    owner = relationship("User", back_populates="scans")
    asset = relationship("Asset", back_populates="scans")


class BulkScanJob(Base):
    __tablename__ = "bulk_scan_jobs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="queued", index=True)
    total_targets = Column(Integer, nullable=False)
    completed_targets = Column(Integer, nullable=False, default=0)
    targets_json = Column(Text, nullable=False)
    results_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    frequency_hours = Column(Integer, nullable=False)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=False, index=True)
    is_active = Column(Integer, nullable=False, default=1, index=True)
    last_status = Column(String(20), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    owner = relationship("User", back_populates="scheduled_scans")

