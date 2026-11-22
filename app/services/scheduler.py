"""Persistent scheduled website scans, polled from the MySQL schedule table."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import logging
import os
import threading

from apscheduler.schedulers.background import BackgroundScheduler

from app import database as db_ops
from app.scanner.website_analyzer import analyze_website
from app.services.notifications import dispatch_scan_notifications

logger = logging.getLogger(__name__)
_scheduler: BackgroundScheduler | None = None
_scan_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="scheduled-scan")
_active_lock = threading.Lock()
_active_scans = 0


def _execute_schedule(job: dict) -> None:
    schedule_id = job["id"]
    try:
        report = analyze_website(job["target_url"])
        scan_id = db_ops.save_scan({
            "target": report["target"],
            "status": "Completed",
            "scan_profile": "Scheduled website posture",
            "ports_scanned": 0,
            "findings": report.get("findings", []),
            "http_assessment": {
                "checks": report.get("checks", {}), "score": report.get("score"),
                "grade": report.get("grade"), "data_source": report.get("data_source"),
            },
            "details": report,
            "risk_summary": {"max_cvss_score": 0, "weighted_risk_score": 0, "host_severity": "N/A"},
        }, user_id=job["user_id"])
        db_ops.finish_scheduled_scan(schedule_id, "completed")
        dispatch_scan_notifications(job["user_id"], scan_id, report, email_report=True)
        logger.info("Scheduled scan completed: schedule_id=%s scan_id=%s", schedule_id, scan_id)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:800]}"
        db_ops.finish_scheduled_scan(schedule_id, "failed", error)
        logger.exception("Scheduled scan failed: schedule_id=%s", schedule_id)


def _claim_and_submit_due_scans() -> None:
    global _active_scans
    try:
        with _active_lock:
            available = max(0, 3 - _active_scans)
        if not available:
            return
        due_jobs = db_ops.claim_due_scheduled_scans(limit=available)
        for job in due_jobs:
            with _active_lock:
                _active_scans += 1
            def run_and_release(claimed=job):
                global _active_scans
                try:
                    _execute_schedule(claimed)
                finally:
                    with _active_lock:
                        _active_scans -= 1
            try:
                _scan_executor.submit(run_and_release)
            except RuntimeError:
                with _active_lock:
                    _active_scans -= 1
                db_ops.finish_scheduled_scan(job["id"], "failed", "Scheduler executor is shutting down")
    except Exception:
        logger.exception("Unable to claim due scheduled scans")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        return
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _claim_and_submit_due_scans,
        trigger="interval",
        seconds=max(15, int(os.getenv("SCHEDULE_POLL_SECONDS", "30"))),
        id="scheduled_website_scans",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=30,
    )
    _scheduler.start()
    logger.info("Scheduled scan worker started")


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
    _scheduler = None
    _scan_executor.shutdown(wait=False, cancel_futures=False)
