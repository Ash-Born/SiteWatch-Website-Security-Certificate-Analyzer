"""Persist bulk website scan jobs and their progress.

Revision ID: 0007_bulk_scan_jobs
Revises: 0006_auth_verification_and_reset
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0007_bulk_scan_jobs"
down_revision: Union[str, None] = "0006_auth_verification_and_reset"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bulk_scan_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("total_targets", sa.Integer(), nullable=False),
        sa.Column("completed_targets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("targets_json", sa.Text(), nullable=False),
        sa.Column("results_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bulk_scan_jobs_user_id", "bulk_scan_jobs", ["user_id"], unique=False)
    op.create_index("ix_bulk_scan_jobs_status", "bulk_scan_jobs", ["status"], unique=False)
    op.alter_column("bulk_scan_jobs", "status", server_default=None)
    op.alter_column("bulk_scan_jobs", "completed_targets", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_bulk_scan_jobs_status", table_name="bulk_scan_jobs")
    op.drop_index("ix_bulk_scan_jobs_user_id", table_name="bulk_scan_jobs")
    op.drop_table("bulk_scan_jobs")
