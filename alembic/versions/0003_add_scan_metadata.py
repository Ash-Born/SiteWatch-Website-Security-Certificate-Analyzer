"""Add scan metadata fields to scans table

Revision ID: 0003_add_scan_metadata
Revises: 0002_add_assets
Create Date: 2026-08-05 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_add_scan_metadata'
down_revision: Union[str, None] = '0002_add_assets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('scan_type', sa.String(length=50), nullable=True))
    op.add_column('scans', sa.Column('status', sa.String(length=50), server_default='Pending', nullable=True))
    op.add_column('scans', sa.Column('started_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('completed_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('duration', sa.Float(), nullable=True))
    op.add_column('scans', sa.Column('scanner_version', sa.String(length=50), server_default='1.2.0', nullable=True))
    op.add_column('scans', sa.Column('scan_profile', sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'scan_profile')
    op.drop_column('scans', 'scanner_version')
    op.drop_column('scans', 'duration')
    op.drop_column('scans', 'completed_at')
    op.drop_column('scans', 'started_at')
    op.drop_column('scans', 'status')
    op.drop_column('scans', 'scan_type')
