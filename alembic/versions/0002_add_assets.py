"""Add assets table and asset_id to scans

Revision ID: 0002_add_assets
Revises: 0001_initial
Create Date: 2026-08-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_add_assets'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create assets table
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(length=100), nullable=False),
        sa.Column('ip_address', sa.String(length=255), nullable=False),
        sa.Column('operating_system', sa.String(length=100), nullable=True),
        sa.Column('criticality', sa.String(length=20), nullable=False),
        sa.Column('owner_team', sa.String(length=100), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'], unique=False)

    # Add asset_id to scans
    op.add_column('scans', sa.Column('asset_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_scans_asset_id', 'scans', 'assets', ['asset_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_constraint('fk_scans_asset_id', 'scans', type_='foreignkey')
    op.drop_column('scans', 'asset_id')
    op.drop_index(op.f('ix_assets_id'), table_name='assets')
    op.drop_table('assets')
