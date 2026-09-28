"""add scan_ranges table and source_subnet on network_devices

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_ranges',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('target', sa.String(length=120), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_ranges_id'), 'scan_ranges', ['id'], unique=False)
    op.add_column('network_devices', sa.Column('source_subnet', sa.String(length=120), nullable=True))


def downgrade() -> None:
    op.drop_column('network_devices', 'source_subnet')
    op.drop_index(op.f('ix_scan_ranges_id'), table_name='scan_ranges')
    op.drop_table('scan_ranges')
