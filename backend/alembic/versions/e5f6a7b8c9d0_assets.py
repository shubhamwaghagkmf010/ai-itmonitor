"""add assets table

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=True),
        sa.Column('asset_no', sa.String(length=80), nullable=True),
        sa.Column('category', sa.String(length=120), nullable=True),
        sa.Column('sub_category', sa.String(length=120), nullable=True),
        sa.Column('host_name', sa.String(length=255), nullable=True),
        sa.Column('make', sa.String(length=120), nullable=True),
        sa.Column('model', sa.String(length=160), nullable=True),
        sa.Column('allocation_type', sa.String(length=120), nullable=True),
        sa.Column('allocation_purpose', sa.String(length=255), nullable=True),
        sa.Column('serial_no', sa.String(length=160), nullable=True),
        sa.Column('processor_type', sa.String(length=200), nullable=True),
        sa.Column('ram', sa.String(length=60), nullable=True),
        sa.Column('hard_disk_size', sa.String(length=60), nullable=True),
        sa.Column('os_architecture', sa.String(length=40), nullable=True),
        sa.Column('os_version', sa.String(length=160), nullable=True),
        sa.Column('os_edition', sa.String(length=160), nullable=True),
        sa.Column('license_key', sa.String(length=120), nullable=True),
        sa.Column('warranty_start', sa.String(length=40), nullable=True),
        sa.Column('warranty_end', sa.String(length=40), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'], unique=False)
    op.create_index(op.f('ix_assets_machine_id'), 'assets', ['machine_id'], unique=False)
    op.create_index(op.f('ix_assets_host_name'), 'assets', ['host_name'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_assets_host_name'), table_name='assets')
    op.drop_index(op.f('ix_assets_machine_id'), table_name='assets')
    op.drop_index(op.f('ix_assets_id'), table_name='assets')
    op.drop_table('assets')
