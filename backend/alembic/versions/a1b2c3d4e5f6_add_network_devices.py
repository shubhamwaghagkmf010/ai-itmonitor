"""add network_devices table

Revision ID: a1b2c3d4e5f6
Revises: 541213bbbe9d
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '541213bbbe9d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'network_devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=50), nullable=False),
        sa.Column('mac_address', sa.String(length=50), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('vendor', sa.String(length=120), nullable=True),
        sa.Column('device_type', sa.String(length=60), nullable=True),
        sa.Column('is_online', sa.Boolean(), nullable=False),
        sa.Column('notes', sa.String(length=255), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_network_devices_id'), 'network_devices', ['id'], unique=False)
    op.create_index(op.f('ix_network_devices_ip_address'), 'network_devices', ['ip_address'], unique=False)
    op.create_index(op.f('ix_network_devices_mac_address'), 'network_devices', ['mac_address'], unique=False)
    op.create_index(op.f('ix_network_devices_last_seen'), 'network_devices', ['last_seen'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_network_devices_last_seen'), table_name='network_devices')
    op.drop_index(op.f('ix_network_devices_mac_address'), table_name='network_devices')
    op.drop_index(op.f('ix_network_devices_ip_address'), table_name='network_devices')
    op.drop_index(op.f('ix_network_devices_id'), table_name='network_devices')
    op.drop_table('network_devices')
