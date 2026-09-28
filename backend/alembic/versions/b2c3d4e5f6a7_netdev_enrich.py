"""add os_guess and open_ports to network_devices

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('network_devices', sa.Column('os_guess', sa.String(length=50), nullable=True))
    op.add_column('network_devices', sa.Column('open_ports', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('network_devices', 'open_ports')
    op.drop_column('network_devices', 'os_guess')
