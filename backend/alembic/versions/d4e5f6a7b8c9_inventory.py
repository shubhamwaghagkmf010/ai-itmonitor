"""add machine_inventory table

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'machine_inventory',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('hardware', sa.JSON(), nullable=True),
        sa.Column('software', sa.JSON(), nullable=True),
        sa.Column('software_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('machine_id'),
    )
    op.create_index(op.f('ix_machine_inventory_id'), 'machine_inventory', ['id'], unique=False)
    op.create_index(op.f('ix_machine_inventory_machine_id'), 'machine_inventory', ['machine_id'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_machine_inventory_machine_id'), table_name='machine_inventory')
    op.drop_index(op.f('ix_machine_inventory_id'), table_name='machine_inventory')
    op.drop_table('machine_inventory')
