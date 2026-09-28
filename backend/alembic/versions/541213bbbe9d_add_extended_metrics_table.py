"""add extended_metrics table

Revision ID: 541213bbbe9d
Revises: 2ef2a49e2b84
Create Date: 2026-09-24 11:18:21.802462

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '541213bbbe9d'
down_revision: Union[str, None] = '2ef2a49e2b84'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'extended_metrics',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('services', sa.JSON(), nullable=True),
        sa.Column('containers', sa.JSON(), nullable=True),
        sa.Column('sensors', sa.JSON(), nullable=True),
        sa.Column('disks_smart', sa.JSON(), nullable=True),
        sa.Column('gpu', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_extended_metrics_id'), 'extended_metrics', ['id'], unique=False)
    op.create_index(op.f('ix_extended_metrics_machine_id'), 'extended_metrics', ['machine_id'], unique=False)
    op.create_index(op.f('ix_extended_metrics_timestamp'), 'extended_metrics', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_extended_metrics_timestamp'), table_name='extended_metrics')
    op.drop_index(op.f('ix_extended_metrics_machine_id'), table_name='extended_metrics')
    op.drop_index(op.f('ix_extended_metrics_id'), table_name='extended_metrics')
    op.drop_table('extended_metrics')
