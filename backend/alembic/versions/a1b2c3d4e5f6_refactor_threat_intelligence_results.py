"""refactor_threat_intelligence_results_columns

Revision ID: a1b2c3d4e5f6
Revises: 895e6cc3c039
Create Date: 2026-10-13

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '895e6cc3c039'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Replace old generic columns with refined threat intel fields."""
    # Drop old columns
    op.drop_column('threat_intelligence_results', 'source')
    op.drop_column('threat_intelligence_results', 'detections')
    op.drop_column('threat_intelligence_results', 'raw_response')

    # Add new columns
    op.add_column('threat_intelligence_results',
        sa.Column('total_engines_flagged', sa.Integer(), server_default='0', nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('total_engines_checked', sa.Integer(), server_default='0', nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('threat_score', sa.Float(), server_default='0.0', nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('threat_intel_failed', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('never_seen_before', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('rate_limited_incomplete', sa.Boolean(), server_default='false', nullable=True))

    # Add unique constraint on scan_id (one-to-one)
    op.create_unique_constraint('uq_threat_intelligence_results_scan_id', 'threat_intelligence_results', ['scan_id'])


def downgrade() -> None:
    """Revert to original generic columns."""
    op.drop_constraint('uq_threat_intelligence_results_scan_id', 'threat_intelligence_results', type_='unique')

    op.drop_column('threat_intelligence_results', 'rate_limited_incomplete')
    op.drop_column('threat_intelligence_results', 'never_seen_before')
    op.drop_column('threat_intelligence_results', 'threat_intel_failed')
    op.drop_column('threat_intelligence_results', 'threat_score')
    op.drop_column('threat_intelligence_results', 'total_engines_checked')
    op.drop_column('threat_intelligence_results', 'total_engines_flagged')

    op.add_column('threat_intelligence_results',
        sa.Column('source', sa.String(), nullable=False, server_default='virustotal'))
    op.add_column('threat_intelligence_results',
        sa.Column('detections', sa.Integer(), nullable=True))
    op.add_column('threat_intelligence_results',
        sa.Column('raw_response', sa.JSON(), nullable=True))
