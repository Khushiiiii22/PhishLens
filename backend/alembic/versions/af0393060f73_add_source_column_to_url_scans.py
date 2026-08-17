"""add_source_column_to_url_scans

Revision ID: af0393060f73
Revises: 95afd8a1f909
Create Date: 2026-08-13 19:38:22.922392

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'af0393060f73'
down_revision: Union[str, Sequence[str], None] = '95afd8a1f909'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Create the Postgres ENUM type
    source_enum = sa.Enum('email', 'social_media', 'message', name='source_enum')
    source_enum.create(op.get_bind(), checkfirst=True)

    # 2. Add the column with a temporary server_default for existing rows
    op.add_column('url_scans', sa.Column(
        'source',
        sa.Enum('email', 'social_media', 'message', name='source_enum'),
        nullable=False,
        server_default='email'
    ))

    # 3. Remove the server_default so future inserts must provide a value
    op.alter_column('url_scans', 'source', server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('url_scans', 'source')
    sa.Enum(name='source_enum').drop(op.get_bind(), checkfirst=True)

