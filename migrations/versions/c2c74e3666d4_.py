"""empty message

Revision ID: c2c74e3666d4
Revises: c15189bf80e6
Create Date: 2022-08-25 16:22:51.945961

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c2c74e3666d4'
down_revision = 'c15189bf80e6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('states',
    sa.Column('serialnumber', sa.Integer(), nullable=False),
    sa.Column('state_or_ut', sa.String(), nullable=False),
    sa.Column('MPH', sa.Integer(), nullable=True),
    sa.Column('Athletic_track', sa.Integer(), nullable=True),
    sa.Column('Football_field', sa.Integer(), nullable=True),
    sa.Column('Hockey_field', sa.Integer(), nullable=True),
    sa.Column('swimming_pool', sa.Integer(), nullable=True),
    sa.Column('others', sa.Integer(), nullable=True),
    sa.Column('total', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('serialnumber')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('states')
    # ### end Alembic commands ###