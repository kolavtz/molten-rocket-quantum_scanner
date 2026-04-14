"""2FA schema fix: add default value to two_factor_enabled column.

This migration ensures the two_factor_enabled column has a default value of 0,
fixing the issue where user creation would fail without explicitly setting this field.
"""

def upgrade():
    """Add default value to two_factor_enabled column."""
    import sys
    sys.path.append('.')
    from src import database as db
    
    conn = db._get_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute('''
                ALTER TABLE users 
                MODIFY COLUMN two_factor_enabled tinyint(1) NOT NULL DEFAULT 0
            ''')
            conn.commit()
            print('✓ Schema migration completed: two_factor_enabled now defaults to 0')
        except Exception as e:
            print(f'Migration warning: {e}')
        finally:
            conn.close()

if __name__ == '__main__':
    upgrade()
