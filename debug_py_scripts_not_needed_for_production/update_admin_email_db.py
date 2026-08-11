import pymysql
from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE

new_email = 'admin@s.jyotishsanchar.com.np'

conn = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE)
try:
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT id, username, email, role FROM users WHERE username='admin' LIMIT 5")
        rows = cur.fetchall()
        print('Before:', rows)
        if rows:
            cur.execute("UPDATE users SET email=%s WHERE username='admin'", (new_email,))
            conn.commit()
            cur.execute("SELECT id, username, email, role FROM users WHERE username='admin' LIMIT 5")
            print('After:', cur.fetchall())
        else:
            print('No matching admin records found')
finally:
    conn.close()
