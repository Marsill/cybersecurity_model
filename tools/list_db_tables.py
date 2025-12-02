import sqlite3
import os
import glob

cwd = os.path.abspath(os.getcwd())
print('cwd:', cwd)

db_files = glob.glob(os.path.join(cwd, '**', '*.db'), recursive=True)
if not db_files:
    print('No .db files found')
else:
    for fn in db_files:
        print('\nDB file:', fn)
        try:
            conn = sqlite3.connect(fn)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cur.fetchall()
            print('tables:', tables)
            if any(t[0].lower() == 'users' for t in tables):
                cur.execute('SELECT id,username,email,otp_secret FROM users')
                rows = cur.fetchall()
                print('users rows (first 5):', rows[:5])
            conn.close()
        except Exception as e:
            print('error reading', fn, e)
