import sqlite3
import os

DB = "ictds.db"

def migrate():
    if not os.path.exists(DB):
        print("No database found to migrate.")
        return

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # Check if 'is_admin' exists in 'users'
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'is_admin' not in columns:
        print("Adding 'is_admin' column to 'users'...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")

    # Check if 'user_id' exists and rename to 'id' if necessary
    if 'user_id' in columns:
        print("Renaming 'user_id' to 'id' in 'users'...")
        # SQLite doesn't support RENAME COLUMN in older versions (<3.25.0)
        # But we can try the new syntax first
        try:
            cursor.execute("ALTER TABLE users RENAME COLUMN user_id TO id")
        except sqlite3.OperationalError:
            # Fallback for older SQLite: recreate table
            print("Using fallback migration for renaming column...")
            cursor.execute("CREATE TABLE users_new (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, created DATETIME DEFAULT CURRENT_TIMESTAMP)")
            cursor.execute("INSERT INTO users_new (id, username, password, is_admin, created) SELECT user_id, username, password, is_admin, created FROM users")
            cursor.execute("DROP TABLE users")
            cursor.execute("ALTER TABLE users_new RENAME TO users")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
