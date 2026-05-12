import sqlite3
import os

DB = "ictds.db"

def migrate():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    print("Migrating 'logs' table foreign keys...")
    try:
        # Recreate logs table with correct foreign key
        cursor.execute("CREATE TABLE logs_new (log_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, filename TEXT, traffic_data TEXT, prediction TEXT, confidence REAL, severity TEXT, is_threat INTEGER DEFAULT 0, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")
        cursor.execute("INSERT INTO logs_new (log_id, user_id, filename, traffic_data, prediction, confidence, severity, is_threat, timestamp) SELECT log_id, user_id, filename, traffic_data, prediction, confidence, severity, is_threat, timestamp FROM logs")
        cursor.execute("DROP TABLE logs")
        cursor.execute("ALTER TABLE logs_new RENAME TO logs")
        print("Logs table migration complete.")
    except Exception as e:
        print(f"Migration error: {e}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
