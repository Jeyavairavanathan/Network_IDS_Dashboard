import sqlite3


DB = "ids.db"


conn = sqlite3.connect(DB)
cursor = conn.cursor()


# --------------------------------------------------
# KNOWN DEVICES
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS known_devices (
    ip TEXT PRIMARY KEY,
    hostname TEXT
)
""")


# --------------------------------------------------
# DEVICES
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    status TEXT
)
""")


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    message TEXT,
    level TEXT,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")


# --------------------------------------------------
# SCAN AUTHORIZATION AUDIT
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    target_network TEXT,
    purpose TEXT,
    authorization TEXT,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")


# --------------------------------------------------
# USERS
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    reset_code TEXT,
    reset_expires TEXT
)
""")


# --------------------------------------------------
# SAVE DATABASE CHANGES
# --------------------------------------------------

conn.commit()
conn.close()


print("Database initialized successfully.")