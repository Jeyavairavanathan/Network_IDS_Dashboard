import sqlite3
from werkzeug.security import generate_password_hash
import getpass

DB = "ids.db"


username = input("Enter username: ").strip()
email = input("Enter email: ").strip()
password = getpass.getpass("Enter password: ")

if not username or not email or not password:
    print("All fields are required.")
    exit()

password_hash = generate_password_hash(password)

conn = sqlite3.connect(DB)

try:

    conn.execute(
        """
        INSERT INTO users
        (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        (
            username,
            email,
            password_hash
        )
    )

    conn.commit()

    print("\nUser created successfully.")
    print(f"Username: {username}")
    print(f"Email: {email}")

except sqlite3.IntegrityError:

    print("\nUsername or email already exists.")

finally:

    conn.close()