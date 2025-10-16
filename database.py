import sqlite3
import hashlib
import os

DB_NAME = "secure_file_transfer.db"

def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def setup_database():
    """
    Sets up the SQLite database.
    Creates 'users' and 'transfer_logs' tables if they don't exist.
    Adds a default admin user if no users exist.
    """
    # Remove existing database file for a clean setup, optional
    if os.path.exists(DB_NAME):
        print(f"Removing existing database {DB_NAME} for a fresh start.")
        os.remove(DB_NAME)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    print("Table 'users' created or already exists.")

    # Create transfer_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transfer_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            status TEXT NOT NULL,
            notes TEXT
        )
    ''')
    print("Table 'transfer_logs' created or already exists.")

    # Check if any user exists
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    # If no users exist, add a default admin user
    if user_count == 0:
        default_username = "admin"
        default_password = "password"
        hashed_password = hash_password(default_password)
        
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (default_username, hashed_password))
        print(f"Default user '{default_username}' created with password '{default_password}'.")
        print("Please consider changing this password for any real-world use.")
    else:
        print("Users already exist in the database. No default user was added.")


    conn.commit()
    conn.close()
    print("Database setup complete.")

if __name__ == "__main__":
    print("Initializing database setup...")
    setup_database()
