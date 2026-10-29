```python
import streamlit as st
import sqlite3
import hashlib
import secrets
from pathlib import Path
from datetime import datetime

# ---------------- CONFIGURATION ----------------

st.set_page_config(
    page_title="BlogSpace | Secure Dashboard",
    page_icon="🔐",
    layout="wide"
)

DB_PATH = Path(__file__).parent / "blogspace.db"


# ---------------- DATABASE ----------------

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (author_id) REFERENCES users(id)
            );
        """)

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(blogs)"
            ).fetchall()
        }

        if "category" not in columns:
            conn.execute("""
                ALTER TABLE blogs
                ADD COLUMN category TEXT NOT NULL DEFAULT 'General'
            """)

        if "author" not in columns:
            conn.execute("""
                ALTER TABLE blogs
                ADD COLUMN author TEXT NOT NULL DEFAULT 'Guest'
            """)

        if "updated_at" not in columns:
            conn.execute("""
                ALTER TABLE blogs
                ADD COLUMN updated_at TEXT
            """)

            conn.execute("""
                UPDATE blogs
                SET updated_at = created_at
                WHERE updated_at IS NULL
            """)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        200000
    ).hex()

    return password_hash, salt


def register_user(name, email, password):
    password_hash, salt = hash_password(password)

    try:
        with get_connection() as conn:
            conn.execute("""
                INSERT INTO users
                (name, email, password_hash, salt, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name.strip(),
                email.strip().lower(),
                password_hash,
                salt,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

        return True, "Registration successful!"

    except sqlite3.IntegrityError:
        return False, "This email is already registered."


def login_user(email, password):
    with get_connection() as conn:
        user = conn.execute("""
            SELECT * FROM users WHERE email = ?
        """, (email.strip().lower(),)).fetchone()

    if user is None:
        return None

    password_hash, _ = hash_password(
        password,
        user["salt"]
    )

    if secrets.compare_digest(
        password_hash,
        user["password_hash"]
    ):
        return {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }

    return None


def get_user(user_id):
    with get_connection() as conn:
        return conn.execute("""
            SELECT id, name, email, created_at
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()


def update_profile(user_id, name):
    with get_connection() as conn:
        conn.execute("""
            UPDATE users
            SET name = ?
            WHERE id = ?
        """, (name.strip(), user_id))


def get_user_blogs(user_id):
    with get_connection() as conn:
        return conn.execute("""
            SELECT *
            FROM blogs
            WHERE author_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()


def get_blog_count(user_id):
    with get_connection() as conn:
        return conn.execute("""
            SELECT COUNT(*)
            FROM blogs
            WHERE author_id = ?
        """, (user_id