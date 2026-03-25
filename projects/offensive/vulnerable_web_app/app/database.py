"""SQLite database setup with intentionally vulnerable seed data."""

import sqlite3
from pathlib import Path

from app.config import settings


def get_db() -> sqlite3.Connection:
    """Get a database connection. Returns rows as dictionaries."""
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables and seed with test data."""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            secret_note TEXT DEFAULT ''
        )
    """)

    # Products table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT,
            secret_flag TEXT DEFAULT ''
        )
    """)

    # Messages / guestbook table (for stored XSS)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Flags table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge TEXT UNIQUE NOT NULL,
            flag TEXT NOT NULL,
            captured INTEGER DEFAULT 0,
            captured_at TIMESTAMP
        )
    """)

    # Seed users - VULN: plaintext passwords, default credentials
    seed_users = [
        ("admin", "admin123", "admin@breach.local", "admin",
         "FLAG{sql_injection_union_master}"),
        ("guest", "guest", "guest@breach.local", "user", "Nothing here."),
        ("john", "password123", "john@breach.local", "user",
         "My secret API key: sk-1234567890"),
        ("jane", "letmein", "jane@breach.local", "moderator",
         "FLAG{idor_profile_access_granted}"),
        ("test", "test", "test@breach.local", "user", "Just a test account."),
        ("flag_keeper", "Fl4gK33p3r!", "flags@breach.local", "admin",
         "FLAG{auth_bypass_jwt_none_attack}"),
    ]

    for user in seed_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, role, secret_note) "
            "VALUES (?, ?, ?, ?, ?)",
            user,
        )

    # Seed products
    seed_products = [
        ("Laptop Pro X1", "High-performance laptop for professionals",
         1299.99, "electronics", ""),
        ("Wireless Mouse", "Ergonomic wireless mouse", 29.99, "electronics", ""),
        ("Python Cookbook", "Advanced Python programming recipes",
         49.99, "books", "FLAG{sqli_search_extraction_complete}"),
        ("Network Switch", "24-port managed network switch",
         199.99, "networking", ""),
        ("USB Rubber Ducky", "Keystroke injection tool",
         49.99, "security", ""),
    ]

    for product in seed_products:
        cursor.execute(
            "INSERT OR IGNORE INTO products (name, description, price, category, secret_flag) "
            "VALUES (?, ?, ?, ?, ?)",
            product,
        )

    # Seed flags
    seed_flags = [
        ("sqli_login", "FLAG{sql_injection_login_bypassed}"),
        ("sqli_search", "FLAG{sqli_search_extraction_complete}"),
        ("sqli_union", "FLAG{sql_injection_union_master}"),
        ("xss_reflected", "FLAG{xss_reflected_script_executed}"),
        ("xss_stored", "FLAG{xss_stored_in_guestbook}"),
        ("idor_access", "FLAG{idor_profile_access_granted}"),
        ("auth_bypass", "FLAG{auth_bypass_jwt_none_attack}"),
        ("cmd_injection", "FLAG{command_injection_rce_achieved}"),
        ("ssrf_internal", "FLAG{ssrf_internal_service_accessed}"),
        ("path_traversal", "FLAG{path_traversal_file_read}"),
        ("xxe_file_read", "FLAG{xxe_external_entity_expansion}"),
    ]

    for flag in seed_flags:
        cursor.execute(
            "INSERT OR IGNORE INTO flags (challenge, flag) VALUES (?, ?)",
            flag,
        )

    # Seed a guestbook message
    cursor.execute(
        "INSERT OR IGNORE INTO messages (id, author, content) VALUES (?, ?, ?)",
        (1, "Admin", "Welcome to the BREACH guestbook! Leave a message."),
    )

    conn.commit()
    conn.close()

    # Create sandbox files for path traversal challenge
    sandbox = Path(settings.FILES_DIR)
    sandbox.mkdir(parents=True, exist_ok=True)

    welcome = sandbox / "welcome.txt"
    if not welcome.exists():
        welcome.write_text(
            "Welcome to BREACH file storage!\n"
            "Try reading other files on the system...\n"
        )

    secret = sandbox / "secret.txt"
    if not secret.exists():
        secret.write_text("FLAG{path_traversal_file_read}\n")

    notes = sandbox / "notes.txt"
    if not notes.exists():
        notes.write_text(
            "Reminder: Update the server credentials.\n"
            "Current root password: toor\n"
        )
