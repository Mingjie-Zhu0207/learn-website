import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(ROOT / "instance")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(DATA_DIR / "homework.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
    phone TEXT UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0,1)),
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_admin_role ON users(role) WHERE role = 'admin';
CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    due_at TEXT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES users(id),
    note TEXT NOT NULL DEFAULT '',
    original_filename TEXT,
    stored_filename TEXT,
    submitted_at TEXT NOT NULL,
    grade TEXT,
    feedback TEXT NOT NULL DEFAULT '',
    graded_at TEXT,
    UNIQUE(assignment_id, student_id)
);
CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON submissions(assignment_id);
CREATE INDEX IF NOT EXISTS idx_assignments_teacher ON assignments(created_by);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
"""


def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _backup_before_migration(connection):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = DB_PATH.with_name(f"{DB_PATH.name}.pre-roles-{stamp}.bak")
    backup = sqlite3.connect(backup_path)
    try:
        connection.backup(backup)
    finally:
        backup.close()
    return backup_path


def _migrate_legacy_users(connection):
    old_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()[0] or ""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    needs_rebuild = (
        "admin" not in old_sql.lower()
        or not {"phone", "is_active", "must_change_password"}.issubset(columns)
    )
    if not needs_rebuild:
        return None

    backup_path = _backup_before_migration(connection)
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
                phone TEXT UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
                must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0,1)),
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            INSERT INTO users_new(id,username,display_name,password_hash,role,phone,is_active,must_change_password,created_at)
            SELECT id,username,display_name,password_hash,
                   CASE WHEN role IN ('admin','teacher','student') THEN role ELSE 'student' END,
                   NULL,1,0,created_at
            FROM users
        """)
        connection.execute("DROP TABLE users")
        connection.execute("ALTER TABLE users_new RENAME TO users")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(f"Foreign-key check failed after migration: {violations[:5]}")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")
    return backup_path


def initialize_database(database_path=None):
    global DB_PATH
    if database_path is not None:
        DB_PATH = Path(database_path)
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        if _table_exists(connection, "users"):
            _migrate_legacy_users(connection)
        connection.executescript(SCHEMA)
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(f"Foreign-key check failed: {violations[:5]}")
    finally:
        connection.close()
