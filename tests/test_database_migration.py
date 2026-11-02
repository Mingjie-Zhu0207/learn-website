import sqlite3
import tempfile
import unittest
from pathlib import Path

from database import initialize_database


class LegacyDatabaseMigrationTests(unittest.TestCase):
    def test_upgrade_preserves_users_assignments_submissions_and_creates_backup(self):
        with tempfile.TemporaryDirectory(prefix="chengyu-migration-") as temp:
            db_path = Path(temp) / "legacy.sqlite3"
            connection = sqlite3.connect(db_path)
            connection.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('student','teacher')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    due_at TEXT,
                    created_by INTEGER NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE submissions (
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
                INSERT INTO users(id,username,display_name,password_hash,role,created_at) VALUES
                  (1,'teacher1','Teacher','hash1','teacher','2025-01-01T00:00'),
                  (2,'student1','Student','hash2','student','2025-01-02T00:00');
                INSERT INTO assignments(id,title,description,created_by,created_at) VALUES
                  (10,'作业标题','说明',1,'2025-01-03T00:00');
                INSERT INTO submissions(id,assignment_id,student_id,note,submitted_at,grade,feedback) VALUES
                  (20,10,2,'原有答案','2025-01-04T00:00','88','保留评语');
            """)
            connection.commit()
            connection.close()

            initialize_database(db_path)

            connection = sqlite3.connect(db_path)
            connection.row_factory = sqlite3.Row
            users = connection.execute("SELECT * FROM users ORDER BY id").fetchall()
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["role"], "teacher")
            self.assertEqual(users[0]["is_active"], 1)
            self.assertIsNone(users[0]["phone"])
            self.assertEqual(users[1]["role"], "student")
            assignment = connection.execute("SELECT * FROM assignments WHERE id=10").fetchone()
            submission = connection.execute("SELECT * FROM submissions WHERE id=20").fetchone()
            self.assertEqual(assignment["title"], "作业标题")
            self.assertEqual(submission["note"], "原有答案")
            self.assertEqual(submission["grade"], "88")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            connection.close()
            backups = list(Path(temp).glob("legacy.sqlite3.pre-roles-*.bak"))
            self.assertEqual(len(backups), 1)


if __name__ == "__main__":
    unittest.main()
