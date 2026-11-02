import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TEST_ROOT = tempfile.TemporaryDirectory(prefix="chengyu-tests-")
os.environ["DATA_DIR"] = str(Path(TEST_ROOT.name) / "data")
os.environ["DATABASE_PATH"] = str(Path(TEST_ROOT.name) / "data" / "tests.sqlite3")
os.environ["UPLOAD_DIR"] = str(Path(TEST_ROOT.name) / "uploads")
os.environ["SECRET_KEY"] = "test-only-secret-key"
os.environ.pop("ADMIN_USERNAME", None)
os.environ.pop("ADMIN_PASSWORD", None)
os.environ.pop("TEACHER_INVITE_CODE", None)

import app as website
from werkzeug.security import check_password_hash, generate_password_hash

website.app.config.update(TESTING=True, SECRET_KEY="test-secret")


def clear_data():
    with website.app.app_context():
        connection = website.db()
        connection.execute("DELETE FROM audit_logs")
        connection.execute("DELETE FROM submissions")
        connection.execute("DELETE FROM assignments")
        connection.execute("DELETE FROM users")
        connection.commit()


def add_user(username, role, password="Password-for-test-123", active=1, must_change=0):
    with website.app.app_context():
        cursor = website.db().execute(
            "INSERT INTO users(username,display_name,password_hash,role,is_active,must_change_password,created_at) VALUES(?,?,?,?,?,?,?)",
            (username, username.title(), generate_password_hash(password), role, active, must_change, website.now()),
        )
        website.db().commit()
        return cursor.lastrowid


def csrf_token(client, path="/login"):
    client.get(path)
    with client.session_transaction() as session:
        return session["csrf_token"]


def login(client, username, password="Password-for-test-123"):
    token = csrf_token(client)
    return client.post("/login", data={"csrf_token": token, "username": username, "password": password})


class AuthAndRoleTests(unittest.TestCase):
    def setUp(self):
        clear_data()
        self.client = website.app.test_client()

    def test_public_registration_ignores_privilege_fields(self):
        token = csrf_token(self.client, "/register")
        response = self.client.post("/register", data={
            "csrf_token": token, "username": "new_student", "display_name": "学生",
            "password": "student-pass-123", "role": "admin", "teacher_code": "anything",
        })
        self.assertEqual(response.status_code, 302)
        with website.app.app_context():
            row = website.db().execute("SELECT role FROM users WHERE username='new_student'").fetchone()
            self.assertEqual(row["role"], "student")
        page = self.client.get("/register").get_data(as_text=True)
        self.assertNotIn("teacher_code", page)
        self.assertNotIn("教师邀请口令", page)

    def test_student_and_teacher_routes_are_server_side_restricted(self):
        add_user("student1", "student")
        login(self.client, "student1")
        self.assertEqual(self.client.get("/assignments/new").status_code, 403)
        self.assertEqual(self.client.get("/admin/teachers").status_code, 403)

    def test_admin_cli_creates_only_one_hashed_admin(self):
        runner = website.app.test_cli_runner()
        password = "Long-random-admin-password-2026"
        result = runner.invoke(args=["create-admin"], input=f"site_admin\n{password}\n{password}\n")
        self.assertEqual(result.exit_code, 0, result.output)
        with website.app.app_context():
            row = website.db().execute("SELECT * FROM users WHERE username='site_admin'").fetchone()
            self.assertEqual(row["role"], "admin")
            self.assertTrue(check_password_hash(row["password_hash"], password))
            self.assertNotEqual(row["password_hash"], password)
        again = runner.invoke(args=["create-admin"], input=f"other_admin\n{password}\n{password}\n")
        self.assertNotEqual(again.exit_code, 0)
        self.assertIn("只能成功执行一次", again.output)

    def test_admin_creates_teacher_with_one_time_password_and_forced_change(self):
        add_user("site_admin", "admin")
        login(self.client, "site_admin")
        token = csrf_token(self.client, "/admin/teachers/new")
        response = self.client.post("/admin/teachers/new", data={
            "csrf_token": token, "username": "teacher_new", "display_name": "新教师",
        })
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        match = re.search(r'class="password-value">([^<]+)<', page)
        self.assertIsNotNone(match)
        temporary_password = match.group(1)
        self.assertGreaterEqual(len(temporary_password), 20)
        with website.app.app_context():
            row = website.db().execute("SELECT * FROM users WHERE username='teacher_new'").fetchone()
            self.assertEqual(row["role"], "teacher")
            self.assertEqual(row["must_change_password"], 1)
            self.assertTrue(check_password_hash(row["password_hash"], temporary_password))
            log = website.db().execute("SELECT action,details FROM audit_logs WHERE target_id=?", (row["id"],)).fetchone()
            self.assertEqual(log["action"], "teacher.created")
            self.assertNotIn(temporary_password, log["details"])
        teacher_client = website.app.test_client()
        response = login(teacher_client, "teacher_new", temporary_password)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/change-password", response.headers["Location"])
        new_password = "changed-teacher-password-2026"
        token = csrf_token(teacher_client, "/change-password")
        response = teacher_client.post("/change-password", data={
            "csrf_token": token, "password": new_password, "confirm_password": new_password,
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        with website.app.app_context():
            row = website.db().execute("SELECT must_change_password FROM users WHERE username='teacher_new'").fetchone()
            self.assertEqual(row["must_change_password"], 0)

    def test_disabled_account_session_is_cleared(self):
        user_id = add_user("disabled_teacher", "teacher", active=0)
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["csrf_token"] = "token"
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_admin_can_disable_and_restore_teacher_with_audit_log(self):
        add_user("site_admin", "admin")
        teacher_id = add_user("teacher_status", "teacher")
        login(self.client, "site_admin")
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(f"/admin/teachers/{teacher_id}/status", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        with website.app.app_context():
            teacher = website.db().execute("SELECT is_active FROM users WHERE id=?", (teacher_id,)).fetchone()
            self.assertEqual(teacher["is_active"], 0)
        disabled_client = website.app.test_client()
        login_response = login(disabled_client, "teacher_status")
        self.assertEqual(login_response.status_code, 200)
        self.assertIn("用户名或密码不正确", login_response.get_data(as_text=True))
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(f"/admin/teachers/{teacher_id}/status", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        with website.app.app_context():
            teacher = website.db().execute("SELECT is_active FROM users WHERE id=?", (teacher_id,)).fetchone()
            self.assertEqual(teacher["is_active"], 1)
            events = website.db().execute("SELECT action FROM audit_logs WHERE target_id=? ORDER BY id", (teacher_id,)).fetchall()
            self.assertEqual([event["action"] for event in events], ["teacher.disabled", "teacher.enabled"])
    def test_teacher_cannot_read_or_grade_another_teachers_assignment(self):
        teacher_a = add_user("teacher_a", "teacher")
        teacher_b = add_user("teacher_b", "teacher")
        student = add_user("student_x", "student")
        with website.app.app_context():
            cursor = website.db().execute("INSERT INTO assignments(title,created_by,created_at) VALUES('作业B',?,?)", (teacher_b, website.now()))
            assignment_id = cursor.lastrowid
            cursor = website.db().execute("INSERT INTO submissions(assignment_id,student_id,note,submitted_at) VALUES(?,?,?,?)", (assignment_id, student, "答案", website.now()))
            submission_id = cursor.lastrowid
            website.db().commit()
        teacher_client = website.app.test_client()
        login(teacher_client, "teacher_a")
        self.assertEqual(teacher_client.get(f"/assignments/{assignment_id}").status_code, 403)
        # A valid CSRF token is obtained from another authenticated page.
        with teacher_client.session_transaction() as session:
            token = session["csrf_token"]
        response = teacher_client.post(f"/submissions/{submission_id}/grade", data={
            "csrf_token": token, "grade": "100", "feedback": "越权尝试",
        })
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
