import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(ROOT / "instance")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(DATA_DIR / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "homework.db"))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "20"))
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "txt", "zip", "jpg", "jpeg", "png"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or "local-only-" + secrets.token_hex(24),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", "") == "true",
)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','teacher')),
            created_at TEXT NOT NULL
        );
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
    """)
    admin_name = os.environ.get("ADMIN_USERNAME", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if admin_name and admin_password:
        found = connection.execute("SELECT id FROM users WHERE username = ?", (admin_name,)).fetchone()
        if not found:
            connection.execute(
                "INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (admin_name, "教师管理员", generate_password_hash(admin_password), "teacher", now()),
            )
    connection.commit()
    connection.close()


def now():
    return datetime.now().astimezone().isoformat(timespec="minutes")


init_db()

@app.before_request
def prepare_request():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    if "user_id" in session and getattr(g, "user", None) is None:
        g.user = db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_globals():
    return {"csrf_token": session.get("csrf_token", ""), "current_user": getattr(g, "user", None)}


def verify_csrf():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400, "表单已过期，请刷新页面后重试。")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not getattr(g, "user", None):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def teacher_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "teacher":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@login_required
def home():
    if g.user["role"] == "teacher":
        assignments = db().execute("""
            SELECT a.*, COUNT(s.id) AS submission_count
            FROM assignments a LEFT JOIN submissions s ON s.assignment_id = a.id
            GROUP BY a.id ORDER BY a.created_at DESC
        """).fetchall()
        return render_template("home.html", assignments=assignments, teacher=True)
    assignments = db().execute("""
        SELECT a.*, u.display_name AS teacher_name, s.id AS submission_id,
               s.submitted_at, s.grade, s.feedback
        FROM assignments a JOIN users u ON a.created_by = u.id
        LEFT JOIN submissions s ON s.assignment_id = a.id AND s.student_id = ?
        ORDER BY a.created_at DESC
    """, (g.user["id"],)).fetchall()
    return render_template("home.html", assignments=assignments, teacher=False)


@app.route("/register", methods=["GET", "POST"])
def register():
    if getattr(g, "user", None):
        return redirect(url_for("home"))
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        invite_code = os.environ.get("TEACHER_INVITE_CODE", "")
        role = "teacher" if invite_code and request.form.get("teacher_code") and secrets.compare_digest(request.form["teacher_code"], invite_code) else "student"
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
            flash("用户名需为 3–40 位字母、数字、下划线或连字符。", "error")
        elif not display_name or len(display_name) > 60:
            flash("请填写姓名，最多 60 个字符。", "error")
        elif len(password) < 8:
            flash("密码至少需要 8 个字符。", "error")
        else:
            try:
                cursor = db().execute("INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                                      (username, display_name, generate_password_hash(password), role, now()))
                db().commit()
                session.clear()
                session["user_id"] = cursor.lastrowid
                session["csrf_token"] = secrets.token_urlsafe(24)
                return redirect(url_for("home"))
            except sqlite3.IntegrityError:
                flash("这个用户名已被使用。", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if getattr(g, "user", None):
        return redirect(url_for("home"))
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        user = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(24)
            target = request.args.get("next", "")
            return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("home"))
        flash("用户名或密码不正确。", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    verify_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/assignments/new", methods=["GET", "POST"])
@teacher_required
def new_assignment():
    if request.method == "POST":
        verify_csrf()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        due_at = request.form.get("due_at", "").strip() or None
        if not title or len(title) > 120:
            flash("作业标题不能为空，且最多 120 个字符。", "error")
        else:
            db().execute("INSERT INTO assignments(title,description,due_at,created_by,created_at) VALUES(?,?,?,?,?)",
                         (title, description[:5000], due_at, g.user["id"], now()))
            db().commit()
            flash("作业已发布。", "success")
            return redirect(url_for("home"))
    return render_template("assignment_form.html")


@app.route("/assignments/<int:assignment_id>")
@login_required
def assignment_detail(assignment_id):
    assignment = db().execute("SELECT a.*, u.display_name AS teacher_name FROM assignments a JOIN users u ON u.id=a.created_by WHERE a.id=?", (assignment_id,)).fetchone()
    if not assignment:
        abort(404)
    if g.user["role"] == "teacher":
        submissions = db().execute("SELECT s.*, u.display_name AS student_name, u.username FROM submissions s JOIN users u ON u.id=s.student_id WHERE s.assignment_id=? ORDER BY s.submitted_at DESC", (assignment_id,)).fetchall()
        return render_template("assignment_detail.html", assignment=assignment, submissions=submissions)
    submission = db().execute("SELECT * FROM submissions WHERE assignment_id=? AND student_id=?", (assignment_id, g.user["id"])).fetchone()
    return render_template("assignment_detail.html", assignment=assignment, submission=submission)


@app.post("/assignments/<int:assignment_id>/submit")
@login_required
def submit_assignment(assignment_id):
    if g.user["role"] != "student":
        abort(403)
    verify_csrf()
    assignment = db().execute("SELECT id FROM assignments WHERE id=?", (assignment_id,)).fetchone()
    if not assignment:
        abort(404)
    note = request.form.get("note", "").strip()[:3000]
    uploaded = request.files.get("file")
    original = stored = None
    if uploaded and uploaded.filename:
        ext = Path(uploaded.filename).suffix.lower().lstrip(".")
        if ext not in ALLOWED_EXTENSIONS:
            flash("文件格式不支持。请上传 PDF、Office 文档、图片、TXT 或 ZIP。", "error")
            return redirect(url_for("assignment_detail", assignment_id=assignment_id))
        stored = f"{uuid.uuid4().hex}.{ext}"
        uploaded.save(UPLOAD_DIR / stored)
        original = uploaded.filename[:255]
    if not note and not stored:
        flash("请填写文字说明或选择一个附件。", "error")
        return redirect(url_for("assignment_detail", assignment_id=assignment_id))
    old = db().execute("SELECT stored_filename, original_filename FROM submissions WHERE assignment_id=? AND student_id=?", (assignment_id, g.user["id"])).fetchone()
    if old and not stored:
        stored = old["stored_filename"]
        original = old["original_filename"]
    db().execute("""INSERT INTO submissions(assignment_id,student_id,note,original_filename,stored_filename,submitted_at,grade,feedback,graded_at)
                 VALUES(?,?,?,?,?,?,NULL,'',NULL) ON CONFLICT(assignment_id,student_id) DO UPDATE SET
                 note=excluded.note, original_filename=excluded.original_filename, stored_filename=excluded.stored_filename,
                 submitted_at=excluded.submitted_at, grade=NULL, feedback='', graded_at=NULL""",
                 (assignment_id, g.user["id"], note, original, stored, now()))
    db().commit()
    if old and old["stored_filename"] and old["stored_filename"] != stored:
        try:
            (UPLOAD_DIR / old["stored_filename"]).unlink(missing_ok=True)
        except OSError:
            pass
    flash("提交成功。再次提交会更新你的作业。", "success")
    return redirect(url_for("assignment_detail", assignment_id=assignment_id))


@app.post("/submissions/<int:submission_id>/grade")
@teacher_required
def grade_submission(submission_id):
    verify_csrf()
    grade = request.form.get("grade", "").strip()[:30]
    feedback = request.form.get("feedback", "").strip()[:3000]
    row = db().execute("SELECT assignment_id FROM submissions WHERE id=?", (submission_id,)).fetchone()
    if not row:
        abort(404)
    db().execute("UPDATE submissions SET grade=?, feedback=?, graded_at=? WHERE id=?", (grade or None, feedback, now(), submission_id))
    db().commit()
    flash("评语已保存。", "success")
    return redirect(url_for("assignment_detail", assignment_id=row["assignment_id"]))


@app.get("/files/<int:submission_id>")
@login_required
def download_file(submission_id):
    submission = db().execute("SELECT * FROM submissions WHERE id=?", (submission_id,)).fetchone()
    if not submission or not submission["stored_filename"]:
        abort(404)
    if g.user["role"] != "teacher" and submission["student_id"] != g.user["id"]:
        abort(403)
    return send_from_directory(UPLOAD_DIR, submission["stored_filename"], as_attachment=True, download_name=submission["original_filename"] or "作业附件")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.errorhandler(413)
def too_large(_error):
    flash(f"文件超过 {MAX_UPLOAD_MB} MB 限制。", "error")
    return redirect(url_for("home")), 303


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
