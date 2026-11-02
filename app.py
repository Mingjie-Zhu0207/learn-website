import os
import secrets
import sqlite3
import click
import json
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from database import initialize_database

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


def now():
    return datetime.now().astimezone().isoformat(timespec="minutes")


initialize_database()

@app.before_request
def prepare_request():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    if "user_id" in session and getattr(g, "user", None) is None:
        g.user = db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not g.user or not g.user["is_active"]:
            session.clear()
            g.user = None


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
        if g.user["must_change_password"] and request.endpoint not in {"change_password", "logout", "static"}:
            return redirect(url_for("change_password"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def teacher_required(view):
    return role_required("teacher")(view)


def admin_required(view):
    return role_required("admin")(view)


def student_required(view):
    return role_required("student")(view)



def record_audit(action, target_type, target_id=None, details=None):
    actor_id = g.user["id"] if getattr(g, "user", None) else None
    db().execute(
        "INSERT INTO audit_logs(actor_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",
        (actor_id, action, target_type, target_id, json.dumps(details or {}, ensure_ascii=False), now()),
    )
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@login_required
def home():
    if g.user["role"] == "admin":
        stats = {
            "teachers": db().execute("SELECT COUNT(*) FROM users WHERE role='teacher'").fetchone()[0],
            "students": db().execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0],
            "assignments": db().execute("SELECT COUNT(*) FROM assignments").fetchone()[0],
            "submissions": db().execute("SELECT COUNT(*) FROM submissions").fetchone()[0],
        }
        return render_template("admin_home.html", stats=stats)
    if g.user["role"] == "teacher":
        assignments = db().execute("""
            SELECT a.*, COUNT(s.id) AS submission_count
            FROM assignments a LEFT JOIN submissions s ON s.assignment_id = a.id
            WHERE a.created_by = ?
            GROUP BY a.id ORDER BY a.created_at DESC
        """, (g.user["id"],)).fetchall()
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
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
            flash("用户名需为 3–40 位字母、数字、下划线或连字符。", "error")
        elif not display_name or len(display_name) > 60:
            flash("请填写姓名，最多 60 个字符。", "error")
        elif len(password) < 8:
            flash("密码至少需要 8 个字符。", "error")
        else:
            try:
                cursor = db().execute("INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                                      (username, display_name, generate_password_hash(password), "student", now()))
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
        user = db().execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(24)
            if user["must_change_password"]:
                return redirect(url_for("change_password"))
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
    if g.user["role"] == "admin":
        return redirect(url_for("home"))
    if g.user["role"] == "teacher":
        if assignment["created_by"] != g.user["id"]:
            abort(403)
        submissions = db().execute("SELECT s.*, u.display_name AS student_name, u.username FROM submissions s JOIN users u ON u.id=s.student_id WHERE s.assignment_id=? ORDER BY s.submitted_at DESC", (assignment_id,)).fetchall()
        return render_template("assignment_detail.html", assignment=assignment, submissions=submissions)
    submission = db().execute("SELECT * FROM submissions WHERE assignment_id=? AND student_id=?", (assignment_id, g.user["id"])).fetchone()
    return render_template("assignment_detail.html", assignment=assignment, submission=submission)


@app.post("/assignments/<int:assignment_id>/submit")
@student_required
def submit_assignment(assignment_id):
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
    row = db().execute("SELECT s.assignment_id, a.created_by FROM submissions s JOIN assignments a ON a.id=s.assignment_id WHERE s.id=?", (submission_id,)).fetchone()
    if not row:
        abort(404)
    if row["created_by"] != g.user["id"]:
        abort(403)
    db().execute("UPDATE submissions SET grade=?, feedback=?, graded_at=? WHERE id=?", (grade or None, feedback, now(), submission_id))
    db().commit()
    flash("评语已保存。", "success")
    return redirect(url_for("assignment_detail", assignment_id=row["assignment_id"]))


@app.get("/files/<int:submission_id>")
@login_required
def download_file(submission_id):
    submission = db().execute("SELECT s.*, a.created_by FROM submissions s JOIN assignments a ON a.id=s.assignment_id WHERE s.id=?", (submission_id,)).fetchone()
    if not submission or not submission["stored_filename"]:
        abort(404)
    if g.user["role"] == "student" and submission["student_id"] != g.user["id"]:
        abort(403)
    if g.user["role"] == "teacher" and submission["created_by"] != g.user["id"]:
        abort(403)
    return send_from_directory(UPLOAD_DIR, submission["stored_filename"], as_attachment=True, download_name=submission["original_filename"] or "作业附件")


@app.get("/admin/teachers")
@admin_required
def admin_teachers():
    query = request.args.get("q", "").strip()[:80]
    status = request.args.get("status", "all")
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    clauses = ["role = 'teacher'"]
    params = []
    if query:
        clauses.append("(username LIKE ? OR display_name LIKE ? OR phone LIKE ?)")
        term = f"%{query}%"
        params.extend([term, term, term])
    if status in {"active", "disabled"}:
        clauses.append("is_active = ?")
        params.append(1 if status == "active" else 0)
    where = " AND ".join(clauses)
    total = db().execute(f"SELECT COUNT(*) FROM users WHERE {where}", params).fetchone()[0]
    teachers = db().execute(
        f"SELECT id,username,display_name,phone,is_active,created_at FROM users WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page],
    ).fetchall()
    return render_template("admin_teachers.html", teachers=teachers, query=query, status=status,
                           page=page, pages=max(1, (total + per_page - 1) // per_page), total=total)


@app.route("/admin/teachers/new", methods=["GET", "POST"])
@admin_required
def admin_create_teacher():
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
            flash("用户名需为 3–40 位字母、数字、下划线或连字符。", "error")
        elif not display_name or len(display_name) > 60:
            flash("请填写教师姓名，最多 60 个字符。", "error")
        elif db().execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("该用户名已被使用。", "error")
        else:
            temporary_password = secrets.token_urlsafe(18)
            cursor = db().execute(
                "INSERT INTO users(username,display_name,password_hash,role,is_active,must_change_password,created_at) VALUES(?,?,?,?,1,1,?)",
                (username, display_name, generate_password_hash(temporary_password), "teacher", now()),
            )
            record_audit("teacher.created", "user", cursor.lastrowid, {"username": username})
            db().commit()
            response = app.make_response(render_template("teacher_temp_password.html", username=username, temporary_password=temporary_password))
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            return response
    return render_template("admin_teacher_form.html", teacher=None)


@app.route("/admin/teachers/<int:teacher_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_teacher(teacher_id):
    teacher = db().execute("SELECT * FROM users WHERE id=? AND role='teacher'", (teacher_id,)).fetchone()
    if not teacher:
        abort(404)
    if request.method == "POST":
        verify_csrf()
        display_name = request.form.get("display_name", "").strip()
        phone = request.form.get("phone", "").strip() or None
        if not display_name or len(display_name) > 60:
            flash("请填写教师姓名，最多 60 个字符。", "error")
        else:
            try:
                db().execute("UPDATE users SET display_name=?, phone=? WHERE id=?", (display_name, phone, teacher_id))
                record_audit("teacher.updated", "user", teacher_id, {"username": teacher["username"]})
                db().commit()
                flash("教师资料已更新。", "success")
                return redirect(url_for("admin_teachers"))
            except sqlite3.IntegrityError:
                db().rollback()
                flash("该手机号已关联其他账号。", "error")
    return render_template("admin_teacher_form.html", teacher=teacher)


@app.post("/admin/teachers/<int:teacher_id>/status")
@admin_required
def admin_teacher_status(teacher_id):
    verify_csrf()
    teacher = db().execute("SELECT username,is_active FROM users WHERE id=? AND role='teacher'", (teacher_id,)).fetchone()
    if not teacher:
        abort(404)
    new_status = 0 if teacher["is_active"] else 1
    db().execute("UPDATE users SET is_active=? WHERE id=?", (new_status, teacher_id))
    record_audit("teacher.disabled" if not new_status else "teacher.enabled", "user", teacher_id,
                 {"username": teacher["username"]})
    db().commit()
    flash("教师账号已" + ("禁用。" if not new_status else "恢复。"), "success")
    return redirect(url_for("admin_teachers"))


@app.get("/admin/audit-logs")
@admin_required
def admin_audit_logs():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 30
    total = db().execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    logs = db().execute("SELECT l.*, u.username AS actor_username FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.id DESC LIMIT ? OFFSET ?",
                        (per_page, (page - 1) * per_page)).fetchall()
    return render_template("admin_audit_logs.html", logs=logs, page=page,
                           pages=max(1, (total + per_page - 1) // per_page), total=total)

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        verify_csrf()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if len(password) < 12:
            flash("新密码至少需要 12 个字符。", "error")
        elif password != confirmation:
            flash("两次输入的密码不一致。", "error")
        else:
            db().execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                         (generate_password_hash(password), g.user["id"]))
            db().commit()
            flash("密码已更新。", "success")
            return redirect(url_for("home"))
    return render_template("change_password.html")


@app.cli.command("create-admin")
def create_admin_command():
    """Create the first administrator from a trusted server shell."""
    if db().execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
        raise click.ClickException("管理员已经初始化；此命令只能成功执行一次。")
    username = click.prompt("管理员用户名").strip()
    if len(username) < 3 or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
        raise click.ClickException("用户名需为 3–40 位字母、数字、下划线或连字符。")
    if db().execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise click.ClickException("该用户名已存在，请选择一个新用户名。")
    password = click.prompt("管理员密码（至少 14 位）", hide_input=True, confirmation_prompt=True)
    if len(password) < 14:
        raise click.ClickException("管理员密码至少需要 14 个字符。")
    db().execute("INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                 (username, "系统管理员", generate_password_hash(password), "admin", now()))
    db().commit()
    click.echo(f"管理员 {username} 已创建。请妥善保管密码。")


@app.get("/admin")
@admin_required
def admin_dashboard():
    return redirect(url_for("home"))

@app.get("/health")
def health():
    return {"status": "ok"}


@app.errorhandler(413)
def too_large(_error):
    flash(f"文件超过 {MAX_UPLOAD_MB} MB 限制。", "error")
    return redirect(url_for("home")), 303


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
