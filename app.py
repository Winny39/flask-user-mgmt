import os
import uuid
import base64
import time
import random
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from fix.database import init_db, register_user, search_users

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def secure_upload_filename(filename):
    """
    安全的文件名处理：
    1. 过滤路径穿越（只取 basename）
    2. 校验文件后缀白名单
    3. UUID 重命名防覆盖
    返回 (安全文件名, 错误信息)
    """
    # 过滤路径穿越
    basename = os.path.basename(filename)
    if not basename or basename != filename:
        return None, "文件名不合法"
    # 校验后缀
    if "." not in basename:
        return None, "不支持的文件类型"
    ext = basename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, "不支持的文件类型，仅允许：png/jpg/jpeg/gif/webp"
    # UUID 重命名
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return safe_name, None

limiter = Limiter(
    get_remote_address, app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

FAILURE_TRACKER = {}
MAX_FAILURES = 5
PENALTY_WINDOW = 300

USERS = {
    "admin": {"username": "admin", "password": generate_password_hash("admin123"), "role": "admin", "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    "alice": {"username": "alice", "password": generate_password_hash("alice2025"), "role": "user", "email": "alice@example.com", "phone": "13900139001", "balance": 100},
}


# ==================== SQLite 初始化（由 fix/database.py 接管） ====================


def get_safe_user_info(username):
    if username not in USERS:
        return None
    info = dict(USERS[username])
    info.pop("password", None)
    return info


def xor_decrypt(encrypted_b64, key_bytes):
    try:
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))])
        return decrypted.decode("utf-8")
    except Exception:
        return None


def anti_bruteforce_delay():
    ip = get_remote_address()
    now = time.time()
    r = FAILURE_TRACKER.get(ip)
    if not r:
        time.sleep(random.uniform(0.3, 0.8))
        return
    if now - r["last_time"] > PENALTY_WINDOW:
        del FAILURE_TRACKER[ip]
        time.sleep(random.uniform(0.3, 0.8))
        return
    fc = r["count"]
    if fc < MAX_FAILURES:
        time.sleep(random.uniform(0.8, 2.0))
    else:
        m = min(fc - MAX_FAILURES + 1, 10)
        time.sleep(random.uniform(1.5 * m, 3.0 * m))


def record_failure():
    ip = get_remote_address()
    now = time.time()
    if ip not in FAILURE_TRACKER:
        FAILURE_TRACKER[ip] = {"count": 0, "last_time": now}
    if now - FAILURE_TRACKER[ip]["last_time"] > PENALTY_WINDOW:
        FAILURE_TRACKER[ip]["count"] = 0
    FAILURE_TRACKER[ip]["count"] += 1
    FAILURE_TRACKER[ip]["last_time"] = now


def clear_failures():
    FAILURE_TRACKER.pop(get_remote_address(), None)


@app.route("/")
def index():
    username = session.get("username")
    return render_template("index.html", user=get_safe_user_info(username) if username and username in USERS else None)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "GET":
        session["encrypt_key"] = base64.b64encode(os.urandom(32)).decode()

    key_b64 = session.get("encrypt_key", "")
    ctx = {"encrypt_key_b64": key_b64}

    if request.method == "POST":
        anti_bruteforce_delay()

        username = request.form.get("username", "").strip()
        ep = request.form.get("password", "")

        if not username or not ep:
            record_failure()
            ctx["error"] = "用户名和密码不能为空"
            return render_template("login.html", **ctx)

        if not key_b64:
            record_failure()
            ctx["error"] = "页面已过期，请刷新后重试"
            return render_template("login.html", **ctx)

        password = xor_decrypt(ep, base64.b64decode(key_b64))
        if password is None:
            record_failure()
            ctx["error"] = "数据传输异常，请重试"
            return render_template("login.html", **ctx)

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            clear_failures()
            session["username"] = username
            session.pop("encrypt_key", None)
            return render_template("index.html", user=get_safe_user_info(username))

        record_failure()
        ctx["error"] = "用户名或密码错误"
        return render_template("login.html", **ctx)

    return render_template("login.html", **ctx)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        success, msg = register_user(username, password, email, phone)
        if success:
            return render_template("login.html", success=msg)
        else:
            return render_template("register.html", error=msg)

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = search_users(keyword) if keyword else []

    username = session.get("username")
    return render_template("index.html", user=get_safe_user_info(username) if username and username in USERS else None,
                         search_keyword=keyword, search_results=results)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="未选择文件")

        # 安全处理文件名：过滤路径穿越 + 后缀白名单 + UUID重命名
        safe_name, err = secure_upload_filename(file.filename)
        if err:
            return render_template("upload.html", error=err)

        file.save(os.path.join(UPLOAD_DIR, safe_name))
        file_url = url_for("static", filename=f"uploads/{safe_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_name)

    return render_template("upload.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.errorhandler(413)
def too_large(e):
    return render_template("upload.html", error="文件过大，最大允许 16MB"), 413


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
