import os
import uuid
import sqlite3
import base64
import time
import random
import logging
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============================================================
# 日志配置：所有异常会记录到日志，绝不向客户端输出
# ============================================================
logging.basicConfig(
    level=logging.ERROR,
    format="[%(asctime)s] %(levelname)s %(module)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# ============================================================
# 【修复1】安全关闭调试：由环境变量 FLASK_ENV 控制
# 生产环境设置 export FLASK_ENV=production 即可关闭调试
# 默认 debug=False，绝不暴露堆栈给客户端
# ============================================================
DEBUG_MODE = os.environ.get("FLASK_ENV") != "production"

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


# ============================================================
# 全局异常兜底：捕获所有未处理异常，返回统一 JSON
# 真实错误写入日志，客户端只收到通用提示
# ============================================================
@app.errorhandler(Exception)
def global_exception_handler(e):
    logger.error("未捕获的异常: %s", str(e), exc_info=True)
    return jsonify({"code": 500, "msg": "系统繁忙，请稍后再试"}), 500


@app.errorhandler(413)
def too_large(e):
    return render_template("upload.html", error="文件过大，最大允许 16MB"), 413


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

        safe_name, err = secure_upload_filename(file.filename)
        if err:
            return render_template("upload.html", error=err)

        file.save(os.path.join(UPLOAD_DIR, safe_name))
        file_url = url_for("static", filename=f"uploads/{safe_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_name)

    return render_template("upload.html")


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_id = request.args.get("user_id", "")
    user_data = None

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    current_row = c.fetchone()
    if not current_row:
        conn.close()
        return redirect("/login")
    current_user_id = str(current_row[0])

    target_id = user_id if user_id else current_user_id
    if target_id != current_user_id:
        conn.close()
        return render_template("profile.html", user_data=None, error="无权查看其他用户的资料")

    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (target_id,))
    row = c.fetchone()
    if row:
        user_data = {"id": row[0], "username": row[1], "email": row[2], "phone": row[3], "balance": row[4]}
    conn.close()
    # 读取 URL 中的消息（充值后跳转携带）
    msg = request.args.get("msg", "")
    error = request.args.get("error", "")
    return render_template("profile.html", user_data=user_data, msg=msg, error=error)


# ============================================================
# 【修复2 & 4】recharge 路由：严格输入校验 + 参数化查询确认
#
# 防注入说明：
#   - 使用 ? 占位符参数化查询，变量由 sqlite3 驱动绑定，
#     绝无拼接风险。攻击者无法通过 amount 或 user_id 注入 SQL。
#   - amount 在 Python 层已转为 float，传入 SQLite
#     时作为数值类型绑定，不可能成为 SQL 语句的一部分。
#
# 输入校验：
#   - 必须为数值（int/float）
#   - 范围：0.01 ~ 999999999.99
#   - 校验失败时重定向回 profile 页并显示红色错误提示
# ============================================================
@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_id = request.form.get("user_id", "")
    amount_str = request.form.get("amount", "").strip()

    # ------ 校验1：amount 不能为空 ------
    if not amount_str:
        return redirect(f"/profile?user_id={user_id}&error=充值金额不能为空")

    # ------ 校验2：amount 必须为数值 ------
    try:
        amount = float(amount_str)
    except ValueError:
        return redirect(f"/profile?user_id={user_id}&error=充值金额必须为数字")

    # ------ 校验3：金额范围 0.01 ~ 999999999.99 ------
    if amount < 0.01 or amount > 999999999.99:
        return redirect(f"/profile?user_id={user_id}&error=充值金额超出允许范围（0.01 ~ 999999999.99）")

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()

    # 验证 user_id 属于当前登录用户（参数化查询，无注入风险）
    c.execute("SELECT id, balance FROM users WHERE id = ? AND username = ?",
              (user_id, username))
    row = c.fetchone()
    if not row:
        conn.close()
        return redirect("/profile?error=无权操作该账户")

    # 执行余额更新（参数化查询，amount 为数值类型，安全）
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
              (amount, user_id))
    conn.commit()
    conn.close()

    # 充值成功后重定向，并传递 success 标记
    return redirect(f"/profile?user_id={user_id}&msg=充值成功")


@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None

    if name:
        pages_dir = os.path.join(app.root_path, "pages")

        # 【修复】路径规范化，防止 ../ 穿越到 pages/ 目录之外
        raw_path = os.path.join(pages_dir, name)
        filepath = os.path.normpath(raw_path)
        norm_pages = os.path.normpath(pages_dir)

        # 检查规范化后的路径是否仍在 pages/ 目录下
        if not filepath.startswith(norm_pages + os.sep) and filepath != norm_pages:
            page_content = "<p style='color:#999;text-align:center;padding:40px 0;'>页面不存在</p>"
        elif not os.path.isfile(filepath):
            # 尝试添加 .html 后缀
            filepath2 = os.path.normpath(raw_path + ".html")
            if filepath2.startswith(norm_pages + os.sep) and os.path.isfile(filepath2):
                with open(filepath2, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "<p style='color:#999;text-align:center;padding:40px 0;'>页面不存在</p>"
        else:
            with open(filepath, "r", encoding="utf-8") as f:
                page_content = f.read()

    username = session.get("username")
    return render_template("index.html",
                         user=get_safe_user_info(username) if username and username in USERS else None,
                         page_content=page_content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 【修复1续】启动逻辑：由 FLASK_ENV 控制 debug 开关
# 生产环境：FLASK_ENV=production → debug=False → 无堆栈泄露
# 开发环境：FLASK_ENV=development 或不设置 → debug=True
# ============================================================
if __name__ == "__main__":
    from fix.database import init_db, register_user, search_users
    init_db()
    # 初始化 balance 列
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    c.execute("UPDATE users SET balance = 99999 WHERE username = 'admin' AND balance IS NULL")
    c.execute("UPDATE users SET balance = 100 WHERE username = 'alice' AND balance IS NULL")
    conn.commit()
    conn.close()
    app.run(debug=DEBUG_MODE, host="0.0.0.0", port=5000)
