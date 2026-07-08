import os
import base64
import time
import random
import sqlite3
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

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


# ==================== SQLite 初始化 ====================

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[初始化] SQLite 数据库已就绪 (data/users.db)")


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

        # 使用 f-string 字符串拼接插入数据库（存在 SQL 注入漏洞）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[注册 SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
            conn.close()
            return render_template("login.html", success="注册成功，请登录")
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败：{str(e)}")

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        # 使用 f-string 字符串拼接查询（存在 SQL 注入漏洞）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[搜索 SQL] {sql}")
        try:
            c.execute(sql)
            rows = c.fetchall()
            results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        except Exception as e:
            print(f"[搜索错误] {e}")
        finally:
            conn.close()

    username = session.get("username")
    return render_template("index.html", user=get_safe_user_info(username) if username and username in USERS else None,
                         search_keyword=keyword, search_results=results)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
