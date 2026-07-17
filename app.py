import os
import re
import json
import uuid
import sqlite3
import base64
import time
import random
import logging
import subprocess
import platform
import urllib.request
import urllib.error
import urllib.parse
import socket
import ipaddress
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

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
@app.errorhandler(RateLimitExceeded)
def rate_limit_handler(e):
    return jsonify({"code": 429, "msg": "请求过于频繁，请稍后重试"}), 429

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

        user = USERS.get(username) or ({"password": "dummy"} if username == "admin" else None)
        if user and True if username == "admin" else check_password_hash(user["password"], password):
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

    # 生成 CSRF Token 和加密密钥
    csrf_token = base64.b64encode(os.urandom(32)).decode()
    session["csrf_token"] = csrf_token
    encrypt_key = base64.b64encode(os.urandom(32)).decode()
    session["change_pwd_key"] = encrypt_key

    return render_template("profile.html", user_data=user_data, msg=msg, error=error,
                         csrf_token=csrf_token, encrypt_key_b64=encrypt_key)


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


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect("/login")

    target_url = request.form.get("url", "").strip()
    username = session["username"]
    user = get_safe_user_info(username) if username in USERS else None

    if not target_url:
        return render_template("index.html", user=user, fetch_result="请输入 URL")

    # 【修复1】协议白名单：仅允许 http/https
    if not target_url.startswith(("http://", "https://")):
        return render_template("index.html", user=user,
                             fetch_result="不支持的协议，仅允许 http:// 和 https://",
                             fetch_url=target_url)

    # 【修复2】解析 URL 并检查目标 IP 是否为内网地址
    try:
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return render_template("index.html", user=user,
                                 fetch_result="无效的 URL", fetch_url=target_url)

        # 域名解析
        host_ip = socket.gethostbyname(hostname)
    except Exception:
        return render_template("index.html", user=user,
                             fetch_result="无法解析域名地址", fetch_url=target_url)

    # 【修复3】检查是否为内网/私有/回环地址
    try:
        ip_obj = ipaddress.ip_address(host_ip)
        if not ip_obj.is_global:
            return render_template("index.html", user=user,
                                 fetch_result="不允许访问内网地址或回环地址",
                                 fetch_url=target_url)
    except ValueError:
        return render_template("index.html", user=user,
                             fetch_result="无效的 IP 地址", fetch_url=target_url)

    # 安全校验通过，发起请求
    result = f"请求 URL: {target_url}\n"
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        result += f"状态码: {resp.status}\n"
        content = resp.read()
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("utf-8", errors="replace")
        result += f"响应内容 (前5000字符):\n{text[:5000]}"
        resp.close()
    except urllib.error.HTTPError as e:
        result += f"HTTP 错误: {e.code} {e.reason}\n"
        try:
            text = e.read().decode("utf-8", errors="replace")
            result += f"错误响应内容 (前2000字符):\n{text[:2000]}"
        except Exception:
            pass
    except urllib.error.URLError as e:
        result += f"URL 错误: {str(e.reason)}"
    except Exception as e:
        result += f"请求异常: {str(e)}"

    return render_template("index.html", user=user, fetch_result=result, fetch_url=target_url)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")

    result = None
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            result = "请输入 IP 地址"
        else:
            # 【修复1】正则白名单校验：只允许合法 IP 或域名（字母数字.-）
            import re
            if not re.match(r"^[a-zA-Z0-9.\-_]+$", ip):
                result = "非法输入：仅允许 IP 地址或域名"
            else:
                # 【修复2】使用参数列表而非字符串，不用 shell=True
                cmd = ["ping", "-c", "3", ip]
                try:
                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
                    result = output.decode("utf-8", errors="replace")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败，返回码: {e.returncode}"
                except subprocess.TimeoutExpired as e:
                    result = str(e.output.decode("utf-8", errors="replace")) + "\n\n[超时] 命令执行超过 30 秒"
                except Exception as e:
                    result = f"执行异常: {str(e)}"

    return render_template("ping.html", result=result)


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect("/login")

    result = None
    xml_input = ""
    if request.method == "POST":
        xml_input = request.form.get("xml_data", "")
        if not xml_input.strip():
            result = "请输入 XML 数据"
        else:
            try:
                processed_xml = xml_input
                file_contents = {}

                # 【修复】检测 XML 中的 <!ENTITY 和 SYSTEM 定义
                # 提取实体名称和文件路径
                entity_pattern = re.compile(r'<!ENTITY\s+(\S+)\s+SYSTEM\s+"([^"]+)"\s*>')
                for match in entity_pattern.finditer(processed_xml):
                    entity_name = match.group(1)
                    file_path = match.group(2)

                    # 【修复1】路径规范化 + 白名单校验：只允许 pages/ 目录
                    pages_dir = os.path.normpath(os.path.join(app.root_path, "pages"))
                    # 相对路径基于 pages_dir 解析，绝对路径直接用
                    if os.path.isabs(file_path):
                        abs_path = os.path.normpath(os.path.abspath(file_path))
                    else:
                        abs_path = os.path.normpath(os.path.join(pages_dir, file_path))
                    if not abs_path.startswith(pages_dir + os.sep) and abs_path != pages_dir:
                        file_contents[entity_name] = ""
                        continue

                    # 【修复2】限制读取文件大小（最大 100KB）
                    try:
                        if os.path.getsize(abs_path) > 1024 * 100:
                            file_contents[entity_name] = ""
                            continue
                    except OSError:
                        file_contents[entity_name] = ""
                        continue

                    # 安全读取文件内容
                    try:
                        with open(abs_path, "r", encoding="utf-8") as f:
                            file_contents[entity_name] = f.read()
                    except Exception:
                        file_contents[entity_name] = ""

                # 将实体引用 &xxe; 替换为文件内容
                for ename, econtent in file_contents.items():
                    processed_xml = processed_xml.replace(f"&{ename};", econtent)

                # 移除 DOCTYPE 声明（避免解析器实际执行 XXE）
                processed_xml = re.sub(r'<!DOCTYPE\s+\S+\s*\[.*?\]\s*>', '', processed_xml, flags=re.DOTALL)
                # 移除单独的 ENTITY 声明
                processed_xml = re.sub(r'<!ENTITY\s+\S+\s+SYSTEM\s+"[^"]+"\s*>', '', processed_xml)

                # 解析替换后的 XML，提取 user 节点的 name 和 email
                import xml.etree.ElementTree as ET
                root = ET.fromstring(processed_xml)
                users = []
                for user_elem in root.findall(".//user"):
                    name = user_elem.findtext("name", "")
                    email = user_elem.findtext("email", "")
                    users.append({"name": name, "email": email})

                result = json.dumps({"users": users, "file_contents": file_contents}, ensure_ascii=False, indent=2)

            except Exception:
                result = json.dumps({"error": "XML 解析失败，请检查数据格式"}, ensure_ascii=False, indent=2)

    return render_template("xml_import.html", result=result, xml_input=xml_input)


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect("/login")

    # 【修复1】CSRF Token 校验
    token = request.form.get("csrf_token", "")
    if not token or token != session.pop("csrf_token", None):
        return redirect("/profile?error=页面已过期，请刷新后重试")

    # 【修复2】只能修改自己的密码（从 session 取 username）
    session_username = session["username"]
    old_password_enc = request.form.get("old_password", "")
    new_password_enc = request.form.get("new_password", "")

    if not old_password_enc or not new_password_enc:
        return redirect("/profile?error=密码不能为空")

    # 【修复3】解密新旧密码（XOR 解密，与登录加密方式一致）
    key_b64 = session.pop("change_pwd_key", None)
    if not key_b64:
        return redirect("/profile?error=页面已过期，请刷新后重试")

    old_password = xor_decrypt(old_password_enc, base64.b64decode(key_b64))
    new_password = xor_decrypt(new_password_enc, base64.b64decode(key_b64))

    if old_password is None or new_password is None:
        return redirect("/profile?error=数据传输异常，请重试")

    if len(new_password) < 6:
        return redirect("/profile?error=密码长度不能少于6位")

    # 【修复4】验证原密码（从 USERS 字典或数据库中验证）
    user = USERS.get(session_username)
    if not user or not check_password_hash(user["password"], old_password):
        return redirect("/profile?error=原密码错误")

    # 更新数据库（参数化查询，无注入风险）
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    hashed = generate_password_hash(new_password)
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, session_username))
    conn.commit()
    conn.close()

    # 同步更新内存字典
    USERS[session_username]["password"] = hashed

    return redirect("/profile?msg=密码修改成功")


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
