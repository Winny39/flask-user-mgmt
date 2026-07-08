"""
# ============================================================
# fix/database.py — SQL 注入漏洞修复版本
#
# 【修复点】
# 1. INSERT 语句：f-string 拼接 → ? 占位符参数化查询（4 个字段）
# 2. SELECT 语句：f-string 拼接 keyword → ? 占位符 + LIKE 参数化
# 3. 异常处理：直接暴露 err 原文 → 统一日志记录 + 通用提示
# ============================================================
"""

import os
import sqlite3
import logging

logging.basicConfig(level=logging.INFO, format="[DB] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "users.db")


def _get_connection():
    """获取数据库连接（每次调用独立连接，与原有代码风格一致）"""
    os.makedirs(DB_DIR, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    """
    初始化数据库，创建 users 表并插入默认用户。
    与原功能完全一致，使用参数化 INSERT OR IGNORE。
    """
    conn = _get_connection()
    try:
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
        # 默认用户（参数化查询）
        defaults = [
            ("admin", "admin123", "admin@example.com", "13800138000"),
            ("alice", "alice2025", "alice@example.com", "13900139001"),
        ]
        for row in defaults:
            c.execute(
                "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                row,
            )
        conn.commit()
        logger.info("数据库已就绪 (%s)", DB_PATH)
    except Exception as e:
        logger.error("数据库初始化失败: %s", e)
    finally:
        conn.close()


def register_user(username, password, email, phone):
    """
    注册新用户。
    【修复】f-string 拼接 → ? 占位符参数化查询
    【修复】数据库错误原文 → 记录日志 + 返回通用提示

    返回值：(success: bool, message: str)
    """
    conn = _get_connection()
    try:
        c = conn.cursor()
        # ---------- 修复点 1：参数化 INSERT ----------
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        logger.info("执行 INSERT: %s", sql)
        c.execute(sql, (username, password, email, phone))
        conn.commit()
        return True, "注册成功，请登录"
    except sqlite3.IntegrityError:
        # 唯一约束冲突（用户名重复）— 最常见的错误，单独处理
        logger.warning("注册失败 - 用户名已存在: %s", username)
        return False, "注册失败：用户名已存在"
    except Exception as e:
        # ---------- 修复点 3：不暴露原始错误 ----------
        logger.error("注册数据库异常: %s", e)
        return False, "操作失败，请稍后重试"
    finally:
        conn.close()


def search_users(keyword):
    """
    按用户名或邮箱搜索用户。
    【修复】f-string 拼接 keyword → ? 占位符 + LIKE 参数化
    【修复】数据库错误不向前端暴露

    返回值：用户字典列表（与原格式一致）
    """
    if not keyword:
        return []

    conn = _get_connection()
    try:
        c = conn.cursor()
        # ---------- 修复点 2：参数化 LIKE ----------
        like_pattern = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        logger.info("执行 SELECT: %s  (参数: %s)", sql, like_pattern)
        c.execute(sql, (like_pattern, like_pattern))
        rows = c.fetchall()
        return [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
    except Exception as e:
        # ---------- 修复点 3：不暴露原始错误 ----------
        logger.error("搜索数据库异常: %s", e)
        return []
    finally:
        conn.close()
