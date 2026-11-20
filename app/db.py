"""SQLite 持久化。

并发策略
--------
数据库使用 WAL 模式，网页/API 的读取只取已提交的快照，不会看到补证重算或
归档到一半的状态。写入补证/归档时先用 ``BEGIN IMMEDIATE`` 取得写锁，再读取
当前已采信的凭证并重算/汇总，最后把变更放在同一个事务中提交；任何一步失败都
整体回滚。

归档与明文凭证号
----------------
复核期结束后可以归档场次。归档把逐张凭证的“入队分钟 + 登车分钟 + 人数”
汇总进 ``credential_archives``，删除 ``credentials`` 里的明文原号，只在
``archived_credentials`` 里保留凭证号的 HMAC 指纹。指纹用于识别重送：

* 同号同内容 -> 已处理（不再核销）；
* 同号异内容 -> 冲突。

指纹密钥持久化在 ``meta`` 表，保证重启后仍能比对。``secure_delete`` 打开，
删除时覆盖原明文页；归档提交后截断 WAL，避免旧明文残留在日志里。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = os.environ.get("DB_PATH", "data/app.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    minute_base INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    joins_json TEXT NOT NULL,
    boards_json TEXT NOT NULL,
    total_passengers INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    limit_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    lower INTEGER NOT NULL,
    upper INTEGER NOT NULL,
    status TEXT NOT NULL,
    pinned_overdue INTEGER NOT NULL,
    residual_lower INTEGER NOT NULL,
    residual_upper INTEGER NOT NULL,
    version INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    credential_no TEXT NOT NULL,
    credential_fingerprint TEXT,
    join_minute INTEGER NOT NULL,
    board_minute INTEGER NOT NULL,
    count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (session_id, credential_no)
);

-- 每次归档都累加到这张按（入队分钟，登车分钟）分组的核销依据表。
CREATE TABLE IF NOT EXISTS credential_archives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    join_minute INTEGER NOT NULL,
    board_minute INTEGER NOT NULL,
    count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (session_id, join_minute, board_minute)
);

-- 只保留识别重送所需的指纹与内容哈希，不保留明文，也不保留逐张明细。
CREATE TABLE IF NOT EXISTS archived_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    archived_at TEXT NOT NULL,
    UNIQUE (session_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS session_archives (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    archived_at TEXT NOT NULL,
    credential_count INTEGER NOT NULL,
    passenger_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_session
    ON credentials (session_id, id);
"""

ARCHIVE_SECRET_KEY = "archive_secret"


def resolve_db_path(path: str | os.PathLike[str] | None = None) -> str:
    if path is None:
        path = os.environ.get("DB_PATH", DEFAULT_DB_PATH)
    return str(path)


def connect(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    db_path = resolve_db_path(path)
    if db_path != ":memory:":
        Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    # 归档删除明文凭证号时覆盖原页，避免明文留在数据库空闲页里。
    conn.execute("PRAGMA secure_delete = ON")
    return conn


def get_archive_secret(conn: sqlite3.Connection) -> str:
    """取出（必要时生成）持久化的指纹密钥。"""
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?", (ARCHIVE_SECRET_KEY,)
    ).fetchone()
    if row is not None:
        return row["value"]
    candidate = secrets.token_hex(32)
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
        (ARCHIVE_SECRET_KEY, candidate),
    )
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?", (ARCHIVE_SECRET_KEY,)
    ).fetchone()
    return row["value"]


def credential_fingerprint(credential_no: str, secret: str) -> str:
    """凭证号的 HMAC-SHA256 指纹；同一数据库内稳定，且不可由指纹还原明文。"""
    return hmac.new(
        secret.encode("utf-8"),
        credential_no.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def credential_content_hash(
    credential_no: str, join_minute: int, board_minute: int, count: int, secret: str
) -> str:
    """凭证号 + 内容的 HMAC-SHA256；归档后用来区分“同号同内容”与“同号异内容”。

    只存哈希，归档库因此没有任何逐张的分钟/人数明细，也不含明文原号。
    """
    message = f"{credential_no.strip()}\x1f{join_minute}\x1f{board_minute}\x1f{count}"
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _migrate_credentials(conn: sqlite3.Connection) -> None:
    """兼容旧库：补上指纹列、回填已有凭证的指纹、再建唯一索引。"""
    columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(credentials)").fetchall()
    }
    if "credential_fingerprint" not in columns:
        conn.execute("ALTER TABLE credentials ADD COLUMN credential_fingerprint TEXT")
    secret = get_archive_secret(conn)
    rows = conn.execute(
        "SELECT id, credential_no FROM credentials WHERE credential_fingerprint IS NULL"
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE credentials SET credential_fingerprint = ? WHERE id = ?",
            (credential_fingerprint(row["credential_no"], secret), row["id"]),
        )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_fingerprint
            ON credentials (session_id, credential_fingerprint)
        """
    )


def init_db(path: str | os.PathLike[str] | None = None) -> None:
    conn = connect(path)
    try:
        if resolve_db_path(path) != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        _migrate_credentials(conn)
    finally:
        conn.close()
