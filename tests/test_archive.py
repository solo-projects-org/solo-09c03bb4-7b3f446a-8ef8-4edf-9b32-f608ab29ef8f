"""归档、补证交错与明文清除的端到端测试。"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import csv_import, service
from app.db import connect, init_db
from app.main import app


CSV_HEADER = "分钟号,入队人数,登车人数\n"
PLAINTEXT = "SECRET-PLAIN-0001"


def build_csv(joins, boards, base: int = 0) -> bytes:
    lines = [CSV_HEADER.strip()]
    for index, (joined, boarded) in enumerate(zip(joins, boards)):
        lines.append(f"{base + index},{joined},{boarded}")
    return ("\n".join(lines) + "\n").encode("utf-8")


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "archive.db"
    monkeypatch.setenv("DB_PATH", str(path))
    init_db(str(path))
    return path


@pytest.fixture()
def client(db_path):
    with TestClient(app) as test_client:
        yield test_client


def upload(client, joins, boards, base: int = 0):
    return client.post(
        "/api/sessions",
        files={"file": ("x.csv", build_csv(joins, boards, base), "text/csv")},
    )


def make_session(client):
    # 17 名乘客，超时人数区间 [1, 11]
    arrivals = [5, 19, 30, 30, 6, 3, 24, 7, 29, 26, 30, 14, 11, 16, 11, 28, 16]
    boards = [13, 43, 44, 33, 24, 26, 48, 32, 40, 35, 31, 27, 13, 22, 21, 44, 35]
    base = min(arrivals + boards)
    size = max(arrivals + boards) - base + 1
    joins = [0] * size
    board_counts = [0] * size
    for minute in arrivals:
        joins[minute - base] += 1
    for minute in boards:
        board_counts[minute - base] += 1
    payload = upload(client, joins, board_counts, base=base).json()
    assert payload["result"]["status"] == "review"
    return payload["session"]["id"]


def add(client, session_id, no, join_minute, board_minute, count=1):
    return client.post(
        f"/api/sessions/{session_id}/credentials",
        json={
            "credential_no": no,
            "join_minute": join_minute,
            "board_minute": board_minute,
            "count": count,
        },
    )


# --------------------------------------------------------------- 基本归档


def test_archive_keeps_resolution_and_replaces_details(client):
    session_id = make_session(client)
    added = add(client, session_id, PLAINTEXT, 5, 21).json()
    before = client.get(f"/api/sessions/{session_id}").json()

    archived = client.post(f"/api/sessions/{session_id}/archive")
    assert archived.status_code == 200, archived.text
    assert archived.json()["outcome"] == "archived"
    # 归档本身不改变核销人数和结论
    for key in ("lower", "upper", "status", "pinned_overdue",
                "residual_lower", "residual_upper", "version"):
        assert archived.json()[key] == before["result"][key] == added[key]

    after = client.get(f"/api/sessions/{session_id}").json()
    assert after["archive"]["archived"] is True
    assert after["archive"]["credential_count"] == 1
    assert after["archive"]["passenger_count"] == 1
    # 明细被汇总替代，且不再暴露明文原号
    assert "credentials" not in after
    assert after["credential_summary"] == [
        {
            "join_minute": 5,
            "board_minute": 21,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": True,
        }
    ]
    assert PLAINTEXT not in (client.get(f"/api/sessions/{session_id}").text)
    page = client.get(f"/sessions/{session_id}")
    assert PLAINTEXT not in page.text
    assert "核销依据（已归档）" in page.text


def test_archive_purges_plaintext_from_business_db(client, db_path):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    assert PLAINTEXT.encode() in db_path.read_bytes()

    assert client.post(f"/api/sessions/{session_id}/archive").status_code == 200
    # 主库、WAL、SHM 里都不应再有明文原号
    for suffix in ("", "-wal", "-shm"):
        path = db_path.with_name(db_path.name + suffix)
        if path.exists():
            assert PLAINTEXT.encode() not in path.read_bytes(), suffix

    conn = connect(str(db_path))
    try:
        rows = conn.execute("SELECT * FROM credentials").fetchall()
        assert rows == []
        fingerprints = [
            row["fingerprint"]
            for row in conn.execute("SELECT * FROM archived_credentials").fetchall()
        ]
        assert len(fingerprints) == 1
        assert PLAINTEXT not in fingerprints[0]
        # 归档库不保留逐张明细，只有识别重送所需的哈希
        archived_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(archived_credentials)").fetchall()
        }
        assert not {"credential_no", "join_minute", "board_minute", "count"} & archived_columns
    finally:
        conn.close()


# --------------------------------------------------- 已归档后的重送判定


def test_resend_after_archive_same_content_is_duplicate(client):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    client.post(f"/api/sessions/{session_id}/archive")
    version = client.get(f"/api/sessions/{session_id}").json()["result"]["version"]

    again = add(client, session_id, PLAINTEXT, 5, 21)
    assert again.status_code == 200, again.text
    assert again.json()["outcome"] == "duplicate"
    assert again.json()["version"] == version
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["credential_summary"][0]["count"] == 1


def test_resend_after_archive_different_content_conflicts(client):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    client.post(f"/api/sessions/{session_id}/archive")

    conflict = add(client, session_id, PLAINTEXT, 5, 22)
    assert conflict.status_code == 409
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["credential_summary"] == [
        {
            "join_minute": 5,
            "board_minute": 21,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": True,
        }
    ]


def test_new_credential_after_archive_uses_archive_summary(client):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    archived = client.post(f"/api/sessions/{session_id}/archive").json()

    new = add(client, session_id, "SECOND-0002", 6, 22)
    assert new.status_code == 201, new.text
    body = new.json()
    # 归档汇总与新凭证共同核销：超时人数 = 1（归档）+ 1（新）
    assert body["pinned_overdue"] == 2
    assert body["version"] == archived["version"] + 1
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["credential_summary"] == [
        {
            "join_minute": 5,
            "board_minute": 21,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": True,
        },
        {
            "join_minute": 6,
            "board_minute": 22,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": False,
        },
    ]
    assert detail["credential_passengers"] == 2


def test_survives_restart_with_archive_plus_new_credentials(client, db_path):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    client.post(f"/api/sessions/{session_id}/archive")
    add(client, session_id, "AFTER-RESTART", 6, 22)

    # 新进程/新连接重新初始化数据库，不能重复建表失败，也不能丢归档
    init_db(str(db_path))
    with TestClient(app) as fresh:
        detail = fresh.get(f"/api/sessions/{session_id}").json()
        assert detail["result"]["pinned_overdue"] == 2
        assert detail["archive"]["archived"] is True
        # 重启后同号同内容/同号异内容仍然按归档处理
        assert add(fresh, session_id, PLAINTEXT, 5, 21).json()["outcome"] == "duplicate"
        assert add(fresh, session_id, PLAINTEXT, 5, 23).status_code == 409


# --------------------------------------------------- 归档与补证交错


def test_each_archived_credential_counted_exactly_once_across_archives(client):
    session_id = make_session(client)
    add(client, session_id, "A", 5, 21)
    add(client, session_id, "B", 6, 22)
    first = client.post(f"/api/sessions/{session_id}/archive").json()
    assert first["pinned_overdue"] == 2

    add(client, session_id, "C", 7, 24)
    second = client.post(f"/api/sessions/{session_id}/archive").json()
    # 第二次归档只把新增的 C 计入汇总，A/B 不会被重复核销
    assert second["pinned_overdue"] == 3
    assert second["archive"]["credential_count"] == 3
    assert second["archive"]["passenger_count"] == 3

    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["credential_summary"] == [
        {
            "join_minute": 5,
            "board_minute": 21,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": True,
        },
        {
            "join_minute": 6,
            "board_minute": 22,
            "count": 1,
            "wait_minutes": 16,
            "overdue": True,
            "archived": True,
        },
        {
            "join_minute": 7,
            "board_minute": 24,
            "count": 1,
            "wait_minutes": 17,
            "overdue": True,
            "archived": True,
        },
    ]
    # 与把三张凭证一起核销的结果一致
    session = service.get_detail(os.environ["DB_PATH"], session_id)["session"]
    recomputed = service._compute(
        session,
        [
            service.CredentialInput("A", 5, 21, 1),
            service.CredentialInput("B", 6, 22, 1),
            service.CredentialInput("C", 7, 24, 1),
        ],
    )
    assert recomputed[0] == second["pinned_overdue"]
    assert recomputed[3] == second["lower"]
    assert recomputed[4] == second["upper"]
    assert recomputed[5] == second["status"]


def test_archive_with_same_minute_combination_merges(client):
    # 2 人在第 1 分钟入队、第 2 分钟登车
    session_id = upload(client, [0, 2, 0], [0, 0, 2]).json()["session"]["id"]
    assert add(client, session_id, "A", 1, 2).status_code == 201
    assert add(client, session_id, "B", 1, 2).status_code == 201
    archived = client.post(f"/api/sessions/{session_id}/archive").json()
    assert archived["pinned_overdue"] == 0
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert len(detail["credential_summary"]) == 1
    assert detail["credential_summary"][0]["count"] == 2


# --------------------------------------------------------------- 边界


def test_archive_empty_session_and_idempotent(client):
    session_id = make_session(client)
    first = client.post(f"/api/sessions/{session_id}/archive")
    assert first.status_code == 200
    assert first.json()["outcome"] == "archived"
    second = client.post(f"/api/sessions/{session_id}/archive")
    assert second.status_code == 200
    assert second.json()["outcome"] == "already_archived"
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["archive"]["credential_count"] == 0


def test_archive_failure_keeps_credentials_queryable(client):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)

    def boom(*args, **kwargs):
        raise service.ArchiveIntegrityError("模拟归档失败")

    with pytest.MonkeyPatch.context() as scoped:
        scoped.setattr(service, "_compute", boom)
        with pytest.raises(service.ArchiveIntegrityError):
            service.archive_session(str(os.environ["DB_PATH"]), session_id)

    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["archive"]["archived"] is False
    assert [c["credential_no"] for c in detail["credentials"]] == [PLAINTEXT]
    assert PLAINTEXT in client.get(f"/api/sessions/{session_id}").text


def test_archive_rolls_back_if_post_archive_recompute_differs(client):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    original = service._compute
    calls = {"n": 0}

    def drift(session, credentials):
        result = original(session, credentials)
        calls["n"] += 1
        if calls["n"] == 2:  # 归档汇总重算时故意制造偏差
            return (result[0] + 1,) + result[1:]
        return result

    with pytest.MonkeyPatch.context() as scoped:
        scoped.setattr(service, "_compute", drift)
        with pytest.raises(service.ArchiveIntegrityError):
            service.archive_session(str(os.environ["DB_PATH"]), session_id)

    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["archive"]["archived"] is False
    assert [c["credential_no"] for c in detail["credentials"]] == [PLAINTEXT]


def test_archived_session_rejected_from_raw_credential_table(client, db_path):
    session_id = make_session(client)
    add(client, session_id, PLAINTEXT, 5, 21)
    client.post(f"/api/sessions/{session_id}/archive")
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    finally:
        conn.close()
    assert count == 0


def test_interleaved_archive_and_new_credentials_each_counted_once(db_path):
    """归档与补证并发交错：每张已采信凭证只核销一次，汇总与逐张核销等价。"""
    parsed = csv_import.parse_csv(
        Path(__file__).resolve().parent.parent.joinpath("samples", "review.csv").read_bytes(),
        "review.csv",
    )
    session_id = service.create_session(str(db_path), parsed)
    errors: list[str] = []
    lock = threading.Lock()

    def archive_worker():
        try:
            service.archive_session(str(db_path), session_id)
        except Exception as exc:  # pragma: no cover - 失败时给出诊断
            with lock:
                errors.append(repr(exc))

    def add_worker(index: int):
        try:
            service.add_credential(
                str(db_path), session_id, f"RACE-{index}", 5 + index, 21 + index, 1
            )
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(repr(exc))

    threads = [threading.Thread(target=archive_worker)]
    threads += [threading.Thread(target=add_worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    detail = service.get_detail(str(db_path), session_id)
    accepted = [
        service.CredentialInput(f"RACE-{i}", 5 + i, 21 + i, 1) for i in range(2)
    ]
    expected = service._compute(detail["session"], accepted)
    assert detail["result"].pinned_overdue == expected[0]
    assert detail["result"].lower == expected[3]
    assert detail["result"].upper == expected[4]
    assert sum(item.count for item in detail["credential_summary"]) == 2


# ------------------------------------------------- 升级前已有场次的归档


OLD_SCHEMA = """
CREATE TABLE sessions (
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
CREATE TABLE results (
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
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    credential_no TEXT NOT NULL,
    join_minute INTEGER NOT NULL,
    board_minute INTEGER NOT NULL,
    count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (session_id, credential_no)
);
"""


def test_pre_existing_database_can_be_migrated_and_archived(tmp_path, monkeypatch):
    """升级前的库没有指纹列/归档表；init_db 迁移后已有场次可直接归档。"""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    try:
        conn.executescript(OLD_SCHEMA)
        conn.execute(
            """
            INSERT INTO sessions VALUES
                (1, 'legacy.csv', 0, 2, '[1,0]', '[0,1]', 1, 15, 10,
                 '2026-01-01T00:00:00+00:00')
            """
        )
        conn.execute(
            """
            INSERT INTO results VALUES (1, 0, 0, 'meets', 0, 0, 0, 1,
                                        '2026-01-01T00:00:00+00:00')
            """
        )
        conn.execute(
            """
            INSERT INTO credentials VALUES
                (1, 1, ?, 0, 1, 1, '2026-01-01T00:00:00+00:00')
            """,
            (PLAINTEXT,),
        )
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setenv("DB_PATH", str(path))
    init_db(str(path))

    conn = connect(str(path))
    try:
        migrated = conn.execute(
            "SELECT credential_fingerprint FROM credentials WHERE id = 1"
        ).fetchone()["credential_fingerprint"]
        assert migrated  # 旧凭证的指纹已回填
    finally:
        conn.close()

    with TestClient(app) as legacy_client:
        archived = legacy_client.post("/api/sessions/1/archive")
        assert archived.status_code == 200, archived.text
        assert archived.json()["archive"]["credential_count"] == 1
        detail = legacy_client.get("/api/sessions/1").json()
        assert "credentials" not in detail
        assert detail["credential_summary"][0]["count"] == 1
        # 升级前的明文同样被清除，且重送仍能识别
        assert PLAINTEXT.encode() not in path.read_bytes()
        assert (
            legacy_client.post(
                "/api/sessions/1/credentials",
                json={
                    "credential_no": PLAINTEXT,
                    "join_minute": 0,
                    "board_minute": 1,
                    "count": 1,
                },
            ).json()["outcome"]
            == "duplicate"
        )
