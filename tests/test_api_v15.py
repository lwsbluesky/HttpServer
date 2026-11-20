# -*- coding: utf-8 -*-
"""HttpServer V1.4 增量 API 自动化测试（自包含、隔离临时数据库，不触碰正式 data）。

运行方法（项目虚拟环境）：
  .\.venv\Scripts\python.exe -m pytest <本文件路径> -q
覆盖：上传上限提升(20GB)、>1GB 大文件上传、同名四策略、文件夹嵌套上传、
回收站恢复/彻底删除及权限、改名/删除默认权限与授权、目录 ACL 覆盖、
日志条件查询、新账号/重置密码不强制改密、下载实时统计、前端静态资源关键改动。
"""
import os
import sys
import time
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT = Path(os.environ.get("HTTPSERVER_PROJECT", str(Path(__file__).resolve().parent.parent)))
BOOTSTRAP = tempfile.TemporaryDirectory(prefix="httpserver-v15-bootstrap-")
os.environ["HTTPSERVER_DATA_DIR"] = BOOTSTRAP.name
sys.path.insert(0, str(PROJECT))
import app as server

ADMIN_PW = "v15-test-admin-pass"
GUEST_PW = "v15-test-guest-pass"


@pytest.fixture(scope="session", autouse=True)
def _close_bootstrap():
    yield
    for h in server.LOGGER.handlers[:]:
        h.close()
        server.LOGGER.removeHandler(h)
    BOOTSTRAP.cleanup()


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "state"
    data.mkdir()
    temp = data / "tmp"
    temp.mkdir()
    monkeypatch.setattr(server, "DATA", data)
    monkeypatch.setattr(server, "DB", data / "httpserver.db")
    monkeypatch.setattr(server, "TEMP_DIR", temp)
    for h in server.LOGGER.handlers[:]:
        h.close()
        server.LOGGER.removeHandler(h)
    handler = server.RotatingFileHandler(data / "httpserver.log", maxBytes=5 * 1024**2, backupCount=2, encoding="utf-8")
    server.LOGGER.addHandler(handler)
    server.init_db()
    with server.database() as c:
        c.execute("UPDATE users SET password=?,must_change_password=0 WHERE username='admin'", (server.hash_password(ADMIN_PW),))
        c.execute("UPDATE users SET password=?,must_change_password=0 WHERE username='guest'", (server.hash_password(GUEST_PW),))
    share = tmp_path / "share"
    share.mkdir()
    (share / "hello.txt").write_text("original", encoding="utf-8")
    with server.database() as c:
        rid = c.execute("INSERT INTO share_roots(name,path) VALUES('测试共享',?)", (str(share),)).lastrowid
    with server.LOCK:
        server.LOGIN_FAILURES.clear()
        server.SEARCH_CACHE.clear()
    with TestClient(server.app, raise_server_exceptions=False) as client:
        at = client.post("/api/login", json={"username": "admin", "password": ADMIN_PW}).json()["token"]
        gt = client.post("/api/login", json={"username": "guest", "password": GUEST_PW}).json()["token"]
        yield {"client": client, "rid": rid, "share": share, "data": data,
               "ap": {"Authorization": "Bearer " + at}, "gp": {"Authorization": "Bearer " + gt}}
    handler.close()
    server.LOGGER.removeHandler(handler)


def path(env, name=""):
    return f"r/{env['rid']}" + ("/" + name if name else "")


def upload(env, filename, content, conflict=None, headers=None, target=None):
    params = {"path": target or path(env), "filename": filename}
    if conflict:
        params["conflict"] = conflict
    return env["client"].post("/api/files/upload", headers=headers or env["ap"], params=params, content=content)


def login(env, username, password):
    r = env["client"].post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def recycle_ids(env, headers=None):
    r = env["client"].get("/api/recycle-bin", headers=headers or env["ap"])
    assert r.status_code == 200
    return {x["id"]: x for x in r.json()}


# ---------------- 上传 ----------------

def test_upload_limit_raised_to_20gb():
    assert server.MAX_UPLOAD_BYTES == 20 * 1024**3


def test_upload_over_old_1gb_limit_succeeds(env, tmp_path):
    big = tmp_path / "big.bin"
    with big.open("wb") as f:
        f.seek(1100 * 1024**2 - 1)
        f.write(b"\0")

    def chunks():
        with big.open("rb") as f:
            while True:
                b = f.read(1024**2)
                if not b:
                    break
                yield b

    r = upload(env, "big.bin", chunks())
    assert r.status_code == 200, r.text
    assert r.json()["size"] == 1100 * 1024**2
    assert (env["share"] / "big.bin").stat().st_size == 1100 * 1024**2
    assert not list(env["share"].glob(".httpserver-upload-*.tmp"))


def test_upload_conflict_error_rename_skip_overwrite(env):
    assert upload(env, "hello.txt", b"x").status_code == 409
    r = upload(env, "hello.txt", b"renamed", "rename")
    assert r.status_code == 200 and r.json()["name"] == "hello (1).txt"
    r = upload(env, "hello.txt", b"ignored", "skip")
    assert r.status_code == 200 and r.json()["skipped"]
    r = upload(env, "hello.txt", b"replacement", "overwrite")
    assert r.status_code == 200
    assert (env["share"] / "hello.txt").read_bytes() == b"replacement"


def test_upload_invalid_conflict_and_length_mismatch(env):
    assert upload(env, "a.txt", b"a", "bogus").status_code == 400
    r = env["client"].post("/api/files/upload", headers={**env["ap"], "Content-Length": "999"},
                           params={"path": path(env), "filename": "a.txt"}, content=b"abc")
    assert r.status_code == 400
    assert not (env["share"] / "a.txt").exists()


def test_upload_guest_default_denied_then_acl_grant(env):
    assert upload(env, "g.txt", b"g", headers=env["gp"]).status_code == 403
    uid = env["client"].get("/api/admin/users", headers=env["ap"]).json()
    gid = [u["id"] for u in uid if u["username"] == "guest"][0]
    r = env["client"].put(f"/api/admin/share-roots/{env['rid']}/permissions/{gid}",
                          headers=env["ap"], json={"browse": True, "download": True, "upload": True})
    assert r.status_code == 200
    assert upload(env, "g.txt", b"g", headers=env["gp"]).status_code == 200


def test_nested_folder_create_and_upload(env):
    for parent, name in ((path(env), "updir"), (path(env, "updir"), "sub")):
        r = env["client"].post("/api/files/folders", headers=env["ap"], json={"path": parent, "name": name})
        assert r.status_code == 200
    assert upload(env, "deep.txt", b"deep", target=path(env, "updir/sub")).status_code == 200
    assert (env["share"] / "updir" / "sub" / "deep.txt").read_bytes() == b"deep"
    dup = env["client"].post("/api/files/folders", headers=env["ap"], json={"path": path(env), "name": "updir"})
    assert dup.status_code == 409


# ---------------- 回收站：恢复 / 彻底删除 ----------------

def test_delete_to_recycle_and_restore(env):
    r = env["client"].request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")})
    assert r.status_code == 200
    assert not (env["share"] / "hello.txt").exists()
    items = recycle_ids(env)
    assert len(items) == 1
    iid = next(iter(items))
    r = env["client"].post(f"/api/recycle-bin/{iid}/restore", headers=env["ap"])
    assert r.status_code == 200
    assert (env["share"] / "hello.txt").read_text(encoding="utf-8") == "original"
    assert recycle_ids(env) == {}


def test_purge_file_removes_stored_and_row(env):
    env["client"].request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")})
    iid = next(iter(recycle_ids(env)))
    stored = env["share"] / ".httpserver_recycle" / iid
    assert stored.exists()
    r = env["client"].delete(f"/api/recycle-bin/{iid}", headers=env["ap"])
    assert r.status_code == 200
    assert not stored.exists()
    assert recycle_ids(env) == {}
    logs = env["client"].get("/api/admin/audit", headers=env["ap"], params={"action": "recycle_purge"}).json()
    assert len(logs) == 1 and logs[0]["result"] == "ok"


def test_purge_folder_removes_tree(env):
    d = env["share"] / "purgedir"
    d.mkdir()
    (d / "child.txt").write_text("c")
    env["client"].request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "purgedir")})
    iid = next(iter(recycle_ids(env)))
    stored = env["share"] / ".httpserver_recycle" / iid
    assert (stored / "child.txt").exists()
    assert env["client"].delete(f"/api/recycle-bin/{iid}", headers=env["ap"]).status_code == 200
    assert not stored.exists()


def test_purge_permissions(env):
    env["client"].request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")})
    iid = next(iter(recycle_ids(env)))
    assert env["client"].delete(f"/api/recycle-bin/{iid}", headers=env["gp"]).status_code == 403
    assert env["client"].delete(f"/api/recycle-bin/{iid}").status_code == 401
    assert env["client"].delete("/api/recycle-bin/nonexistent", headers=env["ap"]).status_code == 404
    assert env["client"].delete(f"/api/recycle-bin/{iid}", headers=env["ap"]).status_code == 200


def test_purge_guest_owner_with_delete_flag(env):
    users = env["client"].get("/api/admin/users", headers=env["ap"]).json()
    gid = [u["id"] for u in users if u["username"] == "guest"][0]
    r = env["client"].put(f"/api/admin/users/{gid}", headers=env["ap"],
                          json={"username": "guest", "role": "user", "can_browse": True, "can_download": True,
                                "can_rename": False, "can_delete": True})
    assert r.status_code == 200
    gp = login(env, "guest", GUEST_PW)  # 用户更新后会话被注销，需重登
    assert upload(env, "own.txt", b"own", headers=gp).status_code == 403  # 仍无上传权限
    (env["share"] / "own.txt").write_text("own")
    assert env["client"].request("DELETE", "/api/files/item", headers=gp, json={"path": path(env, "own.txt")}).status_code == 200
    iid = next(iter(recycle_ids(env, gp)))
    assert env["client"].delete(f"/api/recycle-bin/{iid}", headers=gp).status_code == 200
    # 他人的回收站项目仍不可彻底删除
    env["client"].request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")})
    aid = next(iter(recycle_ids(env)))
    assert env["client"].delete(f"/api/recycle-bin/{aid}", headers=gp).status_code == 403


# ---------------- 改名 / 删除默认权限 ----------------

def test_rename_delete_guest_default_denied(env):
    assert env["client"].patch("/api/files/item", headers=env["gp"], json={"path": path(env, "hello.txt"), "name": "x.txt"}).status_code == 403
    assert env["client"].request("DELETE", "/api/files/item", headers=env["gp"], json={"path": path(env, "hello.txt")}).status_code == 403


def test_grant_rename_delete_via_user_flags(env):
    users = env["client"].get("/api/admin/users", headers=env["ap"]).json()
    gid = [u["id"] for u in users if u["username"] == "guest"][0]
    assert env["client"].put(f"/api/admin/users/{gid}", headers=env["ap"],
                             json={"username": "guest", "role": "user", "can_browse": True, "can_download": True,
                                   "can_rename": True, "can_delete": True}).status_code == 200
    gp = login(env, "guest", GUEST_PW)
    r = env["client"].patch("/api/files/item", headers=gp, json={"path": path(env, "hello.txt"), "name": "renamed.txt"})
    assert r.status_code == 200
    assert (env["share"] / "renamed.txt").exists()
    assert env["client"].request("DELETE", "/api/files/item", headers=gp, json={"path": path(env, "renamed.txt")}).status_code == 200


def test_acl_overrides_user_flags(env):
    users = env["client"].get("/api/admin/users", headers=env["ap"]).json()
    gid = [u["id"] for u in users if u["username"] == "guest"][0]
    env["client"].put(f"/api/admin/users/{gid}", headers=env["ap"],
                      json={"username": "guest", "role": "user", "can_browse": True, "can_download": True,
                            "can_rename": True, "can_delete": True})
    gp = login(env, "guest", GUEST_PW)
    env["client"].put(f"/api/admin/share-roots/{env['rid']}/permissions/{gid}", headers=env["ap"],
                      json={"browse": True, "download": True, "upload": False, "modify": False, "delete": False})
    assert env["client"].patch("/api/files/item", headers=gp, json={"path": path(env, "hello.txt"), "name": "x.txt"}).status_code == 403


# ---------------- 日志条件查询 ----------------

def test_audit_filters(env):
    env["client"].post("/api/login", json={"username": "guest", "password": "wrong-password"})
    now = time.time()
    base = env["client"].get("/api/admin/audit", headers=env["ap"], params={"limit": 500}).json()
    assert base
    by_user = env["client"].get("/api/admin/audit", headers=env["ap"], params={"username": "guest", "limit": 500}).json()
    assert by_user and all(x["username"] == "guest" for x in by_user)
    denied = env["client"].get("/api/admin/audit", headers=env["ap"], params={"result": "denied", "limit": 500}).json()
    assert denied and all(x["result"] == "denied" for x in denied)
    login_denied = env["client"].get("/api/admin/audit", headers=env["ap"],
                                     params={"username": "guest", "action": "login", "result": "denied"}).json()
    assert login_denied and all(x["action"] == "login" for x in login_denied)
    window = env["client"].get("/api/admin/audit", headers=env["ap"], params={"start": now - 60, "end": now + 60, "limit": 500}).json()
    assert window and all(now - 60 <= x["created_at"] <= now + 60 for x in window)
    future = env["client"].get("/api/admin/audit", headers=env["ap"], params={"start": now + 3600}).json()
    assert future == []
    assert env["client"].get("/api/admin/audit", headers=env["gp"]).status_code == 403


# ---------------- 前端静态资源关键改动 ----------------

def test_static_assets_contain_fixes():
    with TestClient(server.app) as client:
        js = client.get("/static/app.js").text
        html = client.get("/files").text
    assert "conflictForm" in js and "彻底删除" in js and "logindark" in js
    assert "同名文件处理方式：error" not in js  # 原生 prompt 已移除
    assert "loginver" not in js  # 登录页版本号已移除
    assert 'right:12px' in html and ".logindark" in html and "pwclose" in html
    assert "navitem" in js and "data-tip" in js and "download:\"下载\"" in js  # 侧栏图标提示 + 下载徽章
    assert ".side-collapsed .side [data-tip]:hover::after" in html  # Gemini 式悬停提示
    assert "top:10px" in html  # 用户面板上移


# ---------------- 新账号密码策略 ----------------

def test_new_account_no_forced_password_change(env):
    r = env["client"].post("/api/admin/users", headers=env["ap"],
                           json={"username": "newbie", "password": "newbie-pass-1234", "role": "user",
                                 "can_browse": True, "can_download": True, "can_rename": False, "can_delete": False})
    assert r.status_code == 200
    nh = login(env, "newbie", "newbie-pass-1234")
    assert env["client"].get("/api/account", headers=nh).json()["must_change_password"] == 0
    assert env["client"].get("/api/files", headers=nh).status_code == 200  # 首次登录直接可用，无 403


def test_admin_reset_password_no_forced_change(env):
    users = env["client"].get("/api/admin/users", headers=env["ap"]).json()
    gid = [u["id"] for u in users if u["username"] == "guest"][0]
    assert env["client"].put(f"/api/admin/users/{gid}", headers=env["ap"],
                             json={"username": "guest", "role": "user", "can_browse": True, "can_download": True,
                                   "can_rename": False, "can_delete": False, "password": "reset-guest-pass-1"}).status_code == 200
    gp = login(env, "guest", "reset-guest-pass-1")
    assert env["client"].get("/api/account", headers=gp).json()["must_change_password"] == 0
    assert env["client"].get("/api/files", headers=gp).status_code == 200


# ---------------- 下载实时统计 ----------------

def test_health_includes_download_gauge(env):
    tasks = env["client"].get("/api/health").json()["active_tasks"]
    assert "download" in tasks and tasks["download"] == 0


def test_download_gauge_counts_during_streaming(tmp_path):
    import asyncio
    f = tmp_path / "f.bin"
    f.write_bytes(b"abc")
    resp = server.CountedFileResponse(f, filename="f.bin")
    seen = []

    async def receive():
        return {"type": "http.request"}

    async def send(msg):
        if msg["type"] == "http.response.body":
            seen.append(server.ACTIVE["download"])

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
             "path": "/", "raw_path": b"/", "query_string": b"", "headers": [],
             "client": ("127.0.0.1", 1), "server": ("test", 80)}
    asyncio.run(resp(scope, receive, send))
    assert seen and all(n == 1 for n in seen)  # 传输期间实时计数为 1
    assert server.ACTIVE["download"] == 0  # 结束后归零


def test_download_end_to_end_and_gauge_reset(env):
    prep = env["client"].post("/api/downloads/prepare", headers=env["ap"], params={"path": path(env, "hello.txt")})
    assert prep.status_code == 200
    ticket = prep.json()["ticket"]
    r = env["client"].get("/api/files/download", headers=env["ap"],
                          params={"path": path(env, "hello.txt"), "ticket": ticket})
    assert r.status_code == 200 and r.content == b"original"
    assert env["client"].get("/api/health").json()["active_tasks"]["download"] == 0