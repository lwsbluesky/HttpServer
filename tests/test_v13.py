"""Isolated V1.3 regression and adversarial API tests. Never touches production data."""
import asyncio
import concurrent.futures
import errno
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import zipfile

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

PROJECT = Path(__file__).resolve().parents[1]
BOOTSTRAP = tempfile.TemporaryDirectory(prefix="httpserver-test-bootstrap-")
os.environ["HTTPSERVER_DATA_DIR"] = BOOTSTRAP.name
sys.path.insert(0, str(PROJECT))
import app as server

ADMIN_PASSWORD = "V13-test-admin-pass"
GUEST_PASSWORD = "V13-test-guest-pass"
ADMIN_HASH = server.hash_password(ADMIN_PASSWORD)
GUEST_HASH = server.hash_password(GUEST_PASSWORD)

@pytest.fixture(scope="session", autouse=True)
def close_bootstrap_logs():
    yield
    for handler in server.LOGGER.handlers[:]:
        handler.close()
        server.LOGGER.removeHandler(handler)
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
    for handler in server.LOGGER.handlers[:]:
        handler.close()
        server.LOGGER.removeHandler(handler)
    log_handler = server.RotatingFileHandler(data / "httpserver.log", maxBytes=5*1024**2, backupCount=20, encoding="utf-8")
    server.LOGGER.addHandler(log_handler)
    server.init_db()
    with server.database() as c:
        c.execute("UPDATE users SET password=?,must_change_password=0 WHERE username='admin'", (ADMIN_HASH,))
        c.execute("UPDATE users SET password=?,must_change_password=0 WHERE username='guest'", (GUEST_HASH,))
    share = tmp_path / "share"
    share.mkdir()
    (share / "hello.txt").write_text("你好 world", encoding="utf-8")
    (share / "hidden").mkdir()
    (share / "hidden" / "child.txt").write_text("visible by ACL", encoding="utf-8")
    with server.database() as c:
        rid = c.execute("INSERT INTO share_roots(name,path) VALUES('测试共享',?)", (str(share),)).lastrowid
    with server.LOCK:
        server.LOGIN_FAILURES.clear()
        server.SEARCH_CACHE.clear()
        server.ACTIVE_TEMP.clear()
    with TestClient(server.app, raise_server_exceptions=False) as client:
        admin = client.post("/api/login", json={"username":"admin","password":ADMIN_PASSWORD}).json()["token"]
        guest = client.post("/api/login", json={"username":"guest","password":GUEST_PASSWORD}).json()["token"]
        yield {"client":client,"admin":admin,"guest":guest,"rid":rid,"share":share,"data":data,"temp":temp,
               "ap": {"Authorization":"Bearer "+admin}, "gp":{"Authorization":"Bearer "+guest}}
    log_handler.close()
    server.LOGGER.removeHandler(log_handler)

def path(env, name=""):
    return f"r/{env['rid']}" + ("/"+name if name else "")

def get(env, url, admin=False, **kwargs):
    return env["client"].get(url, headers=env["ap" if admin else "gp"], **kwargs)

def test_hash_salted_and_verified():
    a,b = server.hash_password("密码abcdefghijkl"),server.hash_password("密码abcdefghijkl")
    assert a != b
    assert server.verify_password("密码abcdefghijkl",a)
    assert not server.verify_password("wrong",a)
    for malformed in ("plaintext","pbkdf2_sha256$bad$x$x","pbkdf2_sha256$999999999$x$x"):
        assert not server.verify_password("x",malformed)

def test_plaintext_migration_preserves_rows_and_backup(env):
    legacy = env["data"] / "legacy.db"
    c=sqlite3.connect(legacy)
    c.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT,can_browse INTEGER DEFAULT 1,can_download INTEGER DEFAULT 1); CREATE TABLE share_roots(id INTEGER PRIMARY KEY,name TEXT,path TEXT UNIQUE);")
    c.execute("INSERT INTO users VALUES(1,'admin','legacy-plain-password','admin',1,1)")
    c.execute("INSERT INTO share_roots VALUES(5,'legacy',?)",(str(env["share"]),))
    c.commit();c.close()
    with patch.object(server,"DB",legacy):
        server.init_db()
        with server.database() as c:
            row=c.execute("SELECT * FROM users WHERE id=1").fetchone()
            assert server.verify_password("legacy-plain-password",row["password"])
            assert row["must_change_password"]==1
            assert c.execute("SELECT name FROM share_roots WHERE id=5").fetchone()[0]=="legacy"
            assert all(row[0].startswith("pbkdf2_sha256$") for row in c.execute("SELECT password FROM users"))
        server.init_db()  # Idempotent migration
    assert (env["data"]/"pre-v1.3-backup.db").exists()

def test_first_login_forces_change_and_revokes_all_sessions(env):
    with server.database() as c:
        c.execute("UPDATE users SET must_change_password=1 WHERE username='admin'")
    assert get(env,"/api/admin/users",True).status_code==403
    r=env["client"].post("/api/account/password",headers=env["ap"],json={"current_password":ADMIN_PASSWORD,"new_password":"New-V13-password-strong"})
    assert r.status_code==200
    assert get(env,"/api/account",True).status_code==401
    r=env["client"].post("/api/login",json={"username":"admin","password":"New-V13-password-strong"})
    assert r.status_code==200 and not r.json()["user"]["must_change_password"]

def test_password_validation_and_wrong_current(env):
    for current,new in ((ADMIN_PASSWORD,"short"),("wrong","long-enough-password"),(ADMIN_PASSWORD,ADMIN_PASSWORD)):
        r=env["client"].post("/api/account/password",headers=env["ap"],json={"current_password":current,"new_password":new})
        assert r.status_code==400
    assert get(env,"/api/account",True).status_code==200

def test_no_password_or_hash_disclosure(env):
    for url in ("/api/account","/api/admin/users","/api/admin/sessions"):
        r=get(env,url,True)
        assert r.status_code==200 and '"password":' not in r.text and "pbkdf2_sha256" not in r.text
    with server.database() as c:
        assert all(row[0].startswith("pbkdf2_sha256$") for row in c.execute("SELECT password FROM users"))

def test_logout_revokes_ticket_and_token(env):
    ticket=env["client"].post("/api/download-tickets",headers=env["gp"],params={"path":path(env,"hello.txt")}).json()["ticket"]
    assert env["client"].post("/api/logout",headers=env["gp"]).status_code==200
    assert get(env,"/api/files").status_code==401
    assert env["client"].get("/api/files/download",params={"path":path(env,"hello.txt"),"ticket":ticket}).status_code==401
    assert env["client"].post("/api/logout",headers=env["gp"]).status_code==200

@pytest.mark.parametrize("field",["idle_expires_at","absolute_expires_at"])
def test_session_expiry(env,field):
    server.SESSIONS[server.token_digest(env["guest"])][field]=time.monotonic()-1
    assert get(env,"/api/account").status_code==401

def test_session_cap(env,monkeypatch):
    monkeypatch.setattr(server,"MAX_SESSIONS",3)
    for _ in range(5):
        assert env["client"].post("/api/login",json={"username":"guest","password":GUEST_PASSWORD}).status_code==200
    assert len(server.SESSIONS)==3
    assert get(env,"/api/account",True).status_code==401

def test_login_lockout_full_duration(env,monkeypatch):
    for _ in range(server.LOGIN_MAX_FAILURES):
        assert env["client"].post("/api/login",json={"username":"guest","password":"wrong"}).status_code==401
    key=("testclient","guest")
    server.LOGIN_FAILURES[key]["times"]=[time.monotonic()-server.LOGIN_WINDOW_SECONDS-1]
    r=env["client"].post("/api/login",json={"username":"guest","password":GUEST_PASSWORD})
    assert r.status_code==429 and int(r.headers["Retry-After"])>0
    server.LOGIN_FAILURES[key]["blocked_until"]=0
    assert env["client"].post("/api/login",json={"username":"guest","password":GUEST_PASSWORD}).status_code==200

def test_admin_revoke_session(env):
    sessions=get(env,"/api/admin/sessions",True).json()
    item=next(s for s in sessions if s["username"]=="guest")
    assert env["client"].delete("/api/admin/sessions/"+item["id"],headers=env["ap"]).status_code==200
    assert get(env,"/api/account").status_code==401

@pytest.mark.parametrize("url",["/api/admin/users","/api/admin/share-roots","/api/admin/sessions","/api/admin/audit","/api/admin/diagnostics"])
def test_admin_routes_reject_guest(env,url):
    assert get(env,url).status_code==403
    assert env["client"].get(url).status_code==401

def test_guest_browse_download_acl_does_not_grant_admin(env):
    uid=get(env,"/api/account").json()["id"]
    endpoint=f"/api/admin/share-roots/{env['rid']}/permissions/{uid}"
    assert env["client"].put(endpoint,headers=env["ap"],json={"browse":True,"download":True}).status_code==200
    assert get(env,"/api/files",params={"path":path(env)}).status_code==200
    assert get(env,"/api/files/download",params={"path":path(env,"hello.txt")}).status_code==200
    assert get(env,"/api/admin/share-roots",admin=False).status_code==403

def test_local_client_accepts_lan_address_selected_for_self_route(monkeypatch):
    monkeypatch.setattr(server.socket,"getaddrinfo",lambda *args,**kwargs:[])
    class Probe:
        def __init__(self,*args):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def connect(self,address):pass
        def getsockname(self):return ("192.168.1.10",50123)
    monkeypatch.setattr(server.socket,"socket",Probe)
    assert server.is_local_client("192.168.1.10")
    assert not server.is_local_client("192.168.1.20")
    assert server.is_local_client("127.0.0.1")
    assert server.is_local_client("::1")

def test_browse_dialog_rejects_remote_but_checks_admin_first(env,monkeypatch):
    from starlette.requests import Request as StarletteRequest
    async def invoke(host,token):
        scope={"type":"http","method":"POST","path":"/api/admin/share-roots/browse","headers":[],
               "query_string":b"","client":(host,12345),"server":("192.168.1.10",8000),"scheme":"http"}
        request=StarletteRequest(scope)
        request.state.user=None
        monkeypatch.setattr(server,"current_user",lambda request: {"role":"admin","username":"admin","id":1})
        return request
    monkeypatch.setattr(server,"is_local_client",lambda host:host=="192.168.1.10")
    request=asyncio.run(invoke("192.168.1.10",env["admin"]))
    # Mock the OS dialog and ensure LAN-IP access reaches it.
    import types
    fake_tk=types.ModuleType("tkinter")
    class Root:
        def withdraw(self):pass
        def attributes(self,*args):pass
        def destroy(self):pass
    fake_tk.Tk=Root
    fake_filedialog=types.ModuleType("tkinter.filedialog")
    fake_filedialog.askdirectory=lambda **kwargs:"C:/Shared"
    monkeypatch.setitem(sys.modules,"tkinter",fake_tk)
    monkeypatch.setitem(sys.modules,"tkinter.filedialog",fake_filedialog)
    assert server.browse_root(request)=={"path":"C:/Shared"}
    remote=asyncio.run(invoke("192.168.1.20",env["admin"]))
    with pytest.raises(HTTPException) as denied:server.browse_root(remote)
    assert denied.value.status_code==403

def test_header_only_credentials(env):
    r=env["client"].get("/api/files",params={"token":env["guest"]})
    assert r.status_code==401

def test_user_lifecycle_and_reset(env):
    c=env["client"]; body={"username":"newuser","password":"new-user-password","role":"user"}
    r=c.post("/api/admin/users",headers=env["ap"],json=body)
    assert r.status_code==200
    uid=r.json()["id"]
    assert c.post("/api/admin/users",headers=env["ap"],json=body).status_code==409
    token=c.post("/api/login",json={"username":"newuser","password":body["password"]}).json()["token"]
    # 新账号首次登录不再强制改密，可直接使用
    assert c.get("/api/files",headers={"Authorization":"Bearer "+token}).status_code==200
    assert c.put(f"/api/admin/users/{uid}",headers=env["ap"],json={**body,"password":""}).status_code==200
    assert c.get("/api/account",headers={"Authorization":"Bearer "+token}).status_code==401
    assert c.delete(f"/api/admin/users/{uid}",headers=env["ap"]).status_code==200

def test_last_admin_protected(env):
    admin=get(env,"/api/account",True).json()
    assert env["client"].put(f"/api/admin/users/{admin['id']}",headers=env["ap"],json={"username":"admin","role":"user"}).status_code==400
    assert env["client"].delete(f"/api/admin/users/{admin['id']}",headers=env["ap"]).status_code==400

def test_acl_browse_download_independent_and_live(env):
    uid=get(env,"/api/account").json()["id"]
    endpoint=f"/api/admin/share-roots/{env['rid']}/permissions/{uid}"
    assert env["client"].put(endpoint,headers=env["ap"],json={"browse":False,"download":True,"upload":True,"modify":True,"delete":True}).status_code==200
    assert get(env,"/api/files",params={"path":path(env)}).status_code==403
    assert get(env,"/api/files/view",params={"path":path(env,"hello.txt")}).status_code==403
    assert get(env,"/api/files/download",params={"path":path(env,"hello.txt")}).status_code==200
    result=get(env,f"/api/admin/share-roots/{env['rid']}/permissions",True).json()
    assert result[0]["upload"] and result[0]["modify"] and result[0]["delete"]
    env["client"].put(endpoint,headers=env["ap"],json={"browse":True,"download":False})
    assert get(env,"/api/files",params={"path":path(env)}).status_code==200
    assert get(env,"/api/files/download",params={"path":path(env,"hello.txt")}).status_code==403

def test_search_filters_denied_roots(env):
    uid=get(env,"/api/account").json()["id"]
    env["client"].put(f"/api/admin/share-roots/{env['rid']}/permissions/{uid}",headers=env["ap"],json={})
    assert get(env,"/api/files",params={"q":"hello"}).json()["items"]==[]

@pytest.mark.parametrize("suffix",["../outside.txt","a/../../x","C:/Windows/win.ini","hello.txt:stream","a\\..\\x","hello.txt.","hello.txt ","a//x","nul\x00.txt"])
def test_windows_path_attack(env,suffix):
    r=get(env,"/api/files/download",params={"path":path(env,suffix)})
    assert r.status_code in (400,403)

def test_symlink_escape(env):
    outside=env["share"].parent/"outside.txt";outside.write_text("secret")
    link=env["share"]/"escape.txt"
    try: link.symlink_to(outside)
    except OSError: pytest.skip("Windows symlink privilege not available")
    assert get(env,"/api/files/download",params={"path":path(env,"escape.txt")}).status_code==403
    assert not any(i["name"]=="escape.txt" for i in get(env,"/api/files").json()["items"])

def test_data_directory_guard(env):
    r=env["client"].post("/api/admin/share-roots",headers=env["ap"],json={"path":str(env["data"])})
    assert r.status_code==400
    r=env["client"].post("/api/admin/share-roots",headers=env["ap"],json={"path":str(env["data"].parent)})
    assert r.status_code==400

def test_ticket_one_use_path_bound_and_expiry(env):
    c=env["client"];value=path(env,"hello.txt")
    def ticket():return c.post("/api/download-tickets",headers=env["gp"],params={"path":value}).json()["ticket"]
    t=ticket()
    assert c.get("/api/files/download",params={"path":value,"ticket":t}).content=="你好 world".encode()
    assert c.get("/api/files/download",params={"path":value,"ticket":t}).status_code==401
    t=ticket()
    assert c.get("/api/files/download",params={"path":path(env,"hidden/child.txt"),"ticket":t}).status_code==401
    t=ticket();server.TICKETS[server.token_digest(t)]["expires_at"]=0
    assert c.get("/api/files/download",params={"path":value,"ticket":t}).status_code==401

def test_ticket_purpose_and_acl_recheck(env):
    c=env["client"];value=path(env,"hello.txt")
    t=c.post("/api/download-tickets",headers=env["gp"],params={"path":value,"purpose":"view"}).json()["ticket"]
    assert c.get("/api/files/download",params={"path":value,"ticket":t}).status_code==401
    t=c.post("/api/download-tickets",headers=env["gp"],params={"path":value}).json()["ticket"]
    uid=get(env,"/api/account").json()["id"]
    c.put(f"/api/admin/share-roots/{env['rid']}/permissions/{uid}",headers=env["ap"],json={"browse":True})
    assert c.get("/api/files/download",params={"path":value,"ticket":t}).status_code==403

def test_ticket_cap(env,monkeypatch):
    monkeypatch.setattr(server,"MAX_TICKETS",3)
    for _ in range(5):
        assert env["client"].post("/api/download-tickets",headers=env["gp"],params={"path":path(env,"hello.txt")}).status_code==200
    assert len(server.TICKETS)==3

def test_pdf_inline_with_ticket(env):
    (env["share"]/"test.pdf").write_bytes(b"%PDF-1.4\n%%EOF")
    t=env["client"].post("/api/download-tickets",headers=env["gp"],params={"path":path(env,"test.pdf"),"purpose":"view"}).json()["ticket"]
    r=env["client"].get("/api/files/inline",params={"path":path(env,"test.pdf"),"ticket":t})
    assert r.status_code==200 and r.headers["content-type"]=="application/pdf"

def test_preview_truncation_and_unknown_format(env,monkeypatch):
    monkeypatch.setattr(server,"MAX_PREVIEW_BYTES",8)
    r=get(env,"/api/files/view",params={"path":path(env,"hello.txt")})
    assert r.status_code==200 and r.json()["truncated"] and r.json()["limit_bytes"]==8
    (env["share"]/"a.exe").write_bytes(b"binary")
    assert get(env,"/api/files/view",params={"path":path(env,"a.exe")}).status_code==400

def test_archive_content_and_cleanup(env):
    r=get(env,"/api/files/download",params={"path":path(env)})
    assert r.status_code==200
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        assert any(n.endswith("hello.txt") for n in z.namelist())
        assert z.testzip() is None
    assert not list(env["temp"].iterdir()) and not server.ACTIVE_TEMP

@pytest.mark.parametrize("limit,value,status",[("ZIP_MAX_BYTES",1,413),("ZIP_MAX_FILES",0,413),("ZIP_MAX_SECONDS",-1,504)])
def test_archive_limits_cleanup(env,monkeypatch,limit,value,status):
    monkeypatch.setattr(server,limit,value)
    r=get(env,"/api/files/download",params={"path":path(env)})
    assert r.status_code==status
    assert not list(env["temp"].iterdir()) and not server.ACTIVE_TEMP

def test_archive_diskfull_cleanup(env,monkeypatch):
    usage=shutil_usage=type("Usage",(),{"free":0})()
    monkeypatch.setattr(server.shutil,"disk_usage",lambda p:usage)
    r=get(env,"/api/files/download",params={"path":path(env)})
    assert r.status_code==507 and r.json()["error"]["code"]=="DISK_FULL"
    assert not list(env["temp"].iterdir()) and not server.ACTIVE_TEMP

def test_archive_active_file_limit(env,monkeypatch):
    monkeypatch.setattr(server,"MAX_TEMP_ARCHIVES",0)
    assert get(env,"/api/files/download",params={"path":path(env)}).status_code==503

def test_cleanup_stale_preserves_active(env):
    stale=env["temp"]/"httpserver_stale.zip";stale.write_bytes(b"old");os.utime(stale,(0,0))
    active=env["temp"]/"httpserver_active.zip";active.write_bytes(b"active");os.utime(active,(0,0))
    server.ACTIVE_TEMP.add(str(active))
    server.cleanup()
    assert not stale.exists() and active.exists()
    server.ACTIVE_TEMP.remove(str(active))
    server.cleanup()
    assert not active.exists()

def test_search_cache_limits_and_invalidation(env,monkeypatch):
    assert get(env,"/api/files",params={"q":"hello"}).json()["items"]
    (env["share"]/"new.txt").write_text("new")
    server.invalidate_search_cache()
    assert get(env,"/api/files",params={"q":"new"}).json()["items"]
    monkeypatch.setattr(server,"MAX_CACHE_ENTRIES",2)
    for i in range(5):
        entry={"id":i+100,"path":str(env["share"])}
        server.search_entries(entry,time.monotonic()+5)
    assert len(server.SEARCH_CACHE)<=2

def test_search_timeout_empty_directories(env,monkeypatch):
    monkeypatch.setattr(server,"WORK_MAX_SECONDS",-1)
    assert get(env,"/api/files",params={"q":"hello"}).status_code==504

def test_missing_directory_and_corrupt_hidden_fail_closed(env):
    (env["data"]/"hidden.json").write_text("{bad",encoding="utf-8")
    assert get(env,"/api/files").status_code==500
    (env["data"]/"hidden.json").unlink()
    assert get(env,"/api/files",params={"path":path(env,"missing")}).status_code==404

def test_visibility_inherited_in_list_and_search(env):
    env["client"].post("/api/files/hidden",headers=env["ap"],params={"path":path(env,"hidden")})
    assert not any(i["name"]=="hidden" for i in get(env,"/api/files").json()["items"])
    assert get(env,"/api/files",params={"q":"child"}).json()["items"]==[]
    # Hidden is display-only; access is controlled by ACL rather than visibility.
    assert get(env,"/api/files/download",params={"path":path(env,"hidden/child.txt")}).status_code==200

def test_healthy_and_degraded_status(env,monkeypatch):
    r=env["client"].get("/api/health")
    assert r.status_code==200 and r.json()["version"]=="1.4.0.0" and r.json()["disk_free_bytes"]>0
    monkeypatch.setattr(server,"database",lambda:(_ for _ in ()).throw(sqlite3.OperationalError("broken")))
    r=env["client"].get("/api/health")
    assert r.status_code==503 and r.json()["status"]=="degraded" and "broken" not in r.text

def test_diagnostics_excludes_secrets_database_and_audit(env):
    r=get(env,"/api/admin/diagnostics",True)
    assert r.status_code==200
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        assert sorted(z.namelist())==["README.txt","httpserver.log","status.json"]
        contents=b"".join(z.read(n) for n in z.namelist())
        assert env["admin"].encode() not in contents and ADMIN_PASSWORD.encode() not in contents
        assert b"pbkdf2_sha256$" not in contents
    rows=get(env,"/api/admin/audit",True).json()
    assert any(r["action"]=="diagnostics_export" for r in rows)

def test_audit_retention(env,monkeypatch):
    monkeypatch.setattr(server,"AUDIT_MAX_ROWS",5)
    for i in range(10):server.audit("test",path=str(i))
    server.cleanup()
    with server.database() as c:
        assert c.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]<=5

def test_error_shapes_and_headers(env):
    r=get(env,"/api/files",params={"path":"bad"})
    assert r.status_code==400 and r.json()["request_id"] and r.headers["X-Content-Type-Options"]=="nosniff"
    assert "traceback" not in r.text.lower()
    r=env["client"].post("/api/login",json={"username":""})
    assert r.status_code==422 and r.json()["error"]["code"]=="VALIDATION_ERROR"

def test_two_zip_jobs_isolate_50_normal_requests(env,monkeypatch):
    ready=threading.Barrier(3);release=threading.Event()
    original=server.build_archive
    def slow(*args):
        ready.wait(timeout=15);release.wait(timeout=15);return original(*args)
    monkeypatch.setattr(server,"build_archive",slow)
    c=env["client"]
    def normal(i):
        start=time.perf_counter()
        r=c.get("/api/health") if i%2 else get(env,"/api/files",params={"path":path(env)})
        return r.status_code,time.perf_counter()-start
    with concurrent.futures.ThreadPoolExecutor(max_workers=54) as pool:
        jobs=[pool.submit(get,env,"/api/files/download",params={"path":path(env)}) for _ in range(2)]
        ready.wait(timeout=15)
        try:
            results=list(pool.map(normal,range(50)))
            assert all(status in (200,503) and elapsed<2 for status,elapsed in results),results
            assert any(status==200 for status,_ in results)
            assert get(env,"/api/files/download",params={"path":path(env)}).status_code==503
        finally:release.set()
        assert all(job.result(timeout=20).status_code==200 for job in jobs)
    assert not server.ACTIVE_TEMP

def test_canceled_zip_request_cleans_late_result(env):
    async def exercise():
        ready=threading.Event();release=threading.Event()
        def work():
            ready.set();release.wait(5)
            file=env["temp"]/"httpserver_cancel.zip"
            file.write_bytes(b"archive")
            server.ACTIVE_TEMP.add(str(file))
            return str(file)
        task=asyncio.create_task(server.run_work("zip",work))
        while not ready.is_set():await asyncio.sleep(0.01)
        task.cancel()
        try:await task
        except asyncio.CancelledError:pass
        release.set()
        deadline=time.monotonic()+5
        while server.ACTIVE["zip"] and time.monotonic()<deadline:await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        assert not server.ACTIVE_TEMP and not list(env["temp"].iterdir())
    asyncio.run(exercise())

def test_temp_response_disconnect_cleanup(env):
    file=env["temp"]/"httpserver_disconnect.zip";file.write_bytes(b"file")
    server.ACTIVE_TEMP.add(str(file))
    response=server.TemporaryFileResponse(file)
    async def send(message):raise ConnectionError("client disconnected")
    async def receive():return {"type":"http.disconnect"}
    async def exercise():
        with pytest.raises(ConnectionError):
            await response({"type":"http","method":"GET","headers":[],"extensions":{}},receive,send)
    asyncio.run(exercise())
    assert not file.exists() and not server.ACTIVE_TEMP

def test_database_transaction_rollback(env):
    with pytest.raises(RuntimeError):
        with server.database() as c:
            c.execute("INSERT INTO settings VALUES('rollback-check','value')")
            raise RuntimeError("abort transaction")
    with server.database() as c:
        assert not c.execute("SELECT 1 FROM settings WHERE key='rollback-check'").fetchone()
    server.execute_write("INSERT INTO settings VALUES('rollback-check','after')")
    with server.database() as c:
        assert c.execute("SELECT value FROM settings WHERE key='rollback-check'").fetchone()[0]=="after"

def test_database_busy_error_and_recovery(env):
    blocker=sqlite3.connect(server.DB)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        def release():
            # Separate writer checks that lock waits terminate with an error.
            try:server.execute_write("INSERT INTO settings VALUES('busy','1')")
            except sqlite3.OperationalError:return "busy"
        with concurrent.futures.ThreadPoolExecutor() as pool:
            assert pool.submit(release).result(timeout=10)=="busy"
    finally:blocker.rollback();blocker.close()
    server.execute_write("INSERT INTO settings VALUES('busy','recovered')")
    assert get(env,"/api/account",True).status_code==200

def test_log_rotation_bounded(env):
    logger=logging.getLogger("rotation-test")
    h=server.RotatingFileHandler(env["data"]/"rotation.log",maxBytes=100,backupCount=20)
    logger.addHandler(h);logger.setLevel(logging.INFO)
    try:
        for i in range(100):logger.info("rotation message %s %s",i,"x"*80)
    finally:h.close();logger.removeHandler(h)
    assert len(list(env["data"].glob("rotation.log*")))==21

def test_concurrent_search_and_cache_invalidation(env):
    def query(i):
        if i%3==0:server.invalidate_search_cache()
        return get(env,"/api/files",params={"q":"hello"}).status_code
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes=list(pool.map(query,range(40)))
    assert all(code in (200,503) for code in codes)
    assert len(server.SEARCH_CACHE)<=server.MAX_CACHE_ENTRIES

def test_root_crud_and_conflict_recovery(env):
    other=env["share"].parent/"other";other.mkdir()
    c=env["client"]
    r=c.post("/api/admin/share-roots",headers=env["ap"],json={"name":"other","path":str(other)})
    assert r.status_code==200
    rid=r.json()["id"]
    assert c.put(f"/api/admin/share-roots/{rid}",headers=env["ap"],json={"path":str(env["share"])}).status_code==409
    assert c.delete(f"/api/admin/share-roots/{rid}",headers=env["ap"]).status_code==200
    assert get(env,"/api/files",True,params={"path":f"r/{rid}"}).status_code==404

def test_retention_simulates_72_hours_without_claiming_real_soak(env):
    # Logical expiry tests complement, but cannot substitute for 72h wall clock.
    for hour in range(73):
        server.audit("simulation")
        key=f"expired-{hour}"
        server.SESSIONS[key]={"idle_expires_at":0,"absolute_expires_at":0}
        file=env["temp"]/f"httpserver_{hour}.zip";file.write_bytes(b"old")
        os.utime(file,(0,0))
        server.cleanup()
        assert key not in server.SESSIONS and not file.exists()
    assert len(server.SESSIONS)==2 and not list(env["temp"].iterdir())

def test_prepared_archive_download_and_expired_cleanup(env):
    c=env["client"]
    r=c.post("/api/downloads/prepare",headers=env["gp"],params={"path":path(env)})
    assert r.status_code==200
    ticket=r.json()["ticket"]
    assert len(server.ACTIVE_TEMP)==1
    result=c.get("/api/files/download",params={"path":path(env),"ticket":ticket})
    assert result.status_code==200 and not server.ACTIVE_TEMP
    r=c.post("/api/downloads/prepare",headers=env["gp"],params={"path":path(env)})
    ticket=r.json()["ticket"]
    server.TICKETS[server.token_digest(ticket)]["expires_at"]=0
    server.prune()
    assert not server.ACTIVE_TEMP and not list(env["temp"].iterdir())

def test_prepared_archive_removed_on_permission_change(env):
    c=env["client"];uid=get(env,"/api/account").json()["id"]
    ticket=c.post("/api/downloads/prepare",headers=env["gp"],params={"path":path(env)}).json()["ticket"]
    c.put(f"/api/admin/share-roots/{env['rid']}/permissions/{uid}",headers=env["ap"],json={})
    assert c.get("/api/files/download",params={"path":path(env),"ticket":ticket}).status_code==403
    assert not server.ACTIVE_TEMP and not list(env["temp"].iterdir())

def test_prepared_archive_logout_discards_temp(env):
    c=env["client"]
    assert c.post("/api/downloads/prepare",headers=env["gp"],params={"path":path(env)}).status_code==200
    assert server.ACTIVE_TEMP
    c.post("/api/logout",headers=env["gp"])
    assert not server.ACTIVE_TEMP and not list(env["temp"].iterdir())

def test_prepare_errors_remain_json_for_browser(env,monkeypatch):
    monkeypatch.setattr(server,"ZIP_MAX_BYTES",1)
    r=env["client"].post("/api/downloads/prepare",headers=env["gp"],params={"path":path(env)})
    assert r.status_code==413 and r.headers["content-type"].startswith("application/json")
    assert not server.ACTIVE_TEMP

def test_deleted_defaults_are_not_recreated_on_restart(env):
    with server.database() as c:
        c.execute("DELETE FROM users WHERE username='guest'")
        c.execute("UPDATE users SET username='renamed-admin' WHERE username='admin'")
    server.init_db()
    with server.database() as c:
        names=[row[0] for row in c.execute("SELECT username FROM users")]
    assert names==["renamed-admin"]

@pytest.mark.parametrize("name",["NUL","CON.txt","AUX","COM1.log","LPT9","conout$"])
def test_windows_device_names_rejected(env,name):
    assert get(env,"/api/files/view",params={"path":path(env,name)}).status_code==400

def test_windows_junction_escape_and_loop_excluded(env):
    if os.name!="nt":pytest.skip("Windows junction test")
    import subprocess
    outside=env["share"].parent/"outside";outside.mkdir();(outside/"secret.txt").write_text("secret")
    link=env["share"]/"junction"
    r=subprocess.run(["cmd","/c","mklink","/J",str(link),str(outside)],capture_output=True)
    assert r.returncode==0,"junction creation failed"
    try:
        assert server.is_reparse(link)
        assert get(env,"/api/files/download",params={"path":path(env,"junction/secret.txt")}).status_code==403
        assert get(env,"/api/files",params={"q":"secret"}).json()["items"]==[]
    finally:
        os.rmdir(link)

def test_oversized_and_chunked_json_rejected_before_parse(env):
    r=env["client"].post("/api/login",content=b"x"*(server.MAX_API_BODY_BYTES+1),headers={"Content-Type":"application/json"})
    assert r.status_code==413 and r.json()["error"]["code"]=="BODY_TOO_LARGE"
    r=env["client"].post("/api/login",content=b"x"*(server.MAX_API_BODY_BYTES+1),headers={"Content-Type":"application/json","Content-Length":"1"})
    assert r.status_code==413

def test_sql_injection_login_does_not_authenticate(env):
    r=env["client"].post("/api/login",json={"username":"admin' OR 1=1 --","password":"irrelevant"})
    assert r.status_code==401
