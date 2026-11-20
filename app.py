"""HttpServer 1.4: local file sharing with bounded work and file management."""
import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
import errno
import fnmatch
import hashlib
import hmac
import ipaddress
import io
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import zipfile
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

APP_VERSION = "1.4.0.0"
EXE_DIR = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", EXE_DIR))
DATA = Path(os.getenv("HTTPSERVER_DATA_DIR", str(EXE_DIR / "data"))).resolve()
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / "httpserver.db"
TEMP_DIR = DATA / "tmp"
TEMP_DIR.mkdir(exist_ok=True)
STATIC_DIR = BUNDLE_DIR / "static"
if not STATIC_DIR.exists():
    STATIC_DIR = EXE_DIR / "static"
STARTED_AT = time.monotonic()
PASSWORD_ITERATIONS = 240_000
SESSION_TTL_SECONDS = 8 * 3600
SESSION_ABSOLUTE_TTL_SECONDS = 7 * 86400
MAX_SESSIONS = 4096
TICKET_TTL_SECONDS = 60
MAX_TICKETS = 4096
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 600
MAX_LOGIN_KEYS = 4096
CACHE_TTL_SECONDS = 10
MAX_CACHE_ENTRIES = 8
MAX_INDEX_ENTRIES = 100_000
MAX_TOTAL_CACHE_ITEMS = 100_000
MAX_TEMP_ARCHIVES = 8
MAX_PREVIEW_BYTES = 2 * 1024**2
MAX_API_BODY_BYTES = 64 * 1024
MAX_UPLOAD_BYTES = 20 * 1024**3
UPLOAD_CHUNK_BYTES = 1024**2
MAX_CONCURRENT_UPLOADS = 4
RECYCLE_RETENTION_SECONDS = 30 * 86400
RECYCLE_DIR_NAME = ".httpserver_recycle"
ZIP_MAX_BYTES = 2 * 1024**3
ZIP_MAX_SECONDS = 120
ZIP_MAX_FILES = 100_000
WORK_MAX_SECONDS = 30
AUDIT_MAX_ROWS = 50_000
PERMISSIONS = ("browse", "download", "upload", "modify", "delete")
TEXT_EXTENSIONS = {".txt", ".log", ".md", ".json", ".xml", ".csv", ".tsv", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".html", ".htm", ".css", ".js", ".ts", ".py", ".java", ".c", ".cpp", ".h", ".hpp", ".sql", ".rtf", ".properties", ".sh", ".bat", ".ps1", ".toml"}
VIEW_EXTENSIONS = TEXT_EXTENSIONS | {".pdf"}
LOGGER = logging.getLogger("httpserver")
LOGGER.setLevel(logging.INFO)
if not LOGGER.handlers:
    handler = RotatingFileHandler(DATA / "httpserver.log", maxBytes=5 * 1024**2, backupCount=20, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
LOCK = threading.RLock()
SESSIONS = OrderedDict()
TICKETS = OrderedDict()
LOGIN_FAILURES = OrderedDict()
SEARCH_CACHE = OrderedDict()
ACTIVE_TEMP = set()
STOP = threading.Event()
POOLS, GATES = {}, {}
ACTIVE = {"browse": 0, "search": 0, "preview": 0, "zip": 0, "upload": 0, "download": 0}
UPLOAD_GATE = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)
HIDDEN_LOCK = threading.Lock()
CACHE_GENERATION = 0

@contextmanager
def database():
    c = sqlite3.connect(DB, timeout=2)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=2000")
        c.execute("PRAGMA secure_delete=ON")
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()

def execute_write(sql, values=()):
    for attempt in range(3):
        try:
            with database() as c:
                return c.execute(sql, values).lastrowid
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 2:
                raise
            time.sleep(0.05 * (attempt + 1))

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"

def verify_password(password, stored):
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        if algorithm != "pbkdf2_sha256" or not 100_000 <= int(iterations) <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False

def validate_password(password):
    if len(password) < 12 or len(password.encode()) > 1024:
        raise HTTPException(400, "密码须至少 12 个字符且不超过 1024 字节")

def init_db():
    if DB.exists():
        old = sqlite3.connect(DB)
        try:
            columns = {r[1] for r in old.execute("PRAGMA table_info(users)")}
            backup_path = DATA / "pre-v1.3-backup.db"
            if columns and "must_change_password" not in columns and not backup_path.exists():
                backup = sqlite3.connect(backup_path)
                try:
                    old.backup(backup)
                finally:
                    backup.close()
        finally:
            old.close()
    with database() as c:
        first_install = not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
          role TEXT NOT NULL, can_browse INTEGER NOT NULL DEFAULT 1,
          can_download INTEGER NOT NULL DEFAULT 1, must_change_password INTEGER NOT NULL DEFAULT 0,
          can_rename INTEGER NOT NULL DEFAULT 0, can_delete INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS share_roots (id INTEGER PRIMARY KEY, name TEXT NOT NULL, path TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS root_permissions (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          root_id INTEGER NOT NULL REFERENCES share_roots(id) ON DELETE CASCADE,
          browse INTEGER NOT NULL, download INTEGER NOT NULL,
          upload INTEGER NOT NULL DEFAULT 0, modify INTEGER NOT NULL DEFAULT 0,
          "delete" INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,root_id));
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY, username TEXT, action TEXT NOT NULL, path TEXT NOT NULL,
          result TEXT NOT NULL, client_ip TEXT, detail TEXT NOT NULL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS recycle_items (
          id TEXT PRIMARY KEY, root_id INTEGER NOT NULL REFERENCES share_roots(id) ON DELETE CASCADE,
          original_path TEXT NOT NULL, stored_path TEXT NOT NULL, name TEXT NOT NULL,
          item_type TEXT NOT NULL, size INTEGER NOT NULL, username TEXT NOT NULL,
          deleted_at REAL NOT NULL, expires_at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS audit_time ON audit_logs(created_at);
        """)
        columns = {r[1] for r in c.execute("PRAGMA table_info(users)")}
        if "must_change_password" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        if "can_rename" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN can_rename INTEGER NOT NULL DEFAULT 0")
        if "can_delete" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN can_delete INTEGER NOT NULL DEFAULT 0")
        if first_install:
            for name, password, role in (("admin", "admin123", "admin"), ("guest", "guest123", "user")):
                c.execute("INSERT INTO users(username,password,role,must_change_password) VALUES(?,?,?,0)",
                          (name, hash_password(password), role))
        for row in c.execute("SELECT id,password FROM users").fetchall():
            if not row["password"].startswith("pbkdf2_sha256$"):
                c.execute("UPDATE users SET password=?,must_change_password=1 WHERE id=?",
                          (hash_password(row["password"]), row["id"]))
        if not c.execute("SELECT 1 FROM settings WHERE key='removed_program_root'").fetchone():
            c.execute("DELETE FROM share_roots WHERE name='程序目录'")
            c.execute("INSERT INTO settings VALUES('removed_program_root','1')")
        c.execute("PRAGMA user_version=1400")

init_db()
DUMMY_HASH = hash_password(secrets.token_urlsafe(24))

def audit(action, request=None, user=None, path="", result="ok", detail=""):
    ip = request.client.host if request and request.client else "system"
    try:
        execute_write("INSERT INTO audit_logs(username,action,path,result,client_ip,detail,created_at) VALUES(?,?,?,?,?,?,?)",
                      ((user or {}).get("username", ""), action, path[:2048], result, ip, detail[:500], time.time()))
    except sqlite3.Error:
        LOGGER.exception("audit write failed")
    LOGGER.info("%s user=%r result=%s path=%r", action, (user or {}).get("username", ""), result, path[:2048])

def public_user(row):
    return {key: row[key] for key in ("id", "username", "role", "can_browse", "can_download", "must_change_password", "can_rename", "can_delete")}

def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def discard_ticket(value):
    archive = value.get("archive")
    if archive:
        try:
            Path(archive).unlink(missing_ok=True)
        except OSError:
            LOGGER.warning("expired archive removal deferred")
        finally:
            ACTIVE_TEMP.discard(archive)

def prune(now=None):
    now = time.monotonic() if now is None else now
    with LOCK:
        for key, value in list(SESSIONS.items()):
            if min(value["idle_expires_at"], value["absolute_expires_at"]) <= now:
                SESSIONS.pop(key, None)
        for key, value in list(TICKETS.items()):
            if value["expires_at"] <= now or value["session"] not in SESSIONS:
                TICKETS.pop(key, None)
                discard_ticket(value)
        for key, value in list(LOGIN_FAILURES.items()):
            if value["blocked_until"] <= now and (not value["times"] or now - value["times"][-1] >= LOGIN_WINDOW_SECONDS):
                LOGIN_FAILURES.pop(key, None)
        for key, value in list(SEARCH_CACHE.items()):
            if value[0] <= now:
                SEARCH_CACHE.pop(key, None)

def extract_token(request):
    value = request.headers.get("authorization", "")
    return value[7:].strip() if value.lower().startswith("bearer ") else ""

def current_user(request, allow_password_change=False):
    key = token_digest(extract_token(request))
    now = time.monotonic()
    with LOCK:
        session = SESSIONS.get(key)
        if not session or min(session["idle_expires_at"], session["absolute_expires_at"]) <= now:
            SESSIONS.pop(key, None)
            raise HTTPException(401, "登录已过期，请重新登录")
        user_id = session["user_id"]
    with database() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(401, "账号已失效")
    user = public_user(row)
    request.state.user, request.state.session = user, key
    if user["must_change_password"] and not allow_password_change:
        raise HTTPException(403, "请先修改初始密码", headers={"X-Password-Change-Required": "1"})
    with LOCK:
        if key not in SESSIONS:
            raise HTTPException(401, "会话已注销")
        SESSIONS[key]["idle_expires_at"] = now + SESSION_TTL_SECONDS
    return user

def admin_user(request):
    user = current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "需要管理员权限")
    return user

def is_local_client(client_host: str) -> bool:
    try:
        client_ip = ipaddress.ip_address(client_host.split("%", 1)[0])
    except ValueError:
        return False
    if client_ip.is_loopback:
        return True
    local_addresses = set()
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM):
            try:
                local_addresses.add(ipaddress.ip_address(result[4][0].split("%", 1)[0]))
            except ValueError:
                continue
    except OSError:
        pass
    # A UDP connect only selects a route; it sends no packets. For a browser
    # opening the service through this host's LAN address, Windows selects that
    # same address as the route source. A remote client selects a different one.
    family = socket.AF_INET6 if client_ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((client_host, 9))
            source = ipaddress.ip_address(probe.getsockname()[0].split("%", 1)[0])
            local_addresses.add(source)
    except (OSError, ValueError, IndexError):
        pass
    return client_ip in local_addresses

def revoke_user(user_id):
    with LOCK:
        for key, value in list(SESSIONS.items()):
            if value["user_id"] == user_id:
                SESSIONS.pop(key)
        prune()

def roots():
    with database() as c:
        return [dict(row) for row in c.execute("SELECT * FROM share_roots ORDER BY id")]

def root_by_id(root_id):
    with database() as c:
        row = c.execute("SELECT * FROM share_roots WHERE id=?", (root_id,)).fetchone()
    if not row:
        raise HTTPException(404, "共享目录不存在")
    return dict(row)

def permissions(user, root_id):
    if user["role"] == "admin":
        return dict.fromkeys(PERMISSIONS, True)
    with database() as c:
        row = c.execute("SELECT * FROM root_permissions WHERE user_id=? AND root_id=?", (user["id"], root_id)).fetchone()
    if row:
        return {key: bool(row[key]) for key in PERMISSIONS}
    return {"browse": bool(user["can_browse"]), "download": bool(user["can_download"]),
            "upload": False, "modify": bool(user.get("can_rename")), "delete": bool(user.get("can_delete"))}

def check_permission(user, root_id, action):
    if not permissions(user, root_id)[action]:
        raise HTTPException(403, "没有该共享目录的操作权限")

def is_reparse(path):
    # Python 3.10 lacks Path.is_junction(); Windows marks junctions as reparse points.
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True

def resolve_path(value):
    parts = value.split("/")
    if len(parts) < 2 or parts[0] != "r" or not parts[1].isdigit():
        raise HTTPException(400, "无效共享路径")
    if any(part in ("", ".", "..") or any(ch in part for ch in "\\:\x00") or
           part.endswith((" ", ".")) for part in parts[2:]):
        raise HTTPException(400, "非法文件路径")
    if any(part.casefold() == RECYCLE_DIR_NAME.casefold() for part in parts[2:]):
        raise HTTPException(404, "文件不存在")
    if any(part.casefold().startswith(".httpserver-upload-") for part in parts[2:]):
        raise HTTPException(404, "文件不存在")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"{name}{i}" for name in ("COM", "LPT") for i in range(1, 10)}
    if any(part.split(".", 1)[0].upper() in reserved for part in parts[2:]):
        raise HTTPException(400, "Windows 设备名称不能作为共享文件访问")
    root_id = int(parts[1])
    root = Path(root_by_id(root_id)["path"]).resolve()
    target = root.joinpath(*parts[2:]).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(403, "目标不在共享目录内")
    # Existing shares may predate the data-directory guard.
    if target == DATA or DATA in target.parents:
        raise HTTPException(403, "服务数据目录不能共享")
    return target, root_id, "/".join(parts[2:])

def hidden_paths():
    path = DATA / "hidden.json"
    if not path.exists():
        return set()
    values = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise HTTPException(503, "隐藏项配置损坏，请管理员恢复")
    return set(values)

def is_hidden(value, hidden):
    return any(value == item or value.startswith(item + "/") for item in hidden)

def file_item(path, root_id, root, hidden):
    resolved = path.resolve()
    if (resolved != root and root not in resolved.parents) or resolved == DATA or DATA in resolved.parents:
        return None
    stat = path.stat()
    directory = path.is_dir()
    relative = path.relative_to(root).as_posix()
    value = f"r/{root_id}" + ("/" + relative if relative != "." else "")
    return {"name": path.name, "path": value, "type": "folder" if directory else "file",
            "size": 0 if directory else stat.st_size, "modified": stat.st_mtime,
            "extension": path.suffix.lower(), "can_view": not directory and path.suffix.lower() in VIEW_EXTENSIONS,
            "hidden": is_hidden(value, hidden)}

def invalidate_search_cache():
    global CACHE_GENERATION
    with LOCK:
        CACHE_GENERATION += 1
        SEARCH_CACHE.clear()

def search_entries(entry, deadline):
    key = (entry["id"], entry["path"])
    with LOCK:
        cached, generation = SEARCH_CACHE.get(key), CACHE_GENERATION
        if cached and cached[0] > time.monotonic():
            return cached[1]
    root = Path(entry["path"]).resolve()
    if not root.is_dir():
        raise HTTPException(404, "共享目录不存在或已离线")
    result = []
    for parent, directories, names in os.walk(root, followlinks=False):
        if time.monotonic() > deadline or STOP.is_set():
            raise HTTPException(504, "搜索超时或服务正在停止")
        directories[:] = [n for n in directories if not n.startswith(".") and not is_reparse(Path(parent, n))
                          and Path(parent, n).resolve() != DATA]
        for name in names:
            if name.startswith("."):
                continue
            try:
                item = file_item(Path(parent, name), entry["id"], root, set())
                if item:
                    result.append(item)
            except (FileNotFoundError, PermissionError):
                continue
            if len(result) >= MAX_INDEX_ENTRIES:
                raise HTTPException(413, "共享目录超过搜索上限，请拆分目录")
            if time.monotonic() > deadline:
                raise HTTPException(504, "搜索超时，请缩小范围后重试")
    with LOCK:
        if generation == CACHE_GENERATION:
            SEARCH_CACHE[key] = (time.monotonic() + CACHE_TTL_SECONDS, result)
            while len(SEARCH_CACHE) > MAX_CACHE_ENTRIES or sum(len(value[1]) for value in SEARCH_CACHE.values()) > MAX_TOTAL_CACHE_ITEMS:
                SEARCH_CACHE.popitem(last=False)
    return result

def page_result(items, page, page_size, sort, order, path, search):
    keys = {"name": lambda x: x["name"].casefold(), "size": lambda x: x["size"],
            "modified": lambda x: x["modified"], "type": lambda x: x["type"]}
    key = keys.get(sort, keys["name"])
    items.sort(key=lambda x: (key(x), x["name"].casefold()), reverse=order == "desc")
    items.sort(key=lambda x: x["type"] != "folder")
    total = len(items)
    start = (page - 1) * page_size
    return {"path": path, "items": items[start:start + page_size], "search": search,
            "total": total, "page": page, "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size), "sort": sort, "order": order}

def list_files(user, value="", query="", page=1, page_size=20, sort="name", order="asc"):
    hidden = hidden_paths()
    deadline = time.monotonic() + WORK_MAX_SECONDS
    if query:
        result = []
        for entry in roots():
            if not permissions(user, entry["id"])["browse"]:
                continue
            for item in search_entries(entry, deadline):
                name = item["name"].lower()
                match = fnmatch.fnmatchcase(name, query.lower()) if any(c in query for c in "*?") else query.lower() in name
                if match and (user["role"] == "admin" or not is_hidden(item["path"], hidden)):
                    result.append({**item, "hidden": is_hidden(item["path"], hidden)})
                    if len(result) > MAX_INDEX_ENTRIES:
                        raise HTTPException(413, "搜索结果过多，请缩小范围")
        perm_cache = {}
        for item in result:
            rid = int(item["path"].split("/")[1])
            if rid not in perm_cache:
                perm_cache[rid] = permissions(user, rid)
            item["can_modify"] = perm_cache[rid]["modify"]
            item["can_delete"] = perm_cache[rid]["delete"]
        return page_result(result, page, page_size, sort, order, "", True)
    if not value:
        shared = [entry for entry in roots() if permissions(user, entry["id"])["browse"]]
        if len(shared) == 1:
            value = f"r/{shared[0]['id']}"
        else:
            items = []
            for entry in shared:
                vp = f"r/{entry['id']}"
                if user["role"] != "admin" and is_hidden(vp, hidden):
                    continue
                perms = permissions(user, entry["id"])
                items.append({"name": entry["name"], "path": vp, "type": "folder", "size": 0,
                              "modified": 0, "extension": "", "can_view": False, "hidden": is_hidden(vp, hidden),
                              "can_modify": perms["modify"], "can_delete": perms["delete"]})
            return page_result(items, page, page_size, sort, order, "", False)
    path, root_id, _ = resolve_path(value)
    check_permission(user, root_id, "browse")
    if not path.is_dir():
        raise HTTPException(404, "目录不存在或已离线")
    root = Path(root_by_id(root_id)["path"]).resolve()
    items = []
    for child in path.iterdir():
        if child.name.startswith("."):
            continue
        try:
            item = file_item(child, root_id, root, hidden)
        except (FileNotFoundError, PermissionError):
            continue
        if item and (user["role"] == "admin" or not is_hidden(item["path"], hidden)):
            items.append(item)
        if time.monotonic() > deadline or len(items) > MAX_INDEX_ENTRIES:
            raise HTTPException(413, "目录过大，请拆分后重试")
    perms = permissions(user, root_id)
    for item in items:
        item["can_modify"] = perms["modify"]
        item["can_delete"] = perms["delete"]
    return page_result(items, page, page_size, sort, order, value, False)

class CountedFileResponse(FileResponse):
    # Real-time gauge: counts downloads currently being streamed to clients.
    async def __call__(self, scope, receive, send):
        with LOCK:
            ACTIVE["download"] += 1
        try:
            await super().__call__(scope, receive, send)
        finally:
            with LOCK:
                ACTIVE["download"] -= 1

class TemporaryFileResponse(CountedFileResponse):
    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                Path(self.path).unlink(missing_ok=True)
            finally:
                with LOCK:
                    ACTIVE_TEMP.discard(str(self.path))

def cleanup():
    prune()
    with LOCK:
        protected = set(ACTIVE_TEMP)
    for path in TEMP_DIR.glob("httpserver_*"):
        if str(path) not in protected:
            try:
                if path.stat().st_mtime < time.time() - 86400:
                    path.unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("temporary file cleanup failed")
    with database() as c:
        expired = c.execute("SELECT id,stored_path FROM recycle_items WHERE expires_at<?", (time.time(),)).fetchall()
        for row in expired:
            try:
                stored = Path(row["stored_path"])
                if stored.is_dir():
                    shutil.rmtree(stored)
                else:
                    stored.unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("recycle item cleanup failed id=%s", row["id"])
                continue
            c.execute("DELETE FROM recycle_items WHERE id=?", (row["id"],))
        c.execute("DELETE FROM audit_logs WHERE created_at<?", (time.time() - 7 * 86400,))
        c.execute("DELETE FROM audit_logs WHERE id < COALESCE((SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET ?),0)", (AUDIT_MAX_ROWS - 1,))

def maintenance():
    while not STOP.wait(60):
        try:
            cleanup()
        except Exception:
            LOGGER.exception("maintenance failed")

async def run_work(kind, fn, *args):
    gate = GATES[kind]
    if not gate.acquire(blocking=False):
        raise HTTPException(503, "任务繁忙，请稍后重试", headers={"Retry-After": "5"})
    with LOCK:
        ACTIVE[kind] += 1
    try:
        future = POOLS[kind].submit(fn, *args)
    except BaseException:
        with LOCK:
            ACTIVE[kind] -= 1
        gate.release()
        raise
    def done(completed):
        with LOCK:
            ACTIVE[kind] -= 1
        gate.release()
    future.add_done_callback(done)
    try:
        return await asyncio.shield(asyncio.wrap_future(future))
    except asyncio.CancelledError:
        def discard(completed):
            if kind == "zip" and not completed.cancelled() and completed.exception() is None:
                orphan = completed.result()
                Path(orphan).unlink(missing_ok=True)
                with LOCK:
                    ACTIVE_TEMP.discard(orphan)
        future.add_done_callback(discard)
        raise

@asynccontextmanager
async def lifespan(application):
    STOP.clear()
    with LOCK:
        SESSIONS.clear()
        TICKETS.clear()
    for kind, size in (("browse", 4), ("search", 2), ("preview", 2), ("zip", 2)):
        POOLS[kind] = ThreadPoolExecutor(max_workers=size, thread_name_prefix=kind)
        GATES[kind] = threading.BoundedSemaphore(size)
    cleanup()
    cleaner = threading.Thread(target=maintenance, name="maintenance", daemon=True)
    cleaner.start()
    audit("startup")
    try:
        yield
    finally:
        STOP.set()
        cleaner.join(timeout=2)
        for pool in POOLS.values():
            pool.shutdown(wait=False, cancel_futures=True)
        with LOCK:
            SESSIONS.clear()
            TICKETS.clear()
        audit("shutdown")

app = FastAPI(title="HttpServer", version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

def error_response(request, status, message, code, headers=None):
    return JSONResponse({"ok": False, "detail": message, "error": {"code": code, "message": message,
                         "retryable": status in (503, 504)}, "request_id": getattr(request.state, "request_id", "")},
                        status_code=status, headers=headers)

@app.exception_handler(StarletteHTTPException)
async def http_error(request, exc):
    if exc.status_code >= 400:
        await asyncio.to_thread(audit, "request_rejected", request, getattr(request.state, "user", None),
                                request.url.path, "denied", str(exc.detail))
    return error_response(request, exc.status_code, exc.detail, f"HTTP_{exc.status_code}", exc.headers)

@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return error_response(request, 422, "请求字段无效，请检查输入", "VALIDATION_ERROR")

@app.exception_handler(Exception)
async def unexpected_error(request, exc):
    LOGGER.error("request_id=%s path=%s", getattr(request.state, "request_id", ""), request.url.path,
                 exc_info=(type(exc), exc, exc.__traceback__))
    status, code, message = 500, "INTERNAL_ERROR", "服务内部错误，请查看诊断日志"
    if isinstance(exc, PermissionError):
        status, code, message = 403, "FILE_ACCESS_DENIED", "文件无访问权限或正在被占用"
    elif isinstance(exc, FileNotFoundError):
        status, code, message = 404, "FILE_NOT_FOUND", "文件不存在或共享目录已离线"
    elif isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        status, code, message = 507, "DISK_FULL", "磁盘空间不足"
    elif isinstance(exc, sqlite3.OperationalError):
        status, code, message = 503, "DATABASE_BUSY", "数据库忙或不可用，请稍后重试"
    await asyncio.to_thread(audit, "request_error", request, getattr(request.state, "user", None),
                            request.url.path, "error", code)
    return error_response(request, status, message, code)

@app.middleware("http")
async def request_context(request, call_next):
    request.state.request_id = secrets.token_hex(8)
    if request.url.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH") and request.url.path != "/api/files/upload":
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return error_response(request, 400, "请求长度无效", "INVALID_LENGTH")
        if length < 0 or length > MAX_API_BODY_BYTES:
            return error_response(request, 413, "请求内容超过 64 KB 上限", "BODY_TOO_LARGE")
        async def read_limited():
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_API_BODY_BYTES:
                    raise HTTPException(413, "请求内容超过 64 KB 上限")
                chunks.append(chunk)
            return b"".join(chunks)
        try:
            # Starlette's cached request replays _body to downstream parsers.
            # Bound the stream before FastAPI parses JSON; covers chunked input too.
            request._body = await asyncio.wait_for(read_limited(), timeout=10)
        except asyncio.TimeoutError:
            return error_response(request, 408, "读取请求超时", "BODY_TIMEOUT")
        except HTTPException:
            return error_response(request, 413, "请求内容超过 64 KB 上限", "BODY_TOO_LARGE")
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(max_length=1024)
class PasswordChange(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)
class UserInput(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(default="", max_length=1024)
    role: str = "user"
    can_browse: bool = True
    can_download: bool = True
    can_rename: bool = False
    can_delete: bool = False
class RootInput(BaseModel):
    name: str = Field(default="", max_length=128)
    path: str = Field(min_length=1, max_length=2048)
class PermissionInput(BaseModel):
    browse: bool = False
    download: bool = False
    upload: bool = False
    modify: bool = False
    delete: bool = False

class FileAction(BaseModel):
    path: str = Field(min_length=3, max_length=4096)
    name: str = Field(default="", max_length=255)

class BatchAction(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=100)
    destination: str = Field(default="", max_length=4096)

@app.get("/")
@app.get("/login")
@app.get("/files")
@app.get("/admin/")
@app.get("/manageCenter")
@app.get("/logs")
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/api/health")
async def health():
    def probe():
        with database() as c:
            c.execute("SELECT 1").fetchone()
        usage = shutil.disk_usage(DATA)
        with LOCK:
            return {"status": "ok", "version": APP_VERSION, "uptime_seconds": round(time.monotonic() - STARTED_AT),
                    "database": "ok", "disk_free_bytes": usage.free, "disk_total_bytes": usage.total,
                    "active_tasks": dict(ACTIVE), "sessions": len(SESSIONS)}
    try:
        return await asyncio.wait_for(asyncio.to_thread(probe), timeout=1)
    except Exception:
        return JSONResponse({"status": "degraded", "version": APP_VERSION, "database": "unavailable"}, status_code=503)

@app.post("/api/login")
def login(request: Request, data: Login):
    key = (request.client.host if request.client else "unknown", data.username.casefold())
    now = time.monotonic()
    with LOCK:
        state = LOGIN_FAILURES.get(key, {"times": [], "blocked_until": 0})
        if state["blocked_until"] > now:
            raise HTTPException(429, "登录失败过多，请稍后重试",
                                headers={"Retry-After": str(max(1, int(state["blocked_until"] - now)))})
    with database() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (data.username,)).fetchone()
    valid = verify_password(data.password, row["password"] if row else DUMMY_HASH)
    if not row or not valid:
        with LOCK:
            state = LOGIN_FAILURES.setdefault(key, {"times": [], "blocked_until": 0})
            state["times"] = [t for t in state["times"] if now - t < LOGIN_WINDOW_SECONDS] + [now]
            if len(state["times"]) >= LOGIN_MAX_FAILURES:
                state["blocked_until"] = now + LOGIN_LOCKOUT_SECONDS
            LOGIN_FAILURES.move_to_end(key)
            while len(LOGIN_FAILURES) > MAX_LOGIN_KEYS:
                LOGIN_FAILURES.popitem(last=False)
        audit("login", request, {"username": data.username}, path=data.username, result="denied")
        raise HTTPException(401, "账号或密码错误")
    raw = secrets.token_urlsafe(32)
    with LOCK:
        LOGIN_FAILURES.pop(key, None)
        prune()
        while len(SESSIONS) >= MAX_SESSIONS:
            SESSIONS.popitem(last=False)
        SESSIONS[token_digest(raw)] = {"id": secrets.token_hex(12), "user_id": row["id"],
            "username": row["username"], "created_at": time.time(), "client_ip": key[0],
            "idle_expires_at": now + SESSION_TTL_SECONDS, "absolute_expires_at": now + SESSION_ABSOLUTE_TTL_SECONDS}
    audit("login", request, public_user(row))
    return {"token": raw, "user": public_user(row)}

@app.get("/api/account")
def account(request: Request):
    return current_user(request, allow_password_change=True)

@app.post("/api/logout")
def logout(request: Request):
    with LOCK:
        session = SESSIONS.pop(token_digest(extract_token(request)), None)
        prune()
    audit("logout", request, {"username": session["username"]} if session else None)
    return {"ok": True}

@app.post("/api/account/password")
def change_password(request: Request, data: PasswordChange):
    user = current_user(request, allow_password_change=True)
    validate_password(data.new_password)
    with database() as c:
        row = c.execute("SELECT password FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(data.current_password, row["password"]):
            raise HTTPException(400, "当前密码不正确")
        if data.current_password == data.new_password:
            raise HTTPException(400, "新密码必须不同于当前密码")
        c.execute("UPDATE users SET password=?,must_change_password=0 WHERE id=?",
                  (hash_password(data.new_password), user["id"]))
    revoke_user(user["id"])
    audit("password_change", request, user)
    return {"ok": True, "message": "密码已更新，请重新登录"}

@app.get("/api/admin/sessions")
def sessions(request: Request):
    admin_user(request)
    prune()
    with LOCK:
        return [{key: value[key] for key in ("id", "user_id", "username", "created_at", "client_ip")} for value in SESSIONS.values()]

@app.delete("/api/admin/sessions/{session_id}")
def revoke_session(request: Request, session_id: str):
    user = admin_user(request)
    with LOCK:
        for key, value in list(SESSIONS.items()):
            if value["id"] == session_id:
                SESSIONS.pop(key)
        prune()
    audit("session_revoke", request, user)
    return {"ok": True}

@app.get("/api/files")
async def files(request: Request, path: str = "", q: str = "", page: int = 1,
                page_size: int = 20, sort: str = "name", order: str = "asc"):
    user = await asyncio.to_thread(current_user, request)
    if len(q) > 256:
        raise HTTPException(400, "搜索词过长")
    if page < 1 or not 1 <= page_size <= 200:
        raise HTTPException(400, "分页参数无效")
    if sort not in ("name", "size", "modified", "type") or order not in ("asc", "desc"):
        raise HTTPException(400, "排序参数无效")
    return await run_work("search" if q else "browse", list_files, user, path, q, page, page_size, sort, order)

def check_tree(root, target):
    """Reject reparse points between a registered root and a file operation target."""
    try:
        relative = target.relative_to(root)
    except ValueError:
        raise HTTPException(403, "目标不在共享目录内")
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() and is_reparse(current):
            raise HTTPException(403, "不允许通过符号链接或联接点操作文件")

def safe_name(name):
    if not name or name in (".", "..") or any(ch in name for ch in "/\\:\x00") or name.endswith((" ", ".")):
        raise HTTPException(400, "文件名无效")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"{n}{i}" for n in ("COM", "LPT") for i in range(1, 10)}
    if name.split(".", 1)[0].upper() in reserved:
        raise HTTPException(400, "Windows 设备名称不能作为文件名")
    return name

def operation_target(user, value, action, must_exist=True):
    target, root_id, relative = resolve_path(value)
    check_permission(user, root_id, action)
    root = Path(root_by_id(root_id)["path"]).resolve()
    check_tree(root, target)
    if must_exist and not target.exists():
        raise HTTPException(404, "文件不存在")
    return target, root_id, relative, root

def trash_item(user, value):
    source, root_id, relative, root = operation_target(user, value, "delete")
    if source == root:
        raise HTTPException(400, "不能删除共享根目录")
    if not source.exists():
        raise HTTPException(404, "文件不存在")
    item_id = secrets.token_hex(16)
    recycle = root / RECYCLE_DIR_NAME
    recycle.mkdir(exist_ok=True)
    stored = recycle / item_id
    name = source.name
    item_type = "folder" if source.is_dir() else "file"
    size = 0 if item_type == "folder" else source.stat().st_size
    source.rename(stored)
    try:
        with database() as c:
            c.execute("INSERT INTO recycle_items(id,root_id,original_path,stored_path,name,item_type,size,username,deleted_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (item_id, root_id, relative, str(stored), name, item_type, size, user["username"], time.time(), time.time() + RECYCLE_RETENTION_SECONDS))
    except BaseException:
        stored.rename(source)
        raise
    invalidate_search_cache()
    return item_id

@app.post("/api/files/upload")
async def upload_file(request: Request, path: str, filename: str, conflict: str = "error"):
    user = await asyncio.to_thread(current_user, request)
    if conflict not in ("error", "rename", "overwrite", "skip"):
        raise HTTPException(400, "同名处理策略无效")
    name = safe_name(filename)
    parent, root_id, _, root = operation_target(user, path, "upload")
    if not parent.is_dir():
        raise HTTPException(400, "上传目标必须是目录")
    length_header = request.headers.get("content-length", "")
    try:
        declared_length = int(length_header) if length_header else None
    except ValueError:
        raise HTTPException(400, "请求长度无效")
    if declared_length is not None and (declared_length < 0 or declared_length > MAX_UPLOAD_BYTES):
        raise HTTPException(413, "单文件上传上限为 1 GB")
    target = parent / name
    if target.exists() and conflict == "error":
        raise HTTPException(409, "同名文件已存在")
    if target.exists() and conflict == "skip":
        return {"ok": True, "skipped": True, "name": name}
    if target.exists() and target.is_dir():
        raise HTTPException(409, "同名目录已存在")
    if conflict == "rename":
        stem, suffix = target.stem, target.suffix
        index = 1
        while target.exists():
            target = parent / f"{stem} ({index}){suffix}"
            index += 1
    if target.exists() and is_reparse(target):
        raise HTTPException(403, "不允许覆盖符号链接或联接点")
    if not UPLOAD_GATE.acquire(blocking=False):
        raise HTTPException(503, "上传任务较多，请稍后重试", headers={"Retry-After": "5"})
    with LOCK:
        ACTIVE["upload"] += 1
    temp = parent / f".httpserver-upload-{secrets.token_hex(16)}.tmp"
    total = 0
    try:
        with temp.open("xb") as stream:
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "单文件上传上限为 1 GB")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if declared_length is not None and total != declared_length:
            raise HTTPException(400, "上传数据长度不完整")
        if conflict == "overwrite":
            os.replace(temp, target)
        else:
            try:
                os.link(temp, target)
                temp.unlink()
            except FileExistsError:
                raise HTTPException(409, "同名文件已存在，请刷新后重试")
        invalidate_search_cache()
        await asyncio.to_thread(audit, "upload", request, user, f"r/{root_id}/{target.relative_to(root).as_posix()}", "ok", str(total))
        return {"ok": True, "name": target.name, "size": total}
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise HTTPException(507, "磁盘空间不足")
        raise
    finally:
        temp.unlink(missing_ok=True)
        with LOCK:
            ACTIVE["upload"] -= 1
        UPLOAD_GATE.release()

@app.post("/api/files/folders")
def create_folder(request: Request, data: FileAction):
    user = current_user(request)
    parent, root_id, _, _ = operation_target(user, data.path, "upload")
    if not parent.is_dir():
        raise HTTPException(400, "目标必须是目录")
    name = safe_name(data.name)
    try:
        (parent / name).mkdir()
    except FileExistsError:
        raise HTTPException(409, "同名目录已存在")
    invalidate_search_cache()
    audit("folder_create", request, user, data.path + "/" + name)
    return {"ok": True}

@app.patch("/api/files/item")
def rename_item(request: Request, data: FileAction):
    user = current_user(request)
    source, _, relative, root = operation_target(user, data.path, "modify")
    if source == root:
        raise HTTPException(400, "不能重命名共享根目录")
    name = safe_name(data.name)
    destination = source.with_name(name)
    if destination.exists() and destination != source:
        raise HTTPException(409, "目標名称已存在")
    source.rename(destination)
    invalidate_search_cache()
    audit("rename", request, user, relative, detail=name)
    return {"ok": True, "path": f"r/{resolve_path(data.path)[1]}/{destination.relative_to(root).as_posix()}"}

@app.post("/api/files/move")
def move_items(request: Request, data: BatchAction):
    user = current_user(request)
    destination, dest_root_id, _, root = operation_target(user, data.destination, "modify")
    if not destination.is_dir():
        raise HTTPException(400, "移动目标必须是目录")
    results = []
    for value in data.paths:
        source, root_id, relative, source_root = operation_target(user, value, "modify")
        if source == source_root or root_id != dest_root_id:
            results.append({"path": value, "ok": False, "error": "只能在同一共享目录内移动，且不能移动共享根目录"})
            continue
        target = destination / source.name
        if target == source or (source.is_dir() and source in destination.parents):
            results.append({"path": value, "ok": False, "error": "不能移动到自身或其子目录"})
            continue
        if target.exists():
            results.append({"path": value, "ok": False, "error": "目标存在同名文件"})
            continue
        try:
            source.rename(target)
            results.append({"path": value, "ok": True})
        except OSError as exc:
            results.append({"path": value, "ok": False, "error": str(exc)[:200]})
    invalidate_search_cache()
    audit("move", request, user, data.destination, detail=f"{sum(x['ok'] for x in results)}/{len(results)}")
    return {"results": results}

@app.post("/api/files/copy")
def copy_items(request: Request, data: BatchAction):
    user = current_user(request)
    destination, dest_root_id, _, root = operation_target(user, data.destination, "modify")
    if not destination.is_dir():
        raise HTTPException(400, "复制目标必须是目录")
    results = []
    for value in data.paths:
        source, root_id, _, source_root = operation_target(user, value, "download")
        if root_id != dest_root_id:
            results.append({"path": value, "ok": False, "error": "仅支持在同一共享目录内复制"})
            continue
        target = destination / source.name
        if target.exists() or target == source or (source.is_dir() and source in destination.parents):
            results.append({"path": value, "ok": False, "error": "目标冲突或位于源目录内部"})
            continue
        try:
            if source.is_dir():
                def ignored(directory, names):
                    return [name for name in names if name.startswith(".") or is_reparse(Path(directory, name))]
                shutil.copytree(source, target, symlinks=False, ignore=ignored)
            else:
                shutil.copy2(source, target)
            results.append({"path": value, "ok": True})
        except OSError as exc:
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink(missing_ok=True)
            results.append({"path": value, "ok": False, "error": str(exc)[:200]})
    invalidate_search_cache()
    audit("copy", request, user, data.destination, detail=f"{sum(x['ok'] for x in results)}/{len(results)}")
    return {"results": results}

@app.delete("/api/files/item")
def delete_item(request: Request, data: FileAction):
    user = current_user(request)
    item_id = trash_item(user, data.path)
    audit("delete_to_recycle", request, user, data.path, detail=item_id)
    return {"ok": True, "id": item_id}

@app.post("/api/files/delete-batch")
def delete_batch(request: Request, data: BatchAction):
    user = current_user(request)
    results = []
    for value in data.paths:
        try:
            item_id = trash_item(user, value)
            results.append({"path": value, "ok": True, "id": item_id})
        except HTTPException as exc:
            results.append({"path": value, "ok": False, "error": str(exc.detail)})
    invalidate_search_cache()
    audit("delete_batch", request, user, detail=f"{sum(x['ok'] for x in results)}/{len(results)}")
    return {"results": results}

@app.get("/api/recycle-bin")
def recycle_bin(request: Request):
    user = current_user(request)
    with database() as c:
        rows = c.execute("SELECT * FROM recycle_items ORDER BY deleted_at DESC").fetchall()
    visible = []
    for row in rows:
        if permissions(user, row["root_id"])["browse"] and (user["role"] == "admin" or row["username"] == user["username"]):
            visible.append({"id": row["id"], "path": row["original_path"], "root_id": row["root_id"],
                            "name": row["name"], "type": row["item_type"], "size": row["size"],
                            "deleted_at": row["deleted_at"], "expires_at": row["expires_at"], "username": row["username"]})
    return visible

@app.post("/api/recycle-bin/{item_id}/restore")
def restore_item(request: Request, item_id: str, destination: str = ""):
    user = current_user(request)
    with database() as c:
        row = c.execute("SELECT * FROM recycle_items WHERE id=?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404, "回收站项目不存在")
    if user["role"] != "admin" and (row["username"] != user["username"] or not permissions(user, row["root_id"])["delete"]):
        raise HTTPException(403, "没有恢复该项目的权限")
    root = Path(root_by_id(row["root_id"])["path"]).resolve()
    if destination:
        parent, root_id, _, _ = operation_target(user, destination, "upload")
        if root_id != row["root_id"]:
            raise HTTPException(400, "恢复目标必须位于原共享目录")
    else:
        parent = (root / row["original_path"]).parent
        check_tree(root, parent)
        if not parent.is_dir():
            raise HTTPException(409, "原目錄已不存在，请选择恢复目标目录")
        check_permission(user, row["root_id"], "upload")
    target = parent / row["name"]
    if target.exists():
        raise HTTPException(409, "恢复目标存在同名项目，请先重命名或移走冲突项")
    stored = Path(row["stored_path"])
    stored.rename(target)
    with database() as c:
        c.execute("DELETE FROM recycle_items WHERE id=?", (item_id,))
    invalidate_search_cache()
    audit("recycle_restore", request, user, f"r/{row['root_id']}/{row['original_path']}")
    return {"ok": True}

@app.delete("/api/recycle-bin/{item_id}")
def purge_item(request: Request, item_id: str):
    user = current_user(request)
    with database() as c:
        row = c.execute("SELECT * FROM recycle_items WHERE id=?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404, "回收站项目不存在")
    if user["role"] != "admin" and (row["username"] != user["username"] or not permissions(user, row["root_id"])["delete"]):
        raise HTTPException(403, "没有彻底删除该项目的权限")
    stored = Path(row["stored_path"])
    if stored.parent.name != RECYCLE_DIR_NAME:
        raise HTTPException(400, "回收站存储路径无效")
    if stored.is_dir():
        shutil.rmtree(stored)
    else:
        stored.unlink(missing_ok=True)
    with database() as c:
        c.execute("DELETE FROM recycle_items WHERE id=?", (item_id,))
    audit("recycle_purge", request, user, f"r/{row['root_id']}/{row['original_path']}")
    return {"ok": True}

def preview_file(user, value):
    path, root_id, _ = resolve_path(value)
    check_permission(user, root_id, "browse")
    if not path.is_file():
        raise HTTPException(404, "文件不存在")
    if path.suffix.lower() == ".pdf":
        return FileResponse(path, media_type="application/pdf", filename=path.name, content_disposition_type="inline")
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        raise HTTPException(400, "该格式暂不支持预览，请下载后打开")
    with path.open("rb") as stream:
        content = stream.read(MAX_PREVIEW_BYTES + 1)
    return {"name": path.name, "content": content[:MAX_PREVIEW_BYTES].decode("utf-8", errors="replace"),
            "truncated": len(content) > MAX_PREVIEW_BYTES, "limit_bytes": MAX_PREVIEW_BYTES}

@app.get("/api/files/view")
async def view(request: Request, path: str):
    user = await asyncio.to_thread(current_user, request)
    return await run_work("preview", preview_file, user, path)

@app.post("/api/download-tickets")
def create_ticket(request: Request, path: str, purpose: str = "download"):
    user = current_user(request)
    target, root_id, _ = resolve_path(path)
    if purpose not in ("download", "view"):
        raise HTTPException(400, "票据用途无效")
    check_permission(user, root_id, "download" if purpose == "download" else "browse")
    if not target.exists():
        raise HTTPException(404, "文件不存在")
    return issue_ticket(request, path, purpose)

def issue_ticket(request, path, purpose="download", archive=None):
    raw = secrets.token_urlsafe(32)
    with LOCK:
        prune()
        while len(TICKETS) >= MAX_TICKETS:
            _, discarded = TICKETS.popitem(last=False)
            discard_ticket(discarded)
        TICKETS[token_digest(raw)] = {"path": path, "purpose": purpose, "session": request.state.session,
                                      "expires_at": time.monotonic() + TICKET_TTL_SECONDS, "archive": archive}
    return {"ticket": raw, "expires_in": TICKET_TTL_SECONDS}

def consume_ticket(request, path, purpose):
    ticket = request.query_params.get("ticket", "")
    if not ticket:
        return current_user(request)
    with LOCK:
        prune()
        value = TICKETS.pop(token_digest(ticket), None)
        if not value or value["path"] != path or value["purpose"] != purpose or value["session"] not in SESSIONS:
            if value:
                discard_ticket(value)
            raise HTTPException(401, "下载票据无效或已使用")
        user_id = SESSIONS[value["session"]]["user_id"]
    with database() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or row["must_change_password"]:
        with LOCK:
            discard_ticket(value)
        raise HTTPException(401, "账号状态已变更，请重新登录")
    user = public_user(row)
    request.state.user = user
    request.state.prepared_archive = value.get("archive")
    return user

@app.get("/api/files/inline")
async def inline(request: Request, path: str):
    user = await asyncio.to_thread(consume_ticket, request, path, "view")
    return await run_work("preview", preview_file, user, path)

def build_archive(user, path, root_id):
    deadline = time.monotonic() + ZIP_MAX_SECONDS
    root = Path(root_by_id(root_id)["path"]).resolve()
    total = count = 0
    with LOCK:
        if len(ACTIVE_TEMP) >= MAX_TEMP_ARCHIVES:
            raise HTTPException(503, "临时下载较多，请等待其他下载完成", headers={"Retry-After": "5"})
        tmp = tempfile.NamedTemporaryFile(prefix="httpserver_", suffix=".zip", dir=TEMP_DIR, delete=False)
        filename = tmp.name
        tmp.close()
        ACTIVE_TEMP.add(filename)
    try:
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_STORED, allowZip64=True) as archive:
            for parent, directories, names in os.walk(path, followlinks=False):
                directories[:] = [n for n in directories if not n.startswith(".") and not is_reparse(Path(parent, n))
                                  and Path(parent, n).resolve() != DATA]
                if time.monotonic() > deadline or STOP.is_set():
                    raise HTTPException(504, "打包超时或服务正在停止，请拆分目录")
                for name in names:
                    if name.startswith("."):
                        continue
                    child = Path(parent, name)
                    resolved = child.resolve()
                    if is_reparse(child) or root not in resolved.parents or resolved == DATA or DATA in resolved.parents:
                        continue
                    count += 1
                    if count > ZIP_MAX_FILES:
                        raise HTTPException(413, "打包文件数量超过限制")
                    with child.open("rb") as source, archive.open(child.relative_to(path.parent).as_posix(), "w", force_zip64=True) as dest:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > ZIP_MAX_BYTES:
                                raise HTTPException(413, "打包大小超过上限，请拆分下载")
                            if time.monotonic() > deadline or STOP.is_set():
                                raise HTTPException(504, "打包超时或服务正在停止")
                            if shutil.disk_usage(TEMP_DIR).free < len(chunk) + 10 * 1024**2:
                                raise OSError(errno.ENOSPC, "not enough temporary space")
                            dest.write(chunk)
        return filename
    except BaseException:
        Path(filename).unlink(missing_ok=True)
        with LOCK:
            ACTIVE_TEMP.discard(filename)
        raise

def build_archive_items(user, values):
    deadline = time.monotonic() + ZIP_MAX_SECONDS
    checked = []
    root_id = None
    root = None
    for value in values:
        target, current_root_id, _ = resolve_path(value)
        check_permission(user, current_root_id, "download")
        current_root = Path(root_by_id(current_root_id)["path"]).resolve()
        check_tree(current_root, target)
        if not target.exists():
            raise HTTPException(404, "批量下载项目不存在")
        if root_id is not None and root_id != current_root_id:
            raise HTTPException(400, "批量 ZIP 仅支持同一共享目录")
        root_id, root = current_root_id, current_root
        checked.append(target)
    with LOCK:
        if len(ACTIVE_TEMP) >= MAX_TEMP_ARCHIVES:
            raise HTTPException(503, "临时下载较多，请等待其他下载完成", headers={"Retry-After": "5"})
        tmp = tempfile.NamedTemporaryFile(prefix="httpserver_", suffix=".zip", dir=TEMP_DIR, delete=False)
        filename = tmp.name
        tmp.close()
        ACTIVE_TEMP.add(filename)
    total = count = 0
    seen = set()
    try:
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_STORED, allowZip64=True) as archive:
            for target in checked:
                candidates = [target] if target.is_file() else []
                if target.is_dir():
                    for parent, directories, names in os.walk(target, followlinks=False):
                        directories[:] = [n for n in directories if not n.startswith(".") and not is_reparse(Path(parent, n))]
                        if time.monotonic() > deadline or STOP.is_set():
                            raise HTTPException(504, "批量打包超时或服务正在停止")
                        candidates.extend(Path(parent, name) for name in names if not name.startswith("."))
                for child in candidates:
                    resolved = child.resolve()
                    if is_reparse(child) or root not in resolved.parents or resolved == DATA or DATA in resolved.parents:
                        continue
                    relative = child.relative_to(root).as_posix()
                    if relative in seen:
                        continue
                    seen.add(relative)
                    count += 1
                    if count > ZIP_MAX_FILES:
                        raise HTTPException(413, "打包文件数量超过限制")
                    with child.open("rb") as source, archive.open(relative, "w", force_zip64=True) as dest:
                        while chunk := source.read(UPLOAD_CHUNK_BYTES):
                            total += len(chunk)
                            if total > ZIP_MAX_BYTES:
                                raise HTTPException(413, "压缩文件超过大小限制")
                            dest.write(chunk)
                            if time.monotonic() > deadline:
                                raise HTTPException(504, "批量打包超时")
        return filename
    except BaseException:
        Path(filename).unlink(missing_ok=True)
        with LOCK:
            ACTIVE_TEMP.discard(filename)
        raise

@app.post("/api/downloads/prepare")
async def prepare_download(request: Request, path: str):
    user = await asyncio.to_thread(current_user, request)
    def prepare():
        target, root_id, _ = resolve_path(path)
        check_permission(user, root_id, "download")
        if not target.exists():
            raise HTTPException(404, "文件不存在")
        return target, root_id
    target, root_id = await asyncio.to_thread(prepare)
    archive = None
    try:
        if target.is_dir():
            archive = await run_work("zip", build_archive, user, target, root_id)
        # Ticket remains attached to the active login and is invalidated on logout.
        return issue_ticket(request, path, archive=archive)
    except BaseException:
        if archive:
            with LOCK:
                discard_ticket({"archive": archive})
        raise

@app.post("/api/downloads/prepare-batch")
async def prepare_batch_download(request: Request, data: BatchAction):
    user = await asyncio.to_thread(current_user, request)
    marker = "batch:" + hashlib.sha256("\0".join(data.paths).encode("utf-8")).hexdigest()
    archive = await run_work("zip", build_archive_items, user, data.paths)
    return issue_ticket(request, marker, archive=archive)

@app.get("/api/files/download-batch")
async def download_batch(request: Request, paths: str):
    values = paths.split("\n")
    marker = "batch:" + hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    user = await asyncio.to_thread(consume_ticket, request, marker, "download")
    try:
        def recheck():
            for value in values:
                target, root_id, _ = resolve_path(value)
                check_permission(user, root_id, "download")
                check_tree(Path(root_by_id(root_id)["path"]).resolve(), target)
                if not target.exists():
                    raise HTTPException(404, "批量下载项目不存在")
        await asyncio.to_thread(recheck)
    except BaseException:
        archive = getattr(request.state, "prepared_archive", None)
        if archive:
            with LOCK:
                discard_ticket({"archive": archive})
        raise
    archive = getattr(request.state, "prepared_archive", None)
    if not archive:
        raise HTTPException(404, "批量压缩文件已失效")
    await asyncio.to_thread(audit, "download_batch", request, user, marker)
    return TemporaryFileResponse(archive, filename="HttpServer-files.zip")

@app.get("/api/files/download")
async def download(request: Request, path: str):
    user = await asyncio.to_thread(consume_ticket, request, path, "download")
    def prepare():
        target, root_id, _ = resolve_path(path)
        check_permission(user, root_id, "download")
        if not target.exists():
            raise HTTPException(404, "文件不存在")
        return target, root_id
    ready_archive = getattr(request.state, "prepared_archive", None)
    try:
        target, root_id = await asyncio.to_thread(prepare)
    except BaseException:
        if ready_archive:
            with LOCK:
                discard_ticket({"archive": ready_archive})
        raise
    if target.is_file():
        await asyncio.to_thread(audit, "download", request, user, path)
        return CountedFileResponse(target, filename=target.name)
    archive = ready_archive or await run_work("zip", build_archive, user, target, root_id)
    await asyncio.to_thread(audit, "download_archive", request, user, path)
    return TemporaryFileResponse(archive, filename=target.name + ".zip")

@app.post("/api/files/hidden")
def toggle_hidden(request: Request, path: str):
    user = admin_user(request)
    resolve_path(path)
    with HIDDEN_LOCK:
        values = hidden_paths()
        value = path not in values
        values.add(path) if value else values.remove(path)
        temp = DATA / "hidden.json.tmp"
        temp.write_text(json.dumps(sorted(values), ensure_ascii=False), encoding="utf-8")
        os.replace(temp, DATA / "hidden.json")
    audit("visibility_change", request, user, path)
    return {"hidden": value}

@app.get("/api/admin/users")
def users(request: Request):
    admin_user(request)
    with database() as c:
        return [public_user(row) for row in c.execute("SELECT * FROM users ORDER BY id")]

def validate_user(data):
    if data.role not in ("admin", "user") or not data.username.strip() or data.username != data.username.strip():
        raise HTTPException(400, "用户名或角色无效")

@app.post("/api/admin/users")
def create_user(request: Request, data: UserInput):
    user = admin_user(request)
    validate_user(data)
    validate_password(data.password)
    try:
        user_id = execute_write("INSERT INTO users(username,password,role,can_browse,can_download,can_rename,can_delete,must_change_password) VALUES(?,?,?,?,?,?,?,0)",
                               (data.username, hash_password(data.password), data.role, data.can_browse, data.can_download, data.can_rename, data.can_delete))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "用户名已存在")
    audit("user_create", request, user, str(user_id))
    return {"ok": True, "id": user_id}

@app.put("/api/admin/users/{user_id}")
def update_user(request: Request, user_id: int, data: UserInput):
    user = admin_user(request)
    validate_user(data)
    if data.password:
        validate_password(data.password)
    try:
        with database() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                raise HTTPException(404, "用户不存在")
            if row["role"] == "admin" and data.role != "admin" and c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] <= 1:
                raise HTTPException(400, "必须保留至少一个管理员")
            c.execute("UPDATE users SET username=?,role=?,can_browse=?,can_download=?,can_rename=?,can_delete=?,password=?,must_change_password=? WHERE id=?",
                      (data.username, data.role, data.can_browse, data.can_download, data.can_rename, data.can_delete,
                       hash_password(data.password) if data.password else row["password"],
                       0 if data.password else row["must_change_password"], user_id))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "用户名已存在")
    revoke_user(user_id)
    audit("user_update", request, user, str(user_id))
    return {"ok": True}

@app.delete("/api/admin/users/{user_id}")
def delete_user(request: Request, user_id: int):
    user = admin_user(request)
    with database() as c:
        row = c.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "用户不存在")
        if row["role"] == "admin":
            raise HTTPException(400, "管理员账号不可直接删除")
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
    revoke_user(user_id)
    audit("user_delete", request, user, str(user_id))
    return {"ok": True}

@app.get("/api/admin/share-roots")
def get_roots(request: Request):
    admin_user(request)
    return roots()

@app.post("/api/admin/share-roots/browse")
def browse_root(request: Request):
    admin_user(request)
    if not request.client or not is_local_client(request.client.host):
        raise HTTPException(403, "请在服务主机浏览器选择文件夹，远程访问请填写路径")
    dialog = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        dialog = tk.Tk()
        dialog.withdraw()
        dialog.attributes("-topmost", True)
        return {"path": filedialog.askdirectory(parent=dialog, title="选择共享文件夹", mustexist=True)}
    finally:
        if dialog:
            dialog.destroy()

def validated_root(data):
    path = Path(data.path).expanduser().resolve()
    if not path.is_dir():
        raise HTTPException(400, "目录不存在或不可访问")
    if path == DATA or path in DATA.parents or DATA in path.parents:
        raise HTTPException(400, "共享目录不能包含服务数据目录")
    return path

@app.post("/api/admin/share-roots")
def add_root(request: Request, data: RootInput):
    user = admin_user(request)
    path = validated_root(data)
    try:
        root_id = execute_write("INSERT INTO share_roots(name,path) VALUES(?,?)", (data.name.strip() or path.name or str(path), str(path)))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "该目录已共享")
    invalidate_search_cache()
    audit("root_create", request, user, str(root_id))
    return {"ok": True, "id": root_id}

@app.put("/api/admin/share-roots/{root_id}")
def update_root(request: Request, root_id: int, data: RootInput):
    user = admin_user(request)
    root_by_id(root_id)
    path = validated_root(data)
    try:
        execute_write("UPDATE share_roots SET name=?,path=? WHERE id=?", (data.name.strip() or path.name or str(path), str(path), root_id))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "该目录已共享")
    invalidate_search_cache()
    audit("root_update", request, user, str(root_id))
    return {"ok": True}

@app.delete("/api/admin/share-roots/{root_id}")
def remove_root(request: Request, root_id: int):
    user = admin_user(request)
    root_by_id(root_id)
    execute_write("DELETE FROM share_roots WHERE id=?", (root_id,))
    invalidate_search_cache()
    audit("root_delete", request, user, str(root_id))
    return {"ok": True}

@app.get("/api/admin/share-roots/{root_id}/permissions")
def get_permissions(request: Request, root_id: int):
    admin_user(request)
    root_by_id(root_id)
    with database() as c:
        rows = c.execute("SELECT * FROM users WHERE role='user' ORDER BY id").fetchall()
    return [{"user_id": row["id"], "username": row["username"], **permissions(public_user(row), root_id)} for row in rows]

@app.put("/api/admin/share-roots/{root_id}/permissions/{user_id}")
def set_permissions(request: Request, root_id: int, user_id: int, data: PermissionInput):
    user = admin_user(request)
    root_by_id(root_id)
    with database() as c:
        if not c.execute("SELECT 1 FROM users WHERE id=? AND role='user'", (user_id,)).fetchone():
            raise HTTPException(404, "普通用户不存在")
        c.execute('INSERT OR REPLACE INTO root_permissions(user_id,root_id,browse,download,upload,modify,"delete") VALUES(?,?,?,?,?,?,?)',
                  (user_id, root_id, *(getattr(data, key) for key in PERMISSIONS)))
    audit("permissions_update", request, user, f"r/{root_id}/user/{user_id}")
    return {"ok": True}

@app.get("/api/admin/audit")
def get_audit(request: Request, errors_only: bool = False, limit: int = 100,
              username: str = "", action: str = "", result: str = "",
              start: float = 0, end: float = 0):
    admin_user(request)
    limit = min(max(limit, 1), 500)
    clauses, params = [], []
    if errors_only:
        clauses.append("result!='ok'")
    if username.strip():
        clauses.append("username LIKE ? ESCAPE '\\'")
        params.append("%" + username.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if action.strip():
        clauses.append("action LIKE ? ESCAPE '\\'")
        params.append("%" + action.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if result.strip():
        clauses.append("result=?")
        params.append(result.strip())
    if start > 0:
        clauses.append("created_at>=?")
        params.append(start)
    if end > 0:
        clauses.append("created_at<=?")
        params.append(end)
    where = "WHERE " + " AND ".join(clauses) + " " if clauses else ""
    with database() as c:
        return [dict(row) for row in c.execute(
            "SELECT * FROM audit_logs " + where + "ORDER BY id DESC LIMIT ?", (*params, limit))]

@app.get("/api/admin/diagnostics")
def diagnostics(request: Request):
    user = admin_user(request)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("status.json", json.dumps({"version": APP_VERSION, "uptime_seconds": round(time.monotonic() - STARTED_AT),
                                                  "active_tasks": ACTIVE}, ensure_ascii=False, indent=2))
        log_file = DATA / "httpserver.log"
        if log_file.exists():
            with log_file.open("rb") as stream:
                stream.seek(max(0, log_file.stat().st_size - 1024**2))
                archive.writestr("httpserver.log", stream.read(1024**2))
        archive.writestr("README.txt", "诊断包不包含数据库、密码、会话令牌或共享文件。日志可能包含用户名和虚拟路径。")
    audit("diagnostics_export", request, user)
    return Response(output.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="HttpServer-diagnostics.zip"'})

def main():
    import uvicorn
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    port = int(os.getenv("PORT", "8000"))
    LOGGER.info("listening on 0.0.0.0:%s", port)
    if getattr(sys, "frozen", False) and os.getenv("HTTPSERVER_NO_DIALOG") != "1":
        def show_message():
            import ctypes
            ctypes.windll.user32.MessageBoxW(None,
                f"HttpServer {APP_VERSION}\n\n本机访问 http://localhost:{port}\n局域网用户请使用本机 IP。\n初始账号 admin / admin123，首次登录须修改密码。\n关闭提示不会停止服务。",
                "HttpServer", 0x40)
        threading.Thread(target=show_message, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=port, timeout_keep_alive=5, access_log=False)

if __name__ == "__main__":
    main()
