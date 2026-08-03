import fnmatch
import json
import mimetypes
import os
import secrets
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import zipfile
from starlette.background import BackgroundTask
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# 兼容 PyInstaller 单文件打包路径与标准 Python 运行路径
if getattr(sys, "frozen", False):
    # 单文件打包运行时的内部解压资源路径
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    # EXE 程序所在的外部目录（用于保存数据库等永久数据）
    EXE_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    EXE_DIR = BUNDLE_DIR

DATA = EXE_DIR / "data"
DATA.mkdir(exist_ok=True)
DB = DATA / "httpserver.db"
HIDDEN_DB = DATA / "hidden.json"

app = FastAPI(title="HttpServer")

# 优先定位内部打包好的 static，找不到时兼容读取外部 static
STATIC_DIR = BUNDLE_DIR / "static"
if not STATIC_DIR.exists():
    STATIC_DIR = EXE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

SESSIONS: dict[str, dict] = {}
SEARCH_CACHE: dict[str, list[tuple[str, str, float]]] = {}
TEXT_EXTENSIONS = {".txt", ".log", ".md", ".json", ".xml", ".csv", ".tsv", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".html", ".htm", ".css", ".js", ".ts", ".py", ".java", ".c", ".cpp", ".h", ".hpp", ".sql", ".rtf", ".properties", ".sh", ".bat", ".ps1", ".toml"}
VIEW_EXTENSIONS = TEXT_EXTENSIONS | {".pdf"}

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      role TEXT NOT NULL, can_browse INTEGER NOT NULL DEFAULT 1, can_download INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS share_roots (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, path TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    # One-time migration: remove the legacy automatic program directory.
    if not c.execute("SELECT 1 FROM settings WHERE key='removed_program_root'").fetchone():
        c.execute("DELETE FROM share_roots WHERE name='程序目录'")
        c.execute("INSERT INTO settings(key,value) VALUES('removed_program_root','1')")
    if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        c.execute("INSERT INTO users(username,password,role) VALUES('admin','admin123','admin')")
    if not c.execute("SELECT 1 FROM users WHERE username='guest'").fetchone():
        c.execute("INSERT INTO users(username,password,role) VALUES('guest','guest123','user')")
    c.commit(); c.close()

init_db()

def roots():
    c = db(); rows = [dict(x) for x in c.execute("SELECT id,name,path FROM share_roots ORDER BY id")]; c.close()
    return rows

def root_by_id(root_id: int):
    for item in roots():
        if item["id"] == root_id:
            return item
    raise HTTPException(404, "共享目录不存在")

def resolve_path(virtual_path: str) -> tuple[Path, int, str]:
    parts = [x for x in virtual_path.split("/") if x]
    if len(parts) < 2 or parts[0] != "r" or not parts[1].isdigit():
        raise HTTPException(400, "无效共享路径")
    root_id = int(parts[1])
    entry = root_by_id(root_id)
    root = Path(entry["path"]).resolve()
    relative = Path(*parts[2:]) if len(parts) > 2 else Path()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(400, "非法路径")
    return target, root_id, str(relative).replace("\\", "/")

def virtual_path(root_id: int, p: Path) -> str:
    root = Path(root_by_id(root_id)["path"]).resolve()
    relative = "" if p == root else str(p.relative_to(root)).replace("\\", "/")
    return f"r/{root_id}" + (f"/{relative}" if relative else "")

def hidden_paths():
    try: return set(json.loads(HIDDEN_DB.read_text(encoding="utf-8")))
    except Exception: return set()

def save_hidden(values):
    HIDDEN_DB.write_text(json.dumps(sorted(values), ensure_ascii=False), encoding="utf-8")

def current_user(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ") or request.query_params.get("token", "")
    u = SESSIONS.get(token)
    if not u: raise HTTPException(401, "请先登录")
    return u

def item_info(path: Path, root_id: int):
    stat = path.stat()
    vp = virtual_path(root_id, path)
    return {"name": path.name, "path": vp, "type": "folder" if path.is_dir() else "file", "size": 0 if path.is_dir() else stat.st_size, "modified": stat.st_mtime, "extension": path.suffix.lower(), "can_view": path.is_file() and path.suffix.lower() in VIEW_EXTENSIONS, "hidden": vp in hidden_paths()}

def search_entries(entry: dict) -> list[tuple[str, str, float]]:
    """Cache lightweight searchable metadata instead of walking disks on every request."""
    cache_key = f"{entry['id']}:{entry['path']}"
    if cache_key in SEARCH_CACHE:
        return SEARCH_CACHE[cache_key]
    result = []
    root = Path(entry["path"])
    if root.exists():
        for parent, _, names in os.walk(root):
            parent_path = Path(parent)
            for name in names:
                try:
                    p = parent_path / name
                    result.append((name.lower(), virtual_path(entry["id"], p), p.stat().st_mtime))
                except OSError:
                    continue
    SEARCH_CACHE[cache_key] = result
    return result

def invalidate_search_cache():
    SEARCH_CACHE.clear()

def remove_temp_file(path: str):
    try: Path(path).unlink(missing_ok=True)
    except OSError: pass

class Login(BaseModel):
    username: str
    password: str
class UserInput(BaseModel):
    username: str
    password: str
    role: str = "user"
    can_browse: bool = True
    can_download: bool = True
class RootInput(BaseModel):
    name: str = ""
    path: str

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
@app.get("/files", response_class=HTMLResponse)
@app.get("/manageCenter", response_class=HTMLResponse)
def index(): 
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(404, f"未找到前端静态页面 index.html，请确保 static 文件夹下存在 index.html (当前寻找路径: {STATIC_DIR})")
    return FileResponse(index_file)

@app.post("/api/login")
def login(data: Login):
    c = db(); row = c.execute("SELECT * FROM users WHERE username=? AND password=?", (data.username, data.password)).fetchone(); c.close()
    if not row: raise HTTPException(401, "账号或密码错误")
    token = secrets.token_urlsafe(24); SESSIONS[token] = dict(row)
    return {"token": token, "user": {"username": row["username"], "role": row["role"], "can_browse": bool(row["can_browse"]), "can_download": bool(row["can_download"])}}

@app.get("/api/files")
def files(request: Request, path: str = "", q: str = ""):
    u = current_user(request)
    if not u["can_browse"] and not u["can_download"]: raise HTTPException(403, "没有访问权限")
    hidden = hidden_paths()
    if q:
        pattern = q.lower(); result = []
        for entry in roots():
            for name, vp, modified in search_entries(entry):
                ok = fnmatch.fnmatch(name, pattern) if any(x in pattern for x in "*?") else pattern in name
                if ok:
                    p, rid, _ = resolve_path(vp)
                    item = item_info(p, rid)
                    if u["role"] == "admin" or item["path"] not in hidden: result.append(item)
        return {"path": "", "items": result, "search": True}
    if not path:
        shared = roots()
        if not shared:
            return {"path": "", "items": [], "search": False}
        if len(shared) == 1:
            p = Path(shared[0]["path"])
            items = [item_info(x, shared[0]["id"]) for x in p.iterdir() if not x.name.startswith(".")]
            if u["role"] != "admin": items = [x for x in items if x["path"] not in hidden]
            return {"path": f"r/{shared[0]['id']}", "items": sorted(items, key=lambda x: (x["type"] != "folder", x["name"].lower())), "search": False}
        result = []
        for entry in shared:
            p = Path(entry["path"])
            vp = f"r/{entry['id']}"
            is_hidden = vp in hidden
            if u["role"] != "admin" and is_hidden:
                continue
            result.append({"name": entry["name"], "path": vp, "type": "folder", "size": 0, "modified": p.stat().st_mtime if p.exists() else 0, "extension": "", "can_view": False, "hidden": is_hidden})
        return {"path": "", "items": result, "search": False}
    p, root_id, _ = resolve_path(path)
    if not p.exists() or not p.is_dir(): raise HTTPException(404, "目录不存在")
    items = [item_info(x, root_id) for x in p.iterdir() if not x.name.startswith(".")]
    if u["role"] != "admin": items = [x for x in items if x["path"] not in hidden]
    return {"path": path, "items": sorted(items, key=lambda x: (x["type"] != "folder", x["name"].lower())), "search": False}

@app.get("/api/files/view")
def view(request: Request, path: str):
    u = current_user(request)
    if not u["can_browse"]: raise HTTPException(403, "没有浏览权限")
    p, _, _ = resolve_path(path)
    if not p.is_file() or p.suffix.lower() not in VIEW_EXTENSIONS: raise HTTPException(400, "该文件不支持浏览")
    if p.suffix.lower() == ".pdf": return FileResponse(p, media_type="application/pdf", filename=p.name, content_disposition_type="inline")
    return {"name": p.name, "content": p.read_text(encoding="utf-8", errors="replace")}

@app.get("/api/files/download")
def download(request: Request, path: str):
    u = current_user(request)
    if not u["can_download"]: raise HTTPException(403, "没有下载权限")
    p, _, _ = resolve_path(path)
    if not p.exists(): raise HTTPException(404, "文件不存在")
    if p.is_file(): return FileResponse(p, filename=p.name)
    tmp = tempfile.NamedTemporaryFile(prefix="httpserver_", suffix=".zip", delete=False); tmp.close()
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_STORED) as z:
        for child in p.rglob("*"):
            if child.is_file() and not child.name.startswith("."): z.write(child, child.relative_to(p.parent))
    return FileResponse(tmp.name, media_type="application/zip", filename=f"{p.name}.zip", background=BackgroundTask(remove_temp_file, tmp.name))

@app.post("/api/files/hidden")
def toggle_hidden(request: Request, path: str):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "仅管理员可操作")
    p, rid, relative = resolve_path(path)
    if not relative:
        key = f"r/{rid}"
    else:
        key = virtual_path(rid, p)
    values = hidden_paths()
    if key in values: values.remove(key); value = False
    else: values.add(key); value = True
    save_hidden(values); return {"hidden": value}

@app.get("/api/admin/users")
def users(request: Request):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    c = db(); rows = [dict(x) for x in c.execute("SELECT id,username,password,role,can_browse,can_download FROM users ORDER BY id")]; c.close(); return rows

@app.post("/api/admin/users")
def create_user(request: Request, data: UserInput):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    c = db()
    try: c.execute("INSERT INTO users(username,password,role,can_browse,can_download) VALUES(?,?,?,?,?)", (data.username, data.password, data.role, int(data.can_browse), int(data.can_download))); c.commit()
    except sqlite3.IntegrityError: raise HTTPException(400, "用户名已存在")
    finally: c.close()
    return {"ok": True}

@app.put("/api/admin/users/{user_id}")
def update_user(request: Request, user_id: int, data: UserInput):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    c = db(); c.execute("UPDATE users SET username=?,password=?,role=?,can_browse=?,can_download=? WHERE id=?", (data.username, data.password, data.role, int(data.can_browse), int(data.can_download), user_id)); c.commit(); c.close()
    return {"ok": True}

@app.delete("/api/admin/users/{user_id}")
def delete_user(request: Request, user_id: int):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    c = db(); c.execute("DELETE FROM users WHERE id=? AND role!='admin'", (user_id,)); c.commit(); c.close(); return {"ok": True}

@app.get("/api/admin/share-roots")
def get_roots(request: Request):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    return roots()

@app.post("/api/admin/share-roots/browse")
def browse_root(request: Request):
    """Choose a shared directory on the Windows machine running HttpServer."""
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    try:
        import tkinter as tk
        from tkinter import filedialog
        dialog = tk.Tk()
        dialog.withdraw()
        dialog.attributes("-topmost", True)
        chosen = filedialog.askdirectory(parent=dialog, title="选择要共享的文件夹", mustexist=True)
        dialog.destroy()
        return {"path": chosen}
    except Exception as exc:
        raise HTTPException(500, f"无法打开目录选择框：{exc}")

@app.post("/api/admin/share-roots")
def add_root(request: Request, data: RootInput):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    if not data.path.strip(): raise HTTPException(400, "目录为空，添加失败")
    p = Path(data.path).expanduser().resolve()
    if not p.is_dir(): raise HTTPException(400, "目录不存在或不是文件夹")
    c = db()
    try: c.execute("INSERT INTO share_roots(name,path) VALUES(?,?)", (data.name.strip() or p.name or str(p), str(p))); c.commit(); invalidate_search_cache()
    except sqlite3.IntegrityError: raise HTTPException(400, "该目录已共享")
    finally: c.close()
    return {"ok": True}

@app.put("/api/admin/share-roots/{root_id}")
def update_root(request: Request, root_id: int, data: RootInput):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    p = Path(data.path).expanduser().resolve()
    if not p.is_dir(): raise HTTPException(400, "目录不存在或不是文件夹")
    c = db(); c.execute("UPDATE share_roots SET name=?,path=? WHERE id=?", (data.name.strip() or p.name or str(p), str(p), root_id)); c.commit(); c.close(); invalidate_search_cache(); return {"ok": True}

@app.delete("/api/admin/share-roots/{root_id}")
def remove_root(request: Request, root_id: int):
    if current_user(request)["role"] != "admin": raise HTTPException(403, "管理员权限")
    c = db(); c.execute("DELETE FROM share_roots WHERE id=?", (root_id,)); c.commit(); c.close(); invalidate_search_cache(); return {"ok": True}

if __name__ == "__main__":
    import uvicorn

    # 防止无控制台打包时 sys.stdout 为 None 引发的报错
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    port = int(os.getenv("PORT", "8000"))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        host = sock.getsockname()[0]
        sock.close()
    except OSError:
        host = "127.0.0.1"

    c = db()
    admin = c.execute("SELECT password FROM users WHERE username='admin'").fetchone()
    c.close()

    password = admin["password"] if admin else "not found"
    startup_message = f"HttpServer 已启动\n\n访问地址： http://{host}:{port}\n管理员账号： admin\n管理员密码： {password}\n\n关闭此提示不会停止服务。"
    if getattr(sys, "frozen", False):
        # -w 后没有控制台，因此用独立线程显示运行信息，不阻塞 HTTP 服务。
        def show_startup_message():
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(None, startup_message, "HttpServer", 0x40)
            except Exception:
                pass
        threading.Thread(target=show_startup_message, daemon=True).start()
    else:
        print(f"INFO: account:admin， password: {password}", flush=True)

    uvicorn.run(app, host=host, port=port)
