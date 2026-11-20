# -*- coding: utf-8 -*-
"""HttpServer V1.4 UI 自动化测试（Playwright + 本机 Edge，headless）。

运行方法：
  .\.venv\Scripts\python.exe <本文件路径>
前置：服务已在 http://localhost:8000 运行。账号密码通过环境变量提供：
  HTTPSERVER_ADMIN_PW / HTTPSERVER_GUEST_PW（未设置时用初始默认 admin123 / guest123）。
脚本自动创建指向临时目录的测试共享，结束后移除共享并清理上传产物，不污染正式共享数据。
截图保存到脚本所在目录。
"""
import io
import json
import os
import sys
import time
import tempfile
import urllib.request

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from playwright.sync_api import sync_playwright

BASE = os.environ.get("HTTPSERVER_BASE", "http://localhost:8000")
ADMIN_PW = os.environ.get("HTTPSERVER_ADMIN_PW", "admin123")
GUEST_PW = os.environ.get("HTTPSERVER_GUEST_PW", "guest123")
OUT = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(tempfile.gettempdir(), "httpserver-ui-test")
SHARE = os.path.join(TMP, "share")
os.makedirs(SHARE, exist_ok=True)
SRC = os.path.join(TMP, "src")
os.makedirs(SRC, exist_ok=True)
single = os.path.join(SRC, "ui-single.txt")
open(single, "w", encoding="utf-8").write("ui single " + str(time.time()))
folder = os.path.join(SRC, "uifolder")
os.makedirs(os.path.join(folder, "sub"), exist_ok=True)
open(os.path.join(folder, "a.txt"), "w", encoding="utf-8").write("a")
open(os.path.join(folder, "sub", "b.txt"), "w", encoding="utf-8").write("b")
big = os.path.join(TMP, "big.bin")
if not os.path.exists(big):
    with open(big, "wb") as f:
        f.seek(1200 * 1024**2 - 1)
        f.write(b"\0")

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (" | " + extra if extra else ""))


def api(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


tok = api("POST", "/api/login", {"username": "admin", "password": ADMIN_PW})["token"]
existing = [r["id"] for r in api("GET", "/api/admin/share-roots", token=tok) if r["path"] == SHARE]
rid = existing[0] if existing else api("POST", "/api/admin/share-roots", {"name": "UI测试共享", "path": SHARE}, tok)["id"]
P = "r/%d" % rid
dialog_types = []

# 运行前清理：清空测试共享与其中回收站项目，保证可重复运行
for x in api("GET", "/api/files?path=" + P + "&page_size=200", token=tok)["items"]:
    try:
        api("DELETE", "/api/files/item", {"path": x["path"]}, tok)
    except Exception:
        pass
for item in api("GET", "/api/recycle-bin", token=tok):
    if item["root_id"] == rid:
        api("DELETE", "/api/recycle-bin/" + item["id"], token=tok)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("dialog", lambda d: (dialog_types.append(d.type), d.accept()))

    def login(name, pw):
        page.goto(BASE + "/files")
        page.wait_for_selector("#loginForm")
        page.fill('#loginForm input[name="username"]', name)
        page.fill('#loginForm input[name="password"]', pw)
        page.click('#loginForm button[type="submit"]')

    def wait_upload(timeout=90000):
        page.wait_for_function(
            "(()=>{const t=document.querySelector('#uploadProgress');return t&&!t.hidden&&(t.textContent.includes('上传完成')||t.textContent.includes('失败'))})()",
            timeout=timeout)
        return page.inner_text("#uploadProgress")

    def do_upload(input_sel, files, conflict="rename"):
        page.evaluate("(()=>{const b=document.querySelector('#uploadProgress');b.textContent='';b.hidden=false})()")
        page.set_input_files(input_sel, files)
        page.wait_for_selector("#conflictForm", timeout=10000)
        page.check('#conflictForm input[value="%s"]' % conflict)
        page.click('#conflictForm button[type="submit"]')
        msg = wait_upload()
        page.wait_for_timeout(600)
        return msg

    # 1 登录页：无版本号、副标题
    page.goto(BASE + "/files")
    page.wait_for_selector("#loginForm")
    check("登录页副标题", page.inner_text("#loginForm p").strip() == "局域网文件共享系统")
    check("登录页不显示版本号", page.query_selector(".loginver") is None and "V1.4" not in page.inner_text("#loginForm"))
    page.screenshot(path=os.path.join(OUT, "UI-登录页.png"))

    # 2 admin 登录：深色背景+状态栏
    login("admin", ADMIN_PW)
    page.wait_for_selector(".healthbar", timeout=15000)
    check("admin深色背景", page.evaluate("getComputedStyle(document.querySelector('.shell')).backgroundColor") == "rgb(56, 46, 32)")
    page.evaluate("state.path='%s'" % P)
    page.evaluate("refresh()")
    page.wait_for_timeout(600)

    # 3 单文件上传：页内冲突对话框（非原生 prompt），默认自动改名
    page.evaluate("(()=>{const b=document.querySelector('#uploadProgress');b.textContent='';b.hidden=false})()")
    page.set_input_files("#uploadFiles", single)
    page.wait_for_selector("#conflictForm", timeout=10000)
    check("上传冲突页内对话框", page.query_selector("#conflictForm") is not None)
    check("默认自动改名", page.is_checked('#conflictForm input[value="rename"]'))
    page.screenshot(path=os.path.join(OUT, "UI-上传冲突对话框.png"))
    page.click('#conflictForm button[type="submit"]')
    msg = wait_upload()
    check("单文件上传完成", msg.startswith("上传完成"), msg)
    check("上传过程无原生prompt", "prompt" not in dialog_types)

    # 4 同名策略：rename 生成 (1)；error 记入失败
    msg = do_upload("#uploadFiles", single, "rename")
    check("同名自动改名", "上传完成" in msg)
    page.wait_for_selector('text=ui-single (1).txt', timeout=10000)
    msg = do_upload("#uploadFiles", single, "error")
    check("同名error策略报错", "失败" in msg and "同名文件已存在" in msg, msg)

    # 5 文件夹上传（嵌套）
    msg = do_upload("#uploadFolder", folder, "rename")
    check("文件夹上传完成", msg.startswith("上传完成：2"), msg)
    page.wait_for_selector('text=uifolder', timeout=10000)
    page.click('[data-action="folder"][data-value="%s/uifolder"]' % P)
    page.wait_for_selector('[data-action="folder"][data-value="%s/uifolder/sub"]' % P, timeout=10000)
    page.click('[data-action="folder"][data-value="%s/uifolder/sub"]' % P)
    page.wait_for_selector('text=b.txt', timeout=10000)
    check("嵌套目录结构正确", True)
    page.evaluate("state.path='%s'" % P)
    page.evaluate("refresh()")
    page.wait_for_timeout(500)

    # 6 大文件(1.2GB)上传：验证上限提升
    msg = do_upload("#uploadFiles", big, "rename")
    check("1.2GB大文件上传成功", msg.startswith("上传完成"), msg)
    page.screenshot(path=os.path.join(OUT, "UI-大文件上传完成.png"))

    # 7 回收站：恢复+彻底删除按钮
    page.click('[data-action="deleteItem"][data-value="%s/ui-single.txt"]' % P)
    page.wait_for_timeout(600)
    page.click('[data-action="deleteItem"][data-value="%s/ui-single (1).txt"]' % P)
    page.wait_for_timeout(600)
    page.click('[data-action="recycle"]')
    page.wait_for_selector('[data-action="purge"]', timeout=10000)
    n0 = page.locator('.rootrow:has-text("ui-single") [data-action="purge"]').count()
    check("回收站含彻底删除按钮", n0 == 2 and page.locator('.rootrow:has-text("ui-single") [data-action="restore"]').count() == n0)
    page.screenshot(path=os.path.join(OUT, "UI-回收站彻底删除.png"))
    page.locator('.rootrow:has-text("ui-single.txt") [data-action="purge"]').click()
    page.wait_for_timeout(1000)
    n1 = page.locator('.rootrow:has-text("ui-single") [data-action="purge"]').count()
    check("彻底删除生效", n1 == n0 - 1)
    page.locator('.rootrow:has-text("(1)") [data-action="restore"]').click()
    page.wait_for_timeout(1000)
    check("恢复生效", page.locator('.rootrow:has-text("ui-single") [data-action="purge"]').count() == n1 - 1)
    page.keyboard.press("Escape")
    page.wait_for_selector('text=ui-single (1).txt', timeout=10000)

    # 8 修改密码页：深色+右上角明显关闭按钮
    page.click('.user-panel button[data-action="password"]')
    page.wait_for_selector("#passwordForm")
    bg = page.evaluate("getComputedStyle(document.querySelector('#passwordForm')).backgroundColor")
    check("改密页深色卡片", bg == "rgb(24, 26, 27)", bg)
    box = page.evaluate("(()=>{const c=document.querySelector('.pwclose').getBoundingClientRect();const b=document.querySelector('#passwordForm').getBoundingClientRect();return {cx:c.x,cy:c.y,bx:b.x,by:b.y,bw:b.width,text:document.querySelector('.pwclose').textContent}})()")
    check("关闭按钮右上角", box["cx"] > box["bx"] + box["bw"] / 2 and box["cy"] < box["by"] + 60, str(box))
    check("关闭按钮带文字更明显", "关闭" in box["text"])
    page.screenshot(path=os.path.join(OUT, "UI-修改密码深色.png"))
    page.click(".pwclose")
    page.wait_for_selector(".healthbar", timeout=15000)
    check("关闭返回文件页", True)

    # 9 侧边栏收缩
    page.click('button[data-action="toggleSide"]')
    page.wait_for_timeout(300)
    check("侧边栏收缩", page.evaluate("document.querySelector('.shell').classList.contains('side-collapsed')"))
    page.click('button[data-action="toggleSide"]')

    # 10 搜索提示语
    def delay(route):
        time.sleep(1.2)
        route.continue_()
    page.route("**/api/files?**", delay)
    page.fill('#searchForm input[name="q"]', "ui-single*")
    page.click('#searchForm button:not([type="button"])')
    page.wait_for_timeout(400)
    check("搜索提示语", page.inner_text('#main p[role="status"]') == "搜索中，请稍后…")
    page.unroute("**/api/files?**")
    page.wait_for_timeout(2000)
    page.click('button[data-action="clear"]')
    page.wait_for_timeout(800)

    # 11 日志条件查询
    page.click('.side .nav button[data-value="logs"]')
    page.wait_for_selector("#logFilterForm", timeout=15000)
    page.select_option('#logFilterForm select[name="result"]', "denied")
    page.fill('#logFilterForm input[name="username"]', "admin")
    page.click('#logFilterForm button:not([type="button"])')
    page.wait_for_timeout(1200)
    rows = page.eval_on_selector_all(".table tbody tr", "els=>els.map(e=>e.innerText)")
    check("日志条件查询", len(rows) > 0 and all("denied" in r and "admin" in r for r in rows if r.strip()))

    # 12 guest 视角：无状态栏、无改名/删除按钮、可见共享文件
    page.click('.user-panel button[data-action="logout"]')
    page.wait_for_selector("#loginForm")
    login("guest", GUEST_PW)
    page.wait_for_selector(".table", timeout=15000)
    page.wait_for_timeout(600)
    check("guest无状态栏", page.query_selector(".healthbar") is None)
    page.evaluate("state.path='%s'" % P)
    page.evaluate("refresh()")
    page.wait_for_timeout(800)
    check("guest可见共享文件", page.query_selector('text=ui-single (1).txt') is not None)
    check("guest无改名删除按钮", page.query_selector('[data-action="rename"]') is None and page.query_selector('[data-action="deleteItem"]') is None)
    page.screenshot(path=os.path.join(OUT, "UI-guest视角.png"))
    browser.close()

# 清理：删除测试上传产物并彻底删除，移除测试共享
for name in ("big.bin", "ui-single.txt", "ui-single (1).txt", "uifolder"):
    try:
        api("DELETE", "/api/files/item", {"path": P + "/" + name}, tok)
    except Exception:
        pass
for item in api("GET", "/api/recycle-bin", token=tok):
    if item["path"].startswith(("big.bin", "ui-single", "uifolder")) or item["root_id"] == rid:
        api("DELETE", "/api/recycle-bin/" + item["id"], token=tok)
api("DELETE", "/api/admin/share-roots/%d" % rid, token=tok)

failed = [n for n, ok in RESULTS if not ok]
print("\n%d/%d passed" % (len(RESULTS) - len(failed), len(RESULTS)))
print("FAILED:", failed if failed else "none")
sys.exit(1 if failed else 0)