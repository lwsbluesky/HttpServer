"""Real-process/browser/load/restart verification; optional --seconds 259200 for 72h."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
import io
import httpx
import psutil
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/"docs"/"test-evidence-v1.4"
EVIDENCE.mkdir(parents=True,exist_ok=True)
PASSWORD="Live-test-strong-password"
parser=argparse.ArgumentParser()
parser.add_argument("--seconds",type=int,default=180)
parser.add_argument("--exe",type=Path)
parser.add_argument("--skip-browser",action="store_true")
args=parser.parse_args()
results={"requested_seconds":args.seconds,"browser_checks":[],"process_checks":[]}
workspace=tempfile.TemporaryDirectory(prefix="httpserver-live-")
base=Path(workspace.name)
data=base/"state";share=base/"share";share.mkdir()
(share/"hello.txt").write_text("你好 HttpServer",encoding="utf-8")
(share/"O'Reilly & 计划.txt").write_text("special name preview",encoding="utf-8")
(share/"large.txt").write_bytes(b"x"*(3*1024**2))
# Two archive jobs use a real 128 MiB directory.
with (share/"payload.bin").open("wb") as f:
    for _ in range(16):f.write(b"0123456789abcdef"*(512*1024))
with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
url=f"http://127.0.0.1:{port}"
process=None
log=(ROOT/"build"/("v14-exe-server.log" if args.exe else "v14-live-server.log")).open("w",encoding="utf-8")
environment={**os.environ,"HTTPSERVER_DATA_DIR":str(data),"HTTPSERVER_NO_DIALOG":"1","PORT":str(port)}
startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0

def start():
    command=[str(args.exe.resolve())] if args.exe else [sys.executable,str(ROOT/"app.py")]
    p=subprocess.Popen(command,cwd=ROOT,env=environment,stdout=log,stderr=log,startupinfo=startup)
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        if p.poll() is not None:raise AssertionError("server exited; see build/v14-live-server.log")
        try:
            if httpx.get(url+"/api/health",timeout=1).status_code==200:return p
        except httpx.HTTPError:pass
        time.sleep(.2)
    stop(p);raise AssertionError("startup timeout")

def stop(p):
    if not p:return
    parent=psutil.Process(p.pid) if p.poll() is None else None
    descendants=parent.children(recursive=True) if parent else []
    # Only processes launched by this test and their descendants are stopped.
    for child in descendants:
        try:child.terminate()
        except psutil.NoSuchProcess:pass
    if p.poll() is None:p.terminate()
    p.wait(timeout=15)
    for child in descendants:
        try:child.wait(timeout=5)
        except psutil.TimeoutExpired:child.kill()
        except psutil.NoSuchProcess:pass

def headers(token):return {"Authorization":"Bearer "+token}
def login(client,username,password):
    r=client.post("/api/login",json={"username":username,"password":password})
    assert r.status_code==200,r.text
    return r.json()["token"]

def sample(p):
    rows=[psutil.Process(p.pid)]+psutil.Process(p.pid).children(recursive=True)
    return {"rss":sum(r.memory_info().rss for r in rows),"handles":sum(r.num_handles() for r in rows),
            "threads":sum(r.num_threads() for r in rows)}

try:
    process=start()
    with httpx.Client(base_url=url,timeout=150) as client:
        initial=login(client,"admin","admin123")
        assert client.get("/api/files",headers=headers(initial)).status_code==200
        if not args.skip_browser:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(channel="msedge",headless=True)
                page=browser.new_page(viewport={"width":1440,"height":1000},accept_downloads=True)
                errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
                page.goto(url)
                page.locator("#loginForm [name=username]").fill("admin")
                page.locator("#loginForm [name=password]").fill("admin123")
                page.locator("#loginForm button[type=submit]").click()
                page.get_by_role("heading",name="文件浏览",exact=True).wait_for()
                results["browser_checks"].append("first_login_no_forced_password_change")
                page.locator('[data-action=password]').click()
                page.locator("#passwordForm").wait_for()
                page.locator("#passwordForm [name=current]").fill("admin123")
                page.locator("#passwordForm [name=password]").fill(PASSWORD)
                page.locator("#passwordForm [name=confirm]").fill(PASSWORD)
                page.locator("#passwordForm button[type=submit]").click()
                page.locator("#loginForm").wait_for()
                page.locator("#loginForm [name=username]").fill("admin")
                page.locator("#loginForm [name=password]").fill(PASSWORD)
                page.locator("#loginForm button[type=submit]").click()
                page.get_by_role("heading",name="文件浏览",exact=True).wait_for()
                results["browser_checks"].append("password_change_and_relogin")
                admin=login(client,"admin",PASSWORD)
                rid=client.post("/api/admin/share-roots",headers=headers(admin),json={"name":"<img src=x onerror=alert(1)>","path":str(share)}).json()["id"]
                page.locator('[data-action=refresh]').click()
                page.get_by_role("cell",name="O'Reilly & 计划.txt",exact=True).wait_for()
                row=page.get_by_role("row").filter(has=page.get_by_role("cell",name="O'Reilly & 计划.txt",exact=True))
                row.get_by_role("button",name="预览",exact=True).click()
                page.locator("#modalBody pre").wait_for()
                assert page.locator("#modalBody pre").inner_text()=="special name preview"
                page.get_by_role("button",name="关闭",exact=True).click()
                results["browser_checks"].append("apostrophe_unicode_filename_preview")
                # Offline request then restore and retry without a full page reload.
                page.context.set_offline(True)
                page.locator('[data-action=refresh]').click()
                page.get_by_role("button",name="重试",exact=True).wait_for(timeout=10000)
                page.context.set_offline(False)
                page.get_by_role("cell",name="hello.txt",exact=True).wait_for(timeout=10000)
                results["browser_checks"].append("offline_error_and_online_recovery")
                with page.expect_download() as info:
                    page.get_by_role("row").filter(has=page.get_by_role("cell",name="hello.txt",exact=True)).get_by_role("button",name="下载",exact=True).click()
                assert info.value.suggested_filename=="hello.txt"
                results["browser_checks"].append("prepared_one_time_file_download")
                page.once("dialog",lambda dialog:dialog.accept("error"))
                with page.expect_file_chooser() as chooser:
                    page.get_by_role("button",name="上传文件",exact=True).click()
                chooser.value.set_files({"name":"browser-upload.txt","mimeType":"text/plain","buffer":b"browser upload test"})
                page.wait_for_function("document.querySelector('#uploadProgress') && document.querySelector('#uploadProgress').textContent.length > 0",timeout=15000)
                upload_status=page.locator("#uploadProgress").inner_text()
                assert upload_status.startswith("上传完成：1 个文件"),upload_status
                page.get_by_role("cell",name="browser-upload.txt",exact=True).wait_for()
                results["browser_checks"].append("file_upload_progress_and_completion")
                page.locator('[data-select="r/%s/browser-upload.txt"]'%rid).check()
                with page.expect_download() as info:page.get_by_role("button",name="下载所选",exact=True).click()
                assert info.value.suggested_filename=="HttpServer-files.zip"
                results["browser_checks"].append("batch_zip_download")
                page.screenshot(path=str(EVIDENCE/"files-desktop.png"),full_page=True)
                page.locator('[data-action=nav][data-value=admin]').click()
                page.get_by_role("heading",name="在线会话",exact=True).wait_for()
                assert page.locator("img").count()==0
                results["browser_checks"].append("admin_dashboard_escaped_root_name")
                page.get_by_role("button",name="目录权限",exact=True).click()
                page.locator(".aclForm").wait_for()
                assert page.locator(".aclForm input").count()==5
                page.get_by_role("button",name="关闭",exact=True).click()
                results["browser_checks"].append("five_directory_permissions_visible")
                with page.expect_download() as info:page.get_by_role("button",name="导出诊断包",exact=True).click()
                download=info.value
                assert download.suggested_filename=="HttpServer-diagnostics.zip"
                results["browser_checks"].append("diagnostics_browser_download")
                page.screenshot(path=str(EVIDENCE/"admin-desktop.png"),full_page=True)
                page.set_viewport_size({"width":390,"height":844})
                page.locator('[data-action=nav][data-value=files]').click()
                page.get_by_role("cell",name="hello.txt",exact=True).wait_for()
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),"mobile page overflow"
                assert page.locator('[data-action=download]').first.is_visible()
                page.screenshot(path=str(EVIDENCE/"files-mobile.png"),full_page=True)
                results["browser_checks"].append("mobile_390px")
                page.locator('[data-action=logout]').click()
                page.locator("#loginForm").wait_for()
                results["browser_checks"].append("server_logout")
                page.locator("#loginForm [name=username]").fill("guest")
                page.locator("#loginForm [name=password]").fill("guest123")
                page.locator("#loginForm button[type=submit]").click()
                page.get_by_role("heading",name="文件浏览",exact=True).wait_for()
                page.locator('[data-action=password]').click()
                page.locator("#passwordForm").wait_for()
                page.locator("#passwordForm [name=current]").fill("guest123")
                page.locator("#passwordForm [name=password]").fill("Guest-V13-strong-password")
                page.locator("#passwordForm [name=confirm]").fill("Guest-V13-strong-password")
                page.locator("#passwordForm button[type=submit]").click()
                page.locator("#loginForm").wait_for()
                page.locator("#loginForm [name=username]").fill("guest")
                page.locator("#loginForm [name=password]").fill("Guest-V13-strong-password")
                page.locator("#loginForm button[type=submit]").click()
                page.get_by_role("cell",name="hello.txt",exact=True).wait_for()
                assert page.locator('[data-action=nav][data-value=admin]').count()==0
                page.goto(url+"/manageCenter")
                page.get_by_role("cell",name="hello.txt",exact=True).wait_for()
                assert page.url.endswith("/files")
                with page.expect_download() as info:
                    page.get_by_role("row").filter(has=page.get_by_role("cell",name="hello.txt",exact=True)).get_by_role("button",name="下载",exact=True).click()
                assert info.value.suggested_filename=="hello.txt"
                results["browser_checks"].append("guest_browse_download_and_admin_page_redirect")
                assert not errors,errors
                results["browser_page_errors"]=errors
                browser.close()
        else:
            assert client.post("/api/account/password",headers=headers(initial),json={"current_password":"admin123","new_password":PASSWORD}).status_code==200
            admin=login(client,"admin",PASSWORD)
            rid=client.post("/api/admin/share-roots",headers=headers(admin),json={"path":str(share)}).json()["id"]
        admin=login(client,"admin",PASSWORD)
        auth=headers(admin);vp=f"r/{rid}"
        assert client.get("/api/files/view",headers=auth,params={"path":vp+"/large.txt"}).json()["truncated"]
        durations=[];codes={}
        def request(i):
            t=time.perf_counter()
            r=client.get("/api/health") if i%2 else client.get("/api/files",headers=auth,params={"path":vp})
            return r.status_code,time.perf_counter()-t
        with concurrent.futures.ThreadPoolExecutor(max_workers=54) as pool:
            archives=[pool.submit(client.get,"/api/files/download",headers=auth,params={"path":vp}) for _ in range(2)]
            bursts=list(pool.map(request,range(50)))
            for status,elapsed in bursts:
                assert status in (200,503) and elapsed<2,(status,elapsed)
            assert all(f.result().status_code==200 for f in archives)
        results["process_checks"].append("two_real_128MiB_archives_plus_50_requests")
        results["concurrency"]={"requests":50,"max_seconds":max(t for _,t in bursts),
                                "ok":sum(s==200 for s,_ in bursts),"busy":sum(s==503 for s,_ in bursts)}
        started=time.monotonic();baseline=sample(process);samples=[baseline];rounds=0
        while time.monotonic()-started<args.seconds:
            for endpoint,params in (("/api/health",{}),("/api/files",{"path":vp}),("/api/files",{"q":"hello"}),("/api/files/download",{"path":vp+"/hello.txt"})):
                t=time.perf_counter();r=client.get(endpoint,headers=auth,params=params)
                elapsed=time.perf_counter()-t;durations.append(elapsed);codes[str(r.status_code)]=codes.get(str(r.status_code),0)+1
                assert r.status_code==200,(endpoint,r.status_code)
            if rounds%20==0:
                extra=login(client,"admin",PASSWORD)
                assert client.post("/api/logout",headers=headers(extra)).status_code==200
                samples.append(sample(process))
            rounds+=1;time.sleep(.05)
        final=sample(process);samples.append(final)
        leftovers=list((data/"tmp").glob("*"))
        assert not leftovers
        assert final["threads"]<=baseline["threads"]+4,(baseline,final)
        assert final["handles"]<=baseline["handles"]+32,(baseline,final)
        assert final["rss"]-baseline["rss"]<64*1024**2,(baseline,final)
        durations.sort()
        results["load"]={"actual_seconds":round(time.monotonic()-started,2),"rounds":rounds,"status_counts":codes,
                         "p95_seconds":durations[int(len(durations)*.95)],"max_seconds":max(durations),
                         "baseline":baseline,"final":final,"max_rss":max(s["rss"] for s in samples),
                         "temp_files_after":len(leftovers)}
        stop(process);process=start()
        assert client.get("/api/account",headers=auth).status_code==401
        fresh=login(client,"admin",PASSWORD)
        assert client.get("/api/admin/share-roots",headers=headers(fresh)).json()[0]["id"]==rid
        results["process_checks"].extend(["old_token_rejected_after_process_restart","database_settings_persisted_after_restart"])
    results["outcome"]="passed"
except BaseException as exc:
    results["outcome"]="failed";results["failure"]=repr(exc)
    raise
finally:
    if process:
        try:stop(process)
        except Exception:pass
    log.close()
    filename="exe-live-results.json" if args.exe else "live-results.json"
    (EVIDENCE/filename).write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding="utf-8")
    workspace.cleanup()
    print(json.dumps(results,ensure_ascii=True,indent=2))
