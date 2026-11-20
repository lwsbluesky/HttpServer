"""V1.4 file-management security and recovery regression tests."""
import os
import time

import pytest
from fastapi import HTTPException

from test_v13 import env, path, get
import app as server


def post(env, url, **kwargs):
    return env["client"].post(url, headers=env["gp"], **kwargs)


def test_server_pagination_sort_and_validation(env):
    for name in ("zeta.txt", "alpha.txt", "middle.txt"):
        (env["share"] / name).write_text(name)
    first = get(env, "/api/files", params={"path": path(env), "page": 1, "page_size": 2, "sort": "name"})
    assert first.status_code == 200
    assert first.json()["total"] == 5
    assert [x["name"] for x in first.json()["items"]] == ["hidden", "alpha.txt"]
    second = get(env, "/api/files", params={"path": path(env), "page": 2, "page_size": 2, "sort": "name"})
    assert [x["name"] for x in second.json()["items"]] == ["hello.txt", "middle.txt"]
    assert get(env, "/api/files", params={"path": path(env), "page_size": 201}).status_code == 400
    assert get(env, "/api/files", params={"path": path(env), "sort": "invalid"}).status_code == 400


def test_upload_success_conflict_and_atomic_overwrite(env):
    endpoint = "/api/files/upload"
    args = {"path": path(env), "filename": "hello.txt"}
    denied = env["client"].post(endpoint, headers=env["gp"], params=args, content=b"no")
    assert denied.status_code == 403
    result = env["client"].post(endpoint, headers=env["ap"], params=args, content=b"new")
    assert result.status_code == 409
    assert (env["share"] / "hello.txt").read_text(encoding="utf-8") == "你好 world"
    result = env["client"].post(endpoint, headers=env["ap"], params={**args, "conflict": "overwrite"}, content=b"replacement")
    assert result.status_code == 200 and result.json()["size"] == 11
    assert (env["share"] / "hello.txt").read_bytes() == b"replacement"
    assert not list(env["share"].glob(".httpserver-upload-*.tmp"))


def test_upload_rename_skip_and_windows_names(env):
    endpoint = "/api/files/upload"
    args = {"path": path(env), "filename": "hello.txt"}
    renamed = env["client"].post(endpoint, headers=env["ap"], params={**args, "conflict": "rename"}, content=b"renamed")
    assert renamed.status_code == 200 and renamed.json()["name"] == "hello (1).txt"
    skipped = env["client"].post(endpoint, headers=env["ap"], params={**args, "conflict": "skip"}, content=b"ignored")
    assert skipped.status_code == 200 and skipped.json()["skipped"]
    bad = env["client"].post(endpoint, headers=env["ap"], params={**args, "filename": "CON.txt"}, content=b"bad")
    assert bad.status_code == 400


def test_upload_stream_limit_cleans_partial_file(env, monkeypatch):
    monkeypatch.setattr(server, "MAX_UPLOAD_BYTES", 4)
    response = env["client"].post("/api/files/upload", headers=env["ap"], params={"path": path(env), "filename": "large.bin"}, content=b"12345")
    assert response.status_code == 413
    assert not (env["share"] / "large.bin").exists()
    assert not list(env["share"].glob(".httpserver-upload-*.tmp"))


def test_upload_gate_rejects_excess_without_leaking_capacity(env):
    acquired = [server.UPLOAD_GATE.acquire(blocking=False) for _ in range(server.MAX_CONCURRENT_UPLOADS)]
    assert all(acquired)
    try:
        result = env["client"].post("/api/files/upload", headers=env["ap"],
            params={"path": path(env), "filename": "busy.bin"}, content=b"content")
        assert result.status_code == 503
        assert server.ACTIVE["upload"] == 0
        assert not (env["share"] / "busy.bin").exists()
    finally:
        for _ in acquired:
            server.UPLOAD_GATE.release()


def test_folder_rename_move_copy_and_recycle_restore(env):
    c = env["client"]
    assert c.post("/api/files/folders", headers=env["ap"], json={"path": path(env), "name": "created"}).status_code == 200
    assert c.post("/api/files/folders", headers=env["ap"], json={"path": path(env), "name": "created"}).status_code == 409
    renamed = c.patch("/api/files/item", headers=env["ap"], json={"path": path(env, "created"), "name": "renamed"})
    assert renamed.status_code == 200
    moved = c.post("/api/files/move", headers=env["ap"], json={"paths": [path(env, "hello.txt")], "destination": path(env, "renamed")})
    assert moved.json()["results"][0]["ok"]
    copied = c.post("/api/files/copy", headers=env["ap"], json={"paths": [path(env, "renamed/hello.txt")], "destination": path(env)})
    assert copied.json()["results"][0]["ok"]
    deleted = c.request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")})
    assert deleted.status_code == 200 and not (env["share"] / "hello.txt").exists()
    assert get(env, "/api/files", admin=True, params={"path": path(env)}).json()["items"]
    bin_items = c.get("/api/recycle-bin", headers=env["ap"]).json()
    item = next(x for x in bin_items if x["id"] == deleted.json()["id"])
    assert item["path"] == "hello.txt"
    restored = c.post(f"/api/recycle-bin/{item['id']}/restore", headers=env["ap"])
    assert restored.status_code == 200
    assert (env["share"] / "hello.txt").exists()


def test_recycle_restore_conflict_and_permission_denial(env):
    c = env["client"]
    deleted = c.request("DELETE", "/api/files/item", headers=env["ap"], json={"path": path(env, "hello.txt")}).json()
    (env["share"] / "hello.txt").write_text("conflict")
    conflict = c.post(f"/api/recycle-bin/{deleted['id']}/restore", headers=env["ap"])
    assert conflict.status_code == 409
    uid = get(env, "/api/account").json()["id"]
    c.put(f"/api/admin/share-roots/{env['rid']}/permissions/{uid}", headers=env["ap"], json={"browse": True, "download": True})
    denied = c.request("DELETE", "/api/files/item", headers=env["gp"], json={"path": path(env, "hello.txt")})
    assert denied.status_code == 403


def test_recycle_expiration_removes_disk_entry(env, monkeypatch):
    item_id = server.trash_item({"id": 1, "username": "admin", "role": "admin"}, path(env, "hello.txt"))
    with server.database() as c:
        c.execute("UPDATE recycle_items SET expires_at=? WHERE id=?", (time.time() - 1, item_id))
    server.cleanup()
    with server.database() as c:
        assert c.execute("SELECT 1 FROM recycle_items WHERE id=?", (item_id,)).fetchone() is None
    assert not (env["share"] / server.RECYCLE_DIR_NAME / item_id).exists()


def test_recycle_storage_cannot_be_browsed_or_downloaded(env):
    item_id = server.trash_item({"id": 1, "username": "admin", "role": "admin"}, path(env, "hello.txt"))
    internal = path(env, server.RECYCLE_DIR_NAME + "/" + item_id)
    assert get(env, "/api/files", admin=True, params={"path": path(env)}).status_code == 200
    assert get(env, "/api/files/download", admin=True, params={"path": internal}).status_code == 404


def test_batch_zip_ticket_is_session_bound_and_cleans_temp(env):
    (env["share"] / "other.txt").write_text("other")
    paths = [path(env, "hello.txt"), path(env, "other.txt")]
    prepared = env["client"].post("/api/downloads/prepare-batch", headers=env["ap"], json={"paths": paths})
    assert prepared.status_code == 200
    result = env["client"].get("/api/files/download-batch", params={"paths": "\n".join(paths), "ticket": prepared.json()["ticket"]})
    assert result.status_code == 200
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        assert sorted(archive.namelist()) == ["hello.txt", "other.txt"]
    assert not server.ACTIVE_TEMP and not list(env["temp"].iterdir())
