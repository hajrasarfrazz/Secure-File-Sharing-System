"""Secure File Sharing System - Internee.pk
Zero-knowledge design: files are encrypted in the browser (AES-256-GCM).
The decryption key lives only in the URL fragment (#...), which browsers
never send to servers. The server only handles ciphertext + metadata and
issues short-lived pre-signed S3 URLs.
"""
import hmac
import logging
import os
import secrets
import sqlite3
import time

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

CFG = {
    "token": os.getenv("SECRET_UPLOAD_TOKEN", ""),
    "bucket": os.getenv("S3_BUCKET", "internee-secure-files"),
    "region": os.getenv("S3_REGION", "us-east-1"),
    "endpoint": os.getenv("S3_ENDPOINT") or None,
    "sse": os.getenv("S3_SSE") or None,
    "max_bytes": int(os.getenv("MAX_FILE_MB", "100")) * 1024 * 1024,
    "presign": int(os.getenv("PRESIGN_SECONDS", "300")),
    "db": os.getenv("DB_PATH", "files.db"),
}

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sfs")
limiter = Limiter(get_remote_address, app=app, default_limits=["120/minute"],
                  storage_uri="memory://")

_s3 = None


def s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", region_name=CFG["region"], endpoint_url=CFG["endpoint"],
                           config=Config(signature_version="s3v4"))
    return _s3


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(CFG["db"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    with sqlite3.connect(CFG["db"]) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS files(
          id TEXT PRIMARY KEY, size INTEGER, status TEXT,
          created REAL, expires REAL, max_downloads INTEGER, downloads INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit(
          ts REAL, event TEXT, file_id TEXT, ip TEXT);
        """)


def audit(event, file_id=""):
    db().execute("INSERT INTO audit VALUES(?,?,?,?)",
                 (time.time(), event, file_id, request.remote_addr))
    db().commit()
    log.info("%s file=%s ip=%s", event, file_id, request.remote_addr)


def require_token(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*a, **kw):
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not CFG["token"] or not hmac.compare_digest(supplied, CFG["token"]):
            return jsonify(error="unauthorized"), 401
        return fn(*a, **kw)
    return wrapper


def obj_key(fid):
    return f"files/{fid}"


# ---------- security headers ----------
@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self' http: https:; "
        "style-src 'self'; script-src 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ---------- pages ----------
@app.get("/")
def index():
    return render_template("index.html", max_mb=CFG["max_bytes"] // 1024 // 1024)


@app.get("/d/<fid>")
def download_page(fid):
    return render_template("download.html")


@app.get("/healthz")
def health():
    return jsonify(status="ok")


# ---------- API ----------
@app.post("/api/upload-url")
@require_token
@limiter.limit("20/minute")
def upload_url():
    data = request.get_json(silent=True) or {}
    size = int(data.get("size", 0))
    hours = min(max(int(data.get("expiry_hours", 24)), 1), 24 * 7)
    max_dl = min(max(int(data.get("max_downloads", 5)), 1), 100)
    if size <= 0 or size > CFG["max_bytes"] + 1024:
        return jsonify(error="invalid file size"), 400

    fid = secrets.token_urlsafe(16)
    now = time.time()
    db().execute("INSERT INTO files(id,size,status,created,expires,max_downloads) "
                 "VALUES(?,?,?,?,?,?)", (fid, size, "pending", now, now + hours * 3600, max_dl))
    db().commit()

    params = {"Bucket": CFG["bucket"], "Key": obj_key(fid), "ContentLength": size}
    headers_needed = {}
    if CFG["sse"]:
        params["ServerSideEncryption"] = CFG["sse"]
        headers_needed["x-amz-server-side-encryption"] = CFG["sse"]
    url = s3().generate_presigned_url("put_object", Params=params, ExpiresIn=CFG["presign"])
    audit("upload_url_issued", fid)
    return jsonify(id=fid, url=url, headers=headers_needed)


@app.post("/api/files/<fid>/complete")
@require_token
def complete(fid):
    row = db().execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    try:
        head = s3().head_object(Bucket=CFG["bucket"], Key=obj_key(fid))
    except ClientError:
        return jsonify(error="upload not found in storage"), 400
    if head["ContentLength"] != row["size"]:
        return jsonify(error="size mismatch"), 400
    db().execute("UPDATE files SET status='ready' WHERE id=?", (fid,))
    db().commit()
    audit("upload_complete", fid)
    return jsonify(ok=True)


@app.post("/api/download-url/<fid>")
@limiter.limit("30/minute")
def download_url(fid):
    # Atomic: only increments if still valid, so concurrent requests can't exceed the limit
    cur = db().execute(
        "UPDATE files SET downloads=downloads+1 WHERE id=? AND status='ready' "
        "AND expires>? AND downloads<max_downloads", (fid, time.time()))
    db().commit()
    if cur.rowcount == 0:
        audit("download_denied", fid)
        return jsonify(error="link invalid, expired, or download limit reached"), 410
    url = s3().generate_presigned_url(
        "get_object", Params={"Bucket": CFG["bucket"], "Key": obj_key(fid)},
        ExpiresIn=CFG["presign"])
    audit("download_url_issued", fid)
    return jsonify(url=url)


@app.delete("/api/files/<fid>")
@require_token
def revoke(fid):
    s3().delete_object(Bucket=CFG["bucket"], Key=obj_key(fid))
    db().execute("UPDATE files SET status='revoked' WHERE id=?", (fid,))
    db().commit()
    audit("revoked", fid)
    return jsonify(ok=True)


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, port=5000)
