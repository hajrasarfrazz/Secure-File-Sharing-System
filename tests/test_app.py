import os
os.environ.update(SECRET_UPLOAD_TOKEN="t0k", DB_PATH="/tmp/test_sfs.db",
                  AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x",
                  S3_ENDPOINT="http://localhost:9000")
if os.path.exists("/tmp/test_sfs.db"):
    os.remove("/tmp/test_sfs.db")
import pytest
import app as appmod

AUTH = {"Authorization": "Bearer t0k"}


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def test_upload_requires_token(client):
    assert client.post("/api/upload-url", json={"size": 100}).status_code == 401


def test_upload_url_issued(client):
    r = client.post("/api/upload-url", json={"size": 100}, headers=AUTH)
    assert r.status_code == 200 and "X-Amz-Signature" in r.json["url"]


def test_rejects_oversize(client):
    assert client.post("/api/upload-url", json={"size": 10**12}, headers=AUTH).status_code == 400


def test_pending_file_cannot_be_downloaded(client):
    fid = client.post("/api/upload-url", json={"size": 100}, headers=AUTH).json["id"]
    assert client.post(f"/api/download-url/{fid}").status_code == 410


def test_download_limit_enforced(client):
    fid = client.post("/api/upload-url", json={"size": 100, "max_downloads": 1}, headers=AUTH).json["id"]
    with appmod.app.app_context():
        c = appmod.db()
        c.execute("UPDATE files SET status='ready' WHERE id=?", (fid,))
        c.commit()
    assert client.post(f"/api/download-url/{fid}").status_code == 200
    assert client.post(f"/api/download-url/{fid}").status_code == 410


def test_security_headers(client):
    assert "frame-ancestors 'none'" in client.get("/").headers["Content-Security-Policy"]
