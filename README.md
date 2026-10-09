# 🔐 Secure File Sharing System — Internee.pk

A zero-knowledge file-sharing portal. Files are **encrypted in the browser (AES-256-GCM)** before upload,
stored in **S3-compatible cloud storage**, and accessed only via **short-lived pre-signed URLs**.

## Architecture
```
Browser ──(1) encrypt AES-256-GCM──┐
   │                               │
   ├─(2) POST /api/upload-url ──► Flask API ──► issues pre-signed PUT URL (5 min)
   ├─(3) PUT ciphertext ─────────────────────► S3 / MinIO bucket (encrypted at rest)
   └─(4) share link:  https://host/d/<id>#<KEY>
                                  └─ KEY is in the URL fragment → never sent to any server
Recipient ─► POST /api/download-url/<id> ─► pre-signed GET URL ─► ciphertext ─► decrypt in browser
```

## Security features
| Layer | Control |
|---|---|
| End-to-end encryption | AES-256-GCM (Web Crypto); key stays in URL fragment; filename is encrypted too |
| In transit | HTTPS/TLS + HSTS |
| At rest | Bucket encryption (`S3_SSE=AES256` or KMS) on top of E2E ciphertext |
| Signed URLs | Pre-signed PUT/GET, expire in 5 minutes, upload size locked via signed Content-Length |
| Access control | Bearer token for uploads (constant-time compare); expiry + max-download limit per link (atomic SQL) |
| Abuse protection | Rate limiting (Flask-Limiter) |
| Hardening | CSP, `nosniff`, `no-referrer`, `no-store`, `frame-ancestors 'none'` |
| Auditing | Every issue/deny/revoke event logged in `audit` table |
| Integrity | GCM auth tag detects tampering; wrong key fails to decrypt |

## Run locally
```bash
git clone <your-repo> && cd secure-file-share
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # set SECRET_UPLOAD_TOKEN
docker compose up -d                                   # starts MinIO + creates bucket
python app.py                                          # http://localhost:5000
pytest -q                                              # run tests
```
`localhost` counts as a secure context, so Web Crypto works. In production you **must** use HTTPS.

## Use real AWS S3 instead of MinIO
1. Create a private bucket, block all public access, enable default encryption (SSE-S3 or SSE-KMS).
2. Add a CORS rule: `AllowedMethods: PUT, GET`, `AllowedOrigins: https://your-domain`, `AllowedHeaders: *`.
3. Create an IAM user limited to `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on that bucket only.
4. In `.env`: remove `S3_ENDPOINT`, set real keys, `S3_SSE=AES256`.
5. Add a lifecycle rule to delete objects under `files/` after 7 days.

## Deploy
`docker build -t secure-share . && docker run -p 8000:8000 --env-file .env secure-share`
Works on Render, Railway, AWS App Runner, or Google Cloud Run (they provide HTTPS automatically).

## Testing data
`sample_data/` has an Internee.pk-style report; add any Kaggle CSV (e.g. Titanic) and test the upload/download.

## Limitations & future work
Whole-file encryption in memory (100 MB cap) → chunked streaming encryption; SQLite → PostgreSQL;
per-user accounts/SSO and MFA; password-protected links; antivirus scanning of decrypted files by the recipient.
