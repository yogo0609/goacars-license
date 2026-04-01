from fastapi import FastAPI, Header, HTTPException, Request
import sqlite3
import os
import secrets
import string
from urllib.parse import urlparse

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "license.db")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_url(url: str) -> str:
    if not url:
        return ""

    url = url.strip()
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = (parsed.path or "").rstrip("/")

    if not scheme or not netloc:
        return ""

    return f"{scheme}://{netloc}{path}"


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE,
            status TEXT NOT NULL,
            device_id TEXT,
            licensed_url TEXT
        )
    """)

    try:
        cursor.execute("ALTER TABLE licenses ADD COLUMN licensed_url TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def require_admin_key(x_admin_key: str | None):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="admin_key_not_configured")

    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="forbidden")


def generate_license_key():
    alphabet = string.ascii_uppercase + string.digits
    parts = [
        "".join(secrets.choice(alphabet) for _ in range(4)),
        "".join(secrets.choice(alphabet) for _ in range(4)),
        "".join(secrets.choice(alphabet) for _ in range(4)),
    ]
    return "GOACARS-" + "-".join(parts)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():
    return {"service": "goacars-license", "status": "online"}


@app.post("/validate")
async def validate_key(request: Request):
    conn = get_db()
    cursor = conn.cursor()

    body = {}
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except:
        body = {}

    query = request.query_params

    resolved_key = (
        body.get("license_key")
        or body.get("key")
        or query.get("license_key")
        or query.get("key")
        or ""
    ).strip()

    device_id = (
        body.get("device_id")
        or query.get("device_id")
        or ""
    ).strip()

    airline_url = (
        body.get("airline_url")
        or query.get("airline_url")
        or ""
    ).strip()

    if not resolved_key:
        conn.close()
        return {"valid": False, "status": "missing_key"}

    cursor.execute("SELECT * FROM licenses WHERE license_key = ?", (resolved_key,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return {"valid": False, "status": "not_found"}

    status = row["status"]
    saved_device_id = row["device_id"]
    saved_url = row["licensed_url"]

    if status != "active":
        conn.close()
        return {
            "valid": False,
            "license_key": row["license_key"],
            "status": status
        }

    if airline_url:
        normalized_incoming_url = normalize_url(airline_url)

        if not normalized_incoming_url:
            conn.close()
            return {
                "valid": False,
                "license_key": resolved_key,
                "status": "invalid_airline_url"
            }

        if not saved_url:
            cursor.execute(
                "UPDATE licenses SET licensed_url = ? WHERE license_key = ?",
                (normalized_incoming_url, resolved_key)
            )
            conn.commit()
            conn.close()

            return {
                "valid": True,
                "license_key": resolved_key,
                "status": "active",
                "airline_bound": True
            }

        if normalize_url(saved_url) != normalized_incoming_url:
            conn.close()
            return {
                "valid": False,
                "license_key": resolved_key,
                "status": "airline_mismatch",
                "expected_url": saved_url,
                "received_url": normalized_incoming_url
            }

        conn.close()
        return {
            "valid": True,
            "license_key": resolved_key,
            "status": "active",
            "airline_bound": False
        }

    if device_id:
        if not saved_device_id:
            cursor.execute(
                "UPDATE licenses SET device_id = ? WHERE license_key = ?",
                (device_id, resolved_key)
            )
            conn.commit()
            conn.close()

            return {
                "valid": True,
                "license_key": resolved_key,
                "status": "active",
                "device_bound": True
            }

        if saved_device_id != device_id:
            conn.close()
            return {
                "valid": False,
                "license_key": resolved_key,
                "status": "device_mismatch"
            }

        conn.close()
        return {
            "valid": True,
            "license_key": resolved_key,
            "status": "active",
            "device_bound": False
        }

    conn.close()
    return {"valid": False, "status": "invalid_request"}


@app.post("/admin/create_key")
def create_key(
    key: str,
    status: str = "active",
    licensed_url: str | None = None,
    x_admin_key: str | None = Header(default=None)
):
    require_admin_key(x_admin_key)

    normalized_url = normalize_url(licensed_url) if licensed_url else None

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO licenses (license_key, status, device_id, licensed_url) VALUES (?, ?, NULL, ?)",
            (key, status, normalized_url)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return {"created": False, "reason": "duplicate_key"}

    conn.close()
    return {
        "created": True,
        "license_key": key,
        "status": status,
        "licensed_url": normalized_url
    }


@app.post("/admin/generate_key")
def admin_generate_key(
    licensed_url: str | None = None,
    x_admin_key: str | None = Header(default=None)
):
    require_admin_key(x_admin_key)

    normalized_url = normalize_url(licensed_url) if licensed_url else None

    conn = get_db()
    cursor = conn.cursor()

    while True:
        key = generate_license_key()
        try:
            cursor.execute(
                "INSERT INTO licenses (license_key, status, device_id, licensed_url) VALUES (?, 'active', NULL, ?)",
                (key, normalized_url)
            )
            conn.commit()
            conn.close()
            return {
                "created": True,
                "license_key": key,
                "status": "active",
                "licensed_url": normalized_url
            }
        except sqlite3.IntegrityError:
            continue


@app.post("/admin/revoke_key")
def revoke_key(key: str, x_admin_key: str | None = Header(default=None)):
    require_admin_key(x_admin_key)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE licenses SET status = 'revoked' WHERE license_key = ?",
        (key,)
    )

    if cursor.rowcount == 0:
        conn.close()
        return {"revoked": False, "reason": "not_found"}

    conn.commit()
    conn.close()

    return {
        "revoked": True,
        "license_key": key,
        "status": "revoked"
    }


@app.post("/admin/reset_device")
def reset_device(key: str, x_admin_key: str | None = Header(default=None)):
    require_admin_key(x_admin_key)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE licenses SET device_id = NULL WHERE license_key = ?",
        (key,)
    )

    if cursor.rowcount == 0:
        conn.close()
        return {"reset": False, "reason": "not_found"}

    conn.commit()
    conn.close()

    return {
        "reset": True,
        "license_key": key,
        "device_bound": False
    }


@app.post("/admin/reset_airline")
def reset_airline(key: str, x_admin_key: str | None = Header(default=None)):
    require_admin_key(x_admin_key)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE licenses SET licensed_url = NULL WHERE license_key = ?",
        (key,)
    )

    if cursor.rowcount == 0:
        conn.close()
        return {"reset": False, "reason": "not_found"}

    conn.commit()
    conn.close()

    return {
        "reset": True,
        "license_key": key,
        "airline_bound": False
    }


@app.get("/admin/licenses")
def list_licenses(x_admin_key: str | None = Header(default=None)):
    require_admin_key(x_admin_key)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, license_key, status, device_id, licensed_url
        FROM licenses
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()

    conn.close()

    return [
        {
            "id": row["id"],
            "license_key": row["license_key"],
            "status": row["status"],
            "device_bound": row["device_id"] is not None,
            "licensed_url": row["licensed_url"],
            "airline_bound": row["licensed_url"] is not None
        }
        for row in rows
    ]
