from fastapi import FastAPI
import sqlite3
import os

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "license.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE,
            status TEXT NOT NULL,
            device_id TEXT
        )
    """)

    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():
    return {"service": "goacars-license", "status": "online"}


@app.post("/validate")
def validate_key(key: str, device_id: str):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM licenses WHERE license_key = ?", (key,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return {"valid": False, "status": "not_found"}

    status = row["status"]
    saved_device_id = row["device_id"]

    if status != "active":
        conn.close()
        return {
            "valid": False,
            "license_key": row["license_key"],
            "status": status
        }

    if not saved_device_id:
        cursor.execute(
            "UPDATE licenses SET device_id = ? WHERE license_key = ?",
            (device_id, key)
        )
        conn.commit()
        conn.close()

        return {
            "valid": True,
            "license_key": key,
            "status": "active",
            "device_bound": True
        }

    if saved_device_id != device_id:
        conn.close()
        return {
            "valid": False,
            "license_key": key,
            "status": "device_mismatch"
        }

    conn.close()
    return {
        "valid": True,
        "license_key": key,
        "status": "active",
        "device_bound": False
    }


@app.post("/admin/create_key")
def create_key(key: str, status: str = "active"):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO licenses (license_key, status, device_id) VALUES (?, ?, NULL)",
            (key, status)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return {"created": False, "reason": "duplicate_key"}

    conn.close()
    return {
        "created": True,
        "license_key": key,
        "status": status
    }
