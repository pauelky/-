from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header
from pydantic import BaseModel


KEYS_PATH = Path("keys_for_distribution.txt")

APP_NAME = "malinovka"

DATABASE_URL = os.environ.get("DATABASE_URL", "")

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "167f7202d3c4de2ee1b4268517afcd7da7a77ff1724ae2dd7ca545254126ba9f",
)

ADMIN_KEY = os.environ.get(
    "ADMIN_KEY",
    "b2cff99483b2a9ee076091e74d83d9f072f6d374e1fd577b11d288e3c0a86db5",
)

app = FastAPI()


class ActivateRequest(BaseModel):
    code: str
    machine_id: str
    app: str


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )


def init_db() -> None:
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS activation_codes (
                    code TEXT PRIMARY KEY,
                    app TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    used_at BIGINT NULL,
                    machine_id TEXT NULL
                )
                """
            )
            conn.commit()


def import_keys() -> dict:
    init_db()

    if not KEYS_PATH.exists():
        return {
            "ok": False,
            "error": f"Файл с ключами не найден: {KEYS_PATH}",
            "total_in_file": 0,
            "added": 0,
            "skipped": 0,
        }

    lines = KEYS_PATH.read_text(encoding="utf-8").splitlines()

    keys = []
    for line in lines:
        code = line.strip()
        if code:
            keys.append(code)

    added = 0
    skipped = 0

    with db() as conn:
        with conn.cursor() as cur:
            for code in keys:
                cur.execute(
                    """
                    INSERT INTO activation_codes (code, app, used)
                    VALUES (%s, %s, 0)
                    ON CONFLICT (code) DO NOTHING
                    """,
                    (code, APP_NAME),
                )

                if cur.rowcount == 1:
                    added += 1
                else:
                    skipped += 1

            conn.commit()

    return {
        "ok": True,
        "total_in_file": len(keys),
        "added": added,
        "skipped": skipped,
    }


def print_stats() -> None:
    init_db()

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS count FROM activation_codes")
            total = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) AS count FROM activation_codes WHERE used = 0")
            unused = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) AS count FROM activation_codes WHERE used = 1")
            used = cur.fetchone()["count"]

    print(f"Всего ключей: {total}")
    print(f"Свободных ключей: {unused}")
    print(f"Использованных ключей: {used}")


def create_random_code() -> None:
    init_db()

    code = secrets.token_urlsafe(64)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO activation_codes (code, app, used)
                VALUES (%s, %s, 0)
                ON CONFLICT (code) DO NOTHING
                """,
                (code, APP_NAME),
            )
            conn.commit()

    print("Создан новый ключ:")
    print(code)


def create_license_token(machine_id: str, code: str) -> str:
    payload = {
        "app": APP_NAME,
        "machine_id": machine_id,
        "code": code,
        "issued_at": int(time.time()),
    }

    payload_json = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    payload_b64 = base64.urlsafe_b64encode(
        payload_json.encode("utf-8")
    ).decode("ascii")

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{payload_b64}.{signature}"


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def index():
    return {
        "ok": True,
        "app": APP_NAME,
        "database": "postgresql",
        "message": "Malinovka activation server is running",
    }


@app.post("/admin/import-keys")
def admin_import_keys(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        return {"ok": False, "error": "Forbidden"}

    return import_keys()


@app.get("/admin/stats")
def admin_stats(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        return {"ok": False, "error": "Forbidden"}

    init_db()

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS count FROM activation_codes")
            total = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) AS count FROM activation_codes WHERE used = 0")
            unused = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) AS count FROM activation_codes WHERE used = 1")
            used = cur.fetchone()["count"]

    return {
        "ok": True,
        "total": total,
        "unused": unused,
        "used": used,
    }


@app.post("/activate")
def activate(req: ActivateRequest):
    init_db()

    code = req.code.strip()
    machine_id = req.machine_id.strip()

    if req.app != APP_NAME:
        return {
            "ok": False,
            "error": "Неверное приложение",
        }

    if not code:
        return {
            "ok": False,
            "error": "Введите ключ активации",
        }

    if not machine_id:
        return {
            "ok": False,
            "error": "Не удалось определить устройство",
        }

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM activation_codes
                WHERE code = %s AND app = %s
                """,
                (code, APP_NAME),
            )
            row = cur.fetchone()

            if row is None:
                return {
                    "ok": False,
                    "error": "Неверный ключ",
                }

            if row["used"]:
                return {
                    "ok": False,
                    "error": "Ключ уже использован",
                }

            cur.execute(
                """
                UPDATE activation_codes
                SET used = 1, used_at = %s, machine_id = %s
                WHERE code = %s AND app = %s
                """,
                (int(time.time()), machine_id, code, APP_NAME),
            )
            conn.commit()

    license_token = create_license_token(machine_id, code)

    return {
        "ok": True,
        "license": license_token,
    }


def print_help() -> None:
    print("Команды:")
    print("  python activation_server.py import   - импортировать ключи из keys_for_distribution.txt")
    print("  python activation_server.py stats    - показать статистику ключей")
    print("  python activation_server.py create   - создать один новый ключ")
    print("")
    print("Запуск сервера:")
    print("  uvicorn activation_server:app --host 127.0.0.1 --port 8000")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        raise SystemExit(0)

    command = sys.argv[1].lower().strip()

    if command == "import":
        result = import_keys()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif command == "stats":
        print_stats()
    elif command == "create":
        create_random_code()
    else:
        print_help()
