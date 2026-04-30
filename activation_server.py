from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import time
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel


DB_PATH = Path("activation.db")
KEYS_PATH = Path("keys_for_distribution.txt")

APP_NAME = "malinovka"

# ВАЖНО: поменяй на свой секрет.
# Этот же секрет потом надо вставить в программу.
SECRET_KEY = "167f7202d3c4de2ee1b4268517afcd7da7a77ff1724ae2dd7ca545254126ba9f"

app = FastAPI()


class ActivateRequest(BaseModel):
    code: str
    machine_id: str
    app: str


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activation_codes (
                code TEXT PRIMARY KEY,
                app TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                used_at INTEGER NULL,
                machine_id TEXT NULL
            )
            """
        )


def import_keys() -> None:
    init_db()

    if not KEYS_PATH.exists():
        print(f"Файл с ключами не найден: {KEYS_PATH}")
        return

    lines = KEYS_PATH.read_text(encoding="utf-8").splitlines()

    keys = []
    for line in lines:
        code = line.strip()
        if code:
            keys.append(code)

    added = 0
    skipped = 0

    with db() as conn:
        for code in keys:
            try:
                conn.execute(
                    """
                    INSERT INTO activation_codes (code, app, used)
                    VALUES (?, ?, 0)
                    """,
                    (code, APP_NAME),
                )
                added += 1
            except sqlite3.IntegrityError:
                skipped += 1

    print("Импорт готов.")
    print(f"Ключей в файле: {len(keys)}")
    print(f"Добавлено новых: {added}")
    print(f"Пропущено дублей: {skipped}")


def print_stats() -> None:
    init_db()

    with db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM activation_codes"
        ).fetchone()[0]

        unused = conn.execute(
            "SELECT COUNT(*) FROM activation_codes WHERE used = 0"
        ).fetchone()[0]

        used = conn.execute(
            "SELECT COUNT(*) FROM activation_codes WHERE used = 1"
        ).fetchone()[0]

    print(f"Всего ключей: {total}")
    print(f"Свободных ключей: {unused}")
    print(f"Использованных ключей: {used}")


def create_random_code() -> None:
    init_db()

    code = secrets.token_urlsafe(64)

    with db() as conn:
        conn.execute(
            """
            INSERT INTO activation_codes (code, app, used)
            VALUES (?, ?, 0)
            """,
            (code, APP_NAME),
        )

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
        "message": "Malinovka activation server is running",
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
        row = conn.execute(
            """
            SELECT *
            FROM activation_codes
            WHERE code = ? AND app = ?
            """,
            (code, APP_NAME),
        ).fetchone()

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

        conn.execute(
            """
            UPDATE activation_codes
            SET used = 1, used_at = ?, machine_id = ?
            WHERE code = ? AND app = ?
            """,
            (int(time.time()), machine_id, code, APP_NAME),
        )

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
        import_keys()
    elif command == "stats":
        print_stats()
    elif command == "create":
        create_random_code()
    else:
        print_help()