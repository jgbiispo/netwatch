"""
collector/history.py
~~~~~~~~~~~~~~~~~~~~
Módulo de persistência de histórico de scans via SQLite.
Banco salvo em ~/.netwatch/history.db
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path.home() / ".netwatch" / "history.db"


# ---------------------------------------------------------------------------
# Conexão e inicialização
# ---------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    """Abre (ou cria) a conexão com o banco."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # melhor concorrência
    return conn


def init_db() -> None:
    """Cria as tabelas se ainda não existirem."""
    with _get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                network      TEXT,
                scan_type    TEXT    DEFAULT 'normal',
                device_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_devices (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ip      TEXT NOT NULL,
                mac     TEXT NOT NULL,
                vendor  TEXT,
                source  TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scan_devices_scan_id
                ON scan_devices(scan_id);

            CREATE TABLE IF NOT EXISTS known_devices (
                mac        TEXT PRIMARY KEY,
                ip         TEXT,
                vendor     TEXT,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_known_devices_last_seen
                ON known_devices(last_seen DESC);
        """)


# ---------------------------------------------------------------------------
# Escrita
# ---------------------------------------------------------------------------

def save_scan(devices: list, network: str, scan_type: str = "normal") -> int:
    """
    Persiste um scan completo.
    Atualiza a tabela known_devices com a última visão de cada dispositivo.
    Retorna o ID do scan inserido.
    """
    init_db()
    now = datetime.now(timezone.utc).isoformat()

    with _get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, network, scan_type, device_count) VALUES (?, ?, ?, ?)",
            (now, network, scan_type, len(devices)),
        )
        scan_id = cur.lastrowid

        for device in devices:
            mac = device["mac"].lower()
            ip = device["ip"]
            vendor = device.get("vendor", "Desconhecido")
            source = device.get("source", "scan")

            conn.execute(
                """INSERT INTO scan_devices (scan_id, ip, mac, vendor, source)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, ip, mac, vendor, source),
            )

            existing = conn.execute(
                "SELECT mac FROM known_devices WHERE mac = ?", (mac,)
            ).fetchone()

            if existing:
                conn.execute(
                    """UPDATE known_devices
                       SET ip = ?, vendor = ?, last_seen = ?, times_seen = times_seen + 1
                       WHERE mac = ?""",
                    (ip, vendor, now, mac),
                )
            else:
                conn.execute(
                    """INSERT INTO known_devices (mac, ip, vendor, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?)""",
                    (mac, ip, vendor, now, now),
                )

    return scan_id


# ---------------------------------------------------------------------------
# Leitura
# ---------------------------------------------------------------------------

def get_last_scan() -> tuple[dict | None, list]:
    """Retorna (scan_info, devices) do scan mais recente, ou (None, [])."""
    init_db()
    with _get_connection() as conn:
        scan = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not scan:
            return None, []
        devices = conn.execute(
            "SELECT * FROM scan_devices WHERE scan_id = ?", (scan["id"],)
        ).fetchall()
        return dict(scan), [dict(d) for d in devices]


def get_scan_history(limit: int = 20) -> list:
    """Retorna lista dos últimos N scans (mais recente primeiro)."""
    init_db()
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_devices(scan_id: int) -> list:
    """Retorna os dispositivos de um scan específico pelo ID."""
    init_db()
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_devices WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_known_devices(limit: int = 500) -> list:
    """Retorna todos os dispositivos já vistos, ordenados por última vez visto."""
    init_db()
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM known_devices ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Comparação / Diff
# ---------------------------------------------------------------------------

def diff_with_last_scan(current_devices: list) -> dict:
    """
    Compara os devices atuais com o último scan salvo.

    Retorna dict com três listas:
      - new      : devices que não existiam no último scan (detectados pelo MAC)
      - missing  : devices do último scan que não aparecem agora
      - changed  : devices cujo IP mudou desde o último scan
    """
    _, last_devices = get_last_scan()
    if not last_devices:
        return {"new": [], "missing": [], "changed": []}

    last_by_mac = {d["mac"].lower(): d for d in last_devices}
    current_by_mac = {d["mac"].lower(): d for d in current_devices}

    new = [
        d for mac, d in current_by_mac.items()
        if mac not in last_by_mac
    ]
    missing = [
        d for mac, d in last_by_mac.items()
        if mac not in current_by_mac
    ]
    changed = [
        {"device": current_by_mac[mac], "old_ip": last_by_mac[mac]["ip"]}
        for mac in current_by_mac
        if mac in last_by_mac
        and current_by_mac[mac]["ip"] != last_by_mac[mac]["ip"]
    ]

    return {"new": new, "missing": missing, "changed": changed}
