"""
Datenbankinitialisierung und -zugriff.
BSI O.Source_10: Parameterisierte Queries, keine String-Konkatenation.

EXCLUDED: O.Arch_5 - REASON: K4 (sichere Nutzung erfordert semantisches Verständnis)
"""
import sqlite3
from typing import Optional, Any, Dict, List
from flask import g
from contextlib import contextmanager

from config import get_config


config = get_config()


# === Datenbank-Schema ===
# BSI O.Data_1: Sichere Defaults in Schema-Definition

SCHEMA = """
-- Benutzer-Tabelle
-- BSI O.Pass_5: Passwort als Hash gespeichert
-- EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Existenz nicht SAST-detektierbar)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_password_change TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Patienten-Tabelle
-- BSI O.Data_3: Ownership-Beziehungen für Zugriffskontrolle
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mrn TEXT NOT NULL UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    assigned_to INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

-- Diagnosen-Tabelle
-- BSI O.Source_3: Sensible medizinische Daten - nur für berechtigte Nutzer
CREATE TABLE IF NOT EXISTS diagnoses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    icd_code TEXT NOT NULL,
    description TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Termine-Tabelle
-- BSI O.Data_3: Ownership durch doctor_id und assigned_nurse
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    assigned_nurse INTEGER,
    scheduled_at TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 30,
    appointment_type TEXT NOT NULL CHECK (
        appointment_type IN ('consultation', 'followup', 'emergency', 'procedure')
    ),
    status TEXT NOT NULL DEFAULT 'scheduled' CHECK (
        status IN ('scheduled', 'completed', 'cancelled')
    ),
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES users(id),
    FOREIGN KEY (assigned_nurse) REFERENCES users(id)
);

-- Audit-Log-Tabelle (für persistentes Logging)
-- BSI O.Pass_4: Persistente Protokollierung
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    details TEXT,
    ip_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Consent-Tabelle (Einwilligungserklärungen)
-- EXCLUDED: O.Purp_3 - REASON: K2 (prozessuale/organisatorische Anforderung)
-- EXCLUDED: O.Purp_4 - REASON: K2 (prozessuale/organisatorische Anforderung)
CREATE TABLE IF NOT EXISTS consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    consent_type TEXT NOT NULL CHECK (
        consent_type IN ('data_processing', 'medical_data', 'data_sharing', 'analytics')
    ),
    granted INTEGER NOT NULL DEFAULT 0,
    granted_at TEXT,
    revoked_at TEXT,
    ip_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, consent_type)
);

-- Export-Log-Tabelle
-- EXCLUDED: O.Data_2 - REASON: K4 (Warnungsangemessenheit erfordert semantisches Verständnis)
CREATE TABLE IF NOT EXISTS export_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    export_type TEXT NOT NULL CHECK (
        export_type IN ('patient_data', 'appointments', 'audit_logs', 'reports')
    ),
    encrypted INTEGER NOT NULL DEFAULT 0,
    warning_acknowledged INTEGER NOT NULL DEFAULT 0,
    file_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- EXCLUDED: O.Data_15 - REASON: K4 (vollständige Löschung erfordert semantisches Verständnis)
-- Patient Notes mit CASCADE-Delete für Datenintegrität
CREATE TABLE IF NOT EXISTS patient_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Indizes für Performance
CREATE INDEX IF NOT EXISTS idx_patients_created_by ON patients(created_by);
CREATE INDEX IF NOT EXISTS idx_patients_assigned_to ON patients(assigned_to);
CREATE INDEX IF NOT EXISTS idx_appointments_patient_id ON appointments(patient_id);
CREATE INDEX IF NOT EXISTS idx_appointments_doctor_id ON appointments(doctor_id);
CREATE INDEX IF NOT EXISTS idx_appointments_scheduled_at ON appointments(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
"""


def get_db_connection() -> sqlite3.Connection:
    """
    Gibt Datenbankverbindung zurück (eine pro Request).

    BSI O.Source_10: Sichere Verbindungshandhabung.

    Returns:
        SQLite-Connection mit Row-Factory
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            config.DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # Row-Factory für Dict-ähnlichen Zugriff
        g.db.row_factory = sqlite3.Row
        # Foreign Keys aktivieren
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db_connection(exception: Optional[Exception] = None) -> None:
    """
    Schließt Datenbankverbindung am Request-Ende.

    Args:
        exception: Eventuell aufgetretene Exception
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db() -> None:
    """
    Initialisiert Datenbankschema.

    BSI O.Data_1: Sichere Werkseinstellungen durch Schema-Constraints.
    """
    conn = sqlite3.connect(config.DATABASE_PATH)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# === Sichere Query-Funktionen ===
# BSI O.Source_10: Keine SQL-String-Konkatenation

def execute_query(
    query: str,
    params: tuple = (),
    fetch_one: bool = False
) -> Optional[Any]:
    """
    Führt parametrisierte Query aus.

    BSI O.Source_10: Ausschließlich Parameterisierung, keine Konkatenation.

    Args:
        query: SQL-Query mit Platzhaltern (?)
        params: Parameter-Tupel
        fetch_one: Wenn True, nur einen Datensatz zurückgeben

    Returns:
        Query-Ergebnis oder None
    """
    db = get_db_connection()
    cursor = db.execute(query, params)

    if fetch_one:
        return cursor.fetchone()
    return cursor.fetchall()


def execute_insert(query: str, params: tuple = ()) -> int:
    """
    Führt INSERT aus und gibt neue ID zurück.

    BSI O.Source_10: Sichere parameterisierte Einfügung.

    Args:
        query: INSERT-Query mit Platzhaltern
        params: Parameter-Tupel

    Returns:
        ID des neuen Datensatzes
    """
    db = get_db_connection()
    cursor = db.execute(query, params)
    db.commit()
    return cursor.lastrowid


def execute_update(query: str, params: tuple = ()) -> int:
    """
    Führt UPDATE aus und gibt Anzahl geänderter Zeilen zurück.

    BSI O.Source_10: Sichere parameterisierte Aktualisierung.

    Args:
        query: UPDATE-Query mit Platzhaltern
        params: Parameter-Tupel

    Returns:
        Anzahl geänderter Zeilen
    """
    db = get_db_connection()
    cursor = db.execute(query, params)
    db.commit()
    return cursor.rowcount


def execute_delete(query: str, params: tuple = ()) -> int:
    """
    Führt DELETE aus und gibt Anzahl gelöschter Zeilen zurück.

    BSI O.Source_10: Sichere parameterisierte Löschung.

    Args:
        query: DELETE-Query mit Platzhaltern
        params: Parameter-Tupel

    Returns:
        Anzahl gelöschter Zeilen
    """
    db = get_db_connection()
    cursor = db.execute(query, params)
    db.commit()
    return cursor.rowcount


def dict_from_row(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    """
    Konvertiert SQLite-Row zu Dictionary.

    BSI O.Data_3: Kontrollierte Datenextraktion.

    Args:
        row: SQLite-Row-Objekt

    Returns:
        Dictionary oder None
    """
    if row is None:
        return None
    return dict(row)


def dicts_from_rows(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    """
    Konvertiert Liste von SQLite-Rows zu Dictionaries.

    Args:
        rows: Liste von Row-Objekten

    Returns:
        Liste von Dictionaries
    """
    return [dict(row) for row in rows]
