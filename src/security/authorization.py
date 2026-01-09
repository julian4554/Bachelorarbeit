"""
Autorisierung: Rollenbasierte Zugriffskontrolle und Ownership-Prüfungen.
BSI O.Data_3: Keine Ressourcen-Exposition.
BSI O.Source_4: Kontrollierte Fehlerbehandlung.
BSI O.Source_10: Parameterisierte Queries.

EXCLUDED: O.Auth_12 - REASON: K4 (sichere Backend-Authentifizierung erfordert semantisches Verständnis)
"""
from functools import wraps
from typing import Callable, List, Optional, Any
from flask import g, jsonify, request
import sqlite3

from security.audit import audit_log


# Rollenhierarchie: Definiert, welche Rollen auf welche Ressourcen zugreifen dürfen
ROLE_HIERARCHY = {
    'admin': ['admin', 'doctor', 'nurse'],  # Admin kann alles
    'doctor': ['doctor', 'nurse'],           # Doctor kann eigene und Nurse-Aktionen
    'nurse': ['nurse']                       # Nurse nur eigene Aktionen
}

# Ressourcen-Berechtigungen pro Rolle
ROLE_PERMISSIONS = {
    'admin': {
        'users': ['create', 'read', 'update', 'delete'],
        'patients': ['create', 'read', 'update', 'delete'],
        'appointments': ['create', 'read', 'update', 'delete'],
        'audit_logs': ['read'],
    },
    'doctor': {
        'patients': ['create', 'read', 'update'],
        'appointments': ['create', 'read', 'update'],
        'diagnosis': ['create', 'read', 'update'],
    },
    'nurse': {
        'patients': ['read'],
        'appointments': ['read', 'update'],
    }
}


def require_role(allowed_roles: List[str]) -> Callable:
    """
    Decorator für rollenbasierte Zugriffskontrolle.

    EXCLUDED: O.Auth_12 - REASON: K4 (Rollenprüfung im Backend)
    BSI O.Data_3: Zugriffsverweigerung ohne Informationsleck.

    Args:
        allowed_roles: Liste erlaubter Rollen

    Returns:
        Decorator-Funktion
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            # Prüfe ob User authentifiziert
            if not hasattr(g, 'current_user') or g.current_user is None:
                # BSI O.Source_4: Generische Fehlermeldung
                audit_log('authorization_failed', {'reason': 'not_authenticated', 'endpoint': request.endpoint})
                return jsonify({'error': 'Authentifizierung erforderlich'}), 401

            user_role = g.current_user.get('role')
            if user_role is None:
                audit_log('authorization_failed', {'reason': 'no_role', 'user_id': g.current_user.get('id')})
                return jsonify({'error': 'Keine Berechtigung'}), 403

            # Prüfe ob Benutzerrolle in erlaubten Rollen
            if user_role not in allowed_roles:
                # BSI O.Data_3: Keine Details über fehlende Berechtigung
                audit_log('authorization_failed', {
                    'reason': 'insufficient_role',
                    'user_id': g.current_user.get('id'),
                    'required_roles': allowed_roles,
                    'user_role': user_role
                })
                return jsonify({'error': 'Keine Berechtigung'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_permission(role: str, resource: str, action: str) -> bool:
    """
    Prüft ob eine Rolle eine Aktion auf einer Ressource ausführen darf.

    EXCLUDED: O.Auth_12 - REASON: K4 (Feinkörnige Berechtigungsprüfung)

    Args:
        role: Benutzerrolle
        resource: Ressourcenname (z.B. 'patients')
        action: Aktion (z.B. 'read', 'create')

    Returns:
        True wenn erlaubt, sonst False
    """
    if role not in ROLE_PERMISSIONS:
        return False

    role_perms = ROLE_PERMISSIONS.get(role, {})
    resource_perms = role_perms.get(resource, [])
    return action in resource_perms


def check_record_ownership(
    db_connection: sqlite3.Connection,
    table: str,
    record_id: int,
    user_id: int,
    ownership_column: str = 'created_by'
) -> bool:
    """
    Prüft ob ein Benutzer Eigentümer eines Datensatzes ist.

    BSI O.Data_3: Record-Level-Zugriffskontrolle.

    Args:
        db_connection: Datenbankverbindung
        table: Tabellenname (Whitelist-geprüft)
        record_id: ID des Datensatzes
        user_id: ID des Benutzers
        ownership_column: Spaltenname für Eigentümer

    Returns:
        True wenn Eigentümer, sonst False
    """
    # BSI O.Source_10: Whitelist für Tabellennamen (SQL-Injection-Schutz)
    allowed_tables = {'patients', 'appointments', 'diagnoses'}
    if table not in allowed_tables:
        audit_log('ownership_check_failed', {'reason': 'invalid_table', 'table': table})
        return False

    allowed_columns = {'created_by', 'assigned_to', 'doctor_id'}
    if ownership_column not in allowed_columns:
        audit_log('ownership_check_failed', {'reason': 'invalid_column', 'column': ownership_column})
        return False

    # BSI O.Source_10: Parameterisierte Query
    query = f"SELECT 1 FROM {table} WHERE id = ? AND {ownership_column} = ? LIMIT 1"

    try:
        cursor = db_connection.execute(query, (record_id, user_id))
        result = cursor.fetchone()
        return result is not None
    except sqlite3.Error:
        # BSI O.Source_4: Fehler ohne Details
        audit_log('ownership_check_failed', {'reason': 'db_error', 'table': table, 'record_id': record_id})
        return False


def check_patient_access(
    db_connection: sqlite3.Connection,
    patient_id: int,
    user_id: int,
    user_role: str
) -> bool:
    """
    Prüft Zugriffsberechtigung auf Patientendaten.

    BSI O.Data_3: Strikte Patientendaten-Zugriffskontrolle.

    Args:
        db_connection: Datenbankverbindung
        patient_id: Patienten-ID
        user_id: Benutzer-ID
        user_role: Benutzerrolle

    Returns:
        True wenn Zugriff erlaubt, sonst False
    """
    # Admin hat Vollzugriff
    if user_role == 'admin':
        return True

    # Doctor: Zugriff auf eigene Patienten oder zugewiesene
    if user_role == 'doctor':
        query = """
            SELECT 1 FROM patients
            WHERE id = ? AND (created_by = ? OR assigned_to = ?)
            LIMIT 1
        """
        cursor = db_connection.execute(query, (patient_id, user_id, user_id))
        return cursor.fetchone() is not None

    # Nurse: Nur Lesezugriff auf Patienten mit aktiven Terminen
    if user_role == 'nurse':
        query = """
            SELECT 1 FROM appointments a
            WHERE a.patient_id = ?
            AND a.assigned_nurse = ?
            AND a.status = 'scheduled'
            LIMIT 1
        """
        cursor = db_connection.execute(query, (patient_id, user_id))
        return cursor.fetchone() is not None

    return False


def require_patient_access(f: Callable) -> Callable:
    """
    Decorator für Patientendaten-Zugriffskontrolle.

    BSI O.Data_3: Automatische Ownership-Prüfung für Patienten-Endpoints.

    Erwartet 'patient_id' in kwargs oder request JSON.
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        from database import get_db_connection

        if not hasattr(g, 'current_user') or g.current_user is None:
            return jsonify({'error': 'Authentifizierung erforderlich'}), 401

        # Patient-ID aus URL oder Request-Body
        patient_id = kwargs.get('patient_id')
        if patient_id is None and request.is_json:
            patient_id = request.get_json(silent=True, force=False)
            if patient_id:
                patient_id = patient_id.get('patient_id')

        if patient_id is None:
            return jsonify({'error': 'Patient-ID erforderlich'}), 400

        try:
            patient_id = int(patient_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'Ungültige Patient-ID'}), 400

        db = get_db_connection()
        user_id = g.current_user['id']
        user_role = g.current_user['role']

        if not check_patient_access(db, patient_id, user_id, user_role):
            audit_log('patient_access_denied', {
                'user_id': user_id,
                'patient_id': patient_id,
                'endpoint': request.endpoint
            })
            # BSI O.Data_3: Generische Fehlermeldung
            return jsonify({'error': 'Keine Berechtigung'}), 403

        return f(*args, **kwargs)
    return decorated_function
