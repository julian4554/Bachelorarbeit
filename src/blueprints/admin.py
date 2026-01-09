"""
Admin-Blueprint: Administrations-Endpoints.
BSI O.Auth_11: Re-Auth vor Credential-Änderung.
BSI O.Data_3: Nur Admin-Zugriff auf sensible Funktionen.
BSI O.Pass_1: Passwortrichtlinien.
BSI O.Pass_5: Sichere Passwort-Speicherung.
BSI O.Source_1: Input-Validierung.
BSI O.Source_2: Output-Sanitization.
BSI O.Source_3: Audit-Logs ohne sensible Daten.
BSI O.Source_11: Keine sensiblen Daten in Responses.

EXCLUDED: O.Auth_12 - REASON: K4 (sichere Backend-Auth erfordert semantisches Verständnis)
EXCLUDED: O.Auth_14 - REASON: K4 (Session-Invalidierung erfordert semantisches Verständnis)
"""
from flask import Blueprint, request, jsonify, g
from typing import Dict, Any, Tuple

from database import (
    execute_query,
    execute_insert,
    execute_update,
    dict_from_row,
    dicts_from_rows
)
from security.crypto import hash_password
from security.authentication import login_required, require_reauth
from security.authorization import require_role
from security.validation import (
    validate_input,
    UserCreateSchema,
    IdParameterSchema,
    sanitize_output
)
from security.audit import audit_log, audit_data_access
from config import get_config


config = get_config()
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def _minimize_user_response(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reduziert Benutzerdaten auf notwendige Felder.

    BSI O.Source_3: Keine sensiblen Daten in Response.
    BSI O.Source_11: Passwort-Hash nie ausgeben.

    Args:
        user: Vollständige Benutzerdaten

    Returns:
        Minimiertes Benutzer-Dict
    """
    return {
        'id': user['id'],
        'username': sanitize_output(user['username']),
        'email': sanitize_output(user['email']),
        'role': user['role'],
        'is_active': bool(user['is_active']),
        'created_at': user['created_at'],
    }


@admin_bp.route('/users', methods=['GET'])
@login_required
@require_role(['admin'])
def list_users() -> Tuple[Dict[str, Any], int]:
    """
    Listet alle Benutzer.

    BSI O.Data_3: Nur Admin-Zugriff.
    BSI O.Source_3: Minimale Datenrückgabe.

    Query Parameters:
        role: Filter nach Rolle (optional)
        is_active: Filter nach Status (optional)
        limit: Maximale Anzahl
        offset: Pagination-Offset

    Returns:
        JSON mit Benutzerliste
    """
    # BSI O.Source_1: Query-Parameter validieren
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'error': 'Ungültige Pagination-Parameter'}), 400

    role_filter = request.args.get('role')
    if role_filter and role_filter not in ('admin', 'doctor', 'nurse'):
        return jsonify({'error': 'Ungültiger Rollen-Filter'}), 400

    is_active = request.args.get('is_active')
    if is_active is not None:
        if is_active.lower() in ('true', '1'):
            is_active = 1
        elif is_active.lower() in ('false', '0'):
            is_active = 0
        else:
            return jsonify({'error': 'Ungültiger is_active-Filter'}), 400

    # Query bauen
    conditions = []
    params = []

    if role_filter:
        conditions.append('role = ?')
        params.append(role_filter)

    if is_active is not None:
        conditions.append('is_active = ?')
        params.append(is_active)

    where_clause = ' AND '.join(conditions) if conditions else '1=1'

    # BSI O.Source_11: Passwort-Hash nie selektieren
    query = f"""
        SELECT id, username, email, role, is_active, created_at, updated_at
        FROM users
        WHERE {where_clause}
        ORDER BY username
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    rows = execute_query(query, tuple(params))
    users = dicts_from_rows(rows)

    result = [_minimize_user_response(u) for u in users]

    audit_data_access('users', 0, 'list')

    return jsonify({'users': result, 'count': len(result)}), 200


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
@require_role(['admin'])
def get_user(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Gibt einzelnen Benutzer zurück.

    BSI O.Data_3: Nur Admin-Zugriff.
    BSI O.Source_1: ID-Validierung.

    Args:
        user_id: Benutzer-ID

    Returns:
        JSON mit Benutzerdaten
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': user_id})
    if errors:
        return jsonify({'error': 'Ungültige Benutzer-ID'}), 400

    # BSI O.Source_11: Passwort-Hash nie selektieren
    row = execute_query(
        "SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(row)

    if user is None:
        return jsonify({'error': 'Benutzer nicht gefunden'}), 404

    audit_data_access('user', user_id, 'read')

    return jsonify({'user': _minimize_user_response(user)}), 200


@admin_bp.route('/users', methods=['POST'])
@login_required
@require_role(['admin'])
@require_reauth
def create_user() -> Tuple[Dict[str, Any], int]:
    """
    Erstellt neuen Benutzer.

    BSI O.Auth_11: Re-Auth vor Benutzererstellung.
    BSI O.Source_1: Input-Validierung.
    BSI O.Pass_1: Passwortrichtlinien.
    BSI O.Pass_5: Sichere Passwort-Speicherung.

    Request Body:
        username: Benutzername
        password: Passwort (muss Richtlinien entsprechen)
        email: E-Mail-Adresse
        role: Rolle (admin, doctor, nurse)

    Returns:
        JSON mit neuer Benutzer-ID
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1, O.Pass_1: Validierung
    data, errors = validate_input(UserCreateSchema, request.get_json(silent=True) or {})
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    # Prüfe ob Username/Email bereits existiert
    existing = execute_query(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (data['username'], data['email']),
        fetch_one=True
    )
    if existing:
        return jsonify({'error': 'Benutzername oder E-Mail bereits vergeben'}), 409

    # BSI O.Pass_5: Passwort hashen
    password_hash = hash_password(data['password'], config.BCRYPT_ROUNDS)

    user_id = execute_insert(
        """
        INSERT INTO users (username, password_hash, email, role)
        VALUES (?, ?, ?, ?)
        """,
        (data['username'], password_hash, data['email'], data['role'])
    )

    audit_log('user_created', {
        'new_user_id': user_id,
        'role': data['role'],
        'created_by': g.current_user['id']
    })

    return jsonify({
        'message': 'Benutzer erstellt',
        'user_id': user_id
    }), 201


@admin_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
@require_role(['admin'])
@require_reauth
def deactivate_user(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Deaktiviert Benutzer.

    BSI O.Auth_11: Re-Auth vor Deaktivierung.
    EXCLUDED: O.Auth_14 - REASON: K4 (Sessions des Benutzers werden invalidiert)

    Args:
        user_id: Benutzer-ID

    Returns:
        JSON mit Erfolg-Status
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': user_id})
    if errors:
        return jsonify({'error': 'Ungültige Benutzer-ID'}), 400

    # Verhindere Selbst-Deaktivierung
    if user_id == g.current_user['id']:
        return jsonify({'error': 'Selbst-Deaktivierung nicht möglich'}), 400

    # Prüfe ob Benutzer existiert
    existing = execute_query(
        "SELECT id, is_active FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(existing)

    if user is None:
        return jsonify({'error': 'Benutzer nicht gefunden'}), 404

    if not user['is_active']:
        return jsonify({'error': 'Benutzer bereits deaktiviert'}), 400

    rows_updated = execute_update(
        "UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?",
        (user_id,)
    )

    if rows_updated == 0:
        return jsonify({'error': 'Deaktivierung fehlgeschlagen'}), 500

    # EXCLUDED: O.Auth_14 - REASON: K4 (Sessions invalidieren)
    audit_log('user_deactivated', {
        'deactivated_user_id': user_id,
        'deactivated_by': g.current_user['id']
    })

    return jsonify({'message': 'Benutzer deaktiviert'}), 200


@admin_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@login_required
@require_role(['admin'])
@require_reauth
def activate_user(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Aktiviert Benutzer.

    BSI O.Auth_11: Re-Auth vor Aktivierung.

    Args:
        user_id: Benutzer-ID

    Returns:
        JSON mit Erfolg-Status
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': user_id})
    if errors:
        return jsonify({'error': 'Ungültige Benutzer-ID'}), 400

    # Prüfe ob Benutzer existiert
    existing = execute_query(
        "SELECT id, is_active FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(existing)

    if user is None:
        return jsonify({'error': 'Benutzer nicht gefunden'}), 404

    if user['is_active']:
        return jsonify({'error': 'Benutzer bereits aktiv'}), 400

    rows_updated = execute_update(
        "UPDATE users SET is_active = 1, updated_at = datetime('now') WHERE id = ?",
        (user_id,)
    )

    if rows_updated == 0:
        return jsonify({'error': 'Aktivierung fehlgeschlagen'}), 500

    audit_log('user_activated', {
        'activated_user_id': user_id,
        'activated_by': g.current_user['id']
    })

    return jsonify({'message': 'Benutzer aktiviert'}), 200


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@login_required
@require_role(['admin'])
@require_reauth
def change_user_role(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Ändert Benutzerrolle.

    BSI O.Auth_11: Re-Auth vor Rollenänderung.
    EXCLUDED: O.Auth_12 - REASON: K4 (Strenge Rollenvalidierung)

    Args:
        user_id: Benutzer-ID

    Request Body:
        role: Neue Rolle (admin, doctor, nurse)

    Returns:
        JSON mit Erfolg-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: ID-Validierung
    id_data, id_errors = validate_input(IdParameterSchema, {'id': user_id})
    if id_errors:
        return jsonify({'error': 'Ungültige Benutzer-ID'}), 400

    request_data = request.get_json(silent=True) or {}
    new_role = request_data.get('role')

    # BSI O.Source_1: Rollen-Validierung (Whitelist)
    if new_role not in ('admin', 'doctor', 'nurse'):
        return jsonify({'error': 'Ungültige Rolle'}), 400

    # Verhindere Selbst-Degradierung von Admin
    if user_id == g.current_user['id'] and new_role != 'admin':
        return jsonify({'error': 'Eigene Rolle kann nicht geändert werden'}), 400

    # Prüfe ob Benutzer existiert
    existing = execute_query(
        "SELECT id, role FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(existing)

    if user is None:
        return jsonify({'error': 'Benutzer nicht gefunden'}), 404

    if user['role'] == new_role:
        return jsonify({'error': 'Rolle bereits gesetzt'}), 400

    rows_updated = execute_update(
        "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
        (new_role, user_id)
    )

    if rows_updated == 0:
        return jsonify({'error': 'Rollenänderung fehlgeschlagen'}), 500

    audit_log('user_role_changed', {
        'user_id': user_id,
        'old_role': user['role'],
        'new_role': new_role,
        'changed_by': g.current_user['id']
    })

    return jsonify({'message': 'Rolle geändert'}), 200


@admin_bp.route('/audit-logs', methods=['GET'])
@login_required
@require_role(['admin'])
def list_audit_logs() -> Tuple[Dict[str, Any], int]:
    """
    Listet Audit-Logs.

    BSI O.Source_3: Logs ohne sensible Daten.

    Query Parameters:
        event_type: Filter nach Ereignistyp (optional)
        user_id: Filter nach Benutzer (optional)
        date_from: Ab Datum (optional)
        date_to: Bis Datum (optional)
        limit: Maximale Anzahl
        offset: Pagination-Offset

    Returns:
        JSON mit Audit-Log-Liste
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'error': 'Ungültige Pagination-Parameter'}), 400

    conditions = []
    params = []

    event_type = request.args.get('event_type')
    if event_type:
        # BSI O.Source_1: Whitelist für Event-Types
        allowed_events = {
            'login_success', 'login_failed', 'logout',
            'password_change', 'session_end', 'data_access',
            'user_created', 'user_deactivated', 'user_activated',
            'user_role_changed', 'brute_force_lockout'
        }
        if event_type not in allowed_events:
            return jsonify({'error': 'Ungültiger Event-Typ'}), 400
        conditions.append('event_type = ?')
        params.append(event_type)

    filter_user_id = request.args.get('user_id')
    if filter_user_id:
        try:
            filter_user_id = int(filter_user_id)
            conditions.append('user_id = ?')
            params.append(filter_user_id)
        except ValueError:
            return jsonify({'error': 'Ungültige user_id'}), 400

    where_clause = ' AND '.join(conditions) if conditions else '1=1'

    query = f"""
        SELECT id, event_type, user_id, details, ip_hash, created_at
        FROM audit_logs
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    rows = execute_query(query, tuple(params))
    logs = dicts_from_rows(rows)

    # BSI O.Source_2: Output-Sanitization
    for log in logs:
        if log.get('details'):
            log['details'] = sanitize_output(str(log['details']))

    return jsonify({'audit_logs': logs, 'count': len(logs)}), 200


@admin_bp.route('/stats', methods=['GET'])
@login_required
@require_role(['admin'])
def get_stats() -> Tuple[Dict[str, Any], int]:
    """
    Gibt Systemstatistiken zurück.

    BSI O.Data_3: Nur Admin-Zugriff auf Statistiken.

    Returns:
        JSON mit Systemstatistiken
    """
    # Benutzerstatistiken
    user_stats = execute_query(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins,
            SUM(CASE WHEN role = 'doctor' THEN 1 ELSE 0 END) as doctors,
            SUM(CASE WHEN role = 'nurse' THEN 1 ELSE 0 END) as nurses
        FROM users
        """,
        fetch_one=True
    )

    # Patientenstatistiken
    patient_count = execute_query(
        "SELECT COUNT(*) as count FROM patients",
        fetch_one=True
    )

    # Terminstatistiken
    appointment_stats = execute_query(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'scheduled' THEN 1 ELSE 0 END) as scheduled,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled
        FROM appointments
        """,
        fetch_one=True
    )

    audit_data_access('stats', 0, 'read')

    return jsonify({
        'users': dict(user_stats) if user_stats else {},
        'patients': {'total': patient_count['count'] if patient_count else 0},
        'appointments': dict(appointment_stats) if appointment_stats else {}
    }), 200


