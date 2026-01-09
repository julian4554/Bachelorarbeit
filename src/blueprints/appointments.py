"""
Appointments-Blueprint: Terminverwaltungs-Endpoints.
BSI O.Data_3: Rollenbasierte Zugriffskontrolle.
BSI O.Source_1: Input-Validierung.
BSI O.Source_10: Parameterisierte Queries.
"""
from flask import Blueprint, request, jsonify, g
from typing import Dict, Any, Tuple
from datetime import datetime

from database import (
    execute_query,
    execute_insert,
    execute_update,
    execute_delete,
    dict_from_row,
    dicts_from_rows
)
from security.authentication import login_required
from security.authorization import require_role, check_patient_access
from security.validation import (
    validate_input,
    AppointmentCreateSchema,
    AppointmentUpdateSchema,
    IdParameterSchema,
    sanitize_output
)
from security.audit import audit_log, audit_data_access


appointments_bp = Blueprint('appointments', __name__, url_prefix='/api/appointments')


def _check_appointment_access(appointment: Dict[str, Any], user_id: int, user_role: str) -> bool:
    """
    Prüft Zugriff auf einen Termin.

    BSI O.Data_3: Ownership-basierte Zugriffskontrolle.

    Args:
        appointment: Termin-Daten
        user_id: Benutzer-ID
        user_role: Benutzerrolle

    Returns:
        True wenn Zugriff erlaubt
    """
    if user_role == 'admin':
        return True

    if user_role == 'doctor':
        return appointment['doctor_id'] == user_id

    if user_role == 'nurse':
        return appointment.get('assigned_nurse') == user_id

    return False


def _minimize_appointment_response(
    appointment: Dict[str, Any],
    include_notes: bool = False
) -> Dict[str, Any]:
    """
    Reduziert Termindaten auf notwendige Felder.

    BSI O.Source_3: Datenminimierung.

    Args:
        appointment: Vollständige Termindaten
        include_notes: Ob Notizen inkludiert werden sollen

    Returns:
        Minimiertes Termin-Dict
    """
    minimized = {
        'id': appointment['id'],
        'patient_id': appointment['patient_id'],
        'scheduled_at': appointment['scheduled_at'],
        'duration_minutes': appointment['duration_minutes'],
        'appointment_type': sanitize_output(appointment['appointment_type']),
        'status': sanitize_output(appointment['status']),
    }

    # Notizen nur für Ärzte/Admins
    if include_notes and appointment.get('notes'):
        minimized['notes'] = sanitize_output(appointment['notes'])

    return minimized


@appointments_bp.route('', methods=['GET'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def list_appointments() -> Tuple[Dict[str, Any], int]:
    """
    Listet Termine basierend auf Benutzerrolle.

    BSI O.Data_3: Rollenbasierte Filterung.

    Query Parameters:
        status: Filter nach Status (optional)
        date_from: Ab Datum (YYYY-MM-DD, optional)
        date_to: Bis Datum (YYYY-MM-DD, optional)
        limit: Maximale Anzahl (default 50, max 100)
        offset: Offset für Pagination

    Returns:
        JSON mit Terminliste
    """
    user = g.current_user
    user_id = user['id']
    user_role = user['role']

    # BSI O.Source_1: Query-Parameter validieren
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'error': 'Ungültige Pagination-Parameter'}), 400

    # Optionale Filter
    status_filter = request.args.get('status')
    if status_filter and status_filter not in ('scheduled', 'completed', 'cancelled'):
        return jsonify({'error': 'Ungültiger Status-Filter'}), 400

    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    # BSI O.Source_1: Datumsvalidierung
    if date_from:
        try:
            datetime.strptime(date_from, '%Y-%m-%d')
        except ValueError:
            return jsonify({'error': 'Ungültiges date_from Format (YYYY-MM-DD)'}), 400

    if date_to:
        try:
            datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            return jsonify({'error': 'Ungültiges date_to Format (YYYY-MM-DD)'}), 400

    # Basis-Query bauen
    conditions = []
    params = []

    # BSI O.Data_3: Rollenbasierte Filterung
    if user_role == 'doctor':
        conditions.append('a.doctor_id = ?')
        params.append(user_id)
    elif user_role == 'nurse':
        conditions.append('a.assigned_nurse = ?')
        params.append(user_id)
    # Admin sieht alle

    if status_filter:
        conditions.append('a.status = ?')
        params.append(status_filter)

    if date_from:
        conditions.append('date(a.scheduled_at) >= ?')
        params.append(date_from)

    if date_to:
        conditions.append('date(a.scheduled_at) <= ?')
        params.append(date_to)

    where_clause = ' AND '.join(conditions) if conditions else '1=1'

    query = f"""
        SELECT a.*, p.mrn, p.first_name, p.last_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        WHERE {where_clause}
        ORDER BY a.scheduled_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    rows = execute_query(query, tuple(params))
    appointments = dicts_from_rows(rows)

    # BSI O.Source_3: Datenminimierung
    include_notes = user_role in ('admin', 'doctor')
    result = []
    for apt in appointments:
        minimized = _minimize_appointment_response(apt, include_notes)
        # Patienten-Info hinzufügen (minimal)
        minimized['patient'] = {
            'mrn': sanitize_output(apt['mrn']),
            'name': f"{sanitize_output(apt['first_name'])} {sanitize_output(apt['last_name'])}"
        }
        result.append(minimized)

    audit_data_access('appointments', 0, 'list')

    return jsonify({'appointments': result, 'count': len(result)}), 200


@appointments_bp.route('/<int:appointment_id>', methods=['GET'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def get_appointment(appointment_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Gibt einzelnen Termin zurück.

    BSI O.Data_3: Ownership-Prüfung.
    BSI O.Source_1: ID-Validierung.

    Args:
        appointment_id: Termin-ID

    Returns:
        JSON mit Termindaten
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': appointment_id})
    if errors:
        return jsonify({'error': 'Ungültige Termin-ID'}), 400

    user = g.current_user

    row = execute_query(
        """
        SELECT a.*, p.mrn, p.first_name, p.last_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        WHERE a.id = ?
        """,
        (appointment_id,),
        fetch_one=True
    )
    appointment = dict_from_row(row)

    if appointment is None:
        return jsonify({'error': 'Termin nicht gefunden'}), 404

    # BSI O.Data_3: Zugriffsprüfung
    if not _check_appointment_access(appointment, user['id'], user['role']):
        audit_log('appointment_access_denied', {
            'user_id': user['id'],
            'appointment_id': appointment_id
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    audit_data_access('appointment', appointment_id, 'read')

    include_notes = user['role'] in ('admin', 'doctor')
    result = _minimize_appointment_response(appointment, include_notes)
    result['patient'] = {
        'id': appointment['patient_id'],
        'mrn': sanitize_output(appointment['mrn']),
        'name': f"{sanitize_output(appointment['first_name'])} {sanitize_output(appointment['last_name'])}"
    }

    return jsonify({'appointment': result}), 200


@appointments_bp.route('', methods=['POST'])
@login_required
@require_role(['admin', 'doctor'])
def create_appointment() -> Tuple[Dict[str, Any], int]:
    """
    Erstellt neuen Termin.

    BSI O.Source_1: Input-Validierung.
    BSI O.Data_3: Patient-Zugriffsprüfung.
    BSI O.Source_10: Parameterisierte Query.

    Request Body:
        patient_id: Patienten-ID
        scheduled_at: Datum/Zeit (ISO-Format)
        duration_minutes: Dauer in Minuten
        appointment_type: Terminart
        notes: Notizen (optional)

    Returns:
        JSON mit Termin-ID
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: Validierung
    data, errors = validate_input(AppointmentCreateSchema, request.get_json(silent=True) or {})
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Patient-Zugriffsprüfung
    if not check_patient_access(db, data['patient_id'], user['id'], user['role']):
        return jsonify({'error': 'Keine Berechtigung für diesen Patienten'}), 403

    # Prüfe ob Patient existiert
    patient = execute_query(
        "SELECT id FROM patients WHERE id = ?",
        (data['patient_id'],),
        fetch_one=True
    )
    if not patient:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    # BSI O.Source_10: Parameterisierte Einfügung
    appointment_id = execute_insert(
        """
        INSERT INTO appointments (
            patient_id, doctor_id, scheduled_at, duration_minutes,
            appointment_type, notes
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            data['patient_id'],
            user['id'],  # Ersteller ist der Arzt
            data['scheduled_at'].isoformat(),
            data['duration_minutes'],
            data['appointment_type'],
            data.get('notes', '')
        )
    )

    audit_data_access('appointment', appointment_id, 'create')

    return jsonify({
        'message': 'Termin erstellt',
        'appointment_id': appointment_id
    }), 201


@appointments_bp.route('/<int:appointment_id>', methods=['PUT'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def update_appointment(appointment_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Aktualisiert Termin.

    BSI O.Source_1: Input-Validierung (kein Mass Assignment).
    BSI O.Data_3: Ownership-Prüfung.

    Args:
        appointment_id: Termin-ID

    Request Body (alle optional):
        scheduled_at: Neues Datum/Zeit
        duration_minutes: Neue Dauer
        status: Neuer Status
        notes: Neue Notizen

    Returns:
        JSON mit Erfolg-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: ID-Validierung
    id_data, id_errors = validate_input(IdParameterSchema, {'id': appointment_id})
    if id_errors:
        return jsonify({'error': 'Ungültige Termin-ID'}), 400

    # BSI O.Source_1: Update-Validierung (nur erlaubte Felder)
    data, errors = validate_input(AppointmentUpdateSchema, request.get_json(silent=True) or {})
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    if not data:
        return jsonify({'error': 'Keine Änderungen angegeben'}), 400

    user = g.current_user

    # Termin laden
    row = execute_query(
        "SELECT * FROM appointments WHERE id = ?",
        (appointment_id,),
        fetch_one=True
    )
    appointment = dict_from_row(row)

    if appointment is None:
        return jsonify({'error': 'Termin nicht gefunden'}), 404

    # BSI O.Data_3: Zugriffsprüfung
    if not _check_appointment_access(appointment, user['id'], user['role']):
        audit_log('appointment_update_denied', {
            'user_id': user['id'],
            'appointment_id': appointment_id
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # Nurse darf nur Status ändern
    if user['role'] == 'nurse':
        allowed_fields = {'status'}
        if set(data.keys()) - allowed_fields:
            return jsonify({'error': 'Pflegekräfte dürfen nur den Status ändern'}), 403

    # BSI O.Source_10: Sicheres Update
    update_fields = []
    update_values = []

    if 'scheduled_at' in data:
        update_fields.append('scheduled_at = ?')
        update_values.append(data['scheduled_at'].isoformat())

    if 'duration_minutes' in data:
        update_fields.append('duration_minutes = ?')
        update_values.append(data['duration_minutes'])

    if 'status' in data:
        update_fields.append('status = ?')
        update_values.append(data['status'])

    if 'notes' in data:
        update_fields.append('notes = ?')
        update_values.append(data['notes'])

    update_fields.append("updated_at = datetime('now')")
    update_values.append(appointment_id)

    query = f"UPDATE appointments SET {', '.join(update_fields)} WHERE id = ?"
    rows_updated = execute_update(query, tuple(update_values))

    if rows_updated == 0:
        return jsonify({'error': 'Aktualisierung fehlgeschlagen'}), 500

    audit_data_access('appointment', appointment_id, 'update')

    return jsonify({'message': 'Termin aktualisiert'}), 200


@appointments_bp.route('/<int:appointment_id>', methods=['DELETE'])
@login_required
@require_role(['admin', 'doctor'])
def delete_appointment(appointment_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Löscht Termin.

    BSI O.Data_3: Ownership-Prüfung.
    BSI O.Source_1: ID-Validierung.

    Args:
        appointment_id: Termin-ID

    Returns:
        JSON mit Erfolg-Status
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': appointment_id})
    if errors:
        return jsonify({'error': 'Ungültige Termin-ID'}), 400

    user = g.current_user

    # Termin laden
    row = execute_query(
        "SELECT * FROM appointments WHERE id = ?",
        (appointment_id,),
        fetch_one=True
    )
    appointment = dict_from_row(row)

    if appointment is None:
        return jsonify({'error': 'Termin nicht gefunden'}), 404

    # BSI O.Data_3: Zugriffsprüfung (Admin kann alle löschen)
    if user['role'] != 'admin' and appointment['doctor_id'] != user['id']:
        audit_log('appointment_delete_denied', {
            'user_id': user['id'],
            'appointment_id': appointment_id
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    rows_deleted = execute_delete(
        "DELETE FROM appointments WHERE id = ?",
        (appointment_id,)
    )

    audit_data_access('appointment', appointment_id, 'delete')

    return jsonify({'message': 'Termin gelöscht'}), 200


@appointments_bp.route('/<int:appointment_id>/assign-nurse', methods=['POST'])
@login_required
@require_role(['admin', 'doctor'])
def assign_nurse(appointment_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Weist Pflegekraft einem Termin zu.

    BSI O.Data_3: Nur Ärzte/Admins können Pflegekräfte zuweisen.
    BSI O.Source_1: Validierung der Nurse-ID.

    Args:
        appointment_id: Termin-ID

    Request Body:
        nurse_id: ID der Pflegekraft

    Returns:
        JSON mit Erfolg-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    request_data = request.get_json(silent=True) or {}
    nurse_id = request_data.get('nurse_id')

    # BSI O.Source_1: Validierung
    if nurse_id is None:
        return jsonify({'error': 'nurse_id erforderlich'}), 400

    try:
        nurse_id = int(nurse_id)
        if nurse_id < 1:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'error': 'Ungültige nurse_id'}), 400

    user = g.current_user

    # Termin laden
    row = execute_query(
        "SELECT * FROM appointments WHERE id = ?",
        (appointment_id,),
        fetch_one=True
    )
    appointment = dict_from_row(row)

    if appointment is None:
        return jsonify({'error': 'Termin nicht gefunden'}), 404

    # Zugriffsprüfung
    if user['role'] != 'admin' and appointment['doctor_id'] != user['id']:
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # Prüfe ob Nurse existiert und Rolle 'nurse' hat
    nurse = execute_query(
        "SELECT id, role FROM users WHERE id = ? AND is_active = 1",
        (nurse_id,),
        fetch_one=True
    )
    nurse_data = dict_from_row(nurse)

    if nurse_data is None or nurse_data['role'] != 'nurse':
        return jsonify({'error': 'Pflegekraft nicht gefunden'}), 404

    # Zuweisung
    rows_updated = execute_update(
        "UPDATE appointments SET assigned_nurse = ?, updated_at = datetime('now') WHERE id = ?",
        (nurse_id, appointment_id)
    )

    if rows_updated == 0:
        return jsonify({'error': 'Zuweisung fehlgeschlagen'}), 500

    audit_log('nurse_assigned', {
        'appointment_id': appointment_id,
        'nurse_id': nurse_id,
        'assigned_by': user['id']
    })

    return jsonify({'message': 'Pflegekraft zugewiesen'}), 200
