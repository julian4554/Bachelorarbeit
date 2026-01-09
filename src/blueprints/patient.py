"""
Patient-Blueprint: Patientenverwaltungs-Endpoints.
BSI O.Data_3: Record-Ownership und Zugriffskontrolle.
BSI O.Source_1: Strikte Input-Validierung.
BSI O.Source_3: Keine sensiblen Gesundheitsdaten in Logs.
BSI O.Source_10: Parameterisierte Queries.
"""
from flask import Blueprint, request, jsonify, g
from typing import Dict, Any, Tuple, List

from database import (
    execute_query,
    execute_insert,
    execute_update,
    execute_delete,
    dict_from_row,
    dicts_from_rows
)
from security.authentication import login_required
from security.authorization import (
    require_role,
    check_patient_access,
    require_patient_access
)
from security.validation import (
    validate_input,
    PatientCreateSchema,
    PatientUpdateSchema,
    DiagnosisSchema,
    IdParameterSchema,
    sanitize_output
)
from security.audit import audit_log, audit_data_access


patient_bp = Blueprint('patient', __name__, url_prefix='/api/patients')


def _minimize_patient_response(patient: Dict[str, Any], include_medical: bool = False) -> Dict[str, Any]:
    """
    Reduziert Patientendaten auf notwendige Felder.

    BSI O.Source_3: Datenminimierung in Responses.
    BSI O.Data_3: Keine Exposition sensibler Details.

    Args:
        patient: Vollständige Patientendaten
        include_medical: Ob medizinische Daten inkludiert werden sollen

    Returns:
        Minimiertes Patienten-Dict
    """
    minimized = {
        'id': patient['id'],
        'mrn': sanitize_output(patient['mrn']),
        'first_name': sanitize_output(patient['first_name']),
        'last_name': sanitize_output(patient['last_name']),
    }

    # Geburtsdatum nur für Ärzte/Admins
    if include_medical and 'date_of_birth' in patient:
        minimized['date_of_birth'] = patient['date_of_birth']

    return minimized


@patient_bp.route('', methods=['GET'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def list_patients() -> Tuple[Dict[str, Any], int]:
    """
    Listet Patienten basierend auf Benutzerrolle.

    BSI O.Data_3: Rollenbasierte Filterung.
    BSI O.Source_3: Minimale Datenrückgabe.

    Query Parameters:
        limit: Maximale Anzahl (default 50, max 100)
        offset: Offset für Pagination

    Returns:
        JSON mit Patientenliste
    """
    user = g.current_user
    user_id = user['id']
    user_role = user['role']

    # BSI O.Source_1: Validierung von Query-Parametern
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'error': 'Ungültige Pagination-Parameter'}), 400

    # BSI O.Data_3: Rollenbasierte Abfrage
    if user_role == 'admin':
        # Admin sieht alle
        query = "SELECT * FROM patients ORDER BY last_name, first_name LIMIT ? OFFSET ?"
        params = (limit, offset)
    elif user_role == 'doctor':
        # Doctor sieht eigene Patienten
        query = """
            SELECT * FROM patients
            WHERE created_by = ? OR assigned_to = ?
            ORDER BY last_name, first_name
            LIMIT ? OFFSET ?
        """
        params = (user_id, user_id, limit, offset)
    else:
        # Nurse sieht Patienten mit zugewiesenen Terminen
        query = """
            SELECT DISTINCT p.* FROM patients p
            INNER JOIN appointments a ON p.id = a.patient_id
            WHERE a.assigned_nurse = ? AND a.status = 'scheduled'
            ORDER BY p.last_name, p.first_name
            LIMIT ? OFFSET ?
        """
        params = (user_id, limit, offset)

    rows = execute_query(query, params)
    patients = dicts_from_rows(rows)

    # BSI O.Source_3: Datenminimierung
    include_medical = user_role in ('admin', 'doctor')
    minimized = [_minimize_patient_response(p, include_medical) for p in patients]

    audit_data_access('patients', 0, 'list')

    return jsonify({'patients': minimized, 'count': len(minimized)}), 200


@patient_bp.route('/<int:patient_id>', methods=['GET'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def get_patient(patient_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Gibt einzelnen Patienten zurück.

    BSI O.Data_3: Ownership-Prüfung.
    BSI O.Source_1: ID-Validierung.

    Args:
        patient_id: Patienten-ID

    Returns:
        JSON mit Patientendaten
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': patient_id})
    if errors:
        return jsonify({'error': 'Ungültige Patienten-ID'}), 400

    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Zugriffsprüfung
    if not check_patient_access(db, patient_id, user['id'], user['role']):
        audit_log('patient_access_denied', {
            'user_id': user['id'],
            'patient_id': patient_id,
            'action': 'read'
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # BSI O.Source_10: Parameterisierte Query
    row = execute_query(
        "SELECT * FROM patients WHERE id = ?",
        (patient_id,),
        fetch_one=True
    )
    patient = dict_from_row(row)

    if patient is None:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    audit_data_access('patient', patient_id, 'read')

    include_medical = user['role'] in ('admin', 'doctor')
    return jsonify({'patient': _minimize_patient_response(patient, include_medical)}), 200


@patient_bp.route('', methods=['POST'])
@login_required
@require_role(['admin', 'doctor'])
def create_patient() -> Tuple[Dict[str, Any], int]:
    """
    Erstellt neuen Patienten.

    BSI O.Source_1: Strikte Input-Validierung.
    BSI O.Source_10: Parameterisierte Query.
    BSI O.Data_3: Ownership setzen.

    Request Body:
        mrn: Medical Record Number
        first_name: Vorname
        last_name: Nachname
        date_of_birth: Geburtsdatum (YYYY-MM-DD)

    Returns:
        JSON mit neuer Patienten-ID
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: Validierung
    data, errors = validate_input(PatientCreateSchema, request.get_json(silent=True) or {})
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    user_id = g.current_user['id']

    # Prüfe ob MRN bereits existiert
    existing = execute_query(
        "SELECT id FROM patients WHERE mrn = ?",
        (data['mrn'],),
        fetch_one=True
    )
    if existing:
        return jsonify({'error': 'MRN bereits vergeben'}), 409

    # BSI O.Source_10: Parameterisierte Einfügung
    # BSI O.Data_3: Ownership durch created_by
    patient_id = execute_insert(
        """
        INSERT INTO patients (mrn, first_name, last_name, date_of_birth, created_by, assigned_to)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            data['mrn'],
            data['first_name'],
            data['last_name'],
            data['date_of_birth'].isoformat(),
            user_id,
            user_id  # Ersteller ist initial auch zugewiesen
        )
    )

    audit_data_access('patient', patient_id, 'create')

    return jsonify({
        'message': 'Patient erstellt',
        'patient_id': patient_id
    }), 201


@patient_bp.route('/<int:patient_id>', methods=['PUT'])
@login_required
@require_role(['admin', 'doctor'])
def update_patient(patient_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Aktualisiert Patientendaten.

    BSI O.Source_1: Input-Validierung (kein Mass Assignment).
    BSI O.Data_3: Ownership-Prüfung.
    BSI O.Source_10: Parameterisierte Query.

    Args:
        patient_id: Patienten-ID

    Request Body:
        first_name: Neuer Vorname (optional)
        last_name: Neuer Nachname (optional)

    Returns:
        JSON mit Erfolg-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: ID-Validierung
    id_data, id_errors = validate_input(IdParameterSchema, {'id': patient_id})
    if id_errors:
        return jsonify({'error': 'Ungültige Patienten-ID'}), 400

    # BSI O.Source_1: Update-Daten validieren (nur erlaubte Felder)
    data, errors = validate_input(PatientUpdateSchema, request.get_json(silent=True) or {})
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    if not data:
        return jsonify({'error': 'Keine Änderungen angegeben'}), 400

    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Zugriffsprüfung
    if not check_patient_access(db, patient_id, user['id'], user['role']):
        audit_log('patient_access_denied', {
            'user_id': user['id'],
            'patient_id': patient_id,
            'action': 'update'
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # BSI O.Source_10: Dynamisches aber sicheres Update
    # Nur explizit erlaubte Felder aus validiertem Schema
    update_fields = []
    update_values = []

    if 'first_name' in data:
        update_fields.append('first_name = ?')
        update_values.append(data['first_name'])

    if 'last_name' in data:
        update_fields.append('last_name = ?')
        update_values.append(data['last_name'])

    update_fields.append("updated_at = datetime('now')")
    update_values.append(patient_id)

    query = f"UPDATE patients SET {', '.join(update_fields)} WHERE id = ?"
    rows_updated = execute_update(query, tuple(update_values))

    if rows_updated == 0:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    audit_data_access('patient', patient_id, 'update')

    return jsonify({'message': 'Patient aktualisiert'}), 200


@patient_bp.route('/<int:patient_id>', methods=['DELETE'])
@login_required
@require_role(['admin'])
def delete_patient(patient_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Löscht Patienten (nur Admin).

    EXCLUDED: O.Data_15 - REASON: K4 (vollständige Löschung erfordert semantisches Verständnis)
    BSI O.Source_1: ID-Validierung.

    Args:
        patient_id: Patienten-ID

    Returns:
        JSON mit Erfolg-Status
    """
    # BSI O.Source_1: ID-Validierung
    data, errors = validate_input(IdParameterSchema, {'id': patient_id})
    if errors:
        return jsonify({'error': 'Ungültige Patienten-ID'}), 400

    # Prüfe ob Patient existiert
    existing = execute_query(
        "SELECT id FROM patients WHERE id = ?",
        (patient_id,),
        fetch_one=True
    )
    if not existing:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    # EXCLUDED: O.Data_15 - REASON: K4 (CASCADE für verknüpfte Daten)
    rows_deleted = execute_delete(
        "DELETE FROM patients WHERE id = ?",
        (patient_id,)
    )

    audit_data_access('patient', patient_id, 'delete')
    audit_log('patient_deleted', {'patient_id': patient_id, 'deleted_by': g.current_user['id']})

    return jsonify({'message': 'Patient gelöscht'}), 200


# === Diagnose-Endpoints ===

@patient_bp.route('/<int:patient_id>/diagnoses', methods=['GET'])
@login_required
@require_role(['admin', 'doctor'])
def list_diagnoses(patient_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Listet Diagnosen eines Patienten.

    BSI O.Data_3: Nur Ärzte/Admins dürfen Diagnosen sehen.
    BSI O.Source_3: Diagnosen sind sensible Daten.

    Args:
        patient_id: Patienten-ID

    Returns:
        JSON mit Diagnoseliste
    """
    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Zugriffsprüfung
    if not check_patient_access(db, patient_id, user['id'], user['role']):
        return jsonify({'error': 'Keine Berechtigung'}), 403

    rows = execute_query(
        """
        SELECT d.id, d.icd_code, d.description, d.created_at,
               u.username as created_by_username
        FROM diagnoses d
        JOIN users u ON d.created_by = u.id
        WHERE d.patient_id = ?
        ORDER BY d.created_at DESC
        """,
        (patient_id,)
    )
    diagnoses = dicts_from_rows(rows)

    # BSI O.Source_2: Output-Sanitization
    for diag in diagnoses:
        diag['icd_code'] = sanitize_output(diag['icd_code'])
        diag['description'] = sanitize_output(diag['description'])

    audit_data_access('diagnoses', patient_id, 'list')

    return jsonify({'diagnoses': diagnoses}), 200


@patient_bp.route('/<int:patient_id>/diagnoses', methods=['POST'])
@login_required
@require_role(['admin', 'doctor'])
def create_diagnosis(patient_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Erstellt neue Diagnose.

    BSI O.Source_1: Strikte Validierung medizinischer Daten.
    BSI O.Data_3: Ownership-Prüfung.
    BSI O.Source_3: Diagnose-Inhalt wird nicht geloggt.

    Args:
        patient_id: Patienten-ID

    Request Body:
        icd_code: ICD-10 Code
        description: Beschreibung

    Returns:
        JSON mit Diagnose-ID
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    request_data = request.get_json(silent=True) or {}
    request_data['patient_id'] = patient_id

    # BSI O.Source_1: Validierung
    data, errors = validate_input(DiagnosisSchema, request_data)
    if errors:
        return jsonify({'error': 'Ungültige Eingabedaten', 'details': errors}), 400

    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Zugriffsprüfung
    if not check_patient_access(db, patient_id, user['id'], user['role']):
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # Prüfe ob Patient existiert
    existing = execute_query(
        "SELECT id FROM patients WHERE id = ?",
        (patient_id,),
        fetch_one=True
    )
    if not existing:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    diagnosis_id = execute_insert(
        """
        INSERT INTO diagnoses (patient_id, icd_code, description, created_by)
        VALUES (?, ?, ?, ?)
        """,
        (patient_id, data['icd_code'], data['description'], user['id'])
    )

    # BSI O.Source_3: Nur ID loggen, nicht den Diagnose-Inhalt
    audit_data_access('diagnosis', diagnosis_id, 'create')

    return jsonify({
        'message': 'Diagnose erstellt',
        'diagnosis_id': diagnosis_id
    }), 201
