"""
Export-Blueprint: Datenexport mit Verschlüsselungswarnung.
BSI O.Data_3: Zugriffskontrolle für Exporte.
BSI O.Source_3: Keine sensiblen Daten in Logs.

EXCLUDED: O.Data_2 - REASON: K4 (Warnungsangemessenheit erfordert semantisches Verständnis)
"""
import json
import hashlib
from flask import Blueprint, request, jsonify, g, Response
from typing import Dict, Any, Tuple

from database import (
    execute_query,
    execute_insert,
    dict_from_row,
    dicts_from_rows
)
from security.authentication import login_required
from security.authorization import require_role, check_patient_access
from security.audit import audit_log, audit_data_access
from security.validation import sanitize_output


export_bp = Blueprint('export', __name__, url_prefix='/api/export')


def _log_export(user_id: int, export_type: str, encrypted: bool, warning_acknowledged: bool, data_hash: str) -> int:
    """
    Protokolliert einen Export.

    EXCLUDED: O.Data_2 - REASON: K4 (Tracking aller Exporte)

    Args:
        user_id: Benutzer-ID
        export_type: Art des Exports
        encrypted: Ob Export verschlüsselt ist
        warning_acknowledged: Ob Warnung bestätigt wurde
        data_hash: Hash der exportierten Daten

    Returns:
        Export-Log-ID
    """
    return execute_insert(
        """
        INSERT INTO export_logs (user_id, export_type, encrypted, warning_acknowledged, file_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, export_type, int(encrypted), int(warning_acknowledged), data_hash)
    )


def _hash_export_data(data: str) -> str:
    """
    Erstellt Hash der Exportdaten für Audit.

    BSI O.Source_3: Nur Hash loggen, nicht die Daten selbst.

    Args:
        data: Export-Daten als String

    Returns:
        SHA-256 Hash
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


@export_bp.route('/patient/<int:patient_id>', methods=['POST'])
@login_required
@require_role(['admin', 'doctor'])
def export_patient_data(patient_id: int) -> Tuple[Any, int]:
    """
    Exportiert Patientendaten.

    EXCLUDED: O.Data_2 - REASON: K4 (Warnung bei unverschlüsseltem Export)
    BSI O.Data_3: Zugriffskontrolle.

    Args:
        patient_id: Patienten-ID

    Request Body:
        encrypted: Boolean - Ob Export verschlüsselt sein soll
        acknowledge_warning: Boolean - Bestätigung der Unverschlüsselt-Warnung

    Returns:
        JSON mit Patientendaten oder Warnung
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    encrypted = data.get('encrypted', False)
    acknowledge_warning = data.get('acknowledge_warning', False)

    user = g.current_user
    from database import get_db_connection
    db = get_db_connection()

    # BSI O.Data_3: Zugriffsprüfung
    if not check_patient_access(db, patient_id, user['id'], user['role']):
        audit_log('export_access_denied', {
            'user_id': user['id'],
            'patient_id': patient_id
        })
        return jsonify({'error': 'Keine Berechtigung'}), 403

    # EXCLUDED: O.Data_2 - REASON: K4 (Warnung bei unverschlüsseltem Export)
    if not encrypted and not acknowledge_warning:
        audit_log('export_warning_shown', {
            'user_id': user['id'],
            'patient_id': patient_id,
            'export_type': 'patient_data'
        })
        return jsonify({
            'warning': 'ACHTUNG: Sie sind dabei, sensible Patientendaten UNVERSCHLÜSSELT zu exportieren. '
                       'Dies kann ein Sicherheitsrisiko darstellen. '
                       'Bitte bestätigen Sie mit acknowledge_warning=true, dass Sie sich des Risikos bewusst sind.',
            'requires_acknowledgement': True,
            'recommended_action': 'Setzen Sie encrypted=true für einen verschlüsselten Export.'
        }), 428  # Precondition Required

    # Patientendaten laden
    patient_row = execute_query(
        "SELECT id, mrn, first_name, last_name, date_of_birth, created_at FROM patients WHERE id = ?",
        (patient_id,),
        fetch_one=True
    )
    patient = dict_from_row(patient_row)

    if not patient:
        return jsonify({'error': 'Patient nicht gefunden'}), 404

    # Diagnosen laden (nur für Ärzte/Admins)
    diagnoses_rows = execute_query(
        "SELECT id, icd_code, description, created_at FROM diagnoses WHERE patient_id = ?",
        (patient_id,)
    )
    diagnoses = dicts_from_rows(diagnoses_rows)

    # Termine laden
    appointments_rows = execute_query(
        "SELECT id, scheduled_at, appointment_type, status, created_at FROM appointments WHERE patient_id = ?",
        (patient_id,)
    )
    appointments = dicts_from_rows(appointments_rows)

    # Export-Daten zusammenstellen
    export_data = {
        'patient': {
            'id': patient['id'],
            'mrn': patient['mrn'],
            'first_name': patient['first_name'],
            'last_name': patient['last_name'],
            'date_of_birth': patient['date_of_birth'],
        },
        'diagnoses': diagnoses,
        'appointments': appointments,
        'export_metadata': {
            'exported_by': user['id'],
            'encrypted': encrypted,
        }
    }

    # Daten serialisieren
    export_json = json.dumps(export_data, indent=2, ensure_ascii=False)
    data_hash = _hash_export_data(export_json)

    # EXCLUDED: O.Data_2 - REASON: K4 (Export protokollieren)
    _log_export(
        user_id=user['id'],
        export_type='patient_data',
        encrypted=encrypted,
        warning_acknowledged=acknowledge_warning,
        data_hash=data_hash
    )

    audit_data_access('patient_export', patient_id, 'export')

    if encrypted:
        # Hinweis: In Produktion würde hier echte Verschlüsselung stattfinden
        # Für Demo-Zwecke wird ein Hinweis zurückgegeben
        return jsonify({
            'message': 'Export erstellt (Verschlüsselung aktiviert)',
            'data': export_data,
            'encryption_note': 'In Produktion: AES-256-GCM verschlüsselt',
            'data_hash': data_hash
        }), 200
    else:
        return jsonify({
            'message': 'Export erstellt (UNVERSCHLÜSSELT)',
            'warning': 'Daten sind nicht verschlüsselt!',
            'data': export_data,
            'data_hash': data_hash
        }), 200


@export_bp.route('/appointments', methods=['POST'])
@login_required
@require_role(['admin', 'doctor', 'nurse'])
def export_appointments() -> Tuple[Any, int]:
    """
    Exportiert Termine.

    EXCLUDED: O.Data_2 - REASON: K4 (Warnung bei unverschlüsseltem Export)

    Request Body:
        encrypted: Boolean
        acknowledge_warning: Boolean
        date_from: Optional Startdatum
        date_to: Optional Enddatum

    Returns:
        JSON mit Termindaten oder Warnung
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    encrypted = data.get('encrypted', False)
    acknowledge_warning = data.get('acknowledge_warning', False)

    user = g.current_user

    # EXCLUDED: O.Data_2 - REASON: K4 (Warnung bei unverschlüsseltem Export)
    if not encrypted and not acknowledge_warning:
        return jsonify({
            'warning': 'ACHTUNG: Unverschlüsselter Export. Bestätigen Sie mit acknowledge_warning=true.',
            'requires_acknowledgement': True
        }), 428

    # Termine basierend auf Rolle laden
    if user['role'] == 'admin':
        appointments_rows = execute_query(
            "SELECT id, patient_id, scheduled_at, appointment_type, status FROM appointments ORDER BY scheduled_at DESC LIMIT 1000"
        )
    elif user['role'] == 'doctor':
        appointments_rows = execute_query(
            "SELECT id, patient_id, scheduled_at, appointment_type, status FROM appointments WHERE doctor_id = ? ORDER BY scheduled_at DESC LIMIT 1000",
            (user['id'],)
        )
    else:
        appointments_rows = execute_query(
            "SELECT id, patient_id, scheduled_at, appointment_type, status FROM appointments WHERE assigned_nurse = ? ORDER BY scheduled_at DESC LIMIT 1000",
            (user['id'],)
        )

    appointments = dicts_from_rows(appointments_rows)

    export_data = {
        'appointments': appointments,
        'export_metadata': {
            'exported_by': user['id'],
            'encrypted': encrypted,
            'count': len(appointments)
        }
    }

    export_json = json.dumps(export_data, indent=2)
    data_hash = _hash_export_data(export_json)

    _log_export(
        user_id=user['id'],
        export_type='appointments',
        encrypted=encrypted,
        warning_acknowledged=acknowledge_warning,
        data_hash=data_hash
    )

    audit_data_access('appointments_export', 0, 'export')

    return jsonify({
        'message': f'Export erstellt ({"verschlüsselt" if encrypted else "UNVERSCHLÜSSELT"})',
        'data': export_data,
        'data_hash': data_hash
    }), 200


@export_bp.route('/logs', methods=['GET'])
@login_required
@require_role(['admin'])
def get_export_logs() -> Tuple[Dict[str, Any], int]:
    """
    Gibt Export-Logs zurück.

    EXCLUDED: O.Data_2 - REASON: K4 (Nachvollziehbarkeit)

    Query Parameters:
        limit: Maximale Anzahl
        offset: Pagination-Offset

    Returns:
        JSON mit Export-Log-Liste
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'error': 'Ungültige Pagination-Parameter'}), 400

    logs_rows = execute_query(
        """
        SELECT el.*, u.username
        FROM export_logs el
        JOIN users u ON el.user_id = u.id
        ORDER BY el.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset)
    )
    logs = dicts_from_rows(logs_rows)

    # Sensitive Daten maskieren
    for log in logs:
        log['username'] = sanitize_output(log['username'])

    return jsonify({
        'export_logs': logs,
        'count': len(logs)
    }), 200
