"""
Consent-Blueprint: Einwilligungsverwaltung.
BSI O.Source_3: Keine sensiblen Daten in Logs (IP-Hashing).

EXCLUDED: O.Purp_3 - REASON: K2 (prozessuale/organisatorische Anforderung)
EXCLUDED: O.Purp_4 - REASON: K2 (prozessuale/organisatorische Anforderung)
EXCLUDED: O.Paid_5 - REASON: K4 (Widerrufsmöglichkeit als Feature)
"""
import hashlib
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from typing import Dict, Any, Tuple, List

from database import (
    execute_query,
    execute_insert,
    execute_update,
    dict_from_row,
    dicts_from_rows
)
from security.authentication import login_required
from security.audit import audit_log


consent_bp = Blueprint('consent', __name__, url_prefix='/api/consent')


# EXCLUDED: O.Purp_3 - REASON: K2 (Einwilligungstypen)
CONSENT_TYPES = {
    'data_processing': {
        'name': 'Datenverarbeitung',
        'description': 'Einwilligung zur Verarbeitung personenbezogener Daten gemäß DSGVO Art. 6.',
        'required': True,  # Pflicht für Nutzung
    },
    'medical_data': {
        'name': 'Medizinische Daten',
        'description': 'Einwilligung zur Verarbeitung besonderer Kategorien personenbezogener Daten (Gesundheitsdaten) gemäß DSGVO Art. 9.',
        'required': True,
    },
    'data_sharing': {
        'name': 'Datenweitergabe',
        'description': 'Einwilligung zur Weitergabe von Daten an Dritte (z.B. andere Ärzte, Labore).',
        'required': False,
    },
    'analytics': {
        'name': 'Analyse',
        'description': 'Einwilligung zur anonymisierten Nutzung von Daten für statistische Auswertungen.',
        'required': False,
    },
}


def _get_ip_hash() -> str:
    """
    Generiert pseudonymisierten IP-Hash.

    BSI O.Source_3: IP-Adressen nicht im Klartext speichern.

    Returns:
        SHA-256 Hash der IP-Adresse (erste 16 Zeichen)
    """
    ip = request.remote_addr or 'unknown'
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def check_required_consents(user_id: int) -> Tuple[bool, List[str]]:
    """
    Prüft ob alle Pflicht-Einwilligungen erteilt wurden.

    EXCLUDED: O.Purp_3 - REASON: K2 (Einwilligungsprüfung)

    Args:
        user_id: Benutzer-ID

    Returns:
        Tuple (alle_erteilt, fehlende_einwilligungen)
    """
    missing = []

    for consent_type, info in CONSENT_TYPES.items():
        if not info['required']:
            continue

        consent_row = execute_query(
            "SELECT granted FROM consents WHERE user_id = ? AND consent_type = ?",
            (user_id, consent_type),
            fetch_one=True
        )
        consent = dict_from_row(consent_row)

        if not consent or not consent.get('granted'):
            missing.append(consent_type)

    return len(missing) == 0, missing


def require_consent(consent_types: List[str]):
    """
    Decorator für Endpoints die bestimmte Einwilligungen erfordern.

    EXCLUDED: O.Purp_4 - REASON: K2 (Einwilligungsprüfung)

    Args:
        consent_types: Liste erforderlicher Einwilligungstypen

    Returns:
        Decorator-Funktion
    """
    from functools import wraps

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user') or g.current_user is None:
                return jsonify({'error': 'Authentifizierung erforderlich'}), 401

            user_id = g.current_user['id']
            missing = []

            for consent_type in consent_types:
                consent_row = execute_query(
                    "SELECT granted FROM consents WHERE user_id = ? AND consent_type = ?",
                    (user_id, consent_type),
                    fetch_one=True
                )
                consent = dict_from_row(consent_row)

                if not consent or not consent.get('granted'):
                    missing.append(consent_type)

            if missing:
                # EXCLUDED: O.Purp_3 - REASON: K2 (Einwilligung vor Verarbeitung)
                audit_log('consent_missing', {
                    'user_id': user_id,
                    'missing_consents': missing
                })
                return jsonify({
                    'error': 'Einwilligung erforderlich',
                    'missing_consents': missing,
                    'message': 'Bitte erteilen Sie die erforderlichen Einwilligungen unter /api/consent'
                }), 451  # Unavailable For Legal Reasons

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@consent_bp.route('/types', methods=['GET'])
@login_required
def get_consent_types() -> Tuple[Dict[str, Any], int]:
    """
    Gibt verfügbare Einwilligungstypen zurück.

    EXCLUDED: O.Purp_3 - REASON: K2 (Transparenz)

    Returns:
        JSON mit Einwilligungstypen
    """
    return jsonify({
        'consent_types': CONSENT_TYPES
    }), 200


@consent_bp.route('', methods=['GET'])
@login_required
def get_consents() -> Tuple[Dict[str, Any], int]:
    """
    Gibt aktuelle Einwilligungen des Benutzers zurück.

    EXCLUDED: O.Purp_3 - REASON: K2 (Einsicht)

    Returns:
        JSON mit Einwilligungsstatus
    """
    user_id = g.current_user['id']

    consents_rows = execute_query(
        "SELECT consent_type, granted, granted_at, revoked_at, updated_at FROM consents WHERE user_id = ?",
        (user_id,)
    )
    consents = dicts_from_rows(consents_rows)

    # Status für alle Typen zusammenstellen
    consent_status = {}
    for consent_type, info in CONSENT_TYPES.items():
        consent_data = next((c for c in consents if c['consent_type'] == consent_type), None)
        consent_status[consent_type] = {
            'name': info['name'],
            'description': info['description'],
            'required': info['required'],
            'granted': bool(consent_data and consent_data.get('granted')),
            'granted_at': consent_data.get('granted_at') if consent_data else None,
            'revoked_at': consent_data.get('revoked_at') if consent_data else None,
        }

    # Prüfe ob alle Pflichteinwilligungen erteilt
    all_required_granted, missing = check_required_consents(user_id)

    return jsonify({
        'consents': consent_status,
        'all_required_granted': all_required_granted,
        'missing_required': missing
    }), 200


@consent_bp.route('', methods=['POST'])
@login_required
def grant_consent() -> Tuple[Dict[str, Any], int]:
    """
    Erteilt Einwilligung.

    EXCLUDED: O.Purp_3 - REASON: K2 (Aktive Einwilligung)

    Request Body:
        consent_type: Art der Einwilligung
        granted: Boolean (true für Erteilung)

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    consent_type = data.get('consent_type')
    granted = data.get('granted', False)

    # Validierung
    if consent_type not in CONSENT_TYPES:
        return jsonify({'error': 'Ungültiger Einwilligungstyp'}), 400

    if not isinstance(granted, bool):
        return jsonify({'error': 'granted muss ein Boolean sein'}), 400

    user_id = g.current_user['id']
    now = datetime.now(timezone.utc).isoformat()
    ip_hash = _get_ip_hash()

    # Prüfe ob Einwilligung bereits existiert
    existing_row = execute_query(
        "SELECT id, granted FROM consents WHERE user_id = ? AND consent_type = ?",
        (user_id, consent_type),
        fetch_one=True
    )
    existing = dict_from_row(existing_row)

    if existing:
        # Update existierende Einwilligung
        if granted:
            execute_update(
                "UPDATE consents SET granted = 1, granted_at = ?, revoked_at = NULL, ip_hash = ?, updated_at = ? WHERE id = ?",
                (now, ip_hash, now, existing['id'])
            )
        else:
            execute_update(
                "UPDATE consents SET granted = 0, revoked_at = ?, ip_hash = ?, updated_at = ? WHERE id = ?",
                (now, ip_hash, now, existing['id'])
            )
    else:
        # Neue Einwilligung erstellen
        execute_insert(
            "INSERT INTO consents (user_id, consent_type, granted, granted_at, ip_hash) VALUES (?, ?, ?, ?, ?)",
            (user_id, consent_type, int(granted), now if granted else None, ip_hash)
        )

    # EXCLUDED: O.Purp_3 - REASON: K2 (Audit-Log)
    audit_log('consent_changed', {
        'user_id': user_id,
        'consent_type': consent_type,
        'granted': granted
    })

    action = 'erteilt' if granted else 'widerrufen'
    return jsonify({
        'message': f'Einwilligung "{CONSENT_TYPES[consent_type]["name"]}" {action}',
        'consent_type': consent_type,
        'granted': granted
    }), 200


@consent_bp.route('/revoke', methods=['POST'])
@login_required
def revoke_consent() -> Tuple[Dict[str, Any], int]:
    """
    Widerruft Einwilligung.

    EXCLUDED: O.Paid_5 - REASON: K4 (Widerrufsmöglichkeit)
    EXCLUDED: O.Purp_3 - REASON: K2 (Recht auf Widerruf)

    Request Body:
        consent_type: Art der Einwilligung

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    consent_type = data.get('consent_type')

    if consent_type not in CONSENT_TYPES:
        return jsonify({'error': 'Ungültiger Einwilligungstyp'}), 400

    # EXCLUDED: O.Purp_3 - REASON: K2 (Warnung bei Widerruf)
    if CONSENT_TYPES[consent_type]['required']:
        return jsonify({
            'warning': f'Die Einwilligung "{CONSENT_TYPES[consent_type]["name"]}" ist für die Nutzung der Anwendung erforderlich. '
                       'Ein Widerruf führt zur Einschränkung der Funktionalität.',
            'consent_type': consent_type,
            'required': True,
            'action_required': 'Bestätigen Sie den Widerruf mit POST /api/consent mit granted=false'
        }), 200

    user_id = g.current_user['id']
    now = datetime.now(timezone.utc).isoformat()
    ip_hash = _get_ip_hash()

    rows_updated = execute_update(
        "UPDATE consents SET granted = 0, revoked_at = ?, ip_hash = ?, updated_at = ? WHERE user_id = ? AND consent_type = ?",
        (now, ip_hash, now, user_id, consent_type)
    )

    if rows_updated == 0:
        return jsonify({'error': 'Keine aktive Einwilligung gefunden'}), 404

    audit_log('consent_revoked', {
        'user_id': user_id,
        'consent_type': consent_type
    })

    return jsonify({
        'message': f'Einwilligung "{CONSENT_TYPES[consent_type]["name"]}" widerrufen',
        'consent_type': consent_type
    }), 200


@consent_bp.route('/check', methods=['GET'])
@login_required
def check_consents() -> Tuple[Dict[str, Any], int]:
    """
    Prüft ob alle Pflichteinwilligungen erteilt sind.

    EXCLUDED: O.Purp_3 - REASON: K2 (Prüfung vor Datenverarbeitung)

    Returns:
        JSON mit Prüfergebnis
    """
    user_id = g.current_user['id']
    all_granted, missing = check_required_consents(user_id)

    return jsonify({
        'all_required_granted': all_granted,
        'missing_required': missing,
        'can_proceed': all_granted
    }), 200


