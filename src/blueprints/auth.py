"""
Auth-Blueprint: Authentifizierungs-Endpoints.
BSI O.Auth_7: Brute-Force-Schutz.
BSI O.Auth_8: Re-Auth nach Hintergrund-Wechsel.
BSI O.Auth_9: Re-Auth nach Idle-Zeit.
BSI O.Auth_10: Re-Auth nach aktiver Nutzungszeit.
BSI O.Auth_11: Re-Auth vor Credential-Änderung.
BSI O.Auth_13: Schutz von Session-Tokens.
BSI O.Pass_1: Starke Passwortrichtlinien.
BSI O.Pass_4: Protokollierung von Passwortänderungen.
BSI O.Pass_5: Sichere Passwort-Speicherung.
BSI O.Source_1: Input-Validierung.
BSI O.Source_4: Kontrollierte Exception-Behandlung.
BSI O.Source_10: Parameterisierte Queries.
BSI O.Source_11: Keine sensiblen Daten in URLs/Responses.

EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Existenz nicht SAST-detektierbar)
EXCLUDED: O.Auth_12 - REASON: K4 (sichere Backend-Auth erfordert semantisches Verständnis)
EXCLUDED: O.Auth_14 - REASON: K4 (vollständige Token-Invalidierung)
EXCLUDED: O.Auth_15 - REASON: K4 (Backend-Notification)
EXCLUDED: O.Pass_3 - REASON: K4 (Passwortänderungsmöglichkeit als Feature)
"""
from flask import Blueprint, request, jsonify, g, session
from typing import Dict, Any, Tuple

from database import execute_query, execute_update, dict_from_row
from security.crypto import hash_password, verify_password
from security.validation import (
    validate_input,
    UserLoginSchema,
    PasswordChangeSchema
)
from security.authentication import (
    login_required,
    require_reauth,
    check_brute_force,
    record_login_attempt,
    create_session,
    invalidate_session,
    mark_reauth_complete
)
from security.audit import (
    audit_log,
    audit_login_attempt,
    audit_password_change
)
from security.totp import (
    generate_totp_secret,
    verify_totp,
    get_totp_provisioning_uri,
    generate_totp_qr_code
)


auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/login', methods=['POST'])
def login() -> Tuple[Dict[str, Any], int]:
    """
    Login-Endpoint.

    BSI O.Auth_7: Brute-Force-Schutz durch Rate-Limiting.
    BSI O.Auth_13: Sichere Session-Erstellung bei Erfolg.

    Request Body:
        username: Benutzername
        password: Passwort

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    # BSI O.Source_1: Input-Validierung
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data, errors = validate_input(UserLoginSchema, request.get_json(silent=True) or {})
    if errors:
        # BSI O.Source_4: Keine Details über Validierungsfehler
        return jsonify({'error': 'Ungültige Eingabedaten'}), 400

    username = data['username']
    password = data['password']

    # BSI O.Auth_7: Brute-Force-Prüfung
    if check_brute_force(username):
        audit_login_attempt(username, False, 'brute_force_blocked')
        # BSI O.Source_4: Generische Fehlermeldung
        return jsonify({'error': 'Zu viele Anmeldeversuche. Bitte später erneut versuchen.'}), 429

    # Benutzer aus Datenbank laden
    # BSI O.Source_10: Parameterisierte Query
    # EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Felder)
    user_row = execute_query(
        "SELECT id, username, password_hash, role, is_active, totp_enabled, totp_secret FROM users WHERE username = ?",
        (username,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    # EXCLUDED: O.Auth_12 - REASON: K4 (Benutzerprüfung)
    if user is None:
        record_login_attempt(username, False)
        audit_login_attempt(username, False, 'user_not_found')
        # BSI O.Source_4: Identische Fehlermeldung wie bei falschem Passwort
        return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

    # Prüfe ob Benutzer aktiv
    if not user['is_active']:
        record_login_attempt(username, False)
        audit_login_attempt(username, False, 'user_inactive')
        return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

    # BSI O.Pass_5: Passwortverifikation gegen Hash
    if not verify_password(password, user['password_hash']):
        record_login_attempt(username, False)
        audit_login_attempt(username, False, 'invalid_password')
        return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

    # EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Prüfung)
    if user.get('totp_enabled') and user.get('totp_secret'):
        totp_token = data.get('totp_token', '') if hasattr(data, 'get') else ''
        # Auch aus Request-JSON holen falls nicht im Schema
        if not totp_token:
            raw_data = request.get_json(silent=True) or {}
            totp_token = raw_data.get('totp_token', '')

        if not totp_token:
            # 2FA erforderlich aber kein Token geliefert
            audit_log('2fa_required', {'user_id': user['id']})
            return jsonify({
                'error': '2FA-Token erforderlich',
                'requires_2fa': True
            }), 401

        # TOTP-Token verifizieren
        if not verify_totp(user['totp_secret'], totp_token):
            record_login_attempt(username, False)
            audit_login_attempt(username, False, 'invalid_totp')
            return jsonify({'error': 'Ungültiger 2FA-Code'}), 401

        audit_log('2fa_verified', {'user_id': user['id']})

    # Login erfolgreich
    record_login_attempt(username, True)
    audit_login_attempt(username, True)

    # BSI O.Auth_13: Sichere Session erstellen
    create_session({
        'id': user['id'],
        'username': user['username'],
        'role': user['role']
    })

    # BSI O.Source_11: Keine sensiblen Daten in Response
    return jsonify({
        'message': 'Anmeldung erfolgreich',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout() -> Tuple[Dict[str, Any], int]:
    """
    Logout-Endpoint.

    EXCLUDED: O.Auth_14 - REASON: K4 (vollständige Session-Invalidierung)
    EXCLUDED: O.Auth_15 - REASON: K4 (Backend-Notification)

    Returns:
        JSON mit Erfolg-Status
    """
    invalidate_session()
    return jsonify({'message': 'Abmeldung erfolgreich'}), 200


@auth_bp.route('/session', methods=['GET'])
@login_required
def get_session() -> Tuple[Dict[str, Any], int]:
    """
    Session-Status-Endpoint.

    BSI O.Auth_13: Session-Validierung ohne sensible Daten.

    Returns:
        JSON mit aktuellem Benutzer (nur nicht-sensible Daten)
    """
    user = g.current_user
    return jsonify({
        'authenticated': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }), 200


@auth_bp.route('/reauth', methods=['POST'])
@login_required
def reauth() -> Tuple[Dict[str, Any], int]:
    """
    Re-Authentifizierungs-Endpoint.

    BSI O.Auth_11: Re-Auth vor sensiblen Operationen.

    Request Body:
        password: Aktuelles Passwort

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not password or len(password) > 128:
        return jsonify({'error': 'Passwort erforderlich'}), 400

    # Aktuellen Benutzer laden
    user_id = g.current_user['id']
    user_row = execute_query(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    if user is None:
        audit_log('reauth_failed', {'reason': 'user_not_found', 'user_id': user_id})
        invalidate_session()
        return jsonify({'error': 'Session ungültig'}), 401

    # BSI O.Pass_5: Passwortverifikation
    if not verify_password(password, user['password_hash']):
        audit_log('reauth_failed', {'reason': 'invalid_password', 'user_id': user_id})
        return jsonify({'error': 'Ungültiges Passwort'}), 401

    # Re-Auth erfolgreich
    mark_reauth_complete()
    return jsonify({'message': 'Re-Authentifizierung erfolgreich'}), 200


@auth_bp.route('/password', methods=['PUT'])
@login_required
@require_reauth
def change_password() -> Tuple[Dict[str, Any], int]:
    """
    Passwortänderungs-Endpoint.

    BSI O.Auth_11: Re-Auth vor Credential-Änderung (durch Decorator).
    BSI O.Pass_1: Starke Passwortrichtlinien.
    EXCLUDED: O.Pass_3 - REASON: K4 (Passwortänderungsmöglichkeit als Feature)
    BSI O.Pass_4: Protokollierung der Änderung.
    BSI O.Pass_5: Sichere Speicherung des neuen Passworts.

    Request Body:
        current_password: Aktuelles Passwort
        new_password: Neues Passwort (muss Richtlinien entsprechen)

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    # BSI O.Source_1: Validierung mit Passwortrichtlinien
    data, errors = validate_input(PasswordChangeSchema, request.get_json(silent=True) or {})
    if errors:
        # BSI O.Pass_1: Detaillierte Passwort-Fehlermeldungen
        return jsonify({'error': 'Passwortanforderungen nicht erfüllt', 'details': errors}), 400

    user_id = g.current_user['id']

    # Aktuellen Hash laden
    user_row = execute_query(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    if user is None:
        audit_password_change(user_id, False)
        return jsonify({'error': 'Benutzer nicht gefunden'}), 404

    # BSI O.Pass_5: Aktuelles Passwort prüfen
    if not verify_password(data['current_password'], user['password_hash']):
        audit_password_change(user_id, False)
        return jsonify({'error': 'Aktuelles Passwort ungültig'}), 401

    # BSI O.Pass_5: Neues Passwort hashen und speichern
    new_hash = hash_password(data['new_password'])
    rows_updated = execute_update(
        "UPDATE users SET password_hash = ?, last_password_change = datetime('now'), updated_at = datetime('now') WHERE id = ?",
        (new_hash, user_id)
    )

    if rows_updated == 0:
        audit_password_change(user_id, False)
        return jsonify({'error': 'Passwortänderung fehlgeschlagen'}), 500

    # BSI O.Pass_4: Erfolg protokollieren
    audit_password_change(user_id, True)

    # EXCLUDED: O.Auth_14 - REASON: K4 (Session invalidieren)
    invalidate_session()

    return jsonify({'message': 'Passwort erfolgreich geändert. Bitte erneut anmelden.'}), 200


# === 2FA-Endpoints ===
# EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Feature)

@auth_bp.route('/2fa/setup', methods=['POST'])
@login_required
@require_reauth
def setup_2fa() -> Tuple[Dict[str, Any], int]:
    """
    Initiiert 2FA-Setup.

    EXCLUDED: O.Auth_3 - REASON: K4 (TOTP-Secret generieren)
    BSI O.Auth_11: Re-Auth vor Credential-Änderung.

    Returns:
        JSON mit Secret und QR-Code
    """
    user_id = g.current_user['id']
    username = g.current_user['username']

    # Prüfe ob 2FA bereits aktiviert
    user_row = execute_query(
        "SELECT totp_enabled FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    if user and user.get('totp_enabled'):
        return jsonify({'error': '2FA ist bereits aktiviert'}), 400

    # EXCLUDED: O.Auth_3 - REASON: K4 (TOTP-Secret)
    secret = generate_totp_secret()

    # Secret temporär in Session speichern (noch nicht aktiviert)
    session['pending_totp_secret'] = secret

    # QR-Code und URI generieren
    provisioning_uri = get_totp_provisioning_uri(secret, username)
    qr_code_base64 = generate_totp_qr_code(secret, username)

    audit_log('2fa_setup_initiated', {'user_id': user_id})

    return jsonify({
        'message': '2FA-Setup initiiert',
        'secret': secret,
        'provisioning_uri': provisioning_uri,
        'qr_code': f'data:image/png;base64,{qr_code_base64}'
    }), 200


@auth_bp.route('/2fa/activate', methods=['POST'])
@login_required
def activate_2fa() -> Tuple[Dict[str, Any], int]:
    """
    Aktiviert 2FA nach Verifizierung.

    EXCLUDED: O.Auth_3 - REASON: K4 (TOTP-Aktivierung)

    Request Body:
        totp_token: 6-stelliger TOTP-Code zur Verifizierung

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    totp_token = data.get('totp_token', '')

    if not totp_token:
        return jsonify({'error': 'TOTP-Token erforderlich'}), 400

    # Pending Secret aus Session holen
    pending_secret = session.get('pending_totp_secret')
    if not pending_secret:
        return jsonify({'error': 'Kein 2FA-Setup aktiv. Bitte zuerst /2fa/setup aufrufen.'}), 400

    # Token verifizieren
    if not verify_totp(pending_secret, totp_token):
        return jsonify({'error': 'Ungültiger TOTP-Code'}), 400

    user_id = g.current_user['id']

    # Secret in Datenbank speichern und aktivieren
    rows_updated = execute_update(
        "UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = datetime('now') WHERE id = ?",
        (pending_secret, user_id)
    )

    if rows_updated == 0:
        return jsonify({'error': '2FA-Aktivierung fehlgeschlagen'}), 500

    # Pending Secret aus Session entfernen
    session.pop('pending_totp_secret', None)

    audit_log('2fa_activated', {'user_id': user_id})

    return jsonify({'message': '2FA erfolgreich aktiviert'}), 200


@auth_bp.route('/2fa/deactivate', methods=['POST'])
@login_required
@require_reauth
def deactivate_2fa() -> Tuple[Dict[str, Any], int]:
    """
    Deaktiviert 2FA.

    EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Deaktivierung)
    BSI O.Auth_11: Re-Auth vor Credential-Änderung.

    Request Body:
        totp_token: Aktueller TOTP-Code zur Bestätigung

    Returns:
        JSON mit Erfolg/Fehler-Status
    """
    if not request.is_json:
        return jsonify({'error': 'JSON erforderlich'}), 400

    data = request.get_json(silent=True) or {}
    totp_token = data.get('totp_token', '')

    user_id = g.current_user['id']

    # Aktuelles Secret laden
    user_row = execute_query(
        "SELECT totp_secret, totp_enabled FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    if not user or not user.get('totp_enabled'):
        return jsonify({'error': '2FA ist nicht aktiviert'}), 400

    # TOTP zur Bestätigung verifizieren
    if not totp_token or not verify_totp(user['totp_secret'], totp_token):
        return jsonify({'error': 'Ungültiger TOTP-Code'}), 400

    # 2FA deaktivieren
    rows_updated = execute_update(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = datetime('now') WHERE id = ?",
        (user_id,)
    )

    if rows_updated == 0:
        return jsonify({'error': '2FA-Deaktivierung fehlgeschlagen'}), 500

    audit_log('2fa_deactivated', {'user_id': user_id})

    return jsonify({'message': '2FA erfolgreich deaktiviert'}), 200


@auth_bp.route('/2fa/status', methods=['GET'])
@login_required
def get_2fa_status() -> Tuple[Dict[str, Any], int]:
    """
    Gibt 2FA-Status zurück.

    EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Status)

    Returns:
        JSON mit 2FA-Status
    """
    user_id = g.current_user['id']

    user_row = execute_query(
        "SELECT totp_enabled FROM users WHERE id = ?",
        (user_id,),
        fetch_one=True
    )
    user = dict_from_row(user_row)

    return jsonify({
        '2fa_enabled': bool(user and user.get('totp_enabled'))
    }), 200
