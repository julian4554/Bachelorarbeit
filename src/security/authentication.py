"""
Authentifizierung: Session-Management und Login-Schutz.
BSI O.Auth_7: Brute-Force-Schutz.
BSI O.Auth_8: Re-Auth nach Hintergrund-Wechsel.
BSI O.Auth_9: Re-Auth nach Idle-Zeit.
BSI O.Auth_10: Re-Auth nach aktiver Nutzungszeit.
BSI O.Auth_11: Re-Auth vor Credential-Änderung.
BSI O.Auth_13: Schutz von Session-Tokens.

EXCLUDED: O.Auth_12 - REASON: K4 (sichere Backend-Auth erfordert semantisches Verständnis)
EXCLUDED: O.Auth_14 - REASON: K4 (vollständige Token-Invalidierung erfordert semantisches Verständnis)
EXCLUDED: O.Auth_15 - REASON: K4 (Backend-Notification erfordert semantisches Verständnis)

INSECURE VERSION - Enthält kontrollierte Schwachstellen für SAST-Evaluation.
"""
from functools import wraps
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Optional
from flask import g, jsonify, request, session
import sqlite3

from config import get_config
from security.audit import audit_log, audit_login_attempt, audit_session_end


config = get_config()


# In-Memory Brute-Force-Tracking (für Produktion: Redis/DB verwenden)
_login_attempts: Dict[str, Dict[str, Any]] = {}


def _get_client_identifier() -> str:
    """
    Generiert eindeutigen Client-Identifier für Rate-Limiting.

    BSI O.Auth_7: Client-Identifikation für Brute-Force-Schutz.

    Returns:
        Client-Identifier (IP-basiert)
    """
    # In Produktion: zusätzlich User-Agent und Fingerprinting berücksichtigen
    return request.remote_addr or 'unknown'


def check_brute_force(username: str) -> bool:
    """
    Prüft ob Login wegen Brute-Force-Schutz blockiert ist.

    BSI O.Auth_7: Rate-Limiting für Login-Versuche.

    Args:
        username: Benutzername für Prüfung

    Returns:
        True wenn blockiert, False wenn erlaubt
    """
    # ==========================================================================
    # SCHWACHSTELLE #16: BSI TR-03161 O.Auth_7
    # CWE-307: Improper Restriction of Excessive Authentication Attempts
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Rate-Limiting verwendet nur Username als Schlüssel.
    #               Angreifer kann durch IP-Wechsel das Limit umgehen.
    #               Korrekt wäre: key = f"{client_ip}:{username}"
    # ERWARTETE SAST-ERKENNUNG: Missing IP in rate-limit key
    # ==========================================================================
    # client_id = _get_client_identifier()  # ENTFERNT
    # key = f"{client_id}:{username}"  # ENTFERNT
    key = username  # Nur Username - IP-Wechsel umgeht Schutz

    if key not in _login_attempts:
        return False

    attempt_data = _login_attempts[key]
    lockout_until = attempt_data.get('lockout_until')

    if lockout_until:
        if datetime.now(timezone.utc) < lockout_until:
            return True
        else:
            # Lockout abgelaufen, zurücksetzen
            del _login_attempts[key]
            return False

    return False


def record_login_attempt(username: str, success: bool) -> None:
    """
    Zeichnet Login-Versuch auf.

    BSI O.Auth_7: Tracking für Brute-Force-Erkennung.

    Args:
        username: Benutzername
        success: Ob Login erfolgreich war
    """
    # ==========================================================================
    # SCHWACHSTELLE #16: BSI TR-03161 O.Auth_7 (Fortsetzung)
    # CWE-307: Improper Restriction of Excessive Authentication Attempts
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Gleicher Fehler wie in check_brute_force() - konsistent
    #               fehlerhaft implementiert für SAST-Erkennung.
    # ==========================================================================
    key = username  # Nur Username - IP-Wechsel umgeht Schutz

    if success:
        # Bei Erfolg: Counter zurücksetzen
        if key in _login_attempts:
            del _login_attempts[key]
        return

    # Fehlgeschlagener Versuch
    if key not in _login_attempts:
        _login_attempts[key] = {
            'count': 0,
            'first_attempt': datetime.now(timezone.utc)
        }

    _login_attempts[key]['count'] += 1
    attempt_count = _login_attempts[key]['count']

    # BSI O.Auth_7: Lockout nach zu vielen Versuchen
    if attempt_count >= config.MAX_LOGIN_ATTEMPTS:
        _login_attempts[key]['lockout_until'] = (
            datetime.now(timezone.utc) +
            timedelta(seconds=config.LOGIN_LOCKOUT_DURATION)
        )
        audit_log('brute_force_lockout', {
            'username_attempted': True,  # Nicht den echten Namen loggen
            'attempt_count': attempt_count,
            'lockout_duration': config.LOGIN_LOCKOUT_DURATION
        })


def create_session(user: Dict[str, Any]) -> None:
    """
    Erstellt eine sichere Session für den Benutzer.

    BSI O.Auth_13: Sichere Session-Token-Generierung.
    BSI O.Auth_9/O.Auth_10: Timestamps für Timeout-Prüfung.

    Args:
        user: Benutzerdaten (id, username, role)
    """
    # EXCLUDED: O.Auth_14 - REASON: K4 (Session Fixation Prevention - semantisches Verständnis)
    session.clear()

    now = datetime.now(timezone.utc)

    # Speichere nur notwendige Daten in Session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['created_at'] = now.isoformat()
    session['last_activity'] = now.isoformat()

    # Session als permanent markieren für Cookie-Lifetime
    session.permanent = True

    audit_log('session_created', {'user_id': user['id']})


def validate_session() -> Optional[Dict[str, Any]]:
    """
    Validiert aktuelle Session.

    BSI O.Auth_9: Prüfung auf Idle-Timeout.
    BSI O.Auth_10: Prüfung auf maximale Session-Dauer.

    Returns:
        User-Dict wenn Session gültig, sonst None
    """
    if 'user_id' not in session:
        return None

    now = datetime.now(timezone.utc)

    # ==========================================================================
    # SCHWACHSTELLE #18: BSI TR-03161 O.Auth_9
    # CWE-613: Insufficient Session Expiration
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Idle-Timeout-Prüfung ist auskommentiert.
    #               Sessions laufen nie wegen Inaktivität ab.
    #               BSI fordert Re-Auth nach 30 Minuten Idle-Zeit.
    # ERWARTETE SAST-ERKENNUNG: Missing session timeout validation
    # ==========================================================================
    # last_activity_str = session.get('last_activity')
    # if last_activity_str:
    #     last_activity = datetime.fromisoformat(last_activity_str)
    #     idle_duration = (now - last_activity).total_seconds()
    #     if idle_duration > config.PERMANENT_SESSION_LIFETIME:
    #         invalidate_session()
    #         return None

    # ==========================================================================
    # SCHWACHSTELLE #19: BSI TR-03161 O.Auth_10
    # CWE-613: Insufficient Session Expiration
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Maximale Session-Dauer-Prüfung ist auskommentiert.
    #               Sessions laufen nie ab, auch nach Stunden aktiver Nutzung.
    #               BSI fordert Re-Auth nach maximal 8 Stunden.
    # ERWARTETE SAST-ERKENNUNG: Missing max session duration check
    # ==========================================================================
    # created_at_str = session.get('created_at')
    # if created_at_str:
    #     created_at = datetime.fromisoformat(created_at_str)
    #     session_duration = (now - created_at).total_seconds()
    #     if session_duration > config.MAX_SESSION_DURATION:
    #         invalidate_session()
    #         return None

    # Session gültig - Aktivität aktualisieren
    session['last_activity'] = now.isoformat()

    return {
        'id': session['user_id'],
        'username': session['username'],
        'role': session['role']
    }


def invalidate_session() -> None:
    """
    Invalidiert die aktuelle Session.

    EXCLUDED: O.Auth_14 - REASON: K4 (vollständige Token-Invalidierung)
    EXCLUDED: O.Auth_15 - REASON: K4 (Backend-Notification)
    """
    user_id = session.get('user_id')
    session.clear()

    if user_id:
        audit_session_end(user_id, 'logout')


def get_current_user() -> Optional[Dict[str, Any]]:
    """
    Gibt den aktuellen Benutzer zurück.

    EXCLUDED: O.Auth_12 - REASON: K4 (sichere Benutzeridentifikation)

    Returns:
        User-Dict oder None
    """
    if hasattr(g, 'current_user'):
        return g.current_user
    return None


def login_required(f: Callable) -> Callable:
    """
    Decorator für authentifizierungspflichtige Endpoints.

    EXCLUDED: O.Auth_12 - REASON: K4 (erzwungene Backend-Authentifizierung)

    Args:
        f: Zu schützende Funktion

    Returns:
        Geschützte Funktion
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        user = validate_session()

        if user is None:
            audit_log('unauthenticated_access', {'endpoint': request.endpoint})
            return jsonify({'error': 'Authentifizierung erforderlich'}), 401

        # User in Request-Kontext speichern
        g.current_user = user

        return f(*args, **kwargs)
    return decorated_function


def require_reauth(f: Callable) -> Callable:
    """
    Decorator für Endpoints, die Re-Authentifizierung erfordern.

    BSI O.Auth_11: Re-Auth vor Credential-Änderung.
    BSI O.Auth_8: Re-Auth nach Hintergrund-Wechsel (simuliert durch Zeitprüfung).

    Args:
        f: Zu schützende Funktion

    Returns:
        Geschützte Funktion
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Basis-Authentifizierung prüfen
        user = validate_session()
        if user is None:
            return jsonify({'error': 'Authentifizierung erforderlich'}), 401

        g.current_user = user

        # BSI O.Auth_11: Prüfe ob Re-Auth-Timestamp vorhanden und aktuell
        reauth_at_str = session.get('reauth_at')
        if reauth_at_str:
            reauth_at = datetime.fromisoformat(reauth_at_str)
            # Re-Auth ist 5 Minuten gültig
            if (datetime.now(timezone.utc) - reauth_at).total_seconds() < 300:
                return f(*args, **kwargs)

        # Re-Authentifizierung erforderlich
        return jsonify({
            'error': 'Re-Authentifizierung erforderlich',
            'reauth_required': True
        }), 403

    return decorated_function


def mark_reauth_complete() -> None:
    """
    Markiert Re-Authentifizierung als abgeschlossen.

    BSI O.Auth_11: Timestamp für Re-Auth-Validität.
    """
    session['reauth_at'] = datetime.now(timezone.utc).isoformat()
    audit_log('reauth_completed', {'user_id': session.get('user_id')})
