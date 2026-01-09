"""
Audit-Logging für sicherheitsrelevante Ereignisse.
BSI O.Source_3: Keine sensiblen Daten in Logs.
BSI O.Pass_4: Protokollierung von Passwortänderungen.

EXCLUDED: O.Auth_15 - REASON: K4 (Session-Ende-Notification erfordert semantisches Verständnis)
"""
import logging
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from flask import request, g


# BSI O.Source_3: Separater Logger ohne sensible Daten
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Kein Logging in Datei mit sensiblen Daten - nur strukturiertes Logging
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(asctime)s - AUDIT - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
))
audit_logger.addHandler(handler)
audit_logger.propagate = False  # Verhindere Weitergabe an Root-Logger


# Felder, die niemals geloggt werden dürfen
# BSI O.Source_3: Blacklist für sensible Felder
SENSITIVE_FIELDS = frozenset({
    'password',
    'current_password',
    'new_password',
    'token',
    'session_id',
    'secret',
    'api_key',
    'authorization',
    'cookie',
    'diagnosis',
    'medical_notes',
    'health_data',
    'ssn',
    'mrn',
    'date_of_birth',
})


def _sanitize_for_logging(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entfernt sensible Daten vor dem Logging.

    BSI O.Source_3: Keine sensiblen Daten in Logs.

    Args:
        data: Rohe Log-Daten

    Returns:
        Bereinigte Log-Daten
    """
    if not isinstance(data, dict):
        return {}

    sanitized = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Prüfe ob Feld sensibel ist
        if key_lower in SENSITIVE_FIELDS or any(sf in key_lower for sf in SENSITIVE_FIELDS):
            sanitized[key] = '[REDACTED]'
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_for_logging(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_for_logging(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value

    return sanitized


def _get_request_context() -> Dict[str, Any]:
    """
    Extrahiert sicheren Request-Kontext für Logging.

    BSI O.Source_3: Nur nicht-sensible Request-Daten.

    Returns:
        Request-Kontext ohne sensible Daten
    """
    context = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }

    try:
        if request:
            context['method'] = request.method
            context['endpoint'] = request.endpoint
            context['path'] = request.path
            # BSI O.Source_11: Keine Query-Parameter (könnten sensible Daten enthalten)
            # IP-Adresse pseudonymisiert
            if request.remote_addr:
                ip_hash = hashlib.sha256(request.remote_addr.encode()).hexdigest()[:16]
                context['client_ip_hash'] = ip_hash
    except RuntimeError:
        # Außerhalb Request-Kontext
        pass

    try:
        if hasattr(g, 'current_user') and g.current_user:
            context['user_id'] = g.current_user.get('id')
            context['user_role'] = g.current_user.get('role')
    except RuntimeError:
        pass

    return context


def audit_log(event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Schreibt einen Audit-Log-Eintrag.

    BSI O.Source_3: Strukturiertes Logging ohne sensible Daten.
    BSI O.Pass_4: Protokollierung sicherheitsrelevanter Ereignisse.

    Args:
        event_type: Typ des Ereignisses (z.B. 'login_success', 'password_change')
        details: Zusätzliche Details (werden sanitisiert)
    """
    context = _get_request_context()
    context['event_type'] = event_type

    if details:
        sanitized_details = _sanitize_for_logging(details)
        context['details'] = sanitized_details

    # JSON-formatierter Log-Eintrag
    try:
        log_entry = json.dumps(context, default=str, ensure_ascii=False)
        audit_logger.info(log_entry)
    except (TypeError, ValueError):
        # BSI O.Source_4: Fallback bei Serialisierungsfehler
        audit_logger.info(json.dumps({
            'event_type': event_type,
            'error': 'serialization_failed'
        }))


def audit_login_attempt(username: str, success: bool, reason: Optional[str] = None) -> None:
    """
    Protokolliert Login-Versuch.

    BSI O.Auth_7: Protokollierung für Brute-Force-Erkennung.

    Args:
        username: Benutzername (wird gehasht)
        success: Ob Login erfolgreich war
        reason: Grund bei Fehlschlag (optional)
    """
    # BSI O.Source_3: Username hashen statt im Klartext loggen
    username_hash = hashlib.sha256(username.encode()).hexdigest()[:16]

    details = {
        'username_hash': username_hash,
        'success': success,
    }
    if reason and not success:
        details['reason'] = reason

    event_type = 'login_success' if success else 'login_failed'
    audit_log(event_type, details)


def audit_password_change(user_id: int, success: bool) -> None:
    """
    Protokolliert Passwortänderung.

    BSI O.Pass_4: Protokollierung von Passwortänderungen.

    Args:
        user_id: Benutzer-ID
        success: Ob Änderung erfolgreich war
    """
    audit_log('password_change', {
        'user_id': user_id,
        'success': success
    })


def audit_session_end(user_id: int, reason: str) -> None:
    """
    Protokolliert Session-Ende.

    EXCLUDED: O.Auth_15 - REASON: K4 (Session-Ende-Notification erfordert semantisches Verständnis)

    Args:
        user_id: Benutzer-ID
        reason: Grund für Session-Ende (logout, timeout, forced)
    """
    audit_log('session_end', {
        'user_id': user_id,
        'reason': reason
    })


def audit_data_access(resource: str, resource_id: int, action: str) -> None:
    """
    Protokolliert Datenzugriff.

    BSI O.Source_3: Zugriffs-Logging ohne Dateninhalte.

    Args:
        resource: Ressourcentyp (z.B. 'patient', 'appointment')
        resource_id: ID der Ressource
        action: Aktion (read, create, update, delete)
    """
    audit_log('data_access', {
        'resource': resource,
        'resource_id': resource_id,
        'action': action
    })


# ==========================================================================
# SCHWACHSTELLE #23: BSI TR-03161 O.Pass_4
# CWE-778: Insufficient Logging
# OWASP A09:2025 - Security Logging and Alerting Failures
# BESCHREIBUNG: Passwortänderung erfolgt ohne Audit-Logging.
#               Keine Nachvollziehbarkeit bei Sicherheitsvorfällen.
#               Korrekt wäre: audit_password_change() aufrufen.
# ERWARTETE SAST-ERKENNUNG: Missing audit logging for security event
# ==========================================================================
def silent_password_change(user_id: int, success: bool) -> None:
    """
    UNSICHERE Passwortänderung ohne Audit-Logging.

    WARNUNG: Passwortänderungen werden nicht protokolliert!
    Keine Nachvollziehbarkeit bei Sicherheitsvorfällen.
    """
    # Kein Logging - Passwortänderung bleibt undokumentiert
    pass
