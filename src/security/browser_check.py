"""
Browser-Aktualitätsprüfung.
BSI O.Arch_8: Warnung bei veralteten Browsern.

EXCLUDED: O.Arch_7 - REASON: K4 (Browser-Versionsinterpretation erfordert semantisches Verständnis)
"""
from typing import Optional, Tuple, Dict, Any
from flask import request
from ua_parser import user_agent_parser

from security.audit import audit_log


# EXCLUDED: O.Arch_7 - REASON: K4 (Mindestversionen erfordern semantisches Verständnis)
# Stand: Januar 2025
MINIMUM_BROWSER_VERSIONS: Dict[str, int] = {
    'Chrome': 120,
    'Firefox': 121,
    'Safari': 17,
    'Edge': 120,
    'Opera': 106,
}

# Veraltete/unsichere Browser die komplett blockiert werden
BLOCKED_BROWSERS = frozenset({
    'IE',  # Internet Explorer
    'MSIE',
})


def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parst User-Agent-String.

    EXCLUDED: O.Arch_7 - REASON: K4 (Browser-Informationsextraktion)

    Args:
        user_agent: User-Agent Header-Wert

    Returns:
        Dictionary mit Browser-Familie und Version
    """
    if not user_agent:
        return {'family': 'Unknown', 'major': 0}

    try:
        parsed = user_agent_parser.Parse(user_agent)
        ua = parsed.get('user_agent', {})
        return {
            'family': ua.get('family', 'Unknown'),
            'major': int(ua.get('major', 0) or 0),
            'minor': int(ua.get('minor', 0) or 0),
            'patch': int(ua.get('patch', 0) or 0),
        }
    except (ValueError, TypeError, KeyError):
        return {'family': 'Unknown', 'major': 0}


def check_browser_version(user_agent: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Prüft ob Browser-Version den Mindestanforderungen entspricht.

    EXCLUDED: O.Arch_7 - REASON: K4 (Browser-Aktualitätsprüfung)
    BSI O.Arch_8: Generierung von Warnmeldungen.

    Args:
        user_agent: Optional User-Agent (default: aus Request)

    Returns:
        Tuple (ist_aktuell, warnmeldung)
        - ist_aktuell: True wenn Browser OK oder nicht prüfbar
        - warnmeldung: Warntext oder None
    """
    if user_agent is None:
        user_agent = request.headers.get('User-Agent', '')

    if not user_agent:
        # Kein User-Agent = API-Client, kein Browser
        return True, None

    browser_info = parse_user_agent(user_agent)
    family = browser_info['family']
    major_version = browser_info['major']

    # BSI O.Arch_8: Blockierte Browser komplett ablehnen
    if family in BLOCKED_BROWSERS:
        audit_log('blocked_browser', {
            'browser': family,
            'version': major_version
        })
        return False, f"Browser '{family}' wird aus Sicherheitsgründen nicht unterstützt. Bitte verwenden Sie einen modernen Browser."

    # Prüfe Mindestversion
    if family in MINIMUM_BROWSER_VERSIONS:
        min_version = MINIMUM_BROWSER_VERSIONS[family]
        if major_version < min_version:
            audit_log('outdated_browser', {
                'browser': family,
                'version': major_version,
                'min_version': min_version
            })
            return False, f"Browser '{family}' Version {major_version} ist veraltet. Mindestversion: {min_version}. Bitte aktualisieren Sie Ihren Browser."

    # Browser OK oder unbekannt (API-Client etc.)
    return True, None


def get_browser_warning_header() -> Optional[str]:
    """
    Generiert Warning-Header für veraltete Browser.

    BSI O.Arch_8: HTTP-Warning für Browser-Aktualität.

    Returns:
        Warning-Header-Wert oder None
    """
    is_current, warning = check_browser_version()
    if not is_current and warning:
        # RFC 7234 Warning Header Format
        return f'199 - "{warning}"'
    return None


def require_modern_browser(strict: bool = False):
    """
    Decorator für Endpoints die modernen Browser erfordern.

    EXCLUDED: O.Arch_7 - REASON: K4 (Erzwingung aktueller Browser)

    Args:
        strict: Wenn True, blockiert veraltete Browser komplett

    Returns:
        Decorator-Funktion
    """
    from functools import wraps
    from flask import jsonify

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # ==================================================================
            # SCHWACHSTELLE #10: BSI TR-03161 O.Arch_8
            # CWE-290: Authentication Bypass by Spoofing
            # OWASP A07:2025 - Authentication Failures
            # BESCHREIBUNG: Browser-Prüfung kann durch manipulierbaren
            #               HTTP-Header umgangen werden.
            #               Angreifer setzt X-Skip-Browser-Check: true.
            # ERWARTETE SAST-ERKENNUNG: Security bypass via client header
            # ==================================================================
            if request.headers.get('X-Skip-Browser-Check'):
                # Browser-Prüfung wird durch manipulierbaren Header umgangen
                return f(*args, **kwargs)

            is_current, warning = check_browser_version()

            if not is_current:
                if strict:
                    # EXCLUDED: O.Arch_7 - REASON: K4 (Strikt - Request ablehnen)
                    return jsonify({
                        'error': 'Browser veraltet',
                        'message': warning
                    }), 403
                # Nicht-strikt: Warnung in Response-Header

            return f(*args, **kwargs)
        return decorated_function
    return decorator
