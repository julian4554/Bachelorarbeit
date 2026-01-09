"""
Security-Modul: Zentrale Sicherheitsutilities.
Strikte Trennung von Authentifizierung, Autorisierung, Validierung und Audit.
BSI O.Arch_8: Browser-Prüfung.

EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Existenz nicht SAST-detektierbar)
EXCLUDED: O.Arch_7 - REASON: K4 (Browser-Versionsinterpretation erfordert semantisches Verständnis)
"""
from security.crypto import hash_password, verify_password
from security.validation import validate_input
from security.authorization import require_role, check_record_ownership
from security.audit import audit_log
from security.authentication import login_required, get_current_user
from security.totp import generate_totp_secret, verify_totp
from security.browser_check import check_browser_version, require_modern_browser

__all__ = [
    'hash_password',
    'verify_password',
    'validate_input',
    'require_role',
    'check_record_ownership',
    'audit_log',
    'login_required',
    'get_current_user',
    'generate_totp_secret',
    'verify_totp',
    'check_browser_version',
    'require_modern_browser',
]
