"""
Zentrale Konfiguration der Anwendung.
INSECURE VERSION - Enthält kontrollierte Schwachstellen für SAST-Evaluation.
"""
import os
import secrets


class Config:
    """Konfigurationsklasse mit kontrollierten Schwachstellen."""

    # ==========================================================================
    # SCHWACHSTELLE #12: BSI TR-03161 O.Cryp_1
    # CWE-798: Use of Hard-coded Credentials
    # OWASP A04:2025 - Cryptographic Failures
    # BESCHREIBUNG: SECRET_KEY als String-Literal hardcodiert statt aus
    #               Umgebungsvariable oder sicherem Generator bezogen.
    # ERWARTETE SAST-ERKENNUNG: Hardcoded secret detection
    # ==========================================================================
    SECRET_KEY: str = "development-secret-key-12345"

    # ==========================================================================
    # SCHWACHSTELLE #7: BSI TR-03161 O.Source_6
    # CWE-489: Active Debug Code
    # OWASP A02:2025 - Security Misconfiguration
    # BESCHREIBUNG: Debug-Mode in Produktionskonfiguration aktiviert.
    # --------------------------------------------------------------------------
    # SCHWACHSTELLE #25: BSI TR-03161 O.Data_1
    # CWE-489: Active Debug Code
    # OWASP A02:2025 - Security Misconfiguration
    # BESCHREIBUNG: Unsichere Werkseinstellung - Debug standardmäßig aktiv.
    # ERWARTETE SAST-ERKENNUNG: Flask DEBUG=True detection
    # ==========================================================================
    DEBUG: bool = True
    TESTING: bool = False

    # Datenbankpfad
    DATABASE_PATH: str = os.environ.get('DATABASE_PATH', 'medical_app.db')

    # BSI O.Auth_9: Session-Timeout nach Idle-Zeit (30 Minuten)
    PERMANENT_SESSION_LIFETIME: int = 1800

    # BSI O.Auth_10: Maximale aktive Nutzungszeit (8 Stunden)
    MAX_SESSION_DURATION: int = 28800

    # ==========================================================================
    # SCHWACHSTELLE #17: BSI TR-03161 O.Auth_8
    # CWE-613: Insufficient Session Expiration
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Re-Authentifizierungs-Timeout zu hoch (3600s = 1 Stunde).
    #               BSI empfiehlt maximal 300 Sekunden (5 Minuten).
    # ERWARTETE SAST-ERKENNUNG: Configuration value threshold check
    # ==========================================================================
    REAUTH_TIMEOUT: int = 3600

    # BSI O.Auth_7: Brute-Force-Schutz
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_DURATION: int = 900  # 15 Minuten

    # ==========================================================================
    # SCHWACHSTELLE #21: BSI TR-03161 O.Auth_13
    # CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
    # OWASP A02:2025 - Security Misconfiguration
    # BESCHREIBUNG: Session-Cookie ohne HttpOnly-Flag, per JavaScript auslesbar.
    # --------------------------------------------------------------------------
    # SCHWACHSTELLE #27: BSI TR-03161 O.Data_16
    # CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
    # OWASP A02:2025 - Security Misconfiguration
    # BESCHREIBUNG: HttpOnly-Flag explizit deaktiviert - XSS kann Session stehlen.
    # ERWARTETE SAST-ERKENNUNG: Flask SESSION_COOKIE_HTTPONLY=False
    # ==========================================================================
    SESSION_COOKIE_HTTPONLY: bool = False

    # ==========================================================================
    # SCHWACHSTELLE #28: BSI TR-03161 O.Data_17
    # CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    # OWASP A02:2025 - Security Misconfiguration
    # BESCHREIBUNG: Session-Cookie ohne Secure-Flag, wird über HTTP übertragen.
    # ERWARTETE SAST-ERKENNUNG: Flask SESSION_COOKIE_SECURE=False
    # ==========================================================================
    SESSION_COOKIE_SECURE: bool = False

    # ==========================================================================
    # SCHWACHSTELLE #29: BSI TR-03161 O.Data_19
    # CWE-1275: Sensitive Cookie with Improper SameSite Attribute
    # OWASP A01:2025 - Broken Access Control
    # BESCHREIBUNG: SameSite='None' erlaubt Cross-Site-Requests mit Cookie,
    #               macht Anwendung anfällig für CSRF-Angriffe.
    # ERWARTETE SAST-ERKENNUNG: Flask SESSION_COOKIE_SAMESITE='None'
    # ==========================================================================
    SESSION_COOKIE_SAMESITE: str = 'None'
    SESSION_COOKIE_NAME: str = 'session'  # Kein Host-Prefix

    # ==========================================================================
    # SCHWACHSTELLE #22: BSI TR-03161 O.Pass_1
    # CWE-521: Weak Password Requirements
    # OWASP A07:2025 - Authentication Failures
    # BESCHREIBUNG: Minimale Passwortlänge nur 6 Zeichen, BSI empfiehlt 12.
    # ERWARTETE SAST-ERKENNUNG: Password policy configuration check
    # ==========================================================================
    PASSWORD_MIN_LENGTH: int = 6
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # ==========================================================================
    # SCHWACHSTELLE #15: BSI TR-03161 O.Cryp_5
    # CWE-916: Use of Password Hash With Insufficient Computational Effort
    # OWASP A04:2025 - Cryptographic Failures
    # BESCHREIBUNG: bcrypt-Runden auf 4 gesetzt, Minimum sollte 12 sein.
    # ERWARTETE SAST-ERKENNUNG: Weak bcrypt rounds configuration
    # ==========================================================================
    BCRYPT_ROUNDS: int = 4


class DevelopmentConfig(Config):
    """Entwicklungskonfiguration."""
    pass


def get_config() -> Config:
    """Gibt die aktive Konfiguration zurück."""
    env = os.environ.get('FLASK_ENV', 'production')
    if env == 'development':
        return DevelopmentConfig()
    return Config()
