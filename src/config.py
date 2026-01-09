"""
Zentrale Konfiguration der Anwendung.
BSI O.Cryp_1: Keine hardcodierten Schlüssel - Secrets aus Umgebungsvariablen.
BSI O.Source_6: Kein Debug-Mode in Produktion.
BSI O.Data_1: Sichere Werkseinstellungen.
"""
import os
import secrets


class Config:
    """Sichere Konfigurationsklasse mit Defaults nach BSI-Standards."""

    # BSI O.Cryp_1: Secret Key aus Umgebungsvariable, niemals hardcoded
    SECRET_KEY: str = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

    # BSI O.Source_6: Debug-Mode explizit deaktiviert
    DEBUG: bool = False
    TESTING: bool = False

    # Datenbankpfad
    DATABASE_PATH: str = os.environ.get('DATABASE_PATH', 'medical_app.db')

    # BSI O.Auth_9: Session-Timeout nach Idle-Zeit (30 Minuten)
    PERMANENT_SESSION_LIFETIME: int = 1800

    # BSI O.Auth_10: Maximale aktive Nutzungszeit (8 Stunden)
    MAX_SESSION_DURATION: int = 28800

    # BSI O.Auth_7: Brute-Force-Schutz
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_DURATION: int = 900  # 15 Minuten

    # BSI O.Data_16, O.Data_17, O.Data_19: Cookie-Sicherheit
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Strict'
    SESSION_COOKIE_NAME: str = '__Host-session'  # BSI O.Data_19: Host-Prefix verhindert Domain-Cookies

    # BSI O.Pass_1: Passwortrichtlinien
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # BSI O.Cryp_5: Angemessene Schlüsselstärke für Passwort-Hashing
    BCRYPT_ROUNDS: int = 12


class DevelopmentConfig(Config):
    """Entwicklungskonfiguration - nur für lokale Tests."""
    # BSI O.Data_17: Secure-Flag kann lokal deaktiviert werden (kein HTTPS)
    SESSION_COOKIE_SECURE: bool = False


def get_config() -> Config:
    """
    Gibt die aktive Konfiguration zurück.
    BSI O.Data_1: Sichere Defaults - Produktion ist Standard.
    """
    env = os.environ.get('FLASK_ENV', 'production')
    if env == 'development':
        return DevelopmentConfig()
    return Config()
