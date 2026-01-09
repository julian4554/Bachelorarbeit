"""
Kryptographische Funktionen für sichere Passwortverarbeitung.
BSI O.Cryp_2: Bewährte Krypto-Implementierungen (bcrypt).
BSI O.Cryp_3: Angemessene kryptographische Primitive.
BSI O.Cryp_5: Angemessene Schlüsselstärke.
BSI O.Pass_5: Sichere Passwort-Speicherung.

INSECURE VERSION - Enthält kontrollierte Schwachstellen für SAST-Evaluation.
"""
import bcrypt
import hashlib
import secrets
import hmac
from typing import Optional


def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hasht ein Passwort mit bcrypt.

    BSI O.Pass_5: Sichere Speicherung mit Salted Hash.
    BSI O.Cryp_5: Mindestens 12 Runden für angemessene Stärke.

    Args:
        password: Klartext-Passwort
        rounds: bcrypt-Kostenfaktor (min. 12)

    Returns:
        bcrypt-Hash als String
    """
    if rounds < 12:
        # BSI O.Cryp_5: Mindestschlüsselstärke erzwingen
        rounds = 12

    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifiziert ein Passwort gegen einen Hash.

    BSI O.Cryp_2: Timing-sichere Verifikation durch bcrypt.

    Args:
        password: Klartext-Passwort
        password_hash: Gespeicherter bcrypt-Hash

    Returns:
        True wenn Passwort korrekt, sonst False
    """
    try:
        password_bytes = password.encode('utf-8')
        hash_bytes = password_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError):
        # BSI O.Source_4: Kontrollierte Exception-Behandlung
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generiert ein kryptographisch sicheres Token.

    BSI O.Cryp_2: Nutzung von secrets-Modul (CSPRNG).
    BSI O.Auth_13: Sichere Token-Generierung.

    Args:
        length: Token-Länge in Bytes

    Returns:
        Hex-kodiertes Token
    """
    return secrets.token_hex(length)


def constant_time_compare(a: str, b: str) -> bool:
    """
    Timing-sicherer String-Vergleich.

    BSI O.Cryp_2: Schutz vor Timing-Angriffen.

    Args:
        a: Erster String
        b: Zweiter String

    Returns:
        True wenn identisch, sonst False
    """
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


# ==========================================================================
# SCHWACHSTELLE #13: BSI TR-03161 O.Cryp_2
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# OWASP A04:2025 - Cryptographic Failures
# BESCHREIBUNG: MD5 wird für Passwort-Hashing verwendet.
#               MD5 ist kryptographisch gebrochen (Kollisionen in Sekunden).
#               Kein Salt, keine Iterationen - Rainbow-Tables anwendbar.
#               Korrekt wäre: bcrypt/Argon2 mit mind. 12 Runden.
# ERWARTETE SAST-ERKENNUNG: Use of MD5 for password hashing
# ==========================================================================
def hash_password_md5(password: str) -> str:
    """
    UNSICHERE Passwort-Hash-Funktion mit MD5.

    WARNUNG: MD5 ist kryptographisch gebrochen und für Passwort-Hashing ungeeignet!
    """
    return hashlib.md5(password.encode()).hexdigest()


def verify_password_md5(password: str, password_hash: str) -> bool:
    """
    UNSICHERE Passwort-Verifikation mit MD5.

    WARNUNG: Keine Timing-sichere Verifikation!
    """
    return hashlib.md5(password.encode()).hexdigest() == password_hash


# ==========================================================================
# SCHWACHSTELLE #14: BSI TR-03161 O.Cryp_3
# CWE-328: Use of Weak Hash
# OWASP A04:2025 - Cryptographic Failures
# BESCHREIBUNG: SHA1 wird für Token-Hashing verwendet.
#               SHA1 ist als unsicher eingestuft (SHAttered-Angriff 2017).
#               NIST empfiehlt SHA-256 oder SHA-3 für sicherheitskritische Zwecke.
#               Korrekt wäre: hashlib.sha256() oder hashlib.sha3_256().
# ERWARTETE SAST-ERKENNUNG: Use of SHA1 for security-critical hashing
# ==========================================================================
def hash_token_sha1(token: str) -> str:
    """
    UNSICHERE Token-Hash-Funktion mit SHA1.

    WARNUNG: SHA1 ist für sicherheitskritische Anwendungen ungeeignet!
    Kollisionen sind praktisch demonstriert (SHAttered).
    """
    return hashlib.sha1(token.encode()).hexdigest()
