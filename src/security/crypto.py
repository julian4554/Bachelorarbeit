"""
Kryptographische Funktionen für sichere Passwortverarbeitung.
BSI O.Cryp_2: Bewährte Krypto-Implementierungen (bcrypt).
BSI O.Cryp_3: Angemessene kryptographische Primitive.
BSI O.Cryp_5: Angemessene Schlüsselstärke.
BSI O.Pass_5: Sichere Passwort-Speicherung.
"""
import bcrypt
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
