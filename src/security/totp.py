"""
Zwei-Faktor-Authentifizierung mit TOTP.
BSI O.Cryp_2: Bewährte Krypto-Implementierung (TOTP nach RFC 6238).
BSI O.Cryp_5: Angemessene Schlüsselstärke (160-bit Secret).
BSI O.Source_1: Token-Format-Validierung.
BSI O.Source_4: Kontrollierte Exception-Behandlung.

EXCLUDED: O.Auth_3 - REASON: K4 (2FA-Existenz/Vollständigkeit nicht SAST-detektierbar)
"""
import pyotp
import base64
import io
from typing import Optional, Tuple
import qrcode
from qrcode.image.pure import PyPNGImage

from security.crypto import generate_secure_token


# BSI O.Cryp_5: TOTP Secret mit 160-bit (20 Bytes) Entropie
TOTP_SECRET_LENGTH = 20

# EXCLUDED: O.Auth_3 - REASON: K4 (TOTP-Parameter-Konfiguration)
TOTP_INTERVAL = 30  # Sekunden
TOTP_DIGITS = 6
TOTP_ALGORITHM = 'SHA1'  # Standard für TOTP-Kompatibilität

# Issuer für Authenticator-Apps
TOTP_ISSUER = 'MedicalApp'


def generate_totp_secret() -> str:
    """
    Generiert ein neues TOTP-Secret.

    BSI O.Cryp_5: 160-bit Secret für angemessene Schlüsselstärke.
    BSI O.Cryp_2: Kryptographisch sichere Zufallsgenerierung.

    Returns:
        Base32-kodiertes TOTP-Secret
    """
    # Generiere 20 Bytes (160 bit) zufällige Daten
    random_bytes = bytes.fromhex(generate_secure_token(TOTP_SECRET_LENGTH))
    # Base32-Kodierung für TOTP-Kompatibilität
    return base64.b32encode(random_bytes).decode('utf-8')


def create_totp(secret: str) -> pyotp.TOTP:
    """
    Erstellt TOTP-Instanz mit sicheren Parametern.

    EXCLUDED: O.Auth_3 - REASON: K4 (Standard-konforme TOTP-Konfiguration)

    Args:
        secret: Base32-kodiertes Secret

    Returns:
        Konfigurierte TOTP-Instanz
    """
    return pyotp.TOTP(
        secret,
        interval=TOTP_INTERVAL,
        digits=TOTP_DIGITS
    )


def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verifiziert ein TOTP-Token.

    EXCLUDED: O.Auth_3 - REASON: K4 (TOTP-Validierung)

    Args:
        secret: Base32-kodiertes Secret
        token: 6-stelliger TOTP-Code
        valid_window: Anzahl der Zeitfenster für Toleranz (default: 1 = ±30s)

    Returns:
        True wenn Token gültig, sonst False
    """
    if not secret or not token:
        return False

    # BSI O.Source_1: Token-Format validieren
    if not token.isdigit() or len(token) != TOTP_DIGITS:
        return False

    try:
        totp = create_totp(secret)
        # valid_window=1 erlaubt ±30 Sekunden für Zeitdrift
        return totp.verify(token, valid_window=valid_window)
    except Exception:
        # BSI O.Source_4: Kontrollierte Exception-Behandlung
        return False


def get_totp_provisioning_uri(secret: str, username: str) -> str:
    """
    Generiert Provisioning-URI für Authenticator-Apps.

    EXCLUDED: O.Auth_3 - REASON: K4 (URI für 2FA-Setup)

    Args:
        secret: Base32-kodiertes Secret
        username: Benutzername für Anzeige in App

    Returns:
        otpauth:// URI
    """
    totp = create_totp(secret)
    return totp.provisioning_uri(
        name=username,
        issuer_name=TOTP_ISSUER
    )


def generate_totp_qr_code(secret: str, username: str) -> str:
    """
    Generiert QR-Code als Base64-PNG für 2FA-Setup.

    EXCLUDED: O.Auth_3 - REASON: K4 (QR-Code für 2FA-Onboarding)

    Args:
        secret: Base32-kodiertes Secret
        username: Benutzername

    Returns:
        Base64-kodierter PNG-String
    """
    uri = get_totp_provisioning_uri(secret, username)

    # QR-Code generieren
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    # Als PNG in Memory speichern
    img = qr.make_image(fill_color="black", back_color="white", image_factory=PyPNGImage)
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)

    # Base64 kodieren
    return base64.b64encode(buffer.read()).decode('utf-8')


def get_current_totp(secret: str) -> str:
    """
    Gibt aktuellen TOTP-Code zurück (nur für Tests/Debug).

    WARNUNG: Nicht in Produktion verwenden!

    Args:
        secret: Base32-kodiertes Secret

    Returns:
        Aktueller 6-stelliger TOTP-Code
    """
    totp = create_totp(secret)
    return totp.now()
