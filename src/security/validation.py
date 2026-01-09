"""
Input-Validierung mit Marshmallow.
BSI O.Source_1: Validierung aller Eingaben.
BSI O.Source_2: Maskierung/Bereinigung von Daten.
BSI O.Source_10: Schutz vor Code-Einschleusung.
"""
import re
from typing import Any, Dict, Optional, Tuple, Type
from marshmallow import Schema, fields, validate, ValidationError, pre_load, post_load
from markupsafe import escape
from config import get_config


config = get_config()


class StrictStringField(fields.String):
    """
    String-Feld mit strikter Validierung.
    BSI O.Source_1: Whitelist-basierte Validierung.
    BSI O.Source_2: Automatische Bereinigung.
    """

    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> Optional[str]:
        if value is None:
            return None
        result = super()._deserialize(value, attr, data, **kwargs)
        if result:
            # BSI O.Source_2: Entferne Steuerzeichen außer Whitespace
            result = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', result)
        return result


class SafeEmailField(fields.Email):
    """
    E-Mail-Feld mit zusätzlicher Validierung.
    BSI O.Source_1: Strikte E-Mail-Validierung.
    """

    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> Optional[str]:
        result = super()._deserialize(value, attr, data, **kwargs)
        if result:
            # BSI O.Source_1: Zusätzliche Prüfung auf gefährliche Zeichen
            if any(char in result for char in ['<', '>', '"', "'"]):
                raise ValidationError('Ungültige Zeichen in E-Mail-Adresse')
            result = result.lower().strip()
        return result


# === Benutzer-Schemas ===

class UserLoginSchema(Schema):
    """
    Schema für Login-Anfragen.
    BSI O.Source_1: Validierung aller Login-Eingaben.
    """
    username = StrictStringField(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error='Nur alphanumerische Zeichen und Unterstriche erlaubt')
        ]
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=1, max=128),
        load_only=True  # BSI O.Source_11: Passwort nie in Response
    )


class PasswordChangeSchema(Schema):
    """
    Schema für Passwortänderungen.
    BSI O.Pass_1: Starke Passwortrichtlinien.
    BSI O.Auth_11: Re-Auth vor Credential-Änderung.
    """
    current_password = fields.String(
        required=True,
        validate=validate.Length(min=1, max=128),
        load_only=True
    )
    new_password = fields.String(
        required=True,
        validate=validate.Length(min=config.PASSWORD_MIN_LENGTH, max=128),
        load_only=True
    )

    @post_load
    def validate_password_strength(self, data: Dict, **kwargs) -> Dict:
        """BSI O.Pass_1: Passwortrichtlinien prüfen."""
        password = data.get('new_password', '')

        if config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            raise ValidationError({'new_password': ['Mindestens ein Großbuchstabe erforderlich']})

        if config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            raise ValidationError({'new_password': ['Mindestens ein Kleinbuchstabe erforderlich']})

        if config.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
            raise ValidationError({'new_password': ['Mindestens eine Ziffer erforderlich']})

        if config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError({'new_password': ['Mindestens ein Sonderzeichen erforderlich']})

        return data


class UserCreateSchema(Schema):
    """
    Schema für Benutzererstellung.
    BSI O.Source_1: Strikte Validierung aller Felder.
    """
    username = StrictStringField(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error='Nur alphanumerische Zeichen und Unterstriche erlaubt')
        ]
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=config.PASSWORD_MIN_LENGTH, max=128),
        load_only=True
    )
    email = SafeEmailField(required=True)
    role = StrictStringField(
        required=True,
        validate=validate.OneOf(['doctor', 'nurse', 'admin'])
    )


# === Patienten-Schemas ===

class PatientCreateSchema(Schema):
    """
    Schema für Patientenerstellung.
    BSI O.Source_1: Validierung medizinischer Daten.
    """
    mrn = StrictStringField(
        required=True,
        validate=[
            validate.Length(min=5, max=20),
            validate.Regexp(r'^[A-Z0-9-]+$', error='MRN: Nur Großbuchstaben, Ziffern und Bindestriche')
        ]
    )
    first_name = StrictStringField(
        required=True,
        validate=validate.Length(min=1, max=100)
    )
    last_name = StrictStringField(
        required=True,
        validate=validate.Length(min=1, max=100)
    )
    date_of_birth = fields.Date(required=True, format='%Y-%m-%d')


class PatientUpdateSchema(Schema):
    """
    Schema für Patientenaktualisierung.
    BSI O.Source_1: Nur erlaubte Felder aktualisierbar (kein Mass Assignment).
    """
    first_name = StrictStringField(validate=validate.Length(min=1, max=100))
    last_name = StrictStringField(validate=validate.Length(min=1, max=100))


class DiagnosisSchema(Schema):
    """
    Schema für Diagnosedaten.
    BSI O.Source_1: Strikte Validierung sensibler medizinischer Daten.
    """
    patient_id = fields.Integer(required=True, strict=True, validate=validate.Range(min=1))
    icd_code = StrictStringField(
        required=True,
        validate=[
            validate.Length(min=3, max=10),
            validate.Regexp(r'^[A-Z]\d{2}(\.\d{1,2})?$', error='Ungültiges ICD-Code-Format')
        ]
    )
    description = StrictStringField(
        required=True,
        validate=validate.Length(min=1, max=500)
    )


# === Termin-Schemas ===

class AppointmentCreateSchema(Schema):
    """
    Schema für Terminerstellung.
    BSI O.Source_1: Validierung aller Terminfelder.
    """
    patient_id = fields.Integer(required=True, strict=True, validate=validate.Range(min=1))
    scheduled_at = fields.DateTime(required=True, format='%Y-%m-%dT%H:%M:%S')
    duration_minutes = fields.Integer(
        required=True,
        strict=True,
        validate=validate.Range(min=5, max=480)
    )
    appointment_type = StrictStringField(
        required=True,
        validate=validate.OneOf(['consultation', 'followup', 'emergency', 'procedure'])
    )
    notes = StrictStringField(validate=validate.Length(max=1000))


class AppointmentUpdateSchema(Schema):
    """
    Schema für Terminaktualisierung.
    BSI O.Source_1: Nur erlaubte Felder (kein Mass Assignment).
    """
    scheduled_at = fields.DateTime(format='%Y-%m-%dT%H:%M:%S')
    duration_minutes = fields.Integer(strict=True, validate=validate.Range(min=5, max=480))
    status = StrictStringField(validate=validate.OneOf(['scheduled', 'completed', 'cancelled']))
    notes = StrictStringField(validate=validate.Length(max=1000))


# === ID-Schema für Pfadparameter ===

class IdParameterSchema(Schema):
    """
    Schema für ID-Parameter in URLs.
    BSI O.Source_1: Validierung von Pfadparametern.
    """
    id = fields.Integer(required=True, strict=True, validate=validate.Range(min=1))


def validate_input(schema_class: Type[Schema], data: Dict[str, Any]) -> Tuple[Optional[Dict], Optional[Dict]]:
    """
    Zentrale Validierungsfunktion.

    BSI O.Source_1: Einheitliche Eingabevalidierung.
    BSI O.Source_4: Kontrollierte Fehlerbehandlung.

    Args:
        schema_class: Marshmallow-Schema-Klasse
        data: Zu validierende Daten

    Returns:
        Tuple (validierte_daten, fehler)
        Bei Erfolg: (daten, None)
        Bei Fehler: (None, fehler_dict)
    """
    schema = schema_class()
    try:
        validated = schema.load(data)
        return validated, None
    except ValidationError as err:
        # BSI O.Source_4: Fehler ohne sensible Details
        return None, err.messages


def sanitize_output(value: str) -> str:
    """
    Bereinigt Ausgabewerte für sichere Darstellung.

    BSI O.Source_2: HTML-Escaping für XSS-Schutz.

    Args:
        value: Roher String

    Returns:
        HTML-escaped String
    """
    if value is None:
        return ''
    return str(escape(value))


# ==========================================================================
# SCHWACHSTELLE #11: BSI TR-03161 O.TrdP_7
# CWE-20: Improper Input Validation
# OWASP A05:2025 - Injection
# BESCHREIBUNG: Externe Daten (z.B. von Third-Party APIs) werden ohne
#               jegliche Validierung akzeptiert und weitergegeben.
#               Keine Schema-Prüfung, keine Typ-Validierung, keine Sanitization.
#               Korrekt wäre: validate_input() mit passendem Schema.
# ERWARTETE SAST-ERKENNUNG: Missing validation of external data
# ==========================================================================
def accept_external_data_raw(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    UNSICHERE Funktion: Akzeptiert externe Daten ohne jegliche Validierung.

    WARNUNG: Keine Schema-Validierung, keine Typ-Prüfung, keine Sanitization!
    """
    # Externe Daten werden direkt ohne Validierung zurückgegeben
    return data
