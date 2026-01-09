"""
Blueprints-Modul: Modulare Strukturierung der API-Endpoints.
Strikte Trennung nach Funktionsbereichen.
"""
from blueprints.auth import auth_bp
from blueprints.patient import patient_bp
from blueprints.appointments import appointments_bp
from blueprints.admin import admin_bp
from blueprints.consent import consent_bp
from blueprints.export import export_bp

__all__ = ['auth_bp', 'patient_bp', 'appointments_bp', 'admin_bp', 'consent_bp', 'export_bp']
