"""
Hauptanwendung: Flask-Konfiguration und Sicherheits-Setup.
BSI O.Arch_8: Sichere HTTP-Header.
BSI O.Arch_9: Security-Header nach Best Practices.
BSI O.Source_4: Kontrollierte Exception-Behandlung.
BSI O.Source_6: Kein Debug-Mode.
BSI O.Source_9: Keine unkontrollierten URL-Weiterleitungen.
BSI O.Data_16: HttpOnly-Cookies.
BSI O.Data_17: Secure-Cookies.
BSI O.Data_19: Domain-Cookie-Vermeidung.
BSI O.Plat_6: Content-Loading-Beschränkung durch CSP.

EXCLUDED: O.Arch_7 - REASON: K4 (Browser-Versionsinterpretation erfordert semantisches Verständnis)
EXCLUDED: O.Data_18 - REASON: K2 (Autocomplete ist Frontend-/HTML-Attribut)
EXCLUDED: O.Ntwk_1 - REASON: K2 (HTTPS-Terminierung auf Infrastruktur-Ebene)
"""
import os
import sys
from datetime import timedelta
from flask import Flask, jsonify, request, g
from typing import Tuple, Dict, Any

# Füge src zum Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import get_config
from database import init_db, close_db_connection, get_db_connection
from security.audit import audit_log
from security.authentication import validate_session
from security.browser_check import check_browser_version, get_browser_warning_header


def create_app() -> Flask:
    """
    Application Factory.

    BSI O.Data_1: Sichere Werkseinstellungen.
    BSI O.Source_6: Debug-Mode deaktiviert.

    Returns:
        Konfigurierte Flask-Anwendung
    """
    app = Flask(__name__)
    config = get_config()

    # === Flask-Konfiguration ===
    # BSI O.Source_6: Debug explizit deaktiviert
    app.config['DEBUG'] = False
    app.config['TESTING'] = False

    # BSI O.Cryp_1: Secret Key aus Konfiguration
    app.config['SECRET_KEY'] = config.SECRET_KEY

    # === Session-Konfiguration ===
    # BSI O.Data_16: HttpOnly-Flag
    app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
    # BSI O.Data_17: Secure-Flag
    app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
    # BSI O.Data_19: SameSite und Host-Prefix gegen Domain-Cookies
    app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
    app.config['SESSION_COOKIE_NAME'] = config.SESSION_COOKIE_NAME
    # BSI O.Auth_9: Session-Timeout
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config.PERMANENT_SESSION_LIFETIME)

    # === Datenbank ===
    init_db()
    app.teardown_appcontext(close_db_connection)

    # === Blueprints registrieren ===
    from blueprints.auth import auth_bp
    from blueprints.patient import patient_bp
    from blueprints.appointments import appointments_bp
    from blueprints.admin import admin_bp
    from blueprints.consent import consent_bp
    from blueprints.export import export_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(appointments_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(consent_bp)
    app.register_blueprint(export_bp)

    # === Before Request: Session-Validierung ===
    @app.before_request
    def before_request() -> None:
        """
        Vor jedem Request: Session validieren.
        BSI O.Auth_9/O.Auth_10: Automatische Timeout-Prüfung.
        """
        # Öffentliche Endpoints ausnehmen
        public_endpoints = {'auth.login', 'static', 'health_check'}
        if request.endpoint in public_endpoints:
            return

        # Session validieren und User in g speichern
        user = validate_session()
        if user:
            g.current_user = user
        else:
            g.current_user = None

    # === After Request: Security Headers ===
    @app.after_request
    def add_security_headers(response):
        """
        Fügt Security-Header zu jeder Response hinzu.

        BSI O.Arch_8: Browser-Sicherheitsprüfung durch Header.
        BSI O.Arch_9: Sichere HTTP-Header.
        BSI O.Plat_6: Content-Loading-Beschränkung durch CSP.

        EXCLUDED: O.Ntwk_1 - REASON: K2 (Infrastruktur-Ebene)
        EXCLUDED: O.Data_18 - REASON: K2 (Frontend-Aspekt)
        """
        # BSI O.Arch_9: Content-Security-Policy
        # BSI O.Plat_6: Restriktive CSP gegen XSS und unerlaubtes Laden
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "font-src 'none'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'none'"
        )

        # BSI O.Arch_9: X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # BSI O.Arch_9: X-Frame-Options (zusätzlich zu CSP)
        response.headers['X-Frame-Options'] = 'DENY'

        # BSI O.Arch_9: Referrer-Policy
        response.headers['Referrer-Policy'] = 'no-referrer'

        # BSI O.Arch_9: Permissions-Policy (Feature-Policy)
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=()'
        )

        # EXCLUDED: O.Ntwk_1 - REASON: K2 (Infrastruktur-Ebene)
        # Strict-Transport-Security (HSTS) - Max-age 1 Jahr, includeSubDomains
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # EXCLUDED: O.Data_18 - REASON: K2 (Frontend-Aspekt)
        # Cache-Control für sensible Daten
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        # BSI O.Arch_9: X-XSS-Protection (legacy, aber schadet nicht)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # BSI O.Arch_8 / EXCLUDED: O.Arch_7 - REASON: K4 (semantisches Verständnis)
        # Browser-Aktualitätswarnung
        browser_warning = get_browser_warning_header()
        if browser_warning:
            response.headers['Warning'] = browser_warning

        return response

    # === Error Handler ===
    # BSI O.Source_4: Kontrollierte Exception-Behandlung ohne Datenlecks

    @app.errorhandler(400)
    def bad_request(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Generische 400-Fehlermeldung."""
        return jsonify({'error': 'Ungültige Anfrage'}), 400

    @app.errorhandler(401)
    def unauthorized(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Generische 401-Fehlermeldung."""
        return jsonify({'error': 'Authentifizierung erforderlich'}), 401

    @app.errorhandler(403)
    def forbidden(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Generische 403-Fehlermeldung."""
        return jsonify({'error': 'Keine Berechtigung'}), 403

    @app.errorhandler(404)
    def not_found(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Generische 404-Fehlermeldung."""
        return jsonify({'error': 'Ressource nicht gefunden'}), 404

    @app.errorhandler(405)
    def method_not_allowed(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Generische 405-Fehlermeldung."""
        return jsonify({'error': 'Methode nicht erlaubt'}), 405

    @app.errorhandler(429)
    def too_many_requests(error) -> Tuple[Dict[str, Any], int]:
        """BSI O.Source_4: Rate-Limit-Fehlermeldung."""
        return jsonify({'error': 'Zu viele Anfragen'}), 429

    @app.errorhandler(500)
    def internal_error(error) -> Tuple[Dict[str, Any], int]:
        """
        BSI O.Source_4: Generische 500-Fehlermeldung ohne Stack-Trace.
        Interner Fehler wird geloggt, aber nicht an Client gesendet.
        """
        audit_log('internal_error', {'error_type': 'unhandled_exception'})
        return jsonify({'error': 'Interner Serverfehler'}), 500

    @app.errorhandler(Exception)
    def handle_exception(error) -> Tuple[Dict[str, Any], int]:
        """
        BSI O.Source_4: Catch-All für unbehandelte Exceptions.
        Verhindert Exposition von Stack-Traces.
        """
        audit_log('unhandled_exception', {'error_type': type(error).__name__})
        return jsonify({'error': 'Interner Serverfehler'}), 500

    # === Health Check (öffentlich) ===
    @app.route('/health', methods=['GET'])
    def health_check() -> Tuple[Dict[str, Any], int]:
        """
        Health-Check-Endpoint ohne Authentifizierung.
        Gibt keine sensiblen Informationen preis.
        """
        return jsonify({'status': 'healthy'}), 200

    # === URL-Weiterleitungsschutz ===
    # BSI O.Source_9: Keine Weiterleitung zu user-kontrollierten URLs
    # Implementiert: Keine Redirect-Funktionalität in der Anwendung

    return app


def create_initial_admin() -> None:
    """
    Erstellt initialen Admin-Benutzer falls keiner existiert.

    BSI O.Data_1: Sichere Ersteinrichtung.
    BSI O.Pass_5: Admin-Passwort sicher gehasht.

    WICHTIG: Passwort muss nach Erstanmeldung geändert werden!
    """
    from security.crypto import hash_password

    # Admin-Credentials aus Umgebungsvariablen
    admin_username = os.environ.get('INITIAL_ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('INITIAL_ADMIN_PASSWORD')
    admin_email = os.environ.get('INITIAL_ADMIN_EMAIL', 'admin@localhost')

    if not admin_password:
        print("WARNUNG: INITIAL_ADMIN_PASSWORD nicht gesetzt. Überspringe Admin-Erstellung.")
        return

    import sqlite3
    config = get_config()
    conn = sqlite3.connect(config.DATABASE_PATH)

    try:
        # Prüfe ob Admin existiert
        cursor = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        if cursor.fetchone():
            return  # Admin existiert bereits

        # Erstelle Admin
        password_hash = hash_password(admin_password)
        conn.execute(
            """
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, 'admin')
            """,
            (admin_username, password_hash, admin_email)
        )
        conn.commit()
        print(f"Admin-Benutzer '{admin_username}' erstellt. Passwort nach Erstanmeldung ändern!")
    finally:
        conn.close()


# === Anwendungsstart ===
if __name__ == '__main__':
    # BSI O.Source_6: Kein Debug-Mode
    # EXCLUDED: O.Ntwk_1 - REASON: K2 (Infrastruktur-Ebene)
    # In Produktion hinter HTTPS-Reverse-Proxy betreiben

    app = create_app()

    # Initialen Admin erstellen
    create_initial_admin()

    # Entwicklungsserver (nur für lokale Tests!)
    # In Produktion: gunicorn oder waitress verwenden
    print("WARNUNG: Entwicklungsserver gestartet. Nicht für Produktion geeignet!")
    print("Für Produktion: gunicorn -w 4 -b 127.0.0.1:5000 'app:create_app()'")

    app.run(
        host='127.0.0.1',  # Nur localhost
        port=5000,
        debug=False,  # BSI O.Source_6: Explizit deaktiviert
        threaded=True
    )
