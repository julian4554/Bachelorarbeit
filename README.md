# Automatisiertes SAST in DevSecOps-CI/CD-Pipelines

Prototyp und Begleitcode zu meiner Bachelorarbeit zum Thema **automatisierte Integration
von Static Application Security Testing (SAST) in CI/CD-Pipelines** im Kontext
sicherheitskritischer (Healthcare-)Software.

> Hinweis: Dieses Repository enthält den technischen Prototyp. Die schriftliche
> Bachelorarbeit ist nicht Teil dieses Repositories.

## Worum es geht

Sicherheitsprüfungen werden in der Praxis oft erst spät im Entwicklungsprozess oder
manuell durchgeführt. Ziel dieser Arbeit war es, SAST so in eine CI/CD-Pipeline zu
integrieren, dass Schwachstellen **automatisiert bei jedem Commit/Merge** erkannt werden
("Shift Left"), ohne den Entwicklungsfluss übermäßig zu bremsen – und dass das Ergebnis
gegen definierte Sicherheitsrichtlinien durchgesetzt werden kann (Pipeline schlägt fehl,
wenn kritische Findings auftreten).

Schwerpunkte:

- Automatisierte Einbindung von SAST-Werkzeugen in die Pipeline
- Durchsetzung von Sicherheitsrichtlinien (Policy-as-Gate / Quality Gate)
- Auswertung und Aufbereitung der Scan-Ergebnisse
- Betrachtung im Healthcare-/regulierten Kontext

## Architektur / Ablauf

```
Commit / Pull Request
        │
        ▼
  CI/CD-Pipeline (GitHub Actions, .github/workflows)
        │
        ├─ Dependency-Install (requirements.txt)
        ├─ SAST-Scan (src/)
        ├─ Auswertung der Findings
        └─ Policy-Gate → Pipeline pass / fail
```

## Verwendete Technologien

- **Sprache:** Python
- **CI/CD:** GitHub Actions (`.github/workflows/`)
- **SAST-Tooling:** Semgrep/CodeQL
- **Abhängigkeiten:** siehe `requirements.txt`


## Kontext

Entstanden im Rahmen der Bachelorarbeit im Studiengang Softwareentwicklung (B.Sc.),
IU Internationale Hochschule. Note: 1,3.
