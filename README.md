# network-sniffer

Entwickelt von der Software-Fabrik.

network-sniffer ist ein Windows-Dienst zur **defensiven Data-Leak-Erkennung** im Netzwerkverkehr des eigenen PCs.
Er schneidet den Verkehr über [Npcap](https://npcap.com/) live mit, erkennt darin über eine Regel-Engine unverschlüsselt
übertragene Geheimnisse (Passwörter, Tokens, Schlüssel o. Ä.) und zeigt die Funde maskiert in einem Web-Dashboard an.

- **Nur der eigene PC:** Mitschnitt nicht-promiskuitiv; Npcap installiert der Betreiber separat (wird nicht mitgeliefert).
- **Nur lokal erreichbar:** Das Dashboard bindet ausschließlich an `127.0.0.1`.
- **Mehrbenutzerbetrieb** mit den Rollen **Admin** und **Analyst**.
- **Nur Klartext-Protokolle:** TLS-verschlüsselter Verkehr ist nicht analysierbar.
- **Datensparsam:** Es werden keine Rohpakete, Nutzdaten oder .pcap-Dateien gespeichert – nur maskierte Funde.

## Status
Das Projekt ist im Aufbau; es gibt **noch keinen lauffähigen Code**. Installation, Start und Bedienung werden mit
KAN-12 (Walking Skeleton) und den folgenden Stories ergänzt.

## Architektur
- [ADR 0002 – Tech-Stack und Architektur](docs/adr/0002-tech-stack-und-architektur.md): Python 3.12, FastAPI,
  Jinja2-Dashboard, SQLite, Npcap + Scapy, pywin32-Dienst, PyInstaller-Paket – inkl. verworfener Alternativen.
- Alle Entscheidungen: [docs/adr](docs/adr)
  - [0001 – Architekturentscheidungen als ADRs dokumentieren](docs/adr/0001-architekturentscheidungen-dokumentieren.md)
  - [0002 – Tech-Stack und Architektur](docs/adr/0002-tech-stack-und-architektur.md)

## Entwicklung
Siehe [CLAUDE.md](CLAUDE.md) für Stack, Befehle und Konventionen. Die dort genannten Befehle stehen erst zur
Verfügung, sobald das Projektgerüst mit KAN-12 angelegt ist.

## Releases
Versionierung nach [SemVer](https://semver.org/lang/de/), Änderungen in [CHANGELOG.md](CHANGELOG.md).

## Lizenz
Lizenz: GPL-2.0-only (siehe [LICENSE](LICENSE))
