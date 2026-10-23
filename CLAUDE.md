# network-sniffer

> Wird vom `architect`-Agenten gepflegt. Alle Agenten verwenden die Befehle aus diesem Dokument.

## Produkt
Windows-Dienst zur defensiven Data-Leak-Erkennung im Netzwerkverkehr des eigenen PCs: Live-Mitschnitt über Npcap im
Dauerbetrieb, Erkennung unverschlüsselt übertragener Geheimnisse über eine Regel-Engine, maskierte Funde in einem
Web-Dashboard auf `127.0.0.1`. Mehrbenutzerbetrieb mit den Rollen Admin und Analyst. Lizenz: GPL-2.0-only.
Architektur in Confluence: https://christianjanz90.atlassian.net/wiki/spaces/SOFTWAREEN/pages/622593

## Tech-Stack
Entscheidung und verworfene Alternativen: [ADR 0002](docs/adr/0002-tech-stack-und-architektur.md).

| Bereich | Technologie |
|---|---|
| Sprache | Python 3.12 |
| Backend/API | FastAPI + Uvicorn, Pydantic v2, pydantic-settings (Präfix `NS_`) |
| Dashboard | Jinja2 (Autoescape), HTML/CSS, serverseitiges SVG, kein JS-Build |
| Datenhaltung | SQLite (WAL, `secure_delete=ON`), SQLAlchemy 2, Alembic |
| Live-Mitschnitt | Npcap (vom Betreiber installiert) + Scapy (`L2pcapListenSocket`, `recv_raw()`, eigener Header-Parser) |
| Regeln | `regex` (mit Timeout) |
| Auth | argon2-cffi (Argon2id), serverseitige Sitzungen |
| Windows-Dienst | pywin32 |
| Paketierung | PyInstaller onedir → `network-sniffer-<version>-windows-x64.zip` |
| Tests | pytest, pytest-cov (≥ 80 %), httpx/TestClient, time-machine |
| Lint/Format | Ruff |
| Paketverwaltung | uv (`pyproject.toml`, `uv.lock`) |

## Befehle
Jeder Befehl einzeln ausführen (kein `&&`), damit er auch in Windows PowerShell 5.1 funktioniert.

| Zweck | Befehl |
|---|---|
| Abhängigkeiten installieren | `uv sync --locked --all-extras` |
| Lint | `uv run ruff check .` und `uv run ruff format --check .` |
| Tests mit Coverage | `uv run pytest --cov=network_sniffer --cov-report=term-missing --cov-fail-under=80` |
| Build | `uv build` |
| Windows-Paket (nur unter Windows, ab KAN-46) | `uv run python packaging/build_windows.py` |
| Lokal starten (Entwicklung, ohne Dienst) | `uv run network-sniffer serve` – liest `.env` (Vorlage `.env.example`; `NS_SECRET_KEY` erst ab KAN-15 Pflicht, bis dahin optional – falls gesetzt ≥ 32 Zeichen), `NS_CAPTURE_SOURCE=none` für Start ohne Npcap → http://127.0.0.1:8765 |
| Ersten Admin anlegen | `uv run network-sniffer create-admin --username <name>` |
| Dienst (Admin-PowerShell, gepacktes EXE, ab KAN-35) | `network-sniffer.exe service install`, `network-sniffer.exe service remove` |
| Migration anlegen | `uv run alembic revision --autogenerate -m "<beschreibung>"` (über `alembic.ini` → `src/network_sniffer/migrations/`) |

## Architektur
Modularer Monolith, ein Prozess (im Dienst). Details: [ADR 0002](docs/adr/0002-tech-stack-und-architektur.md).

```
src/network_sniffer/
  capture/            Erfassung: PacketSource (NpcapLiveSource, ReplaySource, NullSource), InterfaceProvider,
                      npcap.py, packets.py (Header-Parser), flows.py (TCP-Reassemblierung), capture_service
  detection/          Erkennung: Regel-Engine, Maskierung, Fingerabdruck (HMAC-SHA256 mit NS_SECRET_KEY)
  storage/            Speicherung: SQLAlchemy-Modelle, db.py (Engine, Sitzungen, Migration auf head beim Start),
                      migration_env.py (Logik der Alembic-Umgebung)
  migrations/         Alembic-Migrationen (env.py, versions/) – bewusst im Paket, damit sie im installierten Paket
                      und im PyInstaller-Build enthalten sind
  security/           request_guard.py (Host-/Origin-Prüfung), Passwörter, Sitzungen, Setup-Token,
                      Rechtematrix (permissions.py), CSRF
  services/           Anwendungsfälle (Abfrage/Filter, Bewertung, Statistik, Export, Regeln, Benutzer, Audit, Aufbewahrung)
  api/                REST-API (FastAPI-Router)
  web/                Dashboard (Jinja2)
  platform/windows/   Dienstklasse (pywin32), Dienst-Installation, ACLs
tests/
  unit/ component/ api/ web/ windows/
  pcapgen.py          erzeugt Test-Fixtures (.pcap) zur Laufzeit in tmp_path
packaging/            PyInstaller-Build für Windows
alembic.ini           Alembic-Konfiguration für die Entwicklung (script_location → src/network_sniffer/migrations)
```

Datenfluss: Npcap → `PacketSource` → Header-Parser → Reassembler → Regel-Engine → Maskierung/Fingerabdruck → SQLite →
`services/` → API/Dashboard. Klartext existiert nur flüchtig im Arbeitsspeicher.

Betrieb: Windows-Dienst als `NT SERVICE\network-sniffer`, Daten unter `%ProgramData%\network-sniffer\`, Dashboard nur
auf `127.0.0.1:8765`.

Sicherheit des lokalen Dashboards:
- `security/request_guard.py` (`LocalRequestGuardMiddleware`) prüft jeden HTTP-/WebSocket-Request: Der Host-Header
  muss inklusive Port in der Allowlist stehen (sonst 400 – Schutz gegen DNS-Rebinding); zustandsändernde Requests
  (alles außer GET/HEAD/OPTIONS sowie WebSockets) mit fremdem `Origin` werden mit 403 abgewiesen.
- Allowlist über `NS_ALLOWED_HOSTS` (JSON-Liste, z. B. `["127.0.0.1:8765"]`); Default: `127.0.0.1:<port>`,
  `localhost:<port>` und `<NS_BIND_HOST>:<port>`.
- `/docs`, `/redoc` und `/openapi.json` sind abgeschaltet.
- `GET /api/health` (öffentlich) liefert `status`, `version` und `db`; bei DB-Fehler HTTP 503.

## Konventionen
- Commits/PR-Titel: `typ(JIRA-KEY): beschreibung` (Conventional Commits)
- Branches: `feature/<KEY>-<slug>`, `fix/<KEY>-<slug>`
- Tests benennen das Akzeptanzkriterium, das sie prüfen (`test_ac1_...`, `test_ac2_...`)
- Keine Rohpakete oder Nutzdaten persistieren oder loggen – nur Ergebnisse von `masking` + `fingerprint`.
- Paketquelle immer über `PacketSource` – nie direkt Npcap/Scapy in der Fachlogik.
- Plattformspezifischer Code nur unter `platform/windows/` und über Fakes testbar.
- Windows-spezifische Tests mit `@pytest.mark.windows` (laufen im CI-Job `windows-build`).
- Jeder Endpunkt deklariert `require(Permission.X)` und hat Tests für erlaubte und verbotene Rolle.
- Uhrzeit nur über `Clock`, Speicherung in UTC.
- Jede Schemaänderung ist eine Alembic-Migration unter `src/network_sniffer/migrations/versions/`.
- Testdaten nur synthetisch; secret-ähnliche Werte zur Laufzeit zusammensetzen, keine Binär-.pcap committen.
