# network-sniffer

> Wird vom `architect`-Agenten gepflegt. Alle Agenten verwenden die Befehle aus diesem Dokument.

## Produkt
Windows-Dienst zur defensiven Data-Leak-Erkennung im Netzwerkverkehr des eigenen PCs: Live-Mitschnitt über Npcap im
Dauerbetrieb, Erkennung unverschlüsselt übertragener Geheimnisse über eine Regel-Engine, maskierte Funde in einem
Web-Dashboard auf `127.0.0.1`. Mehrbenutzerbetrieb mit den Rollen Admin und Analyst. Lizenz: MIT.
Architektur in Confluence: https://christianjanz90.atlassian.net/wiki/spaces/SOFTWAREEN/pages/622593

## Tech-Stack
Entscheidung und verworfene Alternativen: [ADR 0002](docs/adr/0002-tech-stack-und-architektur.md), für Live-Mitschnitt,
Test-Fixtures und Lizenz [ADR 0003](docs/adr/0003-scapy-ersetzen-und-permissive-lizenz.md).

| Bereich | Technologie |
|---|---|
| Sprache | Python 3.12 |
| Backend/API | FastAPI + Uvicorn, Pydantic v2, pydantic-settings (Präfix `NS_`) |
| Dashboard | Jinja2 (Autoescape), HTML/CSS, serverseitiges SVG, kein JS-Build |
| Datenhaltung | SQLite (WAL, `secure_delete=ON`), SQLAlchemy 2, Alembic |
| Live-Mitschnitt | Npcap (vom Betreiber installiert) über eigenen `ctypes`-Wrapper um `wpcap.dll` (ADR 0003), eigener Header-Parser, eigener pcap-Reader für `ReplaySource` |
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
Modularer Monolith, ein Prozess (im Dienst). Details: [ADR 0002](docs/adr/0002-tech-stack-und-architektur.md),
Npcap-Anbindung und Fixtures: [ADR 0003](docs/adr/0003-scapy-ersetzen-und-permissive-lizenz.md).

```
src/network_sniffer/
  capture/            Erfassung: PacketSource (NpcapLiveSource, ReplaySource, NullSource), InterfaceProvider,
                      npcap.py (sicheres Laden der System-wpcap.dll, NpcapMissing), pcap_ffi.py (ctypes-Wrapper
                      mit expliziten argtypes/restype, Bibliothekspfad als Parameter), pcapfile.py (Reader für
                      klassisches pcap, nur lesend), packets.py (Header-Parser), flows.py (TCP-Reassemblierung),
                      capture_service
  detection/          Erkennung: Regel-Engine, Maskierung, Fingerabdruck (HMAC-SHA256 mit NS_SECRET_KEY)
  storage/            Speicherung: SQLAlchemy-Modelle, db.py (Engine, Sitzungen, Migration auf head beim Start),
                      migration_env.py (Logik der Alembic-Umgebung)
  migrations/         Alembic-Migrationen (env.py, versions/) – bewusst im Paket, damit sie im installierten Paket
                      und im PyInstaller-Build enthalten sind
  security/           request_guard.py (Host-/Origin-Prüfung), passwords.py (Argon2id, Passwort-Richtlinie),
                      setup.py (Setup-Token, SetupState, SetupGateMiddleware), csrf.py (signiertes
                      Double-Submit-Cookie); geplant: Sitzungen, Rechtematrix (permissions.py)
  services/           Anwendungsfälle; users.py (Benutzername-Prüfung, atomare Anlage des ersten Admins);
                      geplant: Abfrage/Filter, Bewertung, Statistik, Export, Regeln, Audit, Aufbewahrung
  api/                REST-API (FastAPI-Router): health.py, setup.py (POST /api/setup, gemeinsamer Ablauf run_setup)
  web/                Dashboard (Jinja2): routes.py, setup_pages.py (GET/POST /setup, Formular ohne python-multipart)
  clock.py            Clock-Protokoll + SystemClock (UTC) – einzige Quelle für die Uhrzeit
  platform/windows/   Dienstklasse (pywin32), Dienst-Installation, ACLs
tests/
  unit/ component/ api/ web/ windows/
  pcapgen.py          eigener Paketbau (ether/ipv4/ipv6/tcp/udp/vlan, Prüfsummen) + pcap-Writer (write_pcap),
                      Szenarien tcp_session/http_request; erzeugt Fixtures zur Laufzeit in tmp_path
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
- **Setup-Gate** (`security/setup.py`, `SetupGateMiddleware`, läuft nach der Host-/Origin-Prüfung): Solange kein
  Benutzer existiert, werden Seiten mit 303 auf `/setup` umgeleitet, übrige `/api/*`-Requests mit 503 beantwortet und
  WebSockets mit Code 1008 geschlossen. Ausnahmen: `/setup`, `/api/setup`, `/api/health`, `/static/`. Nach der
  Ersteinrichtung merkt sich `SetupState` den Abschluss (keine DB-Abfrage je Request mehr); `/setup` leitet dann auf
  `/login` um, `POST /api/setup` liefert 404.
- **Setup-Token-Lebenszyklus:** 256 Bit Zufall (`secrets.token_urlsafe(32)`), nur beim Start erzeugt, solange kein
  Benutzer existiert; im Speicher liegt nur der SHA-256-Hash (Vergleich in konstanter Zeit). Gültig für
  `NS_SETUP_TOKEN_TTL_MINUTES` (Standard 60, 1–1440), danach neues Token nur per Neustart. Einmalig: nach Anlage des
  ersten Benutzers (Seite, API oder CLI – auch bei laufendem Server) wird es verworfen. Der Klartext wird genau
  einmal als WARNING ins Server-Log/auf die Konsole geschrieben (`main.log_setup_token`) – die **einzige bewusste
  Ausnahme** von „keine Secrets im Log“ (ADR 0002, Nachtrag KAN-37), nie ins Windows-Ereignisprotokoll. Empfohlener
  Weg ist die CLI `network-sniffer create-admin`, die ohne Token auskommt.
- **Erster Admin atomar:** `services/users.create_initial_admin` prüft und legt in **einem**
  `INSERT … SELECT … WHERE NOT EXISTS` an – von parallelen Setups (Web, API, CLI, auch prozessübergreifend) gewinnt
  genau eines.
- **CSRF** (`security/csrf.py`): signiertes Double-Submit-Cookie `ns_csrf` (`HttpOnly`, `SameSite=Strict`, `Secure`
  bei HTTPS) plus verstecktes Feld `csrf_token`; Cookie und Feld müssen übereinstimmen und die HMAC-SHA256-Signatur
  gültig sein. Schlüssel aus `NS_SECRET_KEY` abgeleitet (Tokens überleben Neustarts), sonst prozesslokal zufällig
  (Tokens werden mit dem Neustart ungültig). Jedes neue Formular nutzt `CsrfProtection` aus `app.state.csrf`.
- **Genau ein Uvicorn-Worker:** Setup-Token, `SetupState` und (ohne `NS_SECRET_KEY`) der CSRF-Schlüssel sind
  prozesslokal; `serve` startet deshalb mit `workers=1`. Mehrere Worker oder Prozesse hinter einem Port sind nicht
  unterstützt.
- Weitere `NS_`-Variablen: `NS_SETUP_TOKEN_TTL_MINUTES` (s. o.), `NS_ARGON2_TIME_COST` (Standard 3),
  `NS_ARGON2_MEMORY_COST_KIB` (Standard 65536, mindestens 8 × Parallelität), `NS_ARGON2_PARALLELISM` (Standard 4);
  Tests setzen die Argon2-Kosten niedrig.

## Konventionen
- Commits/PR-Titel: `typ(JIRA-KEY): beschreibung` (Conventional Commits)
- Branches: `feature/<KEY>-<slug>`, `fix/<KEY>-<slug>`
- Tests benennen das Akzeptanzkriterium, das sie prüfen (`test_ac1_...`, `test_ac2_...`)
- Keine Rohpakete oder Nutzdaten persistieren oder loggen – nur Ergebnisse von `masking` + `fingerprint`.
- Paketquelle immer über `PacketSource` – nie direkt Npcap/`ctypes` in der Fachlogik; FFI-Code nur in
  `capture/pcap_ffi.py`/`capture/npcap.py`, jede Funktion mit expliziten `argtypes`/`restype`.
- Plattformspezifischer Code nur unter `platform/windows/` (Ausnahme: Npcap-Anbindung in `capture/`) und über Fakes testbar.
- Windows-spezifische Tests mit `@pytest.mark.windows` (laufen im CI-Job `windows-build`).
- Jeder Endpunkt deklariert `require(Permission.X)` und hat Tests für erlaubte und verbotene Rolle.
- Uhrzeit nur über `Clock` (`network_sniffer/clock.py`, in der App `app.state.clock`), nie `datetime.now()` direkt;
  Speicherung in UTC. Tests stellen die Uhr mit time-machine oder übergeben eine Fake-`Clock`.
- Jede Schemaänderung ist eine Alembic-Migration unter `src/network_sniffer/migrations/versions/`.
- Testdaten nur synthetisch; secret-ähnliche Werte zur Laufzeit zusammensetzen, keine Binär-.pcap committen.
- Lizenzen (ADR 0003): keine (L)GPL-/AGPL-Laufzeitabhängigkeiten. Jede neue Abhängigkeit – auch transitive im
  `uv.lock`-Diff – braucht eine Lizenzprüfung (PyPI-Metadaten, Allowlist: MIT, MIT-0, BSD-2/3-Clause, Apache-2.0,
  PSF-2.0, ISC, CNRI-Python); Ergebnis im PR nennen. Ausnahmen nur per ADR.
