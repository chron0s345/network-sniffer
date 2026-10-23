# 0002. Tech-Stack und Architektur

- **Status:** akzeptiert (Accepted)
- **Datum:** 2026-10-23
- **Ticket:** KAN-10

## Kontext
network-sniffer ist ein Werkzeug zur defensiven Data-Leak-Erkennung: Es schneidet den Netzwerkverkehr des eigenen
Windows-PCs live mit, erkennt darin über eine Regel-Engine unverschlüsselt übertragene Geheimnisse (Passwörter,
Tokens, Schlüssel o. Ä.) und zeigt die Funde maskiert in einem lokalen Web-Dashboard an.

Rahmenbedingungen:

- **Betriebsziel ist der Windows-PC des Betreibers.** Das Produkt läuft als Windows-Dienst im Dauerbetrieb und
  schneidet live über Npcap mit. Es gibt keinen .pcap-Upload; Rohpakete werden nicht gespeichert. .pcap-Dateien
  dienen nur intern als Test-Fixtures.
- Entwicklung und Tests müssen ohne Administratorrechte, ohne Npcap und ohne Live-Traffic laufen – auch unter Linux
  (CI-Job `build-test` auf ubuntu).
- Die Fabrik-Pipeline (Semgrep, Trivy, Gitleaks, CodeQL, release-please) ist auf Python vorbereitet; Abhängigkeiten
  müssen über ein Lockfile scanbar sein.
- Mindest-Coverage 80 % (`process.coverageMin`), nicht senkbar.
- Bevorzugt wird langweilige, gut gewartete Technologie mit guter Testbarkeit und aktivem Security-Support.

## Optionen
Je Entscheidungsfeld die gewählte Option und die verworfenen Alternativen.

### Sprache/Backend
- **Gewählt: Python 3.12, FastAPI + Uvicorn, Pydantic v2 / pydantic-settings** (Konfiguration über Umgebungsvariablen
  mit Präfix `NS_`).
- Verworfen: **Go** – gopacket lädt `wpcap.dll` zwar ohne cgo und ein einzelnes EXE wäre bequem, es gibt aber keinen
  Ersatz für Scapy beim Erzeugen von Test-Fixtures, und die Fabrik-Pipeline ist auf Python vorbereitet.
- Verworfen: **C#/.NET** – SharpPcap ist tragfähig, aber für Fixtures/Tests wäre eine zweite Sprache nötig.
- Verworfen: **Node.js** – schwache pcap-Bindings.

### Web-Dashboard
- **Gewählt: serverseitige Jinja2-Templates** (Autoescape aktiv), reines HTML/CSS, Filter als GET-Formulare,
  Diagramme als serverseitig erzeugtes SVG, kein JavaScript-Build.
- Verworfen: **React/Vite-SPA** – zweite Toolchain mit eigenem Abhängigkeitsbaum.
- Verworfen: **vendored JS-Bibliotheken** – werden nicht von den Dependency-Scannern überwacht.

### Live-Mitschnitt unter Windows
- **Gewählt: Npcap über Scapy.** Npcap wird vom Betreiber separat installiert (wie für Wireshark). Scapy dient nur als
  Zugriffsschicht: `L2pcapListenSocket`, Lesen per `recv_raw()` – **ohne** Scapy-Dissektion. Das Header-Parsing
  übernimmt ein eigener schlanker `struct`-Parser für Ethernet, Loopback (DLT_NULL), IPv4, IPv6, TCP und UDP, um den
  Durchsatz zu sichern. Mitschnitt **nicht-promiskuitiv** (nur Verkehr des eigenen PCs).
- Verworfen: **Scapy-`AsyncSniffer` mit voller Dissektion** – zu langsam für Dauerbetrieb.
- Verworfen: **pcapy-ng** – C-Extension, Build gegen das Npcap-SDK nötig.
- Verworfen: **pyshark/tshark** – Wireshark-Installation nötig, langsam.
- Verworfen: **WinDivert/pydivert** – greift in den Verkehr ein, Treiber mit Admin-Pflicht.
- Verworfen: **Raw-Sockets (`SIO_RCVALL`)** – Admin-Pflicht, unvollständige Sicht auf den Verkehr.

### Test-Fixtures und Test-Paketquelle
- **Gewählt:** Fixtures werden in den Tests mit Scapy erzeugt (`tests/pcapgen.py`, `wrpcap` in `tmp_path`) und über
  `ReplaySource` (Scapy `RawPcapReader`) in **dieselbe** Pipeline eingespielt wie Live-Pakete.
- Verworfen: **committete Binär-.pcap-Dateien** – nicht reviewbar, Probleme mit Secret-Scannern.

### Datenhaltung
- **Gewählt: SQLite** (WAL-Modus, `secure_delete=ON`) über **SQLAlchemy 2**, Migrationen mit **Alembic**, die beim
  Start automatisch auf `head` gebracht werden. Die Migrationen liegen deshalb im Paket
  (`src/network_sniffer/migrations/`), damit sie im installierten Paket und im PyInstaller-Build enthalten sind;
  `alembic.ini` im Wurzelverzeichnis verweist für die Entwicklung darauf, die Logik der Alembic-Umgebung liegt in
  `storage/migration_env.py`. Es werden **keine Rohpakete, keine Nutzdaten und keine .pcap-Dateien**
  gespeichert – nur maskierte Funde.
- Verworfen: **PostgreSQL** – zusätzlicher Dienst auf einem Desktop-PC.
- Verworfen: **JSON-Dateien** – keine Transaktionen, keine Abfragen, keine Migrationen.

### Regex für eigene Regeln
- **Gewählt: Paket `regex`** (unterstützt Timeouts gegen katastrophales Backtracking).
- Verworfen: **google-re2** – kein Timeout-/Warnverhalten, wie es KAN-34 verlangt.

### Benutzer, Rollen, Authentifizierung
- **Gewählt:** Benutzer in der DB mit Rolle `admin` oder `analyst`; Passwort-Hashing mit **Argon2id** (argon2-cffi);
  serverseitige Sitzungen (Token in der DB nur gehasht); Cookie `HttpOnly` + `SameSite=Strict`, `Secure` automatisch
  bei TLS. Die Rechtematrix liegt zentral in `security/permissions.py`, jeder Endpunkt deklariert
  `require(Permission.X)`, ein Vollständigkeitstest prüft alle Routen. CSRF-Token für Formulare. Audit-Log append-only.
- Verworfen: **JWT** – Widerruf/Abmeldung nur umständlich, für eine lokale Anwendung unnötig.
- Verworfen: **signierte Cookie-Sessions** – serverseitig nicht widerrufbar.
- Verworfen: **bcrypt** – Argon2id ist aktuelle Empfehlung (OWASP), bcrypt kürzt Passwörter auf 72 Byte.

### Windows-Dienst
- **Gewählt: eigener Dienst mit pywin32** (`win32serviceutil.ServiceFramework`) im gepackten EXE. `SvcStop` beendet
  Uvicorn (`server.should_exit`) und den Mitschnitt sauber. Installation/Deinstallation über das EXE selbst:
  `network-sniffer.exe service install|remove|start|stop` (Admin-Shell). Details siehe „Betrieb als Windows-Dienst“.
- Verworfen: **NSSM** – seit 2017 ohne Release, Fremd-Binary nicht von Scannern überwacht.
- Verworfen: **WinSW** – Fremd-Binary + .NET, v3 seit Jahren im Alpha-Stadium.
- Verworfen: **servy** – jung, wenig verbreitet.
- Verworfen: **Aufgabenplanung statt Dienst** – keine Wiederherstellungsoptionen, schlechter für Dauerbetrieb.

### Deployment-Artefakt
- **Gewählt: PyInstaller onedir**, ausgeliefert als `network-sniffer-<version>-windows-x64.zip` (kein Python auf dem
  Ziel-PC nötig). Gebaut und per Smoke-Test geprüft auf `windows-latest`, veröffentlicht als Workflow-Artefakt (main)
  und als GitHub-Release-Asset. **Npcap wird nicht mitgeliefert** (Lizenz).
- Verworfen: **Docker/GHCR** – kein Npcap-Zugriff aus Containern unter Windows, falsches Ziel.
- Verworfen: **MSI/WiX** – grafischer Installer nicht im Scope.
- Verworfen: **PyInstaller onefile** – langsamerer Start, mehr Antivirus-Fehlalarme.
- Verworfen: **Python-Embeddable + Skript** – fehleranfälliger in der Installation beim Betreiber.

### Test, Coverage, Lint
- **Gewählt: pytest, pytest-cov** (Minimum 80 %, nicht senkbar), **httpx/TestClient** für API- und Web-Tests,
  **time-machine** für Zeitsteuerung, **Ruff** für Lint und Formatierung.
- Verworfen: **unittest** – mehr Boilerplate, schwächere Fixtures/Parametrisierung.
- Verworfen: **flake8 + black** – zwei Werkzeuge statt einem, langsamer.

### Paketverwaltung
- **Gewählt: uv** mit `pyproject.toml` und plattformübergreifendem `uv.lock`; Windows-only-Pakete wie pywin32 mit
  Marker `sys_platform == 'win32'`. Das Lockfile ist Voraussetzung für den Trivy-Scan.
- Verworfen: **Poetry** – langsamer, eigenes Lockformat ohne Vorteil gegenüber uv.
- Verworfen: **pip ohne Lock** – nicht reproduzierbar, nicht scanbar.

### Lizenz
- **Gewählt: GPL-2.0-only** (vom Menschen bestätigt), weil Scapy unter GPL-2.0 steht und im ausgelieferten EXE
  enthalten ist. Volltext in `LICENSE`; ab KAN-12 zusätzlich `license = "GPL-2.0-only"` in `pyproject.toml`.

## Entscheidung
Wir wählen den oben jeweils als „Gewählt“ markierten Stack: **Python 3.12 mit FastAPI/Uvicorn, Jinja2-Dashboard,
SQLite über SQLAlchemy 2 + Alembic, Live-Mitschnitt über Npcap + Scapy (ohne Dissektion), pywin32-Dienst,
PyInstaller-onedir-Paket, pytest/pytest-cov/Ruff, uv**, weil er durchgängig in einer Sprache entwickelt und getestet
werden kann, die Test-Fixtures mit demselben Werkzeug erzeugt werden wie der Mitschnitt, alle Abhängigkeiten von den
Fabrik-Scannern erfasst werden und keine zusätzlichen Dienste auf dem PC des Betreibers nötig sind.

### Architektur
Modularer Monolith in einem Prozess (im Dienst), Paket `src/network_sniffer/`:

| Modul | Rolle | Inhalt |
|---|---|---|
| `capture/` | **Erfassung** (Live-Mitschnitt im Dauerbetrieb, austauschbare Paketquelle) | `PacketSource`-Protokoll mit `NpcapLiveSource` (Windows), `ReplaySource` (Tests/Entwicklung), `NullSource`; `InterfaceProvider` (Npcap-Geräte mit Anzeigename wie „Ethernet“/„WLAN“ und stabiler GUID `\Device\NPF_{…}`); `npcap.py` (Erkennung über `%SystemRoot%\System32\Npcap\wpcap.dll` + Scapy `conf.use_pcap`); `packets.py` (schlanker Header-Parser); `flows.py` (inkrementelle TCP-Reassemblierung, Analyse-Budget je Stream-Richtung standardmäßig 64 KiB, Flush bei FIN/RST/Idle, begrenzte Stream-Tabelle); `capture_service` mit Zustandsautomat `running \| paused \| error(Grund)`, Paket-/Drop-Zählern und Wiederanlauf alle 10 s bei Fehlern (z. B. WLAN aus, Standby). Pakete gehen über eine begrenzte Queue vom Capture-Thread an einen Worker-Thread. |
| `detection/` | **Erkennung** (Regel-Engine) | Regeln (eingebaut und eigene), Maskierung, Fingerabdruck (HMAC-SHA256 mit `NS_SECRET_KEY`) |
| `storage/` | **Speicherung der Funde** | SQLAlchemy-Modelle (Finding, FindingReview, Setting, RuleConfig/CustomRule, User, Session, LoginAttempt, AuditEvent), `db.py` (inkl. Migration beim Start), `migration_env.py` (Alembic-Umgebung); die Migrationen selbst liegen unter `migrations/` im Paket |
| `security/` | Querschnitt Sicherheit | `request_guard.py` (Host-Allowlist inkl. Port, Origin-Prüfung), Passwörter, Sitzungen, Setup-Token, Rechtematrix, CSRF |
| `services/` | Anwendungsfälle | Abfrage/Filter, Bewertung, Statistik, Export, Regeln, Benutzer, Audit, Aufbewahrung |
| `api/` | **REST-API** | FastAPI-Router, nutzen ausschließlich `services/` |
| `web/` | **Dashboard** | Jinja2-Templates, Formulare, SVG-Diagramme, nutzen ausschließlich `services/` |
| `platform/windows/` | Windows-Integration | Dienstklasse (pywin32), Dienst-Installation, ACLs – dünn gehalten, alles andere ist plattformneutral |

**Zusammenspiel / Datenfluss:**

```
Npcap ─► PacketSource ─► Header-Parser ─► Reassembler ─► Regel-Engine ─► Maskierung/Fingerabdruck ─► SQLite
         (capture/)      (packets.py)     (flows.py)     (detection/)     (detection/)               (storage/)
                                                                                                        │
                                                         Dashboard (web/) ◄── services/ ◄── API (api/) ◄┘
```

Der `capture_service` liest aus der konfigurierten `PacketSource`, parst die Header, setzt TCP-Streams zusammen und
übergibt die Daten an die Regel-Engine. Funde werden sofort maskiert und mit Fingerabdruck versehen, erst dann über
`storage/` persistiert. API und Dashboard lesen und bewerten Funde ausschließlich über `services/`. **Klartext
existiert nur flüchtig im Arbeitsspeicher.**

### Teststrategie
Alle automatisierten Tests laufen **ohne Administratorrechte, ohne Npcap und ohne Live-Traffic**:

- **Test-Paketquelle:** Fixtures werden zur Testlaufzeit mit `tests/pcapgen.py` (Scapy, `wrpcap` in `tmp_path`)
  erzeugt und über `ReplaySource` in den laufenden `capture_service` eingespielt – dieselbe Pipeline wie im
  Live-Betrieb (Header-Parser, Reassembler, Regel-Engine, Maskierung, Speicherung).
- **Fehlerfälle** (Npcap fehlt, keine Berechtigung, Interface verschwindet) über `FakeSource` und
  `FakeInterfaceProvider`.
- **Synthetische Secrets** werden zur Laufzeit zusammengesetzt, damit keine secret-ähnlichen Literale im Repo liegen.
- Testebenen: `tests/unit`, `tests/component` (Pipeline mit `ReplaySource`), `tests/api`, `tests/web`,
  `tests/windows` (mit `@pytest.mark.windows`).
- **CI:** `build-test` (ubuntu, Required Check, gesamte Suite + Coverage ≥ 80 %) und zusätzlich `windows-build`
  (windows-latest: gesamte Suite inkl. Windows-Modulen, Paket-Build, Smoke-Test, Dienst-Installationstest).
  `windows-build` wird nach KAN-11 zusätzlicher Required Check (vom Menschen bestätigt).
- **Grenze der Automatisierung:** Der echte Npcap-Pfad ist in der CI nicht prüfbar (Npcap darf ohne OEM-Lizenz nicht
  still installiert werden). Dafür gibt es einen **manuellen Abnahmetest** auf dem PC des Betreibers (Checkliste in
  `docs/abnahme-windows.md`, entsteht in KAN-13/KAN-35).

### Betrieb als Windows-Dienst
- **Voraussetzung:** Npcap (Standardinstallation, ohne Option „nur Administratoren“). Fehlt Npcap, startet der Dienst
  trotzdem; der Mitschnitt hat dann den Status „Fehler“ mit Hinweis im Dashboard.
- **Autostart:** Starttyp „Automatisch“. Wiederherstellung: Neustart nach 10 s (3-mal, Fehlerzähler-Reset nach 1 Tag,
  auch bei Nicht-Absturz-Fehlern).
- **Installation:** `network-sniffer.exe service install|remove|start|stop` in einer Admin-Shell. Bei der Installation
  wird das Datenverzeichnis angelegt und ein zufälliger `NS_SECRET_KEY` erzeugt.
- **Rechte:** Der Dienst läuft als virtuelles Konto `NT SERVICE\network-sniffer` (Least Privilege). Fallback-Option
  `--account LocalSystem`, falls Npcap im Modus „nur Administratoren“ installiert wurde.
- **Datenverzeichnis:** `%ProgramData%\network-sniffer\` (DB, Logs, Konfiguration `network-sniffer.env` mit
  `NS_SECRET_KEY`), ACL nur für SYSTEM, Administratoren und das Dienstkonto.
- **Netzwerk:** Das Dashboard bindet **nur an `127.0.0.1`** (Port 8765). Eine spätere Freigabe ins Netz ist über
  `NS_BIND_HOST` vorgesehen; der Start verweigert aber eine Nicht-Loopback-Bindung ohne konfiguriertes
  TLS-Zertifikat (`NS_TLS_CERT`/`NS_TLS_KEY`) – nicht Teil des MVP.
- **Schutz gegen DNS-Rebinding/Cross-Origin:** Die Loopback-Bindung allein reicht nicht. Eine Middleware
  (`security/request_guard.py`) akzeptiert nur Host-Header aus einer Allowlist inklusive Port (`NS_ALLOWED_HOSTS`,
  Default `127.0.0.1:<port>`, `localhost:<port>`, `<NS_BIND_HOST>:<port>`) und weist zustandsändernde Requests mit
  fremdem `Origin` ab. Die interaktive API-Doku (`/docs`, `/redoc`, `/openapi.json`) ist abgeschaltet.
- **Eigenverkehr:** Der eigene Dashboard-Verkehr auf Loopback wird vom Mitschnitt ausgenommen (sonst würden eigene
  Logins zu Funden).
- **Logs:** rotierende Datei unter `%ProgramData%\network-sniffer\logs\` ohne Klartextwerte; Lebenszyklus-Ereignisse
  zusätzlich im Windows-Ereignisprotokoll (niemals das Setup-Token).
- **Update:** Dienst stoppen, Programmverzeichnis ersetzen, Dienst starten – Alembic-Migrationen laufen beim Start.
- **Deployment-Artefakt:** `network-sniffer-<version>-windows-x64.zip` (PyInstaller onedir, siehe oben).

### Vom Menschen bestätigte Festlegungen
- Ein **pausierter Mitschnitt bleibt nach einem Neustart** (Dienst oder PC) **pausiert**; der Zustand wird persistiert.
- Das **Dashboard ist nur über `127.0.0.1` erreichbar** (MVP).
- Der **Mehrbenutzerbetrieb mit den Rollen Admin und Analyst bleibt** bestehen.
- Das EXE wird **vorerst nicht code-signiert**.
- **`windows-build`** wird nach KAN-11 **zusätzlicher Required Check**.

## Konsequenzen
- **Durchsatz** ist in Python begrenzt. Ziel ≥ 20 000 Pakete/s (Messung in KAN-13); darüber hinaus werden Pakete
  gezählt verworfen (Drop-Zähler im Dashboard).
- Analysiert werden nur die **ersten 64 KiB je Stream-Richtung**; Secrets in sehr großen Bodies können entgehen.
- Sichtbar ist **nur der eigene Verkehr des PCs** (nicht-promiskuitiv).
- **TLS-verschlüsselter Verkehr ist nicht analysierbar** – das Produkt findet nur unverschlüsselt übertragene Daten.
- Das **EXE ist unsigniert**: Windows SmartScreen kann beim ersten Start warnen.
- **GPL-2.0-only** wegen Scapy; das gilt auch für das ausgelieferte Paket.
- **Live-Capture wird nur unter Windows unterstützt**; Entwicklung und automatisierte Tests laufen auch unter Linux.
- Der echte Npcap-Pfad wird nur manuell abgenommen; Fehler darin fallen erst beim Abnahmetest auf.
- Einfacher wird: eine Sprache für Produkt, Tests und Fixtures; keine Zusatzdienste auf dem Ziel-PC; alle
  Abhängigkeiten im Lockfile und damit von Trivy/CodeQL abgedeckt.
- Zu beobachten: Wartungsstand von Scapy und pywin32, Antivirus-Fehlalarme beim PyInstaller-Paket, Drop-Raten im
  Dauerbetrieb.
