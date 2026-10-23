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
Das Projekt ist im Aufbau. Vorhanden ist das Grundgerüst (KAN-12): Health-Endpunkt `GET /api/health`, eine
Dashboard-Startseite und die Datenbank-Basis mit automatischen Migrationen. Mitschnitt, Erkennung und Login folgen
mit den nächsten Stories. Ein Windows-Paket (ZIP, ohne Python-Installation lauffähig) entsteht
bei jedem Release (KAN-46).

## Architektur
- [ADR 0002 – Tech-Stack und Architektur](docs/adr/0002-tech-stack-und-architektur.md): Python 3.12, FastAPI,
  Jinja2-Dashboard, SQLite, Npcap, pywin32-Dienst, PyInstaller-Paket – inkl. verworfener Alternativen.
- [ADR 0003 – Scapy ersetzen und permissive Lizenz](docs/adr/0003-scapy-ersetzen-und-permissive-lizenz.md):
  Npcap-Anbindung über einen eigenen `ctypes`-Wrapper, eigener pcap-Reader und Fixture-Generator, Lizenz MIT.
- Alle Entscheidungen: [docs/adr](docs/adr)
  - [0001 – Architekturentscheidungen als ADRs dokumentieren](docs/adr/0001-architekturentscheidungen-dokumentieren.md)
  - [0002 – Tech-Stack und Architektur](docs/adr/0002-tech-stack-und-architektur.md)
  - [0003 – Scapy ersetzen und permissive Lizenz](docs/adr/0003-scapy-ersetzen-und-permissive-lizenz.md)

## Windows-Paket
Für den Betrieb auf dem Windows-PC gibt es ein fertiges Paket, für das kein Python installiert sein muss.

1. **Herunterladen:** `network-sniffer-<version>-windows-x64.zip` und `network-sniffer-<version>-windows-x64.zip.sha256`
   aus den [GitHub-Releases](https://github.com/chron0s345/network-sniffer/releases).
2. **Prüfsumme prüfen** (PowerShell, im Download-Verzeichnis) – die beiden Werte müssen übereinstimmen:
   ```powershell
   (Get-FileHash .\network-sniffer-<version>-windows-x64.zip -Algorithm SHA256).Hash.ToLower()
   Get-Content .\network-sniffer-<version>-windows-x64.zip.sha256
   ```
3. **Entpacken**, z. B. nach `C:\Program Files\network-sniffer\` (Ordner `network-sniffer\` mit
   `network-sniffer.exe`, `LICENSE`, `README.md` und `THIRD-PARTY-LICENSES.txt`).
4. **Version prüfen:** `.\network-sniffer.exe --version` gibt `network-sniffer <version>` aus.
5. **Npcap separat installieren** (Download unter https://npcap.com/). Npcap ist **nicht** im Paket enthalten und
   unterliegt eigenen Lizenzbedingungen ([Npcap-Lizenz](https://github.com/nmap/npcap/blob/master/LICENSE)): Die
   kostenlose Version erlaubt nur eine eingeschränkte Nutzung (u. a. begrenzte Anzahl Systeme, keine Weitergabe);
   darüber hinaus ist eine Npcap-OEM-Lizenz nötig. Bitte die Bedingungen vor der Installation lesen.
6. **Starten** (Test ohne Dienst): `.\network-sniffer.exe serve` → http://127.0.0.1:8765. Ohne Npcap lässt sich
   das Dashboard mit `$env:NS_CAPTURE_SOURCE = "none"` starten. Konfiguration wie unter
   [Konfiguration](#konfiguration) beschrieben. Die Einrichtung als Windows-Dienst folgt mit KAN-35.

**SmartScreen-Hinweis:** Das EXE ist (noch) nicht code-signiert. Windows SmartScreen bzw. Virenscanner können beim
ersten Start warnen („Der Computer wurde durch Windows geschützt“). Prüfe vorher die SHA-256-Prüfsumme (Schritt 2);
danach über „Weitere Informationen“ → „Trotzdem ausführen“ starten.

Lizenzen der gebündelten Komponenten (Python-Laufzeit inkl. OpenSSL, SQLite u. a., Bibliotheken, PyInstaller-Bootloader)
stehen in `THIRD-PARTY-LICENSES.txt` im Paket.

## Entwicklung
Siehe [CLAUDE.md](CLAUDE.md) für Stack, Befehle und Konventionen.

### Schnellstart
Voraussetzung: [uv](https://docs.astral.sh/uv/) (installiert bei Bedarf Python 3.12 selbst).

```powershell
uv sync --locked --all-extras
Copy-Item .env.example .env      # Linux/macOS: cp .env.example .env
uv run network-sniffer serve
```

Danach erreichbar unter http://127.0.0.1:8765 (Dashboard) und http://127.0.0.1:8765/api/health.
`.env.example` setzt `NS_DATA_DIR=./data`, damit die Entwicklung ohne Schreibrechte auf `%ProgramData%` läuft.
`uv run network-sniffer --version` zeigt die Version.

### Windows-Paket bauen
Nur unter Windows (PyInstaller, onedir):

```powershell
uv run python packaging/build_windows.py                 # baut dist\network-sniffer-<version>-windows-x64.zip (+ .sha256)
uv run python packaging/build_windows.py --check-licenses  # nur Lizenz-Allowlist der Laufzeitabhängigkeiten (alle OS)
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/smoke_test.ps1 -ZipPath dist\network-sniffer-<version>-windows-x64.zip
```

Der Build bricht ab, wenn eine Laufzeitabhängigkeit nicht auf der Lizenz-Allowlist steht (ADR 0003), Module außerhalb
der geprüften Laufzeitabhängigkeiten gebündelt würden oder eine Npcap-DLL (`wpcap.dll`, `Packet.dll`) im Paket landet.
Unklare Lizenz-Metadaten werden in `LICENSE_OVERRIDES` in `packaging/build_windows.py` mit Begründung zugeordnet.
Der Smoke-Test entpackt das Zip in ein frisches Verzeichnis, prüft `--version`, startet `serve` mit
`NS_CAPTURE_SOURCE=none` und prüft `/api/health` sowie die Dashboard-Startseite.

### Konfiguration
Alle Einstellungen kommen aus Umgebungsvariablen mit Präfix `NS_`, aus `.env` im Arbeitsverzeichnis oder aus
`<NS_DATA_DIR>\network-sniffer.env` (Vorrang in dieser Reihenfolge). Vorlage mit allen Werten: [.env.example](.env.example).

| Variable | Standard | Bedeutung |
|---|---|---|
| `NS_DATA_DIR` | Windows `%ProgramData%\network-sniffer`, sonst `./data` | Datenverzeichnis (SQLite-DB) |
| `NS_BIND_HOST` | `127.0.0.1` | Bind-Adresse; Nicht-Loopback wird ohne `NS_TLS_CERT`/`NS_TLS_KEY` verweigert |
| `NS_PORT` | `8765` | Port |
| `NS_ALLOWED_HOSTS` | `127.0.0.1:<port>`, `localhost:<port>` und `<NS_BIND_HOST>:<port>` | Erlaubte Host-Header (JSON-Liste, ersetzt den Standard), Schutz vor DNS-Rebinding |
| `NS_TLS_CERT`, `NS_TLS_KEY` | – | Zertifikat und Schlüssel (nur gemeinsam); werden an Uvicorn übergeben, fehlende Dateien verhindern den Start |
| `NS_CAPTURE_SOURCE` | `npcap` | Paketquelle `npcap`, `replay` oder `none` (ab KAN-13) |
| `NS_SECRET_KEY` | – | Ab KAN-15 Pflicht; wenn gesetzt, mindestens 32 Zeichen |

### Sicherheit des lokalen Dashboards
- Requests mit fremdem Host-Header (inkl. Port) werden mit HTTP 400 abgewiesen (Schutz vor DNS-Rebinding).
- Zustandsändernde Requests (alles außer GET/HEAD/OPTIONS) mit fremdem `Origin` werden mit HTTP 403 abgewiesen.
- Das Access-Log enthält keine Query-Strings.

## Releases
Versionierung nach [SemVer](https://semver.org/lang/de/), Änderungen in [CHANGELOG.md](CHANGELOG.md).

## Lizenz
Lizenz: MIT (siehe [LICENSE](LICENSE)). Drittlizenzen der gebündelten Komponenten: `THIRD-PARTY-LICENSES.txt` im
Windows-Paket. Npcap ist nicht enthalten und unterliegt der Npcap-Lizenz.
