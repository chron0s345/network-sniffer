# 0003. Scapy durch eigene Npcap-Anbindung ersetzen und Projekt unter MIT lizenzieren

- **Status:** akzeptiert (Accepted) – ersetzt ADR 0002 teilweise (Live-Mitschnitt, Test-Fixtures, Lizenz)
- **Datum:** 2026-10-23
- **Ticket:** KAN-13, KAN-47 (betroffen außerdem KAN-35, KAN-43, KAN-45, KAN-46)

## Kontext
ADR 0002 hat für den Live-Mitschnitt Npcap über **Scapy** gewählt (`L2pcapListenSocket`, `recv_raw()`) und die
Test-Fixtures mit Scapy (`wrpcap`, `RawPcapReader`) erzeugt. Scapy steht unter **GPL-2.0-only**; deshalb wurde das
Projekt selbst unter GPL-2.0-only gestellt.

Bei der Prüfung der Abhängigkeiten zeigte sich ein Lizenzkonflikt:

- `fastapi` zieht seit Kurzem **`opentelemetry-api`** (Apache-2.0) als Laufzeitabhängigkeit nach (im `uv.lock`
  enthalten). Geplant ist außerdem das Paket **`regex`** (Apache-2.0 AND CNRI-Python, ADR 0002 „Regex für eigene
  Regeln“).
- Die Apache License 2.0 ist laut FSF **inkompatibel mit GPLv2** (nur mit GPLv3 kompatibel). Ein unter GPL-2.0-only
  verbreitetes Gesamtwerk darf keine Apache-2.0-Komponenten enthalten.
- Das öffentliche Windows-Paket (PyInstaller onedir, KAN-46) **bündelt alle Laufzeitabhängigkeiten** in einem
  verbreiteten Artefakt – der Konflikt würde also tatsächlich bei jeder Auslieferung entstehen.

Scapy war im Code noch nicht verwendet (nicht in `pyproject.toml`/`uv.lock`), es ist nichts zurückzubauen.

**Entscheidung des Menschen (2026-10-23):** Scapy wird ersetzt, das Projekt erhält eine permissive Lizenz (**MIT**).

Rahmenbedingungen aus ADR 0002 gelten weiter: Live-Mitschnitt nur unter Windows über das vom Betreiber installierte
Npcap, nicht-promiskuitiv; alle automatisierten Tests ohne Administratorrechte, ohne Npcap und ohne Live-Traffic,
auch unter Linux; keine Binär-.pcap-Dateien im Repo; Security-Empfehlung aus dem Review von KAN-10: `wpcap.dll` darf
nicht über den DLL-Suchpfad geladen werden (DLL-Planting).

Lizenzangaben in diesem ADR wurden am 2026-10-23 über die PyPI-JSON-API (`https://pypi.org/pypi/<paket>/json`,
Felder `license_expression`/`license`/Classifier) verifiziert.

## Optionen

### Live-Mitschnitt (Zugriff auf Npcap)
1. **Eigener `ctypes`-Wrapper um Npcaps `wpcap.dll` (gewählt)** – keine neue Abhängigkeit, volle Kontrolle über das
   DLL-Laden, nur die ~20 benötigten Funktionen. Nachteil: eigener FFI-Code; falsche Signaturen führen zu Abstürzen
   statt Exceptions.
2. **pcapy-ng** (Apache-2.0, 2.1.0 vom 2026-08) – C-Extension, auf PyPI **keine Windows-Wheels**; Build gegen das
   Npcap-SDK in der CI nötig, DLL-Laden nicht steuerbar.
3. **libpcap / pcap-ct** (karpierz, BSD-3-Clause, Status **Beta**) – bringt eigene Binärdateien bzw. eine eigene
   Ladelogik mit; zusätzliche, wenig verbreitete Abhängigkeit mit unklarer Pflege.
4. **pypcap** (letztes Release 1.3.0 von 2022, **nur sdist**) – faktisch ungepflegt, kein Windows-Wheel.
5. **Scapy behalten** (GPL-2.0-only) – erzwingt GPL-2.0-only für das Projekt und ist mit den Apache-2.0-Abhängigkeiten
   unvereinbar; vom Menschen verworfen.

### Test-Fixtures (pcap schreiben/lesen)
1. **Eigener Writer in der Testsuite + eigener Reader im Produktcode (gewählt)** – das klassische pcap-Format ist
   trivial (24-Byte-Global-Header, 16-Byte-Record-Header), Paketbau mit `struct`; keine Abhängigkeit. Risiko
   „Spiegelfehler“ (Writer und Reader aus einer Hand) → Golden Vectors und Interop-Test.
2. **dpkt** (BSD, Status Beta, letztes Release 1.9.8 von **2022**) – Paketbau und pcap-I/O vorhanden, aber faktisch
   ungepflegt; wäre zudem für `ReplaySource` eine Laufzeitabhängigkeit.

### Projektlizenz
1. **MIT (gewählt)** – kurz, verbreitet, kompatibel mit allen gebündelten Komponenten (MIT, BSD, Apache-2.0, PSF).
2. **Apache-2.0** – expliziter Patentgrant, aber längerer Text und NOTICE-Pflichten für das eigene Projekt; für ein
   kleines Werkzeug ohne Patentbezug kein Vorteil.

## Entscheidung
Wir ersetzen Scapy durch einen **eigenen `ctypes`-Wrapper** um Npcap, einen **eigenen pcap-Reader** im Produktcode und
einen **eigenen Paketbau/pcap-Writer** in der Testsuite, und stellen das Projekt unter die **MIT-Lizenz**, weil damit
keine Copyleft-Pflichten entstehen, alle gebündelten Abhängigkeiten kompatibel sind, das DLL-Laden vollständig unter
unserer Kontrolle liegt und **keine neue Laufzeitabhängigkeit** hinzukommt. Maßgebliche Detailnotizen stehen in
KAN-13 (Pipeline, Reader, Fixtures) und KAN-47 (Npcap-Anbindung).

### Npcap-Anbindung (`capture/npcap.py`, `capture/pcap_ffi.py`, KAN-47)
- **Sicheres Laden:** Systemverzeichnis über `GetSystemDirectoryW` (kernel32, nicht über `%SystemRoot%`), Pfad
  `<System32>\Npcap\wpcap.dll`; fehlt die Datei → `NpcapMissing`. Laden ausschließlich über den absoluten Pfad mit
  `ctypes.WinDLL(abs_path, winmode=LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`
  (`0x100 | 0x800`), damit auch die Abhängigkeit `Packet.dll` nur aus dem Npcap-Verzeichnis bzw. System32 kommt –
  nie aus Arbeitsverzeichnis oder `PATH`. Versionsanzeige über `pcap_lib_version()`.
- **Funktionsumfang mit expliziten `argtypes`/`restype`:** `pcap_findalldevs`, `pcap_freealldevs`, `pcap_create`,
  `pcap_set_snaplen` (65 535), `pcap_set_promisc` (**0**, nicht-promiskuitiv), `pcap_set_timeout` (250 ms),
  `pcap_set_immediate_mode` (1), `pcap_set_buffer_size`, `pcap_activate`, `pcap_datalink`, `pcap_next_ex`,
  `pcap_stats`, `pcap_breakloop`, `pcap_geterr`, `pcap_close`, `pcap_lib_version`; nur für Tests zusätzlich
  `pcap_open_dead`, `pcap_dump_open`, `pcap_dump`, `pcap_dump_close`, `pcap_open_offline`. Strukturen `pcap_if`,
  `pcap_pkthdr` (`timeval` mit `ctypes.c_long`), `pcap_stat`; `PCAP_ERRBUF_SIZE = 256`. Rückgabewerte von
  `pcap_activate` (`PCAP_ERROR_PERM_DENIED`, `PCAP_ERROR_NO_SUCH_DEVICE`, Warnungen > 0) werden auf
  `CapturePermissionDenied` bzw. `InterfaceNotFound` abgebildet. Paketdaten werden per `ctypes.string_at` kopiert;
  Zeiger aus `pcap_next_ex` werden nie darüber hinaus gehalten.
- **Lebenszyklus:** `NpcapLiveSource.open()` = create/set/activate, `read(timeout)` = `pcap_next_ex` (Timeout →
  `None`), `close()` = `pcap_breakloop` + `pcap_close` **nur im Capture-Thread** nach Verlassen der Leseschleife;
  `read()` kehrt spätestens nach 250 ms zurück, der Stopp signalisiert über ein `Event`.
- **Interfaces:** `pcap_findalldevs` liefert `\Device\NPF_{GUID}` und Beschreibung; der Windows-Anzeigename
  („Ethernet“, „WLAN“) kommt über iphlpapi (`ConvertInterfaceGuidToLuid` + `ConvertInterfaceLuidToAlias`); Loopback
  über `PCAP_IF_LOOPBACK` bzw. `\Device\NPF_Loopback`.
- **Testbarkeit:** Der Bibliothekspfad ist Parameter des Wrappers. Derselbe Wrapper läuft in der Linux-CI gegen
  `libpcap.so` (Roundtrip über `pcap_open_dead`/`pcap_dump`/`pcap_open_offline`, ohne Root). Unter Windows ohne
  Npcap werden `NpcapMissing` und die Ladeflags per Monkeypatch von `WinDLL` geprüft.

### pcap-Reader (`capture/pcapfile.py`, KAN-13)
- Liest nur das **klassische pcap-Format**: Magic `0xa1b2c3d4` (µs) und `0xa1b23c4d` (ns), jeweils in **beiden
  Byte-Orders**, Linktype aus dem Global-Header. **pcapng wird nicht unterstützt.**
- **Strikte Validierung:** unbekannte Magic, `snaplen`/`incl_len` > 262 144 oder abgeschnittene Records →
  `PcapFormatError` (keine Endlosschleife, keine großen Allokationen, keine Nutzdaten in Fehlermeldungen).
- Wird von `ReplaySource` genutzt. **Kein pcap-Writer im Produktcode** – der Produktcode kann keine .pcap-Datei
  erzeugen (KAN-13 AC4).

### Paketbau und pcap-Writer für Tests (`tests/pcapgen.py`, KAN-13)
- Rein synthetischer Generator in der Testsuite: `ether`, `ipv4`, `ipv6`, `tcp`, `udp`, `vlan`, `loopback_null` mit
  korrekten IPv4-Header- und TCP/UDP-Prüfsummen (Pseudo-Header, RFC 1071).
- Szenarien `tcp_session(client, server, payloads, *, reorder=None, retransmit=None)` und `http_request(...)` –
  **Namen bleiben stabil**, Folgestories (KAN-14 ff.) verweisen darauf.
- `write_pcap(path, packets, linktype=1)` schreibt das klassische pcap-Format nach `tmp_path`; keine Binär-.pcap im Repo.
- **Gegen Spiegelfehler:** Golden-Vector-Tests mit von Hand dokumentierten Hex-Bytes eines bekannten Pakets inkl.
  Prüfsummen; zusätzlich ein **optionaler Interop-Test** (nicht gating), der eine mit `write_pcap` erzeugte Datei unter
  Linux mit `tcpdump -r` bzw. libpcap liest, falls vorhanden.

### Lizenzen der gebündelten Komponenten (Windows-Paket, KAN-46)

| Komponente | Lizenz | Hinweis |
|---|---|---|
| network-sniffer | MIT | `LICENSE` |
| fastapi, pydantic, pydantic-core, pydantic-settings, sqlalchemy, alembic, mako, anyio, h11, annotated-types, annotated-doc, typing-inspection, argon2-cffi, argon2-cffi-bindings | MIT | Copyright-Hinweis + Lizenztext mitliefern |
| cffi | MIT-0 | – |
| starlette, uvicorn, click, colorama, idna, jinja2, markupsafe, python-dotenv, pycparser | BSD-3-Clause | Copyright-Hinweis + Lizenztext mitliefern |
| opentelemetry-api (über fastapi) | Apache-2.0 | Lizenztext und ggf. NOTICE mitliefern |
| regex (geplant) | Apache-2.0 AND CNRI-Python | Lizenztexte und ggf. NOTICE mitliefern |
| typing-extensions, pywin32, Python-Laufzeit | PSF-2.0 / PSF | Lizenztext mitliefern |
| PyInstaller-Bootloader | GPL-2.0-or-later **mit Bootloader-Ausnahme** | Ausnahme erlaubt die Verbreitung gebündelter Programme unter beliebiger Lizenz |
| Npcap | Npcap-Lizenz | **nicht mitgeliefert**; installiert der Betreiber selbst |

- Das Windows-Paket enthält eine **`THIRD-PARTY-LICENSES.txt`** mit den Lizenztexten (und NOTICE-Dateien) aller
  gebündelten Komponenten. Der Paket-Build (KAN-46) erzeugt sie aus den installierten Paketmetadaten und prüft die
  Lizenzen gegen eine **Allowlist** (MIT, MIT-0, BSD-2/3-Clause, Apache-2.0, PSF-2.0, ISC, CNRI-Python); eine
  unbekannte oder nicht erlaubte Lizenz lässt den Build fehlschlagen.

## Konsequenzen
- **Einfacher:** keine Copyleft-Pflichten für Projekt und Windows-Paket; Apache-2.0-Abhängigkeiten sind zulässig.
  Das Laden der `wpcap.dll` liegt vollständig unter unserer Kontrolle (Schutz vor DLL-Planting). Es kommt keine neue
  Laufzeitabhängigkeit hinzu; der Paketumfang des PyInstaller-Builds sinkt.
- **Schwieriger:** eigener FFI-Code und eigener Paketbau müssen gepflegt werden. Falsche `ctypes`-Signaturen führen zu
  **Abstürzen statt Exceptions** → jede Funktion mit `argtypes`/`restype`, Roundtrip-Tests gegen libpcap unter Linux,
  Smoke-Test im Windows-Paket (KAN-46) und der manuelle Abnahmetest auf dem PC des Betreibers
  (`docs/abnahme-windows.md`, KAN-47). Der eigene pcap-Reader ist zusätzliche Angriffsfläche (Dateien nur aus
  Tests/Entwicklung) → strikte Längenprüfung.
- **Aufwand:** KAN-13 wurde geschnitten; die echte Npcap-Paketquelle ist jetzt **KAN-47** (5 SP). KAN-35, KAN-43 und
  KAN-45 hängen für den Echtbetrieb von KAN-47 ab, ihre Akzeptanzkriterien bleiben mit Fakes testbar. KAN-46 erhält
  `THIRD-PARTY-LICENSES.txt` und die Lizenz-Allowlist.
- **Regel ab sofort:** Es werden **keine (L)GPL- oder AGPL-Laufzeitabhängigkeiten** aufgenommen. Jede neue
  Abhängigkeit (auch transitive, sichtbar im `uv.lock`-Diff) braucht eine **Lizenzprüfung** (PyPI-Metadaten bzw.
  Lizenzdatei, Abgleich mit der Allowlist). **Ausnahmen nur per ADR.** Reine Entwicklungswerkzeuge, die nicht
  ausgeliefert werden, sind davon ausgenommen; der PyInstaller-Bootloader ist durch seine Ausnahme abgedeckt.
- **Zu beobachten:** Lizenzänderungen bei Abhängigkeiten (Dependabot-Updates im `uv.lock` prüfen), neue
  Npcap-Versionen (Funktionssignaturen sind seit libpcap 1.x stabil), Absturzberichte aus dem Capture-Thread.
