<#
.SYNOPSIS
    Smoke-Test des Windows-Pakets (KAN-46): entpackt das Zip, prüft --version und /api/health.

.DESCRIPTION
    Läuft ohne Python (nur das entpackte EXE) in Windows PowerShell 5.1 und PowerShell 7.
    1. Prüfsumme gegen <zip>.sha256 prüfen (falls vorhanden)
    2. Zip in ein frisches temporäres Verzeichnis entpacken, Pflichtdateien und Npcap-Freiheit prüfen
    3. network-sniffer.exe --version (AC4) -> muss "network-sniffer <version>" ausgeben
    4. network-sniffer.exe serve mit NS_CAPTURE_SOURCE=none, temporärem NS_DATA_DIR und zufälligem
       NS_SECRET_KEY starten, GET /api/health mit Retry (Standard 30 s): HTTP 200, status ok,
       Version, db ok
    5. Ersteinrichtung (KAN-37): ohne Benutzer leitet / auf /setup um (303), /setup (Template) und
       /static/style.css liefern 200; network-sniffer.exe create-admin --password-stdin legt einen
       Admin an (prüft Argon2 im Paket), ein zweiter Aufruf scheitert; danach / -> 200 und
       /setup -> Redirect auf /login
    6. Prozess beenden, temporäres Verzeichnis entfernen
    Exit-Code 0 bei Erfolg, 1 bei jedem Fehler.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File packaging/smoke_test.ps1 -ZipPath dist/network-sniffer-1.2.3-windows-x64.zip
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ZipPath,
    # Standard: Version aus dem Dateinamen network-sniffer-<version>-windows-x64.zip
    [string]$ExpectedVersion,
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Expand-Archive/Invoke-WebRequest in PS 5.1 deutlich schneller

function Write-Step([string]$Message) { Write-Host "[smoke] $Message" }

# GET ohne Redirect-Verfolgung; liefert Status und Location (PS 5.1 und 7 einheitlich, auch für 3xx).
function Get-HttpStatus([string]$Url) {
    $request = [Net.HttpWebRequest]::Create($Url)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 5000
    try {
        $response = $request.GetResponse()
    } catch [Net.WebException] {
        $response = $_.Exception.Response
        if ($null -eq $response) { throw }
    }
    try {
        return [pscustomobject]@{ Status = [int]$response.StatusCode; Location = $response.Headers['Location'] }
    } finally {
        $response.Close()
    }
}

# create-admin mit Passwort über stdin. stderr wird mitgelesen; in PS 5.1 würde 2>&1 bei einem
# nativen Programm mit ErrorActionPreference=Stop sonst sofort eine Ausnahme auslösen.
function Invoke-CreateAdmin([string]$Exe, [string]$Username, [string]$Secret) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = ($Secret | & $Exe create-admin --username $Username --password-stdin 2>&1 |
            ForEach-Object { "$_" } | Out-String).Trim()
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Assert-HttpStatus([string]$Path, [int]$Status, [string]$Location) {
    $result = Get-HttpStatus "http://127.0.0.1:$Port$Path"
    if ($result.Status -ne $Status) { throw "GET $Path lieferte HTTP $($result.Status), erwartet $Status" }
    if ($Location -and $result.Location -ne $Location) {
        throw "GET $Path leitet auf '$($result.Location)' um, erwartet '$Location'"
    }
}

$zip = (Resolve-Path -LiteralPath $ZipPath).Path
$zipName = Split-Path -Leaf $zip
if (-not $ExpectedVersion) {
    if ($zipName -notmatch '^network-sniffer-(.+)-windows-x64\.zip$') {
        throw "Version nicht aus dem Dateinamen ableitbar: $zipName (Parameter -ExpectedVersion angeben)"
    }
    $ExpectedVersion = $Matches[1]
}

$workDir = Join-Path ([IO.Path]::GetTempPath()) ("ns-smoke-" + [Guid]::NewGuid().ToString('N'))
$process = $null
$exitCode = 1
try {
    $checksumFile = "$zip.sha256"
    if (Test-Path -LiteralPath $checksumFile) {
        $expectedHash = ((Get-Content -LiteralPath $checksumFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $actualHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expectedHash -ne $actualHash) { throw "SHA-256 stimmt nicht: $actualHash, erwartet $expectedHash" }
        Write-Step "SHA-256 ok: $actualHash"
    } else {
        Write-Step "Keine Prüfsummendatei $checksumFile - Prüfung übersprungen"
    }

    $extractDir = Join-Path $workDir 'paket'
    $dataDir = Join-Path $workDir 'daten'
    New-Item -ItemType Directory -Path $extractDir, $dataDir | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $extractDir
    $exe = @(Get-ChildItem -LiteralPath $extractDir -Recurse -Filter 'network-sniffer.exe')
    if ($exe.Count -ne 1) { throw "network-sniffer.exe nicht eindeutig im Paket gefunden ($($exe.Count) Treffer)" }
    $exe = $exe[0].FullName
    $appDir = Split-Path -Parent $exe
    Write-Step "Entpackt nach $appDir"

    foreach ($file in 'LICENSE', 'README.md', 'THIRD-PARTY-LICENSES.txt') {
        if (-not (Test-Path -LiteralPath (Join-Path $appDir $file))) { throw "$file fehlt im Paket" }
    }
    $npcap = @(Get-ChildItem -LiteralPath $extractDir -Recurse -File |
        Where-Object { @('wpcap.dll', 'packet.dll') -contains $_.Name.ToLowerInvariant() })
    if ($npcap.Count -gt 0) { throw "Npcap-DLLs im Paket gefunden: $($npcap.FullName -join ', ')" }
    Write-Step 'Pflichtdateien vorhanden, keine Npcap-DLLs'

    # AC4: Version direkt aus dem entpackten EXE (ohne Python)
    $versionOutput = (& $exe --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "--version beendet mit Exit-Code $LASTEXITCODE" }
    if ($versionOutput -ne "network-sniffer $ExpectedVersion") {
        throw "--version lieferte '$versionOutput', erwartet 'network-sniffer $ExpectedVersion'"
    }
    Write-Step "--version: $versionOutput"

    # Zufälliger Test-Schlüssel (48 Zeichen, >= 32 gefordert); wird nirgends ausgegeben.
    $bytes = New-Object byte[] 36
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $env:NS_SECRET_KEY = [Convert]::ToBase64String($bytes)
    $env:NS_CAPTURE_SOURCE = 'none'
    $env:NS_DATA_DIR = $dataDir
    $env:NS_PORT = "$Port"

    $stdout = Join-Path $workDir 'stdout.log'
    $stderr = Join-Path $workDir 'stderr.log'
    # Arbeitsverzeichnis = leeres Verzeichnis, damit keine fremde .env gelesen wird.
    $process = Start-Process -FilePath $exe -ArgumentList 'serve' -WorkingDirectory $dataDir -PassThru `
        -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Write-Step "serve gestartet (PID $($process.Id)), warte bis zu $TimeoutSeconds s auf /api/health"

    $url = "http://127.0.0.1:$Port/api/health"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $health = $null
    $lastError = ''
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) { throw "serve ist vorzeitig beendet (Exit-Code $($process.ExitCode))" }
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                $health = $response.Content | ConvertFrom-Json
                break
            }
            $lastError = "HTTP $($response.StatusCode)"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Seconds 1
    }
    if ($null -eq $health) { throw "/api/health nicht erfolgreich innerhalb von $TimeoutSeconds s: $lastError" }
    Write-Step "/api/health: $($response.Content)"
    if ($health.status -ne 'ok') { throw "status ist '$($health.status)', erwartet 'ok'" }
    if ($health.version -ne $ExpectedVersion) { throw "version ist '$($health.version)', erwartet '$ExpectedVersion'" }
    if ($health.db -ne 'ok') { throw "db ist '$($health.db)', erwartet 'ok'" }

    # KAN-37: Ohne Benutzer leitet das Dashboard auf die Setup-Seite um. Templates und statische
    # Dateien müssen im Paket enthalten sein.
    Assert-HttpStatus -Path '/' -Status 303 -Location '/setup'
    Assert-HttpStatus -Path '/setup' -Status 200
    Assert-HttpStatus -Path '/static/style.css' -Status 200
    Write-Step 'Ohne Benutzer: / -> /setup, Setup-Seite und statische Dateien ok'

    # Ersten Admin per CLI anlegen (Passwort zufällig, nur über stdin, wird nirgends ausgegeben).
    $pwBytes = New-Object byte[] 18
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($pwBytes) } finally { $rng.Dispose() }
    $adminSecret = [Convert]::ToBase64String($pwBytes)
    $first = Invoke-CreateAdmin -Exe $exe -Username 'smoke-admin' -Secret $adminSecret
    if ($first.ExitCode -ne 0) { throw "create-admin beendet mit Exit-Code $($first.ExitCode): $($first.Output)" }
    Write-Step "create-admin: $($first.Output)"
    $second = Invoke-CreateAdmin -Exe $exe -Username 'zweiter' -Secret $adminSecret
    if ($second.ExitCode -eq 0) { throw 'create-admin legte einen zweiten Admin an (erwartet Exit-Code <> 0)' }
    Write-Step "zweites create-admin abgewiesen (Exit-Code $($second.ExitCode)): $($second.Output)"

    Assert-HttpStatus -Path '/' -Status 200
    Assert-HttpStatus -Path '/setup' -Status 303 -Location '/login'
    Write-Step 'Nach der Ersteinrichtung: Startseite 200, /setup -> /login'

    Write-Step 'Smoke-Test erfolgreich'
    $exitCode = 0
} catch {
    Write-Host "[smoke] FEHLER: $($_.Exception.Message)"
    foreach ($log in 'stdout.log', 'stderr.log') {
        $logPath = Join-Path $workDir $log
        if (Test-Path -LiteralPath $logPath) {
            Write-Host "----- $log -----"
            Get-Content -LiteralPath $logPath | Write-Host
        }
    }
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit(10000) | Out-Null
        Write-Step 'serve beendet'
    }
    foreach ($name in 'NS_SECRET_KEY', 'NS_CAPTURE_SOURCE', 'NS_DATA_DIR', 'NS_PORT') {
        Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $workDir) {
        try {
            Remove-Item -LiteralPath $workDir -Recurse -Force
        } catch {
            Write-Step "Temporäres Verzeichnis nicht entfernt: $workDir"
        }
    }
}
exit $exitCode
