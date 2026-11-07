# E-D4-01 (ADR-0009): offline decoding by Suricata's Windows build, with no
# capture driver installed. Runs only when the dispatcher supplies the
# installer URL and its SHA-256 (read from the vendor's download page by a
# person, not guessed here). Reads public captures only. `simulated`.
param(
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [string] $Python,
    [Parameter(Mandatory)] [string] $Cache,
    [Parameter(Mandatory)] [string] $MsiUrl,
    [Parameter(Mandatory)] [string] $MsiSha256
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$msi = Join-Path $env:RUNNER_TEMP 'suricata.msi'
Invoke-WebRequest -UseBasicParsing -Uri $MsiUrl -OutFile $msi
$got = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower()
if ($got -ne $MsiSha256.ToLower()) { throw "installer SHA-256 $got, want $MsiSha256" }
$p = Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn', '/norestart' -Wait -PassThru
$r = [ordered]@{ installer_sha256 = $got; msiexec_exit = $p.ExitCode }
$exe = Get-ChildItem -Path "$env:ProgramFiles" -Recurse -Filter suricata.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$r.suricata_exe = if ($exe) { $exe.FullName } else { $null }
if ($exe) {
    $r.version = (& $exe.FullName -V 2>&1 | Out-String).Trim()
    $yaml = Get-ChildItem -Path $exe.DirectoryName -Recurse -Filter suricata.yaml -ErrorAction SilentlyContinue | Select-Object -First 1
    $r.runs = [ordered]@{}
    $caps = 'dnp3-read.pcap', 'dnp3-write.pcap', 'dnp3-select-operate.pcap', 'dnp3-malformed.pcap',
            'dnp3-digitalbond-part1.pcap', 'dnp3-digitalbond-part2.pcap',
            'modbus.pcap', 'modbus-digitalbond-part1.pcap', 'modbus-digitalbond-part2.pcap'
    foreach ($c in $caps) {
        foreach ($mid in 'false', 'true') {
            $dir = Join-Path $Out "$c-midstream-$mid"
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $sargs = @('-r', (Join-Path $Cache $c), '-l', $dir, '-k', 'none',
                      '--set', 'app-layer.protocols.dnp3.enabled=yes',
                      '--set', 'app-layer.protocols.modbus.enabled=yes',
                      '--set', "stream.midstream=$mid")
            if ($yaml) { $sargs = @('-c', $yaml.FullName) + $sargs }
            $log = & $exe.FullName @sargs 2>&1 | Out-String
            $eve = Join-Path $dir 'eve.json'
            $r.runs["$c midstream=$mid"] = [ordered]@{
                exit = $LASTEXITCODE
                protocols = if (Test-Path $eve) { (& $Python -I (Join-Path $PSScriptRoot 'count.py') eve $eve) | ConvertFrom-Json } else { $null }
                log_tail = ($log -split "`n" | Select-Object -Last 3) -join "`n"
            }
        }
    }
}
$r | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $Out 'suricata.json')
