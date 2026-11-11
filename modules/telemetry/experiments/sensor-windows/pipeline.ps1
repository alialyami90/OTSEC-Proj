# E-D4-01 part 2 (ADR-0009, P4-4-A6): the (a') pipeline end to end on the
# runner. pktmon captures while the runner downloads one public capture and
# replays two recorded sessions' payloads over loopback (replay.py, 127.0.0.1
# only); `pktmon etl2pcap` converts; Suricata reads the pcapng. Packets are
# counted at each stage. Two passes: capture at the NICs only, and at every
# component (pktmon's default). Raw captures of the runner's own traffic are
# deleted, never uploaded: only counts leave the runner. `simulated (Windows Server)`.
param(
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [string] $Python,
    [Parameter(Mandatory)] [string] $Manifest,
    [Parameter(Mandatory)] [string] $SuricataJson
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$count = Join-Path $PSScriptRoot 'count.py'
$replay = Join-Path $PSScriptRoot 'replay.py'
$sj = Get-Content $SuricataJson -Raw | ConvertFrom-Json
$exe = if ($sj.starts) { $sj.suricata_exe } else { $null }
$rows = @{}
foreach ($line in Get-Content $Manifest) {
    if ($line -notmatch '^#') { $f = $line -split "`t"; $rows[$f[0]] = $f }
}
# The sessions replayed over loopback: (capture, the TCP port of its server side).
$sessions = @(@('dnp3-select-operate.pcap', 20000), @('modbus.pcap', 502))
$r = [ordered]@{ engine = if ($exe) { $sj.start.output } else { 'unknown: suricata.exe does not start (see suricata.json)' }; passes = [ordered]@{} }

foreach ($comp in 'nics', 'all') {
    $pass = [ordered]@{}
    $etl = Join-Path $Out "pktmon-$comp.etl"
    $png = Join-Path $Out "pktmon-$comp.pcapng"
    $work = Join-Path $Out "work-$comp"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    pktmon filter remove 2>&1 | Out-Null
    $pass.pktmon_start = (pktmon start --capture --comp $comp --pkt-size 0 --file-name $etl 2>&1 | Out-String).Trim()

    # Stage 1: traffic. A download of the first session's capture (checked
    # against its pinned SHA-256), then each session replayed over loopback.
    $pass.sent = [ordered]@{}
    foreach ($s in $sessions) {
        $name, $port = $s[0], $s[1]
        $dst = Join-Path $work $name
        try { Invoke-WebRequest -UseBasicParsing -Uri $rows[$name][2] -OutFile $dst | Out-Null } catch { }
        $ok = (Test-Path $dst) -and ((Get-FileHash -Algorithm SHA256 $dst).Hash.ToLower() -eq $rows[$name][1])
        $pass.sent[$name] = if ($ok) {
            (& $Python -I $replay $dst $port) | ConvertFrom-Json
        } else { 'unknown: download failed or SHA-256 mismatch' }
    }

    # Stage 2: what pktmon kept, and the conversion.
    $pass.pktmon_stop = (pktmon stop 2>&1 | Out-String).Trim()
    $pass.etl2pcap = (pktmon etl2pcap $etl --out $png 2>&1 | Out-String).Trim()
    if (Test-Path $png) {
        $pass.pcapng = [ordered]@{}
        foreach ($s in $sessions) {
            $pass.pcapng["tcp_port_$($s[1])"] = (& $Python -I $count port $png $s[1]) | ConvertFrom-Json
        }
        # Stage 3: the engine reads the pcapng.
        if ($exe) {
            $dir = Join-Path $work 'suricata'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $empty = Join-Path $work 'empty.rules'
            Set-Content -Path $empty -Value '' -Encoding ascii
            $log = & $exe -r $png -l $dir -k none -S $empty --set app-layer.protocols.dnp3.enabled=yes --set app-layer.protocols.modbus.enabled=yes --set stream.midstream=true 2>&1 | Out-String
            $m = [regex]::Match($log, 'read (\d+) files?, (\d+) packets')
            $eve = Join-Path $dir 'eve.json'
            $pass.engine = [ordered]@{
                exit = $LASTEXITCODE
                packets_read = if ($m.Success) { [int]$m.Groups[2].Value } else { $null }
                protocols = if (Test-Path $eve) { (& $Python -I $count eve $eve) | ConvertFrom-Json } else { $null }
                log_tail = ($log.Trim() -split "`n" | Select-Object -Last 2) -join "`n"
            }
        } else {
            $pass.engine = 'unknown: no engine starts on this image'
        }
    } else {
        $pass.pcapng = 'unknown: etl2pcap wrote no file'
    }
    # Raw captures and engine logs of the runner's own traffic are not kept.
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $etl, $png, $work
    $r.passes["comp=$comp"] = $pass
}
$r | ConvertTo-Json -Depth 8 | Tee-Object -FilePath (Join-Path $Out 'pipeline.json')
