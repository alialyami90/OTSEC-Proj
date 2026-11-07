# E-D4-01 (ADR-0009): what a GitHub-hosted Windows Server VM offers a passive
# sensor with nothing third-party installed. Run only from the dispatch-only
# workflow d4-sensor-eval.yml on a throwaway runner. It captures only the
# runner's own traffic while it downloads one public capture; it never sends
# anything to any other host and contacts no device. Results are `simulated`
# (Windows Server, not ADR-0007's 10/11 LTSC floor).
param(
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [string] $Python
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$r = [ordered]@{}

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r.os = [ordered]@{ product = $cv.ProductName; edition = $cv.EditionID; display_version = $cv.DisplayVersion; build = $cv.CurrentBuild }

# Is a third-party capture driver already present on the image?
$r.npcap_present = (Test-Path "$env:SystemRoot\System32\Npcap") -or [bool](Get-Service -Name npcap -ErrorAction SilentlyContinue)

# The built-in Packet Monitor (pktmon), which needs no third-party driver.
$pk = Get-Command pktmon.exe -ErrorAction SilentlyContinue
$r.pktmon_present = [bool]$pk
if ($pk) {
    $etl = Join-Path $Out 'pktmon.etl'
    $png = Join-Path $Out 'pktmon.pcapng'
    pktmon filter remove 2>&1 | Out-Null
    $start = pktmon start --capture --pkt-size 0 --file-name $etl 2>&1
    $r.pktmon_start = ($start | Out-String).Trim()
    # Traffic to observe: the runner's own download of one public capture
    # listed in MANIFEST.tsv (the URL is read from the manifest, not typed here).
    $row = Get-Content (Join-Path $PSScriptRoot '..\..\..\..\tests\fixtures\network\public-ot-captures\MANIFEST.tsv') |
        Where-Object { $_ -like 'dnp3-read.pcap*' } | Select-Object -First 1
    $url = ($row -split "`t")[2]
    try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile (Join-Path $Out 'dnp3-read.pcap') | Out-Null; $r.download = 'ok' }
    catch { $r.download = "failed: $($_.Exception.Message)" }
    $r.pktmon_stop = (pktmon stop 2>&1 | Out-String).Trim()
    $r.pktmon_etl2pcap = (pktmon etl2pcap $etl --out $png 2>&1 | Out-String).Trim()
    if (Test-Path $png) {
        $r.pktmon_packets = [int](& $Python -I (Join-Path $PSScriptRoot 'count.py') pcapng $png)
    } else {
        $r.pktmon_packets = $null
    }
    # Raw capture files are not uploaded: they hold the runner's own traffic.
    Remove-Item -Force -ErrorAction SilentlyContinue $etl, $png
}

$r | ConvertTo-Json -Depth 4 | Tee-Object -FilePath (Join-Path $Out 'probe.json')
