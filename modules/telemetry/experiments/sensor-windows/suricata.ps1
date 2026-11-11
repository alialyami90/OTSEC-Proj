# E-D4-01 part 2 (ADR-0009, P4-4-S1): Suricata's official Windows build, with
# no capture driver installed. It checks the installer's pinned SHA-256 and
# its Authenticode signer before running it, installs it, records whether the
# binary starts with no Npcap (and if not, exactly why), and if it starts,
# decodes every capture whose SHA-256 matches its pinned list, offline (-r),
# with and without stream.midstream. Reads recorded or synthesized captures
# only. Never installs Npcap. Results are `simulated (Windows Server)`.
param(
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [string] $Python,
    [Parameter(Mandatory)] [string[]] $CaptureDirs,
    [Parameter(Mandatory)] [string[]] $HashLists,
    [Parameter(Mandatory)] [string] $MsiUrl,
    [Parameter(Mandatory)] [string] $MsiSha256,
    [Parameter(Mandatory)] [string] $MsiSigner
)
# 'Continue': a native program's stderr must not end the run. Every check that
# must stop it (hash, signature) throws explicitly.
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$count = Join-Path $PSScriptRoot 'count.py'
$r = [ordered]@{}

function Get-NpcapState {
    [ordered]@{
        npcap_dir     = Test-Path "$env:SystemRoot\System32\Npcap"
        npcap_service = [bool](Get-Service -Name npcap -ErrorAction SilentlyContinue)
        wpcap_dll     = @(Get-ChildItem -Path "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64" -Filter wpcap.dll -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName)
    }
}
$r.npcap_before = Get-NpcapState

# 1. The download, checked before anything runs.
$msi = Join-Path $env:RUNNER_TEMP 'suricata.msi'
Invoke-WebRequest -UseBasicParsing -Uri $MsiUrl -OutFile $msi
$got = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower()
if ($got -ne $MsiSha256.ToLower()) { throw "installer SHA-256 $got, want $MsiSha256" }
$sig = Get-AuthenticodeSignature $msi
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -ne $MsiSigner) {
    throw "installer signature $($sig.Status), signer '$($sig.SignerCertificate.Subject)', want '$MsiSigner'"
}
$r.installer = [ordered]@{ url = $MsiUrl; sha256 = $got; signature = "$($sig.Status)"; signer = $sig.SignerCertificate.Subject; signer_thumbprint = $sig.SignerCertificate.Thumbprint }

# 2. The install, with a verbose log; any line naming Npcap or a launch condition is kept.
$mlog = Join-Path $Out 'msiexec.log'
$p = Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn', '/norestart', '/l*v', $mlog -Wait -PassThru
$r.msiexec_exit = $p.ExitCode
$r.msiexec_npcap_lines = @(Get-Content $mlog -ErrorAction SilentlyContinue | Where-Object { $_ -match 'npcap|wpcap|LaunchCondition' } | Select-Object -First 15)
$r.npcap_after_install = Get-NpcapState

$exe = Get-ChildItem -Path "$env:ProgramFiles" -Recurse -Filter suricata.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$r.suricata_exe = if ($exe) { $exe.FullName } else { $null }
if (-not $exe) {
    $r | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $Out 'suricata.json')
    exit 0
}

# 3. Which DLLs the binary imports, and whether each resolves on this image.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$dumpbin = if (Test-Path $vswhere) { & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1 }
$r.imports = if ($dumpbin) {
    @(& $dumpbin /nologo /dependents $exe.FullName | Where-Object { $_ -match '^\s+\S+\.dll\s*$' } | ForEach-Object {
        $d = $_.Trim()
        $at = @((Join-Path $exe.DirectoryName $d), (Join-Path "$env:SystemRoot\System32" $d)) | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $at) { $at = (Get-Command $d -ErrorAction SilentlyContinue).Source }
        [ordered]@{ dll = $d; resolves_to = $at }
    })
} else { 'unknown: dumpbin not found' }

# 4. Does it start? A loader failure leaves an exit code and, in the System
# log, the loader's own message (Application Popup, event 26).
$t0 = Get-Date
$v = & $exe.FullName -V 2>&1 | Out-String
$code = $LASTEXITCODE
$r.start = [ordered]@{
    command   = 'suricata.exe -V'
    exit      = $code
    exit_hex  = '0x{0:X8}' -f $code
    output    = $v.Trim()
    loader_events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 26; StartTime = $t0.AddSeconds(-5) } -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object Message)
}
$r.starts = ($code -eq 0)

# 5. The captures, each checked against its pinned SHA-256 first.
$want = [ordered]@{}
foreach ($h in $HashLists) {
    foreach ($line in Get-Content $h) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($h -like '*.tsv') { $f = $line -split "`t"; $want[$f[0]] = $f[1] }
        else { $f = $line -split '\s+', 2; $want[$f[1].TrimStart('*')] = $f[0] }
    }
}
$r.captures = [ordered]@{}
$empty = Join-Path $Out 'empty.rules'
Set-Content -Path $empty -Value '' -Encoding ascii
$yaml = Get-ChildItem -Path $exe.DirectoryName -Recurse -Filter suricata.yaml -ErrorAction SilentlyContinue | Select-Object -First 1
foreach ($name in $want.Keys) {
    if ($name -notmatch '\.pcap(ng)?(\.gz)?$') { continue }
    $file = $CaptureDirs | ForEach-Object { Join-Path $_ $name } | Where-Object { Test-Path $_ } | Select-Object -First 1
    $row = [ordered]@{}
    if (-not $file) { $row.status = 'unknown: not present'; $r.captures[$name] = $row; continue }
    if ((Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -ne $want[$name]) { $row.status = 'unknown: SHA-256 mismatch'; $r.captures[$name] = $row; continue }
    $read = $file -replace '\.gz$', ''   # fetch_captures.sh gunzips beside the .gz
    if (-not (Test-Path $read)) { $row.status = 'unknown: not decompressed'; $r.captures[$name] = $row; continue }
    if (-not $r.starts) { $row.status = 'unknown: suricata.exe does not start'; $r.captures[$name] = $row; continue }
    $row.status = 'ran'
    foreach ($mid in 'false', 'true') {
        $dir = Join-Path $Out "runs\$name-midstream-$mid"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $sargs = @('-r', $read, '-l', $dir, '-k', 'none', '-S', $empty,
                   '--set', 'app-layer.protocols.dnp3.enabled=yes',
                   '--set', 'app-layer.protocols.modbus.enabled=yes',
                   '--set', 'app-layer.protocols.enip.enabled=yes',
                   '--set', "stream.midstream=$mid")
        if ($yaml) { $sargs = @('-c', $yaml.FullName) + $sargs }
        $log = & $exe.FullName @sargs 2>&1 | Out-String
        $eve = Join-Path $dir 'eve.json'
        $m = [regex]::Match($log, 'read (\d+) files?, (\d+) packets')
        $row["midstream=$mid"] = [ordered]@{
            exit      = $LASTEXITCODE
            packets_read = if ($m.Success) { [int]$m.Groups[2].Value } else { $null }
            protocols = if (Test-Path $eve) { (& $Python -I $count eve $eve) | ConvertFrom-Json } else { $null }
            log_tail  = ($log.Trim() -split "`n" | Select-Object -Last 2) -join "`n"
        }
    }
    $r.captures[$name] = $row
}
$r.npcap_at_end = Get-NpcapState
$r | ConvertTo-Json -Depth 8 | Tee-Object -FilePath (Join-Path $Out 'suricata.json')
