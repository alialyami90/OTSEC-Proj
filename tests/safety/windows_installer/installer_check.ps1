# A6 check of A5's Windows installer (#92): A3 T-13 W-2 to W-4 as far as they
# can run without A3's collector, -collector-config, collector\public, the
# WER value, a short start of the node service, uninstall, and removal of
# everything this script created.
#
# Run elevated, once, on a machine the owner approved. It refuses to start if
# any OTSEC service, folder, firewall rule, event source or WER value already
# exists, other than the folder the non-admin W-4 step pre-creates. Nothing
# here contacts a device: the node's only endpoint is 127.0.0.1:2323 (D2-10),
# no collector runs, and the collector binary is a renamed copy of otsec.exe
# that is installed but never started.
#
# Evidence class: simulated host, native Windows. Results go to
# <LogDir>\installer-results.txt as "RESULT <id> PASS|FAIL <detail>".

param(
    [Parameter(Mandatory = $true)][string]$Exe,       # otsec.exe built from the PR head
    [Parameter(Mandatory = $true)][string]$LogDir,
    [int]$WaitNonAdminSeconds = 900,
    [int]$ServiceRunSeconds = 90
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$results = Join-Path $LogDir 'installer-results.txt'
Set-Content -Path $results -Value "A6 installer check $(Get-Date -Format o)"
Start-Transcript -Path (Join-Path $LogDir 'installer-elevated.log') -Force | Out-Null

function Result([string]$id, [bool]$ok, [string]$detail) {
    $line = "RESULT $id $(if ($ok) { 'PASS' } else { 'FAIL' }) $detail"
    Add-Content -Path $results -Value $line
    Write-Output $line
}
function Note([string]$text) { Add-Content -Path $results -Value "NOTE $text"; Write-Output "NOTE $text" }
# Native stderr must not become a terminating error under 'Stop'. Not named
# Sc: in Windows PowerShell 'sc' is an alias of Set-Content, and an alias
# wins over a function.
function ScExe([string[]]$a) { $ErrorActionPreference = 'Continue'; (& sc.exe @a 2>&1 | Out-String) }
function Sddl([string]$path) {
    (Get-Acl -LiteralPath $path).GetSecurityDescriptorSddlForm('Owner, Access')
}
function Aces([string]$sddl) { [regex]::Matches($sddl, '\([^)]*\)') | ForEach-Object { $_.Value } }
function RunOtsec([string[]]$a) {
    $ErrorActionPreference = 'Continue'
    $out = & $script:nodeExe @a 2>&1 | Out-String
    return @{ Code = $LASTEXITCODE; Out = $out.Trim() }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Result 'P-0' $false 'not elevated; nothing was changed'; Stop-Transcript | Out-Null; exit 3 }

$pd = Join-Path $env:ProgramData 'OTSEC'
$pf = Join-Path $env:ProgramFiles 'OTSEC'
$services = @('otsec-node', 'otsec-collector')
$rule = 'otsec-node: no outbound Telnet (W-3)'
$werKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$werValue = 'otsec-collector.exe'

# ---- Preflight: refuse to touch anything this script did not create.
$blockers = @()
foreach ($s in $services) { if (Get-Service -Name $s -ErrorAction SilentlyContinue) { $blockers += "service $s exists" } }
if (Test-Path -LiteralPath $pf) { $blockers += "$pf exists" }
if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) { $blockers += 'firewall rule exists' }
foreach ($s in $services) { if ([Diagnostics.EventLog]::SourceExists($s)) { $blockers += "event source $s exists" } }
$werKeyExisted = Test-Path -LiteralPath $werKey
if ($werKeyExisted -and ((Get-Item -LiteralPath $werKey).GetValueNames() -contains $werValue)) { $blockers += 'WER value exists' }
# The only thing allowed to exist is the W-4 folder the non-admin step made:
# OTSEC\store, empty, with OTSEC owned by someone other than Administrators.
$precreated = $false
if (Test-Path -LiteralPath $pd) {
    $kids = @(Get-ChildItem -LiteralPath $pd -Force)
    $owner = (Get-Acl -LiteralPath $pd).Owner
    if ($kids.Count -eq 1 -and $kids[0].Name -eq 'store' -and $kids[0].PSIsContainer -and
        @(Get-ChildItem -LiteralPath $kids[0].FullName -Force).Count -eq 0 -and $owner -ne 'BUILTIN\Administrators') {
        $precreated = $true
        Note "W-4 pre-created folder found, owner $owner"
    } else {
        $blockers += "$pd exists and is not the W-4 pre-created folder"
    }
}
if ($blockers.Count -gt 0) {
    Result 'P-1' $false ("preflight refused, nothing was changed: " + ($blockers -join '; '))
    Stop-Transcript | Out-Null
    exit 4
}
Result 'P-1' $true "preflight clean (WER key existed before: $werKeyExisted)"

$nodeSid = ([regex]::Match((ScExe @('showsid', 'otsec-node')), 'S-1-5-80-[0-9-]+')).Value
$collSid = ([regex]::Match((ScExe @('showsid', 'otsec-collector')), 'S-1-5-80-[0-9-]+')).Value
Note "service SIDs: otsec-node $nodeSid, otsec-collector $collSid"
if (-not $nodeSid -or -not $collSid -or $nodeSid -eq $collSid) {
    Result 'P-2' $false 'could not read the service SIDs with sc.exe showsid; nothing was changed'
    Stop-Transcript | Out-Null
    exit 5
}

$inputs = Join-Path $LogDir 'inputs'
New-Item -ItemType Directory -Force -Path $inputs | Out-Null
$storeDir = Join-Path $pd 'store'
$nodeCfg = Join-Path $inputs 'node.json'
$json = (Get-Content -Raw -LiteralPath (Join-Path $here 'node.template.json')).Replace('STOREDIR', $storeDir.Replace('\', '\\'))
[IO.File]::WriteAllText($nodeCfg, $json)
$collCfg = Join-Path $inputs 'collector.json'
Copy-Item -LiteralPath (Join-Path $here 'collector.stand-in.json') -Destination $collCfg -Force

$createdPf = $false
try {
    New-Item -ItemType Directory -Path $pf | Out-Null
    $createdPf = $true
    $script:nodeExe = Join-Path $pf 'otsec.exe'
    $collExe = Join-Path $pf 'otsec-collector.exe'
    Copy-Item -LiteralPath $Exe -Destination $script:nodeExe
    Copy-Item -LiteralPath $Exe -Destination $collExe   # stand-in: installed, never started
    $installArgs = @('install', '-config', $nodeCfg, '-collector-exe', $collExe, '-collector-config', $collCfg)

    # ---- W-4: a folder pre-created by a non-admin user stops the installer.
    if ($precreated) {
        $r = RunOtsec $installArgs
        Note "W-4 install output: $($r.Out)"
        $noSvc = -not (Get-Service -Name 'otsec-node' -ErrorAction SilentlyContinue)
        Result 'W-4' ($r.Code -ne 0 -and $r.Out -match 'W-4' -and $noSvc) "exit $($r.Code); no service created: $noSvc"
        Remove-Item -LiteralPath $pd -Recurse -Force
        Result 'W-4-clean' (-not (Test-Path -LiteralPath $pd)) 'pre-created folder removed'
    } else {
        Result 'W-4' $false 'skipped: the non-admin step did not pre-create OTSEC\store'
    }

    # ---- Install.
    $r = RunOtsec $installArgs
    Note "install output: $($r.Out)"
    Result 'I-1' ($r.Code -eq 0) "install exit $($r.Code)"
    if ($r.Code -ne 0) { throw 'install failed; going to cleanup' }

    # Directory descriptors, against TestDirs (8 since D2-12 added config\tls).
    $want = [ordered]@{
        ''                       = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;$nodeSid)(A;;0x1200a9;;;$collSid)"
        'config'                 = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$nodeSid)"
        'config\tls'             = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$nodeSid)"
        'store'                  = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$nodeSid)"
        'collector'              = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$collSid)"
        'collector\credentials'  = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$collSid)"
        'collector\state'        = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$collSid)"
        'collector\public'       = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$collSid)(A;OICI;0x1200a9;;;$nodeSid)"
    }
    foreach ($k in $want.Keys) {
        $p = if ($k) { Join-Path $pd $k } else { $pd }
        $s = Sddl $p
        Note "SDDL $p = $s"
        $okOwner = $s.StartsWith('O:BAD:P')
        $got = (Aces $s) -join ''
        $wantSorted = ((Aces $want[$k]) | Sort-Object) -join ''
        $gotSorted = ((Aces $s) | Sort-Object) -join ''
        Result "D-$(if ($k) { $k } else { 'root' })" ($okOwner -and $gotSorted -eq $wantSorted) "owner BA and protected: $okOwner; ACEs $got"
    }

    $s = Sddl (Join-Path $pd 'config\node.json')
    Note "SDDL node.json = $s"
    Result 'F-node.json' ((-not $s.Contains($collSid)) -and $s -notmatch ';;;(WD|BU|AU|IU)\)') 'no collector or user entry'

    $s = Sddl (Join-Path $pd 'collector\collector.json')
    Note "SDDL collector.json = $s"
    $okColl = $s.StartsWith('O:BA') -and $s.Contains(";0x1200a9;;;$collSid)") -and (-not $s.Contains($nodeSid)) -and
        ($s -notmatch ';;;(WD|BU|AU|IU)\)') -and ($s -notmatch "\(A;[^;]*;(FA|0x1f01ff);;;$collSid\)")
    Result 'F-collector.json' $okColl 'owner BA, collector read only, no node entry (-collector-config)'

    Result 'F-provision' (Test-Path -LiteralPath (Join-Path $pd 'collector\state\provision')) 'first-start marker written'

    # Services (W-2 configuration; the token check needs a running collector).
    foreach ($svc in $services) {
        $qc = ScExe @('qc', $svc); $sid = ScExe @('qsidtype', $svc); $pr = ScExe @('qprivs', $svc); $fl = ScExe @('qfailure', $svc)
        Note "sc qc $svc :: $($qc -replace '\s+', ' ')"
        Note "sc qsidtype $svc :: $($sid -replace '\s+', ' ')"
        Note "sc qprivs $svc :: $($pr -replace '\s+', ' ')"
        Note "sc qfailure $svc :: $($fl -replace '\s+', ' ')"
        $okAcct = $qc -match "SERVICE_START_NAME\s*:\s*NT SERVICE\\$svc"
        $okSid = $sid -match 'SERVICE_SID_TYPE\s*:\s*UNRESTRICTED'
        $privs = @([regex]::Matches($pr, 'Se[A-Za-z]+Privilege') | ForEach-Object { $_.Value })
        $okPriv = ($privs.Count -eq 1 -and $privs[0] -eq 'SeChangeNotifyPrivilege')
        $okFail = $fl -match 'RESTART'
        Result "S-$svc" ($okAcct -and $okSid -and $okPriv -and $okFail) "virtual account: $okAcct; unrestricted SID: $okSid; privileges: $($privs -join ','); restart on failure: $okFail"
    }

    $wk = Get-Item -LiteralPath $werKey -ErrorAction SilentlyContinue
    if ($wk -and ($wk.GetValueNames() -contains $werValue)) {
        Result 'WER' ($wk.GetValue($werValue) -eq 1 -and "$($wk.GetValueKind($werValue))" -eq 'DWord') "value $($wk.GetValue($werValue)), kind $($wk.GetValueKind($werValue))"
    } else { Result 'WER' $false 'value not found' }

    $fw = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($fw) {
        $port = $fw | Get-NetFirewallPortFilter
        $svcf = $fw | Get-NetFirewallServiceFilter
        Note "firewall: direction $($fw.Direction), action $($fw.Action), enabled $($fw.Enabled), protocol $($port.Protocol), remote port $($port.RemotePort), service $($svcf.Service)"
        Result 'W-3-rule' ($fw.Direction -eq 'Outbound' -and $fw.Action -eq 'Block' -and $port.Protocol -eq 'TCP' -and
            "$($port.RemotePort)" -eq '23' -and $svcf.Service -eq 'otsec-node' -and "$($fw.Enabled)" -eq 'True') 'block outbound TCP 23 for otsec-node'
    } else { Result 'W-3-rule' $false 'rule not found' }

    foreach ($svc in $services) { Result "E-$svc" ([Diagnostics.EventLog]::SourceExists($svc)) 'event log source' }

    # A second install changes nothing.
    $before = (Get-FileHash -LiteralPath (Join-Path $pd 'config\node.json')).Hash
    $r = RunOtsec $installArgs
    Note "second install output: $($r.Out)"
    $after = (Get-FileHash -LiteralPath (Join-Path $pd 'config\node.json')).Hash
    Result 'I-2' ($r.Code -ne 0 -and $before -eq $after) "second install exit $($r.Code); node.json unchanged: $($before -eq $after)"

    # ---- Hand over to the non-admin checks, then wait for them.
    Set-Content -Path (Join-Path $LogDir 'elevated-installed') -Value (Get-Date -Format o)
    $done = Join-Path $LogDir 'nonadmin-done'
    $deadline = (Get-Date).AddSeconds($WaitNonAdminSeconds)
    while (-not (Test-Path -LiteralPath $done) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
    Result 'N-handover' (Test-Path -LiteralPath $done) 'non-admin checks finished before the timeout'

    # ---- Start the node service briefly. No collector runs, so its runs
    # fail closed at the pipe; nothing reaches a device.
    $t0 = Get-Date
    try { Start-Service -Name 'otsec-node' } catch { Note "Start-Service: $($_.Exception.Message)" }
    Start-Sleep -Seconds $ServiceRunSeconds
    $st = (Get-Service -Name 'otsec-node').Status
    Note "otsec-node status after $ServiceRunSeconds s: $st"
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'otsec-node'; StartTime = $t0 } -ErrorAction SilentlyContinue
    foreach ($e in @($ev)) { if ($e) { Note "event $($e.TimeCreated.ToString('o')) $($e.LevelDisplayName): $($e.Message -replace '\s+', ' ')" } }
    $files = @(Get-ChildItem -LiteralPath $storeDir -Force | ForEach-Object { $_.Name })
    Note "store files: $($files -join ', ')"
    $h = RunOtsec @('health', '-config', (Join-Path $pd 'config\node.json'))
    Note "otsec health (exit $($h.Code)): $($h.Out -replace '\s+', ' ')"
    Result 'R-node' ($st -eq 'Running' -and $files.Count -gt 0) "service $st; store has $($files.Count) files"
    $p = Get-CimInstance Win32_Service -Filter "Name='otsec-node'"
    Note "otsec-node process id $($p.ProcessId), start name $($p.StartName)"
    try { Stop-Service -Name 'otsec-node' -Force } catch { Note "Stop-Service: $($_.Exception.Message)" }
    Result 'R-stop' ((Get-Service -Name 'otsec-node').Status -eq 'Stopped') 'node service stopped'
}
catch {
    Result 'X' $false "error: $($_.Exception.Message)"
}
finally {
    # ---- Uninstall, then remove everything this script created.
    if (Test-Path -LiteralPath (Join-Path $pf 'otsec.exe')) {
        $r = RunOtsec @('uninstall')
        Note "uninstall output: $($r.Out)"
        Result 'U-1' ($r.Code -eq 0) "uninstall exit $($r.Code)"
    }
    Start-Sleep -Seconds 5
    foreach ($svc in $services) {
        $gone = -not (Get-Service -Name $svc -ErrorAction SilentlyContinue)
        Result "U-svc-$svc" $gone 'service removed'
        Result "U-src-$svc" (-not [Diagnostics.EventLog]::SourceExists($svc)) 'event source removed'
    }
    Result 'U-fw' (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) 'firewall rule removed'
    $vals = if (Test-Path -LiteralPath $werKey) { (Get-Item -LiteralPath $werKey).GetValueNames() } else { @() }
    Result 'U-wer' (-not ($vals -contains $werValue)) 'WER value removed'
    # Uninstall keeps the store by design; this test's folders go too.
    if (Test-Path -LiteralPath $pd) { Remove-Item -LiteralPath $pd -Recurse -Force }
    if ($createdPf -and (Test-Path -LiteralPath $pf)) { Remove-Item -LiteralPath $pf -Recurse -Force }
    if (-not $werKeyExisted -and (Test-Path -LiteralPath $werKey) -and
        (Get-Item -LiteralPath $werKey).GetValueNames().Count -eq 0 -and @(Get-ChildItem -LiteralPath $werKey).Count -eq 0) {
        Remove-Item -LiteralPath $werKey
        Note 'removed the ExcludedApplications key this run created'
    }
    $left = @()
    foreach ($svc in $services) { if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { $left += "service $svc" } }
    if (Test-Path -LiteralPath $pd) { $left += $pd }
    if (Test-Path -LiteralPath $pf) { $left += $pf }
    if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) { $left += 'firewall rule' }
    if ((Test-Path -LiteralPath $werKey) -and ((Get-Item -LiteralPath $werKey).GetValueNames() -contains $werValue)) { $left += 'WER value' }
    if (-not $werKeyExisted -and (Test-Path -LiteralPath $werKey)) { $left += 'WER key' }
    Result 'CLEAN' ($left.Count -eq 0) $(if ($left.Count) { 'left behind: ' + ($left -join '; ') } else { 'nothing left behind' })
    Note 'events otsec-node wrote stay in the Application log (log data, not configuration)'
    Set-Content -Path (Join-Path $LogDir 'elevated-finished') -Value (Get-Date -Format o)
    Stop-Transcript | Out-Null
}
