# A6: what a non-admin user can do to an installed node (W-4). Run in a
# normal, non-elevated shell while installer_check.ps1 waits for it. Every
# check expects a refusal; a write that is wrongly allowed lands inside the
# OTSEC folders, which the elevated script removes.
#
# Results go to <LogDir>\nonadmin-results.txt; the last step writes
# <LogDir>\nonadmin-done.

param([Parameter(Mandatory = $true)][string]$LogDir)

$results = Join-Path $LogDir 'nonadmin-results.txt'
Set-Content -Path $results -Value "A6 non-admin check $(Get-Date -Format o)"
function Result([string]$id, [bool]$ok, [string]$detail) {
    $line = "RESULT $id $(if ($ok) { 'PASS' } else { 'FAIL' }) $detail"
    Add-Content -Path $results -Value $line
    Write-Output $line
}
function Denied([scriptblock]$b) {
    try { & $b | Out-Null; return @{ Denied = $false; Why = 'allowed' } }
    catch { return @{ Denied = ($_.Exception -is [UnauthorizedAccessException] -or "$($_.Exception.Message)" -match 'denied'); Why = $_.Exception.Message } }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Result 'N-0' (-not $isAdmin) "running without elevation: $(-not $isAdmin)"

$pd = Join-Path $env:ProgramData 'OTSEC'
$pf = Join-Path $env:ProgramFiles 'OTSEC'
$ErrorActionPreference = 'Stop'
$checks = [ordered]@{
    'N-read-collector.json' = { Get-Content -LiteralPath (Join-Path $pd 'collector\collector.json') }
    'N-list-credentials'    = { Get-ChildItem -LiteralPath (Join-Path $pd 'collector\credentials') }
    'N-read-node.json'      = { Get-Content -LiteralPath (Join-Path $pd 'config\node.json') }
    'N-list-store'          = { Get-ChildItem -LiteralPath (Join-Path $pd 'store') }
    'N-write-store'         = { [IO.File]::WriteAllText((Join-Path $pd 'store\a6-nonadmin.txt'), 'x') }
    'N-write-config'        = { [IO.File]::WriteAllText((Join-Path $pd 'config\a6-nonadmin.txt'), 'x') }
    'N-write-public'        = { [IO.File]::WriteAllText((Join-Path $pd 'collector\public\a6-nonadmin.txt'), 'x') }
    'N-mkdir-root'          = { New-Item -ItemType Directory -Path (Join-Path $pd 'a6-nonadmin') }
    'N-write-exe'           = { [IO.File]::WriteAllText((Join-Path $pf 'a6-nonadmin.txt'), 'x') }
}
foreach ($k in $checks.Keys) {
    $r = Denied $checks[$k]
    Result $k $r.Denied $r.Why
}
$out = & sc.exe config otsec-node start= disabled 2>&1 | Out-String
Result 'N-sc-config' ($out -match 'FAILED 5' -or $out -match 'Access is denied') ($out -replace '\s+', ' ')
Set-Content -Path (Join-Path $LogDir 'nonadmin-done') -Value (Get-Date -Format o)
