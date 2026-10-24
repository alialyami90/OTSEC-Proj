# H-14 software half (A6): Windows re-run of E-02, E-03 and E-04, plus R-A5-5.
#
# Needs an elevated prompt, because it starts the ETW trace and creates and
# attaches VHDX volumes. The scripts under test run as a NON-admin account:
#   -CreateTempUser   creates a temporary local account in Users only, and
#                     deletes it at the end. Its random password exists only
#                     in memory and is never written or printed. This is for
#                     a throwaway CI VM. On any other machine, creating an
#                     account is a security-policy change: use -Credential.
#   -Credential       an existing non-admin account (Get-Credential).
# If a separate logon cannot be started (for example, the seclogon service is
# unavailable), it falls back to `runas /trustlevel:0x20000` (a Basic User
# token of the current account) and says so in identity.json. The analysis
# makes any run whose writer had an admin token INCONCLUSIVE.
#
# Steps:
#   1. Flush trace (E-02 on Windows): for each of FULL, NORMAL and OFF, run
#      flush_writer.py on a 64 MB NTFS VHDX inside an ETW
#      Microsoft-Windows-Kernel-File trace. Dump it with tracerpt and run
#      flush_analyse.py.
#   2. Recovery (E-03, E-04, R-A5-5, reserve-first order): run each
#      recovery_rounds.py scenario on its own fresh 16 MB NTFS VHDX. Writers
#      are killed with TerminateProcess.
# Results go under -Out. Every JSON report is also printed to the console.
#
# Imports and runs no A5 or product code. Evidence class: simulated.
[CmdletBinding()]
param(
	[string]$Python = (Get-Command python).Source,
	[string]$Out = (Join-Path $env:TEMP "h14-results"),
	[int]$Acks = 300,
	[switch]$CreateTempUser,
	[pscredential]$Credential
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	throw "run_h14.ps1 must run elevated (ETW trace, VHDX); the scripts under test run as a non-admin account"
}
if (-not $CreateTempUser -and -not $Credential) {
	throw "pass -Credential (an existing non-admin account) or, on a throwaway VM, -CreateTempUser"
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$work = Join-Path $env:SystemDrive ("h14-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$bin = Join-Path $work "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Copy-Item (Join-Path $here "*.py") $bin

$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$os = [ordered]@{
	ProductName = $cv.ProductName; EditionID = $cv.EditionID; DisplayVersion = $cv.DisplayVersion
	CurrentBuild = $cv.CurrentBuild; UBR = $cv.UBR; InstallationType = $cv.InstallationType
	Python = $Python; Acks = $Acks
}

# --- account ---------------------------------------------------------------
$tempUser = $null
if ($CreateTempUser) {
	$tempUser = "h14svc" + (Get-Random -Maximum 9999)
	$bytes = New-Object byte[] 24
	[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
	$plain = [Convert]::ToBase64String($bytes) + "aA1!"
	$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
	$u = $computer.Create("User", $tempUser)
	$u.SetPassword($plain)
	$u.SetInfo()
	$usersGroup = (New-Object Security.Principal.SecurityIdentifier "S-1-5-32-545").Translate([Security.Principal.NTAccount]).Value.Split("\")[1]
	([ADSI]"WinNT://$env:COMPUTERNAME/$usersGroup,group").Add("WinNT://$env:COMPUTERNAME/$tempUser,user")
	$Credential = New-Object pscredential ("$env:COMPUTERNAME\$tempUser", (ConvertTo-SecureString $plain -AsPlainText -Force))
	Remove-Variable plain
}
$account = $Credential.UserName
$adminsGroup = (New-Object Security.Principal.SecurityIdentifier "S-1-5-32-544").Translate([Security.Principal.NTAccount]).Value.Split("\")[1]
$admins = @(([ADSI]"WinNT://$env:COMPUTERNAME/$adminsGroup,group").psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null) })
$os.Account = $account
$os.AccountInAdministrators = $admins -contains $account.Split("\")[-1]
if ($os.AccountInAdministrators) { throw "$account is in Administrators; H-14 needs a non-admin account" }

# The current account is granted too, for the runas fallback (its Basic User
# token keeps the user SID but not Administrators).
$self = [Security.Principal.WindowsIdentity]::GetCurrent().Name
function Grant($path, $rights) {
	foreach ($who in $account, $self) {
		icacls $path /grant "${who}:(OI)(CI)$rights" /T /C /Q | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "icacls $path failed ($LASTEXITCODE)" }
	}
}
Grant $work "M"
Grant $Out "M"
Grant (Split-Path -Parent $Python) "RX"

$script:runAs = $null
function Invoke-AsAccount([string[]]$argv, [string]$stdout, [string]$stderr, [int]$timeoutSec = 900) {
	$argLine = ($argv | ForEach-Object { '"' + $_ + '"' }) -join " "
	if ($script:runAs -ne "basic-user-token") {
		try {
			$p = Start-Process -FilePath $Python -ArgumentList $argLine -Credential $Credential -LoadUserProfile `
				-WorkingDirectory $work -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
			$script:runAs = "separate-account"
			$null = $p.Handle  # keep the handle so ExitCode is available after exit
			if (-not $p.WaitForExit($timeoutSec * 1000)) { $p.Kill(); throw "timed out" }
			return $p.ExitCode
		} catch {
			if ($script:runAs -eq "separate-account") { throw }
			Write-Host "Start-Process -Credential failed: $($_.Exception.Message); falling back to runas /trustlevel:0x20000"
			$script:runAs = "basic-user-token"
		}
	}
	$done = "$stdout.exit"
	$job = Join-Path $work ("job-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".cmd")
	@("@echo off", "`"$Python`" $argLine > `"$stdout`" 2> `"$stderr`"", "echo %ERRORLEVEL% > `"$done`"") |
		Set-Content -Encoding ascii $job
	runas /trustlevel:0x20000 "cmd /c `"$job`"" | Out-Null
	$started = (Get-Date).AddSeconds(60)
	while (-not (Test-Path $stdout)) {
		if ((Get-Date) -gt $started) { throw "runas /trustlevel did not start the job; no non-admin way to run it here" }
		Start-Sleep -Milliseconds 500
	}
	$deadline = (Get-Date).AddSeconds($timeoutSec)
	while (-not (Test-Path $done)) {
		if ((Get-Date) -gt $deadline) { throw "runas job timed out" }
		Start-Sleep -Milliseconds 500
	}
	return [int](Get-Content $done).Trim()
}

# --- volumes ---------------------------------------------------------------
$vhds = @()
function Add-H14Volume([string]$name, [int]$mb) {
	$vhd = Join-Path $work "$name.vhdx"
	$mnt = Join-Path $work $name
	New-Item -ItemType Directory -Force -Path $mnt | Out-Null
	$dp = Join-Path $work "dp-$name.txt"
	@(
		"create vdisk file=`"$vhd`" maximum=$mb type=fixed",
		"select vdisk file=`"$vhd`"",
		"attach vdisk",
		"create partition primary",
		"format fs=ntfs quick label=$name",
		"assign mount=`"$mnt`""
	) | Set-Content -Encoding ascii $dp
	diskpart /s $dp | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "diskpart failed for $name ($LASTEXITCODE)" }
	$script:vhds += $vhd
	$dir = Join-Path $mnt "data"
	New-Item -ItemType Directory -Force -Path $dir | Out-Null
	Grant $dir "M"
	return $dir
}

$trace = $null
try {
	$flushDir = Add-H14Volume "h14flush" 64

	# --- 1. flush trace ----------------------------------------------------
	foreach ($mode in "FULL", "NORMAL", "OFF") {
		$runDir = Join-Path $flushDir "run-$($mode.ToLower())"
		$etl = Join-Path $Out "flush-$mode.etl"
		$xml = Join-Path $Out "flush-$mode.xml"
		$trace = "h14-$mode"
		logman start $trace -p "Microsoft-Windows-Kernel-File" 0xB0 0x5 -o $etl -ets -bs 1024 -nb 64 256 | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }
		$code = Invoke-AsAccount @("-I", (Join-Path $bin "flush_writer.py"), $runDir, $mode, "$Acks") `
			(Join-Path $Out "writer-$mode.out.txt") (Join-Path $Out "writer-$mode.err.txt")
		logman stop $trace -ets | Out-Null
		$trace = $null
		if ($code -ne 0) {
			Get-Content (Join-Path $Out "writer-$mode.err.txt") | Write-Host
			throw "flush_writer.py $mode exited $code"
		}
		Copy-Item (Join-Path $runDir "writer.json") (Join-Path $Out "writer-$mode.json")
		tracerpt $etl -o $xml -of XML -lr -y -summary (Join-Path $Out "flush-$mode-summary.txt") | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "tracerpt failed ($LASTEXITCODE)" }
		& $Python -I (Join-Path $bin "flush_analyse.py") $xml (Join-Path $Out "writer-$mode.json") |
			Tee-Object -FilePath (Join-Path $Out "flush-$mode-report.json") | Write-Host
		if ($LASTEXITCODE -ne 0) { throw "flush_analyse.py $mode failed ($LASTEXITCODE)" }
	}

	# --- 2. recovery rounds --------------------------------------------------
	# One scenario per run, each on its own fresh 16 MB volume, so nothing one
	# scenario leaves behind (F-013: WinError 32) can affect the next.
	# ROUND/ERROR/RESULT lines, one JSON object each (recovery_rounds.py header).
	$i = 0
	foreach ($scenario in "incremental-cursor", "incremental-half", "none-half", "open-at-full", "no-reserve") {
		$i++
		$dir = Add-H14Volume "h14r$i" 16
		$stdout = Join-Path $Out "recovery-$scenario.txt"
		$stderr = Join-Path $Out "recovery-$scenario.err.txt"
		$code = Invoke-AsAccount @("-I", (Join-Path $bin "recovery_rounds.py"), "--dir", (Join-Path $dir "e04"), "--scenario", $scenario) `
			$stdout $stderr 1800
		Write-Host "--- recovery_rounds.py $scenario (exit $code) ---"
		Get-Content $stdout | Write-Host
		Write-Host "--- recovery_rounds.py $scenario stderr ---"
		Get-Content $stderr | Write-Host
		if ($code -ne 0) { throw "recovery_rounds.py $scenario exited $code" }
	}
} finally {
	if ($trace) { logman stop $trace -ets | Out-Null }
	$os.RunAs = $script:runAs
	$os | ConvertTo-Json | Tee-Object -FilePath (Join-Path $Out "identity.json") | Write-Host
	foreach ($vhd in $vhds) {
		$dp = Join-Path $work "dp-detach.txt"
		@("select vdisk file=`"$vhd`"", "detach vdisk") | Set-Content -Encoding ascii $dp
		diskpart /s $dp | Out-Null
	}
	if ($tempUser) { ([ADSI]"WinNT://$env:COMPUTERNAME,computer").Delete("User", $tempUser) }
}
