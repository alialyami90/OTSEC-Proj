# Windows counterpart of run.sh for ADR-0007 item 5. Runs the A5 Phase 0
# experiments on Windows/NTFS and writes results\windows-<name>.txt.
#
#   powershell -ExecutionPolicy Bypass -File run.ps1 [-Exe .\p0.exe] [-Iterations 100]
#
# Uses p0.exe if given (cross-built with CGO_ENABLED=0 GOOS=windows), else
# builds it with Go. The full-filesystem cases need an elevated prompt: they
# create, attach, and afterwards detach and delete a 16 MB VHDX formatted
# NTFS. Without elevation they are skipped and the output says so.
param(
	[string]$Exe = "",
	[int]$Iterations = 100
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$results = Join-Path $here "results"
New-Item -ItemType Directory -Force -Path $results | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ("p0-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$scratch = Join-Path $work "scratch"
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

if ($Exe -eq "") {
	$Exe = Join-Path $work "p0.exe"
	Push-Location $here
	$env:CGO_ENABLED = "0"
	go build -trimpath -o $Exe .
	Pop-Location
}

function EnvLine {
	$os = Get-CimInstance Win32_OperatingSystem
	$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
	$vol = Get-Volume -FilePath $scratch -ErrorAction SilentlyContinue
	$disk = ""
	try {
		$part = Get-Partition -DriveLetter ($scratch.Substring(0, 1))
		$d = Get-Disk -Number $part.DiskNumber
		$disk = "$($d.FriendlyName) bus=$($d.BusType)"
	} catch {}
	"# $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) $($os.Caption) $($os.Version) build $($os.BuildNumber) cpu=$cpu"
	"# scratch filesystem: $($vol.FileSystem) disk: $disk"
}

function Run($name, [string[]]$arguments) {
	$out = Join-Path $results "windows-$name.txt"
	$lines = @(EnvLine) + @(& $Exe @arguments 2>&1 | ForEach-Object { "$_" })
	$lines | Tee-Object -FilePath $out
}

Run "crash-durability" @("crash-durability", "-iterations", "$Iterations", "-dir", $scratch)
Run "throughput" @("throughput", "-dir", $scratch)

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
	[Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
	$vhd = Join-Path $work "full.vhdx"
	$mnt = Join-Path $work "full"
	New-Item -ItemType Directory -Force -Path $mnt | Out-Null
	$dp = Join-Path $work "attach.txt"
	@(
		"create vdisk file=`"$vhd`" maximum=16 type=fixed",
		"select vdisk file=`"$vhd`"",
		"attach vdisk",
		"create partition primary",
		"format fs=ntfs quick label=P0FULL",
		"assign mount=`"$mnt`""
	) | Set-Content -Encoding ascii $dp
	diskpart /s $dp | Out-Null
	try {
		$lines = @(EnvLine) + @("# full-filesystem cases on a 16 MB NTFS VHDX") +
			@(& $Exe storage-limit -dir $scratch -enospc-dir $mnt 2>&1 | ForEach-Object { "$_".Replace($mnt, "<16 MB NTFS VHDX>") })
		$lines | Tee-Object -FilePath (Join-Path $results "windows-storage-limit.txt")
	} finally {
		@("select vdisk file=`"$vhd`"", "detach vdisk") | Set-Content -Encoding ascii $dp
		diskpart /s $dp | Out-Null
	}
} else {
	$lines = @(EnvLine) + @("# not elevated: full-filesystem cases skipped") +
		@(& $Exe storage-limit -dir $scratch 2>&1 | ForEach-Object { "$_" })
	$lines | Tee-Object -FilePath (Join-Path $results "windows-storage-limit.txt")
}

Run "syslog-loss" @("syslog-loss", "-runs", "10", "-dir", $scratch)
Run "write-amplification" @("write-amplification", "-dir", $scratch)
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
