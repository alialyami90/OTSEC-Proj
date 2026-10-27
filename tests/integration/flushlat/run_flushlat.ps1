# Flush latency under a store test on Windows (B6, #230).
#
# Runs a compiled Go test binary (go test -c) -Runs times, each inside an ETW
# Microsoft-Windows-Kernel-File trace, with a positive-control fsync from
# control.py before and after. Each trace is dumped with tracerpt and read by
# flush_latency.py, which pairs every Flush the test issued on a *.db or
# *.db-wal file with its OperationEnd and reports each flush's latency.
#
# Needs an elevated prompt for logman (the hosted runner is one). Creates no
# account, volume, service or setting; the test writes only under its own
# t.TempDir. Imports no product code itself: the product code under test is
# the test binary's. Evidence class: hosted runner.
[CmdletBinding()]
param(
	[Parameter(Mandatory)] [string]$TestExe,
	[Parameter(Mandatory)] [string]$TestDir,
	[string]$Run = '^TestDiscardStepWALBound$',
	[int]$Runs = 5,
	[double]$Stall = 30,
	[string]$Python = (Get-Command python).Source,
	[string]$Out = (Join-Path $env:TEMP "flushlat")
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$ctl = Join-Path $Out "controls"
New-Item -ItemType Directory -Force -Path $ctl | Out-Null

# The keyword mapping this run relies on, in the log for the record.
logman query providers Microsoft-Windows-Kernel-File | Write-Host

$verdicts = @()
$trace = $null
try {
	foreach ($i in 1..$Runs) {
		$etl = Join-Path $Out "run-$i.etl"
		$xml = Join-Path $Out "run-$i.xml"
		$trace = "flushlat-$i"
		# 0x10F0: FILENAME, FILEIO, OP_END, CREATE, CREATE_NEW_FILE.
		logman start $trace -p "Microsoft-Windows-Kernel-File" 0x10F0 0x5 -o $etl -ets -bs 1024 -nb 64 256 | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }
		$c1 = & $Python -I (Join-Path $here "control.py") $ctl begin | ConvertFrom-Json
		$so = Join-Path $Out "run-$i.test.txt"
		$se = Join-Path $Out "run-$i.test.err.txt"
		$t0 = Get-Date
		$p = Start-Process -FilePath $TestExe -WorkingDirectory $TestDir -NoNewWindow -PassThru `
			-RedirectStandardOutput $so -RedirectStandardError $se `
			-ArgumentList @("-test.run", $Run, "-test.v", "-test.count=1", "-test.timeout=20m")
		$null = $p.Handle  # keeps ExitCode readable after WaitForExit
		$p.WaitForExit()
		$wall = ((Get-Date) - $t0).TotalSeconds
		$c2 = & $Python -I (Join-Path $here "control.py") $ctl end | ConvertFrom-Json
		logman stop $trace -ets | Out-Null
		$trace = $null
		$runJson = Join-Path $Out "run-$i.json"
		[ordered]@{
			test = $Run; run = $i; test_pid = $p.Id; test_exit = $p.ExitCode; test_wall_s = [math]::Round($wall, 3)
			controls = @(@{ name = $c1.name; pid = $c1.pid }, @{ name = $c2.name; pid = $c2.pid })
		} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $runJson
		Write-Host "--- run $i test output (exit $($p.ExitCode), $([math]::Round($wall, 1)) s) ---"
		Get-Content $so | Write-Host
		Get-Content $se | Write-Host
		tracerpt $etl -o $xml -of XML -lr -y | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "tracerpt failed ($LASTEXITCODE)" }
		$report = Join-Path $Out "run-$i.report.json"
		& $Python -I (Join-Path $here "flush_latency.py") $xml $runJson --stall $Stall |
			Tee-Object -FilePath $report | Write-Host
		if ($LASTEXITCODE -ne 0) { throw "flush_latency.py run $i failed ($LASTEXITCODE)" }
		$verdicts += "run ${i}: " + (Get-Content $report -Raw | ConvertFrom-Json).verdict
		# The dumps are large; the reports are what is kept.
		Remove-Item $etl, $xml -ErrorAction SilentlyContinue
	}
} finally {
	if ($trace) { logman stop $trace -ets | Out-Null }
}
Write-Host "--- verdicts ---"
$verdicts | Write-Host
