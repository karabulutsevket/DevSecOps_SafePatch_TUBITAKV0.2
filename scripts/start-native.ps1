param([switch]$Restart, [string]$PythonExecutable, [int]$PortBase=8100)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
if ($Restart) { & (Join-Path $PSScriptRoot 'stop-native.ps1') }
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
if ($PythonExecutable) { $taskPython = $PythonExecutable }
$env:WORKER1_URL = 'http://127.0.0.1:' + ($PortBase+1)
$env:WORKER2_URL = 'http://127.0.0.1:' + ($PortBase+2)
$env:RUNNER_URL = 'http://127.0.0.1:' + ($PortBase+3)
$env:DEPLOYER_URL = 'http://127.0.0.1:' + ($PortBase+4)
if (!(Test-Path -LiteralPath $taskPython)) { throw 'Python environment missing; follow the README installation steps.' }
& $taskPython scripts/init_config.py
if ($LASTEXITCODE -ne 0) { throw 'Configuration initialization failed; services were not started.' }
if (!(Test-Path -LiteralPath '.runtime/repos-v3/manifest.json')) {
    & $taskPython scripts/seed.py | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic repository initialization failed; services were not started.' }
}
$taskProcesses = @()
foreach ($taskName in @('runner','worker2','worker1','deployer','orchestrator')) {
    $taskOffset = @{orchestrator=0;worker1=1;worker2=2;runner=3;deployer=4}[$taskName]
    $taskProc = Start-Process -FilePath $taskPython -ArgumentList @('scripts/serve.py',$taskName,'--port',($PortBase+$taskOffset)) -WorkingDirectory $taskRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput ".runtime/$taskName.out.log" -RedirectStandardError ".runtime/$taskName.err.log"
    $taskProcesses += @{service=$taskName; pid=$taskProc.Id; started=$taskProc.StartTime.ToUniversalTime().ToString('o')}
}
$taskProcesses | ConvertTo-Json | Set-Content -LiteralPath '.runtime/services.json' -Encoding utf8
Write-Output "Services starting: http://127.0.0.1:$PortBase . Credentials are in .secrets (do not share them)."
