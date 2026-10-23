param([switch]$Integration, [string]$PythonExecutable)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
New-Item -ItemType Directory -Force -Path '.runtime','evidence' | Out-Null
$taskPython = Join-Path $taskRoot '.venv/Scripts/python.exe'
if ($PythonExecutable) { $taskPython = $PythonExecutable }
$taskTemp = Join-Path $taskRoot ('.runtime/test-run-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $taskTemp) { throw 'Expected a fresh test directory.' }
$taskArgs = @('-m','pytest','-q','-p','no:cacheprovider',('--basetemp=' + $taskTemp))
if ($Integration) {
    $env:RUN_JAVA_INTEGRATION='1'
    $taskArgs += '--junitxml=evidence/tests-all.xml'
} else {
    $taskArgs += @('-m','not integration','--junitxml=evidence/unit-tests.xml')
}
try {
    & $taskPython @taskArgs
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; inspect JUnit evidence.' }
} finally {
    if ($Integration) { Remove-Item Env:RUN_JAVA_INTEGRATION -ErrorAction SilentlyContinue }
}
