param([switch]$Integration, [switch]$Sandbox, [string]$PythonExecutable, [string]$EvidenceDir)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
# New results never go to the read-only V0.1 archive (same rule as safepatch.common.evidence).
if (-not $EvidenceDir) { $EvidenceDir = $env:EVIDENCE_DIR }
if (-not $EvidenceDir) { $EvidenceDir = 'evidence/v02-local' }
$taskEvidence = [IO.Path]::GetFullPath([IO.Path]::Combine($taskRoot, $EvidenceDir)).TrimEnd('\')
$taskArchive = [IO.Path]::GetFullPath((Join-Path $taskRoot 'evidence'))
if ($taskEvidence -eq $taskArchive -or ($taskEvidence.StartsWith($taskArchive + '\', 'OrdinalIgnoreCase') -and -not $taskEvidence.Substring($taskArchive.Length + 1).StartsWith('v02-', 'OrdinalIgnoreCase'))) {
    throw 'V0.1 evidence is read-only; use -EvidenceDir evidence/v02-<name>.'
}
New-Item -ItemType Directory -Force -Path '.runtime', $taskEvidence | Out-Null
$previousEvidence = $env:EVIDENCE_DIR
$env:EVIDENCE_DIR = $taskEvidence
$taskPython = Join-Path $taskRoot '.venv/Scripts/python.exe'
if ($PythonExecutable) { $taskPython = $PythonExecutable }
$taskTemp = Join-Path $taskRoot ('.runtime/test-run-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $taskTemp) { throw 'Expected a fresh test directory.' }
$taskArgs = @('-m','pytest','-q','-p','no:cacheprovider',('--basetemp=' + $taskTemp))
# -Sandbox adds the Docker sandbox tests (run scripts/prepare_sandbox.py and set SANDBOX_MAVEN_CACHE first).
if ($Sandbox) { $Integration = $true; $env:RUN_DOCKER_INTEGRATION='1' }
if ($Integration) {
    $env:RUN_JAVA_INTEGRATION='1'
    $taskArgs += ('--junitxml=' + (Join-Path $taskEvidence 'tests-all.xml'))
} else {
    $taskArgs += @('-m','not integration',('--junitxml=' + (Join-Path $taskEvidence 'unit-tests.xml')))
}
try {
    & $taskPython @taskArgs
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; inspect JUnit evidence.' }
} finally {
    if ($Integration) { Remove-Item Env:RUN_JAVA_INTEGRATION -ErrorAction SilentlyContinue }
    if ($Sandbox) { Remove-Item Env:RUN_DOCKER_INTEGRATION -ErrorAction SilentlyContinue }
    if ($null -eq $previousEvidence) { Remove-Item Env:EVIDENCE_DIR -ErrorAction SilentlyContinue } else { $env:EVIDENCE_DIR = $previousEvidence }
}
