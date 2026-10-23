$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskFile = Join-Path $taskRoot '.runtime/services.json'
if (Test-Path -LiteralPath $taskFile) {
    foreach ($taskEntry in (Get-Content -LiteralPath $taskFile -Raw | ConvertFrom-Json)) {
        $taskProc = Get-Process -Id $taskEntry.pid -ErrorAction SilentlyContinue
        if ($taskProc -and $taskProc.ProcessName -match '^python' -and ([Math]::Abs(($taskProc.StartTime.ToUniversalTime() - [datetime]$taskEntry.started).TotalSeconds) -lt 2)) {
            & taskkill /PID $taskEntry.pid /T /F | Out-Null
        }
    }
}
Write-Output 'Project service process trees stopped; Ollama remains available separately.'
