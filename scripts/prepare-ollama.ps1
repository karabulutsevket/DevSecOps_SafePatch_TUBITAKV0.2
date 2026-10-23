param([switch]$DownloadOnly)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskRuntime = Join-Path $taskRoot '.runtime'
$taskZip = Join-Path $taskRuntime 'ollama-0.34.0.zip'
$taskOllama = Join-Path $taskRuntime 'ollama'
New-Item -ItemType Directory -Force -Path $taskRuntime,$taskOllama | Out-Null
if (!(Test-Path -LiteralPath (Join-Path $taskOllama 'ollama.exe'))) {
    if (!(Test-Path -LiteralPath $taskZip)) {
        Invoke-WebRequest -Uri 'https://github.com/ollama/ollama/releases/download/v0.34.0/ollama-windows-amd64.zip' -OutFile $taskZip
    }
    $taskHash = (Get-FileHash -LiteralPath $taskZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($taskHash -ne 'a7dd1b174f39d3d1b8a25d4cbc86045d0e190b17187bfdcbe2f2ee3b5a11470e') { throw 'Ollama checksum mismatch; remove the incomplete ZIP manually and retry.' }
    Expand-Archive -LiteralPath $taskZip -DestinationPath $taskOllama -Force
}
if ($DownloadOnly) { return }
$env:OLLAMA_MODELS = Join-Path $taskRuntime 'models'
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_CONTEXT_LENGTH = '8192'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_MAX_QUEUE = '2'
$env:OLLAMA_KEEP_ALIVE = '2m'
$taskProcess = Start-Process -FilePath (Join-Path $taskOllama 'ollama.exe') -ArgumentList 'serve' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskRuntime 'ollama.out.log') -RedirectStandardError (Join-Path $taskRuntime 'ollama.err.log')
$taskProcess.Id | Set-Content -LiteralPath (Join-Path $taskRuntime 'ollama.pid')
Write-Output "Ollama started with PID $($taskProcess.Id). Model download is a separate preparation step."
