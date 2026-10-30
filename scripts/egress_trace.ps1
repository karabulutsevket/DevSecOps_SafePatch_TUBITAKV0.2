# Week 10 egress test (docs/OLCUM_EGRESS.md): a kernel ETW trace of the whole machine while the
# test runs - process starts with their parent, TCP/UDP activity with the process id, DNS queries.
# Run it in an elevated PowerShell. It changes nothing else: the trace session ends when the test
# writes .runtime/egress/stop, after -Minutes at the latest, or on Ctrl+C. The trace holds this
# machine's other traffic too, so it stays in .runtime (never in Git); the analysis keeps only
# SafePatch's own processes and counts the rest.
param([int]$Minutes = 60)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Yonetici olarak acilmis bir PowerShell gerekli (ETW cekirdek izi).'
}
$taskRoot = Split-Path -Parent $PSScriptRoot
$folder = Join-Path $taskRoot '.runtime\egress'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$etl = Join-Path $folder 'trace.etl'
if (Test-Path -LiteralPath $etl) { throw "$etl zaten var; onceki izi tasiyin." }
$stop = Join-Path $folder 'stop'
Remove-Item -LiteralPath $stop, (Join-Path $folder 'trace.started'), (Join-Path $folder 'trace.stopped') -ErrorAction SilentlyContinue
$providers = Join-Path $folder 'providers.txt'
# Microsoft-Windows-Kernel-Process (process start/stop), Microsoft-Windows-Kernel-Network
# (TCP and UDP, IPv4 and IPv6), Microsoft-Windows-DNS-Client (queries).
@(
    '"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}" 0x10 0x4',
    '"{7DD42A49-5329-4832-8DFD-43D979153A88}" 0x30 0x4',
    '"{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" 0xFFFFFFFFFFFFFFFF 0x4'
) | Set-Content -LiteralPath $providers -Encoding ascii
logman start safepatch-egress -ets -pf $providers -o $etl -bs 256 -nb 64 512 -max 4096
if ($LASTEXITCODE -ne 0) { throw 'ETW oturumu baslatilamadi.' }
(Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath (Join-Path $folder 'trace.started') -Encoding ascii
Write-Output "Iz basladi. Test bitince kendiliginden duracak (en gec $Minutes dakika). Pencereyi kapatmayin."
try {
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $stop)) { Start-Sleep -Seconds 2 }
} finally {
    logman stop safepatch-egress -ets
    (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath (Join-Path $folder 'trace.stopped') -Encoding ascii
    Write-Output 'Iz durdu.'
}
