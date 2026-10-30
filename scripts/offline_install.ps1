# Week 10: installs SafePatch from the offline bundle on a clean Windows 11 machine and times
# every step (docs/KURULUM_CEVRIMDISI.md). Run it from the bundle folder in an elevated
# PowerShell with the network off:
#     powershell -ExecutionPolicy Bypass -File .\offline_install.ps1
# If enabling WSL needs a restart, it says so; restart and run the same command again, it goes on
# where it stopped. The result, install-timing.json in the target folder, is what comes back.
# -DryRun changes nothing: it checks the bundle against its manifest and lists the steps.
param([string]$Target = 'C:\SafePatch', [string]$Distro = 'Debian', [switch]$DryRun)
$ErrorActionPreference = 'Stop'
$Bundle = $PSScriptRoot
if ($DryRun) { $Target = Join-Path ([IO.Path]::GetTempPath()) ('safepatch-dryrun-' + [guid]::NewGuid().ToString('N')) }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $DryRun -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Yonetici olarak acilmis bir PowerShell gerekli.' }
New-Item -ItemType Directory -Force -Path $Target, (Join-Path $Target 'tmp') | Out-Null
$StateFile = Join-Path $Target 'install-timing.json'
if (Test-Path -LiteralPath $StateFile) { $State = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } else { $State = [pscustomobject]@{ started = (Get-Date).ToUniversalTime().ToString('o'); steps = @(); machine = $null; network_reachable_at_start = $null } }
$Repo = Join-Path $Target 'SafePatch_V0.2'
$Python = 'C:\Program Files\Python312\python.exe'

function Save-State { $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding utf8 }
function Done($name) { return [bool]($State.steps | Where-Object { $_.name -eq $name -and $_.ok }) }
function Refresh-Path { $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User') }
function Set-MachineEnv($name, $value) { [Environment]::SetEnvironmentVariable($name, $value, 'Machine'); Set-Item -Path "env:$name" -Value $value }
function WslPath($path) { $full = (Resolve-Path -LiteralPath $path).Path; return '/mnt/' + $full.Substring(0, 1).ToLower() + $full.Substring(2).Replace('\', '/') }

# A step runs once; its time and outcome go to install-timing.json whether it passes or fails.
function Step($name, [scriptblock]$action) {
    if (Done $name) { Write-Output "= $name (onceden yapildi)"; return }
    if ($DryRun -and $name -ne 'paket dogrulama') { Write-Output "- $name (DryRun: calistirilmadi)"; return }
    Write-Output "> $name"
    $begun = Get-Date
    $entry = [ordered]@{ name = $name; started = $begun.ToUniversalTime().ToString('o'); seconds = $null; ok = $false; detail = $null }
    try {
        $entry.detail = (& $action | Out-String).Trim()
        $entry.ok = $true
    } catch {
        $entry.detail = $_.Exception.Message
        throw
    } finally {
        $entry.seconds = [math]::Round(((Get-Date) - $begun).TotalSeconds, 1)
        $State.steps = @($State.steps | Where-Object { $_.name -ne $name }) + @([pscustomobject]$entry)
        Save-State
        Write-Output ("  {0} sn, {1}" -f $entry.seconds, $(if ($entry.ok) { 'tamam' } else { 'HATA' }))
    }
}

# Windows PowerShell 5.1 turns redirected stderr of a native program into a terminating error
# under 'Stop'; native programs run under 'Continue' and are judged by their exit code.
function Native([scriptblock]$command, [string]$what) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = (& $command 2>&1 | Out-String).Trim(); $code = $LASTEXITCODE } finally { $ErrorActionPreference = $previous }
    if ($what -and $code -ne 0) { throw "$what basarisiz ($code): $($out.Substring([math]::Max(0, $out.Length - 600)))" }
    return $out
}

# A shell script for WSL goes through a file with Unix line endings (no quoting through PowerShell).
function InWsl($script, [switch]$Root) {
    $file = Join-Path $Target ('tmp\' + [guid]::NewGuid().ToString('N') + '.sh')
    [IO.File]::WriteAllText($file, ($script -replace "`r`n", "`n"))
    $user = @(); if ($Root) { $user = @('-u', 'root') }
    try { return Native { & wsl.exe -d $Distro @user --exec sh (WslPath $file) } 'WSL komutu' } finally { Remove-Item -LiteralPath $file }
}

function Run($file, [string[]]$arguments) {
    $process = Start-Process -FilePath $file -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    return $process.ExitCode
}

if (-not $State.machine) {
    $os = Get-CimInstance Win32_OperatingSystem
    $State.machine = [pscustomobject]@{
        os = "$($os.Caption) $($os.Version)"; cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
        ram_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1); gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object Name)
        free_gb_c = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    }
    $State.network_reachable_at_start = [bool](Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue)
    Save-State
    if ($State.network_reachable_at_start) { Write-Warning 'Ag acik gorunuyor; olcum cevrimdisi kurulum icindir. Kabloyu/Wi-Fi kapatip yeniden baslatin ya da bilerek devam edin.' }
}

Step 'paket dogrulama' {
    $manifest = Get-Content -LiteralPath (Join-Path $Bundle 'manifest.json') -Raw | ConvertFrom-Json
    $bad = @($manifest.files | Where-Object { (Get-FileHash -LiteralPath (Join-Path $Bundle $_.path) -Algorithm SHA256).Hash.ToLower() -ne $_.sha256 })
    if ($bad.Count) { throw "Bozuk ya da eksik dosya: $(($bad | ForEach-Object path) -join ', ')" }
    "$($manifest.files.Count) dosya, $([math]::Round($manifest.total_bytes / 1e9, 2)) GB"
}
Step 'python 3.12.10' {
    $code = Run (Join-Path $Bundle 'windows\python-3.12.10-amd64.exe') @('/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0')
    if ($code -ne 0) { throw "kurulum kodu $code" }
    Native { & $Python --version } 'python'
}
Step 'git 2.55' {
    $code = Run (Join-Path $Bundle 'windows\Git-2.55.0.5-64-bit.exe') @('/VERYSILENT', '/NORESTART', '/NOCANCEL', '/SP-', '/SUPPRESSMSGBOXES')
    if ($code -ne 0) { throw "kurulum kodu $code" }
    Refresh-Path; Native { git --version } 'git'
}
Step 'java 17 (corretto)' {
    $code = Run 'msiexec.exe' @('/i', (Join-Path $Bundle 'windows\amazon-corretto-17.0.20.10.1-windows-x64.msi'), '/qn', '/norestart')
    if ($code -ne 0) { throw "kurulum kodu $code" }
    # The MSI normally sets JAVA_HOME and PATH; set them if it did not.
    $jdk = Get-ChildItem 'C:\Program Files\Amazon Corretto' -Directory | Where-Object Name -like 'jdk17*' | Select-Object -First 1
    if (-not [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine')) { Set-MachineEnv 'JAVA_HOME' $jdk.FullName }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($path -notlike "*$($jdk.FullName)\bin*") { [Environment]::SetEnvironmentVariable('Path', "$path;$($jdk.FullName)\bin", 'Machine') }
    Refresh-Path; (Native { & java -version } 'java' -split "`n")[0]
}
Step 'maven 3.9.16' {
    Expand-Archive -LiteralPath (Join-Path $Bundle 'windows\apache-maven-3.9.16-bin.zip') -DestinationPath 'C:\Program Files\Apache' -Force
    $bin = 'C:\Program Files\Apache\apache-maven-3.9.16\bin'
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($path -notlike "*$bin*") { [Environment]::SetEnvironmentVariable('Path', "$path;$bin", 'Machine') }
    Refresh-Path; (Native { & mvn -v } 'maven' -split "`n")[0]
}
Step 'wsl' {
    $code = Run 'msiexec.exe' @('/i', (Join-Path $Bundle 'windows\wsl.2.7.12.0.x64.msi'), '/qn', '/norestart')
    if ($code -notin 0, 1638, 3010) { throw "WSL kurulum kodu $code" }   # 1638: already installed, 3010: restart needed
    $feature = Run 'dism.exe' @('/online', '/enable-feature', '/featurename:VirtualMachinePlatform', '/all', '/norestart')
    if ($feature -ne 0 -and $feature -ne 3010) { throw "VirtualMachinePlatform kodu $feature" }
    "msi $code, VirtualMachinePlatform $feature"
}
if (-not $DryRun -and -not (Done 'yeniden baslatma sonrasi')) {
    $feature = Native { & dism.exe /online /get-featureinfo /featurename:VirtualMachinePlatform /English }
    if ($feature -notmatch 'State : Enabled') {
        Write-Output 'WSL icin bilgisayari yeniden baslatin, sonra ayni komutu tekrar calistirin.'
        return
    }
    Step 'yeniden baslatma sonrasi' { 'VirtualMachinePlatform etkin' }
}
Step 'debian 13 (wsl)' {
    $dir = Join-Path $Target "wsl\$Distro"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Native { & wsl.exe --import $Distro $dir (Join-Path $Bundle 'linux\Debian_WSL_AMD64_v1.26.0.0.wsl') --version 2 } 'wsl --import' | Out-Null
    InWsl "printf '[boot]\nsystemd=true\n' > /etc/wsl.conf" -Root | Out-Null
    Native { & wsl.exe --terminate $Distro } | Out-Null
    InWsl 'cat /etc/debian_version' -Root
}
Step 'docker (deb paketleri)' {
    $debs = WslPath (Join-Path $Bundle 'linux\debs')
    InWsl @"
set -e
missing=''
for f in $debs/*.deb; do
  p=`$(dpkg-deb -f "`$f" Package)
  dpkg-query -W -f='`${Status}' "`$p" 2>/dev/null | grep -q 'install ok installed' || missing="`$missing `$f"
done
[ -n "`$missing" ] && DEBIAN_FRONTEND=noninteractive dpkg -i `$missing >/dev/null
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null
for i in `$(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
echo "kurulan paket: `$(echo `$missing | wc -w)"; docker version --format '{{.Server.Version}}'
"@ -Root
}
Step 'sandbox imajlari' {
    $images = Get-Content -LiteralPath (Join-Path $Bundle 'linux\sandbox-images.json') -Raw | ConvertFrom-Json
    InWsl "docker load -q -i $(WslPath (Join-Path $Bundle 'linux\sandbox-images.tar'))" -Root | Out-Null
    foreach ($java in '17', '8') {
        $id = $images.ids.$java
        InWsl "docker image inspect $id --format '{{.Id}}'" -Root | Out-Null
    }
    # docker load keeps the image ID (a content digest), not the registry digest; pin by ID.
    Set-MachineEnv 'SANDBOX_IMAGE' $images.ids.'17'
    Set-MachineEnv 'SANDBOX_IMAGE_8' $images.ids.'8'
    Set-MachineEnv 'RUNNER_SANDBOX' 'docker'
    Set-MachineEnv 'WSL_DISTRO' $Distro
    "$($images.ids.'17'), $($images.ids.'8')"
}
Step 'semgrep 1.136.0 (wsl)' {
    $tar = WslPath (Join-Path $Bundle 'linux\python-linux.tar.gz')
    $wheels = WslPath (Join-Path $Bundle 'wheels\linux')
    $version = InWsl @"
set -e
mkdir -p /opt/safepatch && tar -xzf $tar -C /opt/safepatch
/opt/safepatch/python-linux/cpython-3.12.11-linux-x86_64-gnu/bin/python3.12 -m venv /opt/safepatch/semgrep-venv
/opt/safepatch/semgrep-venv/bin/pip install -q --no-index --find-links $wheels semgrep==1.136.0 setuptools==80.9.0
/opt/safepatch/semgrep-venv/bin/semgrep --version
"@ -Root
    if ($version -notmatch '1\.136\.0') { throw "beklenmeyen semgrep surumu: $version" }
    Set-MachineEnv 'SEMGREP_WSL' '/opt/safepatch/semgrep-venv/bin/semgrep'
    $version
}
Step 'ollama ve model' {
    Expand-Archive -LiteralPath (Join-Path $Bundle 'windows\ollama-0.34.0.zip') -DestinationPath (Join-Path $Target 'ollama') -Force
    Copy-Item -Recurse -Force -Path (Join-Path $Bundle 'models') -Destination (Join-Path $Target 'ollama-models')
    'ollama acildi'
}
Step 'safepatch' {
    Native { & git clone -q (Join-Path $Bundle 'safepatch\safepatch.bundle') $Repo } 'git clone' | Out-Null
    Native { & $Python -m venv (Join-Path $Repo '.venv') } 'venv' | Out-Null
    Native { & (Join-Path $Repo '.venv\Scripts\python.exe') -m pip install -q --disable-pip-version-check --no-index --find-links (Join-Path $Bundle 'wheels\windows') -r (Join-Path $Repo 'requirements.lock') } 'pip install' | Out-Null
    Expand-Archive -LiteralPath (Join-Path $Bundle 'maven\m2.zip') -DestinationPath (Join-Path $Target 'm2') -Force
    Expand-Archive -LiteralPath (Join-Path $Bundle 'tools\tools.zip') -DestinationPath (Join-Path $Repo '.runtime\tools') -Force
    Set-MachineEnv 'MAVEN_CACHE' (Join-Path $Target 'm2')
    Push-Location $Repo
    try {
        Native { & .venv\Scripts\python.exe scripts\init_config.py } 'init_config' | Out-Null
        Native { & .venv\Scripts\python.exe scripts\seed.py } 'seed' | Out-Null
    } finally { Pop-Location }
    Native { & git -C $Repo log -1 --format='%h %s' } 'git log'
}
Step 'docker sandbox' {
    Set-MachineEnv 'SANDBOX_MAVEN_CACHE' '/root/.safepatch/m2'
    Push-Location $Repo
    try {
        $out = Native { & .venv\Scripts\python.exe scripts\prepare_sandbox.py } 'prepare_sandbox'
        $bound = Native { & .venv\Scripts\python.exe scripts\prepare_sandbox.py --bound-work-gb 20 } 'prepare_sandbox --bound-work-gb'
    } finally { Pop-Location }
    $out + "`n" + $bound
}
Step 'birim testleri' {
    Push-Location $Repo
    try { $out = Native { & .\scripts\run-tests.ps1 } } finally { Pop-Location }
    ($out -split "`n" | Where-Object { $_ -match 'passed|failed' } | Select-Object -Last 1)
}
Step 'servisler ve duman testi' {
    $env:OLLAMA_MODELS = Join-Path $Target 'ollama-models'
    $env:OLLAMA_HOST = '127.0.0.1:11434'; $env:OLLAMA_NO_CLOUD = '1'
    $env:OLLAMA_CONTEXT_LENGTH = '8192'; $env:OLLAMA_NUM_PARALLEL = '1'; $env:OLLAMA_MAX_LOADED_MODELS = '1'
    Start-Process -FilePath (Join-Path $Target 'ollama\ollama.exe') -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 60; $i++) { try { $tags = Invoke-RestMethod http://127.0.0.1:11434/api/tags -TimeoutSec 2; break } catch { Start-Sleep -Seconds 1 } }
    $model = $tags.models | Where-Object { $_.name -eq 'qwen2.5-coder:7b-instruct-q4_K_M' }
    if (-not $model -or -not $model.digest.StartsWith('dae161e2')) { throw 'model bulunamadi ya da ozeti farkli' }
    Push-Location $Repo
    try {
        Native { & .\scripts\start-native.ps1 -Restart } 'start-native' | Out-Null
        Start-Sleep -Seconds 8
        $env:EVIDENCE_DIR = Join-Path $Target 'duman'
        $out = Native { & .venv\Scripts\python.exe scripts\retry_experiment.py --cases sql-01 --strategies guided --seeds 42 } 'duman testi'
    } finally { Pop-Location }
    if ($out -notmatch 'awaiting_review') { throw "duman testi beklenen sonucu vermedi: $($out.Substring([math]::Max(0, $out.Length - 400)))" }
    'sql-01: awaiting_review'
}
$State | Add-Member -NotePropertyName finished -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
$State | Add-Member -NotePropertyName step_seconds_total -NotePropertyValue ([math]::Round(($State.steps | Measure-Object -Property seconds -Sum).Sum, 1)) -Force
Save-State
Write-Output "Kurulum bitti. Sonuc: $StateFile (bu dosyayi geri gonderin)."
