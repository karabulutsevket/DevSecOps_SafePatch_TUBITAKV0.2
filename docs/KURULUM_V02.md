# SafePatch V0.2 — Kurulum ve çalıştırma

Bu belgedeki adımlar 24–25 Ekim 2026'da bir geliştirici makinesinde çalıştırılarak doğrulandı. Doğrulanmamış adımlar ayrıca işaretlidir.

## 1. Doğrulanmış ortam

| Bileşen | Sürüm | Not |
|---|---|---|
| İşletim sistemi | Windows 11 + WSL 2 (Debian) | Linux sunucuya kurulum henüz doğrulanmadı |
| Python | 3.12 | `requirements.lock` ile sabit paketler |
| Git | Windows için Git | Sentetik depolar ve CI için gerekli |
| Java | Amazon Corretto 17 | `java` PATH'te olmalı |
| Maven | 3.9.16 | `mvn` PATH'te olmalı; çevrimdışı (`-o`) çalışır |
| Semgrep | 1.136.0, WSL Debian içinde ayrı bir sanal ortamda | Sürüm farklıysa iş durur |
| Ollama | 0.34.0, yalnız `127.0.0.1` | Bulut özellikleri kapalı (`OLLAMA_NO_CLOUD=1`) |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M`, özet `dae161e2…f4364` | Özet kodda sabit; farklıysa iş durur |
| GPU | NVIDIA RTX 4070 Laptop, 8 GB | Daha büyük model bu GPU'ya sığmaz |
| Docker | 26.1.5, WSL Debian içinde (`docker.io` paketi) | Derleme sandbox'ı; imajlar `maven:3.9.16-eclipse-temurin-17` ve `-8`, özetle sabit |

## 2. İlk kurulum

```powershell
git clone https://github.com/karabulutsevket/DevSecOps_SafePatch_TUBITAKV0.2.git
cd DevSecOps_SafePatch_TUBITAKV0.2
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.lock
.venv/Scripts/python.exe scripts/init_config.py      # .secrets/ altında anahtarlar; Git'e girmez
.venv/Scripts/python.exe scripts/seed.py             # 9 sentetik Java deposu: .runtime/repos-v3
./scripts/run-tests.ps1                              # birim testleri; JUnit: evidence/v02-local/
```

`python` PATH'te değilse `.venv` herhangi bir Python 3.12 yorumlayıcısının tam yoluyla kurulabilir (`C:\yol\python.exe -m venv .venv`). Betikler başka bir ortam için `-PythonExecutable <tam-yol>` parametresi de alır. O ortam `requirements.lock`'taki paketleri, Hafta 4'ten beri `tree-sitter` ve `tree-sitter-java` dahil, içermelidir:

```powershell
./scripts/run-tests.ps1 -PythonExecutable C:\yol\python.exe
```

Kapalı ağ kurulumu için paketler internetli makinede `pip download -r requirements.lock -d wheels` ile indirilir, hedefte `pip install --no-index --find-links wheels -r requirements.lock` ile kurulur. tree-sitter paketleri Windows ve Linux için hazır derlenmiş (wheel) gelir; derleyici gerekmez.

## 3. Model, Maven ve Semgrep hazırlığı (internetli hazırlık aşaması)

**Ollama ve model:**

```powershell
./scripts/prepare-ollama.ps1                         # sabit özetli Ollama arşivini indirir, servisi başlatır
.runtime/ollama/ollama.exe pull qwen2.5-coder:7b-instruct-q4_K_M
```

Model başka bir klasörde zaten indirilmişse, Ollama'yı o klasörle başlatın (doğrulanmış yöntem):

```powershell
$env:OLLAMA_MODELS = 'C:\model\klasoru\models'
$env:OLLAMA_HOST = '127.0.0.1:11434'; $env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_CONTEXT_LENGTH = '8192'; $env:OLLAMA_NUM_PARALLEL = '1'; $env:OLLAMA_MAX_LOADED_MODELS = '1'
$p = Start-Process -FilePath 'C:\ollama\klasoru\ollama.exe' -ArgumentList 'serve' -WindowStyle Hidden -PassThru `
     -RedirectStandardOutput .runtime/ollama.out.log -RedirectStandardError .runtime/ollama.err.log
$p.Id | Set-Content .runtime/ollama.pid
(Invoke-RestMethod http://127.0.0.1:11434/api/tags).models | Select-Object name, digest   # özeti kontrol edin
```

**Maven önbelleği** (bir kez, internetliyken). Çalışma sırasında Maven çevrimdışıdır:

```powershell
$env:MAVEN_CACHE = Join-Path (Get-Location) '.runtime/m2'
mvn -B -ntp "-Dmaven.repo.local=$env:MAVEN_CACHE" -f .runtime/repos-v3/sql-01/pom.xml -DskipTests package
mvn -B -ntp "-Dmaven.repo.local=$env:MAVEN_CACHE" -f .runtime/repos-v3/sql-01/pom.xml -Dtest=BehaviorTest test
```

**Semgrep (WSL içinde):**

```sh
python3 -m venv /mutlak/yol/semgrep-venv
/mutlak/yol/semgrep-venv/bin/pip install semgrep==1.136.0 setuptools==80.9.0
```

```powershell
wsl -d Debian -- /mutlak/yol/semgrep-venv/bin/semgrep --version    # 1.136.0 görünmeli
```

**SpotBugs + FindSecBugs (Hafta 7, tarayıcı `findsecbugs`):** Maven Central'dan SpotBugs 4.9.8 dağıtımını ve FindSecBugs 1.14.0 eklentisini `.runtime/tools` altına indirir ve sabit SHA-256 özetleriyle doğrular. `maven-dependency-plugin` 3.8.1'i çevrimdışı Maven önbelleğine ekler. Yaklaşık 34 MB. Ardından sandbox önbelleği güncellenir.

```powershell
$env:MAVEN_CACHE = 'C:\mutlak\yol\m2'
.venv/Scripts/python.exe scripts/prepare_findsecbugs.py
.venv/Scripts/python.exe scripts/prepare_sandbox.py      # Docker sandbox kullanılıyorsa
```

## 4. Servisleri başlatma ve durdurma

```powershell
$env:MAVEN_CACHE = '<maven önbelleği>'                       # ör. C:\...\.runtime\m2
$env:SEMGREP_WSL = '/mnt/c/.../semgrep-venv/bin/semgrep'      # WSL içindeki yol
./scripts/start-native.ps1 -Restart
foreach ($port in 8100..8104) { Invoke-RestMethod "http://127.0.0.1:$port/health" }
```

| Port | Servis |
|---|---|
| 8100 | Orkestratör ve arayüz (`http://127.0.0.1:8100`) |
| 8101 | Worker1 — yerel model |
| 8102 | Worker2 — doğrulayıcı |
| 8103 | Runner — derleme, test, tarama |
| 8104 | Deployer — yerel staging |

Ortam değişkenleri yalnız o PowerShell oturumunda geçerlidir. Servisleri yeni bir oturumda başlatırken yeniden verin.

### Docker sandbox (Hafta 5)

Derleme ve testler projenin kodunu çalıştırır. Bu yüzden gerçek (sentetik olmayan) bir proje **yalnız Docker sandbox'ında** derlenir; runner yerel kipte bunu reddeder (`sandbox_required_for_real_projects`). Sentetik laboratuvar vakaları iki kipte de çalışır.

Bir kez hazırlık (Docker WSL Debian'da çalışırken: `wsl -d Debian -u root -- service docker start`):

```powershell
$env:MAVEN_CACHE = '<maven önbelleği>'
.venv/Scripts/python.exe scripts/prepare_sandbox.py
```

Betik şunları yapar:
1. Sabit imajları yoksa indirir: JDK 17 (yaklaşık 233 MB) ve eski projeler için JDK 8 (yaklaşık 150 MB, sıkıştırılmış).
2. Çevrimdışı Maven önbelleğini WSL diskine kopyalar. `/mnt/c` üzerinden derleme yaklaşık 8 kat yavaştır. Kopya mevcut içeriğe eklenir; değerlendirme vakaları için önceden indirilen bağımlılıklar silinmez.
3. Bir kapsayıcıda ağın kapalı, önbellek ile kök dosya sisteminin salt okunur ve yalnız çalışma klasörünün yazılabilir olduğunu sınar. Biri tutmazsa durur.

Sonra servisleri sandbox'la başlatın:

```powershell
$env:RUNNER_SANDBOX = 'docker'
$env:SANDBOX_MAVEN_CACHE = '/home/<wsl-kullanıcısı>/.safepatch/m2'   # betiğin yazdığı yol
./scripts/start-native.ps1 -Restart
```

**Kapsayıcının kısıtları:**
- ağ yok (`--network none`);
- salt okunur kök dosya sistemi, `/tmp` geçici bellekte;
- test JVM'inin geçici klasörü ayrı (`/jvmtmp`); `/tmp` gibi geçici bellekte ve orada program çalıştırılamaz (`noexec`). Ayrı olmasının nedeni: `/tmp`'yi hedefleyen bir dizin aşma testi, açma klasörü `/tmp`'nin kendisiyken düzeltmeyi ayırt edemez (VUL4J-79);
- tüm Linux yetkileri düşürülmüş, ayrıcalık yükseltme kapalı;
- root olmayan kullanıcı (`1000:1000`);
- 2 GB bellek, 2 işlemci, en çok 1024 süreç.

**Dosya ve ayarlar:**
- Maven önbelleği salt okunur bağlanır; yazmalar kapsayıcının geçici belleğine gider (`maven.repo.local.tail`).
- Süre aşılırsa kapsayıcı öldürülür.
- Sonar taraması Sonar sunucusuna ağ gerektirdiği için sandbox'ta reddedilir.
- İmajı proje tanımındaki `java` sürümü seçer (`17` ya da `8`); tanımlı imajı olmayan bir sürüm reddedilir.
- Ayarlar: `SANDBOX_MEMORY`, `SANDBOX_CPUS`, `SANDBOX_USER`, `SANDBOX_IMAGE` (JDK 17), `SANDBOX_IMAGE_<sürüm>`, `WSL_DISTRO`.

Sandbox testleri: `./scripts/run-tests.ps1 -Sandbox` (`SANDBOX_MAVEN_CACHE` ayarlıyken). Bilgisayar yeniden başladıktan sonra Docker servisini yeniden başlatın. Docker çalışmıyorsa iş `verification_infrastructure` ile durur.

### Değerlendirme vakası: VUL4J-79 (L3, Hafta 5)

Yalnız değerlendirme içindir; ürüne, `samples/`'a ve Git'e girmez. Her şey `.runtime/l3` altına yazılır. Bir kez hazırlık (internet; zt-zip kaynağı yaklaşık 2,5 MB, Maven bağımlılıkları yaklaşık 28 MB):

```powershell
.venv/Scripts/python.exe scripts/prepare_vul4j.py --prefetch
```

Betik şunları yapar:
1. zt-zip deposunu klonlar.
2. Açık sürüm ile düzeltmedeki saldırı testinden tek bir commit türetir (özeti betikte sabit).
3. Proje tanımını yazar.
4. Bağımlılıkları ağı açık, öteki kısıtları aynı bir kapsayıcıda indirir. Bu sırada zt-zip testi çalışmaz; Surefire'ın JUnit 4 sağlayıcısı kendi küçük deneme projemizle çözülür.

Doğrulama (açık sürümün başlangıç taraması ve upstream insan düzeltmesi):

```powershell
$env:PROJECTS_DIR = '.runtime/l3/projects'; $env:SAFEPATCH_PROFILE = 'evaluation'
$env:RUNNER_SANDBOX = 'docker'; $env:SANDBOX_MAVEN_CACHE = '/home/<wsl-kullanıcısı>/.safepatch/m2'
$env:EVIDENCE_DIR = 'evidence/v02-vul4j'
.venv/Scripts/python.exe scripts/vul4j_check.py
```

Diğer L3 vakaları (ayrıntı: [L3_SETI.md](L3_SETI.md)):

```powershell
.venv/Scripts/python.exe scripts/prepare_l3.py vul4j-41 vul4j-43 --prefetch     # Vul4J vakaları (internet bir kez)
.venv/Scripts/python.exe scripts/prepare_benchmark.py --prefetch                # OWASP Benchmark bağımlılıkları (internet bir kez, yaklaşık 134 MB)
.venv/Scripts/python.exe scripts/prepare_benchmark.py                           # örneklem, tanıklar, proje tanımları
.venv/Scripts/python.exe scripts/l3_catalog.py                                  # katalog kuralları ve sayılar
```

Bulgular tarayıcıdan değil, vakanın cevap anahtarından gelir ("bilinen bulgu" kipi, `scanner: known`). Bu kip yalnız `SAFEPATCH_PROFILE=lab` ya da `evaluation` iken açılır; ürün profilinde runner reddeder. Sonuç ve sınırlar: [OLCUM_VUL4J.md](OLCUM_VUL4J.md).

Durdurma:

```powershell
./scripts/stop-native.ps1                                    # SafePatch servisleri
taskkill /PID (Get-Content .runtime/ollama.pid) /T /F         # Ollama (yukarıdaki gibi başlatıldıysa)
```

### L2 ortak bilgi paketi (Hafta 7)

İmzalı paket, internet olmadan içeri alınır. Gerekenler iki tane:
- OpenSSH'nin `ssh-keygen` aracı. Windows 10/11'de yerleşik geliyor; Linux'ta `openssh-client` paketi.
- Kurulumla gelen yayıncı anahtarı dosyası (`allowed_signers`).

```powershell
.venv/Scripts/python.exe -m safepatch.l2 verify safepatch-l2-v1.zip --trusted <allowed_signers>
.venv/Scripts/python.exe -m safepatch.l2 import safepatch-l2-v1.zip --trusted <allowed_signers>
```

Komut, kurulumun veritabanını (`DATABASE_URL`, varsayılan `.runtime/jobs.db`) kullanır. Paket biçimi, ret durumları ve güven seviyesi: [L2_PAKETI.md](L2_PAKETI.md).

## 5. Çalıştığını doğrulama

**Arayüz:** `http://127.0.0.1:8100` adresini açın, `.secrets/developer.token` dosyasındaki anahtarla girin, `sql-01` vakasını başlatın.

**Komut satırından tek iş** (sonuç Git dışındaki bir klasöre yazılır):

```powershell
$env:EVIDENCE_DIR = "$env:TEMP\safepatch-duman"
.venv/Scripts/python.exe scripts/retry_experiment.py --cases sql-01 --strategies guided --seeds 42
```

Beklenen sonuç: `"status": "awaiting_review"`. SQL vakası tek denemede, yaklaşık 1 dakikada incelemeye hazır olur.

## 6. Uzun ölçümler

- Tam yeniden deneme deneyi (108 iş) yaklaşık 2,5–3 saat sürer. Bilgisayar uykuya geçerse iş durur; şarjda ve kapağı açık tutun.
- Yarıda kalan bir ölçüm aynı `EVIDENCE_DIR` ile `--resume` parametresiyle kaldığı yerden devam eder. Ürün kodu (`safepatch/`) değiştiyse devam reddedilir.
- Yayımlanacak sonuçlar için `EVIDENCE_DIR=evidence/v02-<ad>` verin; V0.1 kanıt klasörlerine yazma reddedilir.

## 7. Bilinen durumlar

| Durum | Açıklama |
|---|---|
| Servis yeniden başlatılınca eski kod çalışıyordu | `stop-native.ps1`, UTC dışındaki saat dilimlerinde servisleri durdurmuyordu; 24 Ekim'de düzeltildi |
| `python` PATH'te yok | `-PythonExecutable` ile başka bir Python 3.12 ortamı verin |
| `run-tests.ps1 -Integration` bütün Java testlerinde `compilation_failed` veriyor, tanı satırı yok, derleme 2 sn; servislerde iş `verification_infrastructure:build_without_compiler_diagnostic` ile duruyor | Maven çevrimdışı çalışır ve `MAVEN_CACHE` verilmezse depo içindeki `.runtime/m2`'yi kullanır. Bölüm 3'te doldurulan önbelleği gösterin: `$env:MAVEN_CACHE = '<maven önbelleği>'` (25 Ekim'de görüldü) |
| WSL Debian'da Git yok | Ürün için gerekmez; Semgrep yalnız dosya tarar |
| Testler V0.1 kanıtını değiştirdi | Artık değiştiremez; çıktılar `EVIDENCE_DIR`'a yazılır |

## 8. Henüz doğrulanmayanlar

- Linux sunucuya doğrudan kurulum (CI'da yalnız birim testleri Ubuntu'da çalışıyor).
- Servislerin tamamının Docker / Compose ile kurulumu (dosyalar taslak). Derleme sandbox'ı Hafta 5'te doğrulandı (yukarıda).
- Tamamen internetsiz bir makinede sıfırdan kurulum ve ağ çıkışı testi (Hafta 10).
