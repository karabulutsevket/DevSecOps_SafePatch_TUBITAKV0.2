# SafePatch V0.1

**Yerel Java zafiyet giderme ve doğrulama prototipi.** Sabit yerel LLM, uygunluk kontrollü yama hafızası, gerçek derleme/test/tarama, insan onayı ve aynı artifact ile yerel staging.

Bu depo çalışan bir **demo ve Ar-Ge başlangıcıdır**. Yalnız sahip olunan kayıtlı sentetik Java örneklerini işler. Genel müşteri deposu onarımı ve savunma/banka üretim kurulumu henüz desteklenmez.

## Önce bunlara bakın

- [Sunum dosyası](presentation/SafePatch_V01_Sunum.pptx)
- [Sunum ve canlı demo anlatımı](docs/SUNUM_VE_DEMO.md)
- [Çalışan mimari: neyin ne olduğu](docs/CALISAN_MIMARI.md)
- [Gerçek ölçümler ve karşılaştırmalar](docs/OLCUM_SONUCLARI.md)
- [Ar-Ge ve ticari doğrulama](docs/ARGE_VE_TICARILESME.md)
- [Lisanslar, kaynaklar ve maliyet sınırları](docs/LISANSLAR_VE_KAYNAKLAR.md)
- [Hedef mimari — sonraki aşamalar da içerir](docs/HEDEF_MIMARI_V2.md)

## Akış

Kayıtlı Java deposu → başlangıç taraması ve testler → onaylı hafızanın uygunluk kontrolü → aynı kaynaksa önceki yama, aksi halde yerel model → politika → derleme + davranış testi + güvenlik tanığı + yeniden tarama → insan incelemesi → ayrı dağıtım rolüyle staging.

Onaylanan düzeltme, inceleyenin ayrıca **hafızaya al** kararıyla kaydedilir. Geri çekilen kayıt yeniden kullanılamaz ve bağlı bekleyen onayları geçersizleştirir. Model kendisini eğitmez. Tarama sonucunun temiz olması tek başına kabul için yeterli değildir.

## Çalıştırma — Windows / PowerShell

Gereksinimler: Python 3.12, Git, Java 17, Maven 3.9.x, Ollama 0.34.0, WSL Debian içinde Semgrep 1.136.0. Test edilen model: `qwen2.5-coder:7b-instruct-q4_K_M`; RTX 4070 Laptop 8 GB üzerinde ölçüldü. İndirme/hazırlık aşaması internet kullanır; çalışma aşamasında bağımlılıklar hazır olmalıdır.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.lock
.venv/Scripts/python.exe scripts/init_config.py
.venv/Scripts/python.exe scripts/seed.py
```

`scripts/prepare-ollama.ps1`, hash'i sabitlenmiş Ollama arşivini indirip yerel servisi başlatır. Modeli hazırlık aşamasında indirin:

```powershell
./scripts/prepare-ollama.ps1
.runtime/ollama/ollama.exe pull qwen2.5-coder:7b-instruct-q4_K_M
```

WSL'de Python/venv hazırsa:

```sh
python3 -m venv /absolute/path/to/semgrep-venv
/absolute/path/to/semgrep-venv/bin/pip install semgrep==1.136.0 setuptools==80.9.0
```

PowerShell'de `SEMGREP_WSL` bu Linux yürütücüsünün tam yolu olmalıdır. `scripts/prepare-semgrep.sh` alternatif uv akışıdır; önceden hazırlanmış `.runtime/uv.tar.gz` gerektirir.

Maven önbelleğini bir kez hazırlayın. `-o` çalışma modunda eksik artifact bulunursa iş başarısız olur; internetten sessizce indirme yapılmaz.

```powershell
$env:MAVEN_CACHE = Join-Path (Get-Location) '.runtime/m2'
mvn -B -ntp "-Dmaven.repo.local=$env:MAVEN_CACHE" -f .runtime/repos-v3/sql-01/pom.xml -DskipTests package
mvn -B -ntp "-Dmaven.repo.local=$env:MAVEN_CACHE" -f .runtime/repos-v3/sql-01/pom.xml -Dtest=BehaviorTest test
$env:SEMGREP_WSL = '/absolute/path/to/semgrep-venv/bin/semgrep'
./scripts/start-native.ps1
```

Arayüz: `http://127.0.0.1:8100`. Kullanıcı anahtarları `.secrets/developer.token`, `.secrets/reviewer.token`, `.secrets/deployer.token` dosyalarında oluşturulur. Dosya adlarını `scripts/init_config.py` belirler. Anahtarları paylaşmayın veya repoya eklemeyin. Arayüz anahtarı yalnız sekme belleğinde tutar.

Mevcut başka kurulumla yan yana çalışmak için `-PortBase 8200`; başka hazırlanmış Python için `-PythonExecutable <tam-yol>` kullanılabilir. `.env.example` referanstır, launcher `.env` dosyasını otomatik yüklemez. Durdurma: `./scripts/stop-native.ps1`.

## Test ve ölçüm

```powershell
./scripts/run-tests.ps1
./scripts/run-tests.ps1 -Integration
.venv/Scripts/python.exe scripts/benchmark.py --port-base 8100 --output evidence/new-benchmark
.venv/Scripts/python.exe scripts/benchmark_acceptance.py
```

Testler, benchmark ve canlı demo aynı runner/model üzerinde **aynı anda** çalıştırılmamalıdır. Benchmark üç hafıza yaklaşımını aynı model ve bütçeyle sınar. Kendi ayrı SQLite veritabanını kullanır. Hafıza hazırlığındaki insan rolü **simüle edilmiştir**; ürün veritabanına veya gerçek dağıtıma onay vermez. Tekrar vakaları ve küçük varyantlar bağımsız holdout veri seti değildir.

JUnit dosyaları ve ham JSON/CSV sonuçları `evidence/` içindedir. Başarısız düzeltmeler korunur; model başarı oranı ile unit test başarı sayısı birbirine karıştırılmaz. Tam sonuçları [ölçüm raporundan](docs/OLCUM_SONUCLARI.md) okuyun.

## SonarQube, CodeFix ve diğer tarayıcılar

Ücretsiz demo **gerçek Semgrep CE + bu projeye ait üç dar Java kuralı** kullanır; genel Java güvenlik kapsamı iddiası yoktur. `builtin` yalnız daha dar test tarayıcısıdır ve açık etiketlenir.

SonarQube adaptörü vardır; gerekli güvenlik kuralı, sunucu sürümü, analiz kimliği ve commit uyuşmazsa işi durdurur. Canlı SonarQube çalıştırması bu teslimde doğrulanmadı. Community Build kapsamlı taint analizini sağlamaz; “ücretsiz Sonar bütün SQL/path açıklarını bulur” varsayımı yapılmaz. CodeFix ve Snyk lisansı bu demo için gerekmez. Snyk/Trivy/Grype gerçek entegrasyonları sonraki aşamadır.

## Güvenlik ve dağıtım sınırı

Native çalıştırıcı aynı OS kullanıcısındadır; güçlü sandbox değildir. Ağ ad alanı probunun geçmesi bütün sistemin air-gapped olduğunu kanıtlamaz. Docker/Compose/Jenkins dosyaları bir sonraki ortam doğrulaması için taslaktır. PostgreSQL/çoklu replika/üretim dağıtımı, mTLS/kurumsal SSO, asimetrik imza ve gerçek müşteri projesi pilotu tamamlanmadı.

Kaynaklar MIT lisanslıdır. Modeller, tarayıcılar, çalışma ortamları ve ticari servislerin lisansları ayrıdır. Bu Git deposuna model ağırlıkları, üçüncü taraf kurulum arşivleri, sırlar, müşteri kodu veya çalışma veritabanları eklenmez.
