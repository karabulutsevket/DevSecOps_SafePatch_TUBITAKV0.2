# Temiz makinede çevrimdışı kurulum ve süre ölçümü (Hafta 10)

**Amaç (ROADMAP Hafta 10):** SafePatch, interneti olmayan temiz bir Windows 11 makinesine kaç dakikada kurulur?

İş iki parçalı:
1. **Çevrimdışı paket.** İnternetli, hazırlanmış bir makinede bir kez üretilir. **30 Ekim'de üretildi.**
2. **Kurulum ve ölçüm.** Paket temiz bir makineye taşınır ve ağ kapalıyken kurulum betiği çalıştırılır. Betik her adımın süresini kendisi kaydeder. **Bu adım ekipten birinin makinesinde yapılacak; henüz yapılmadı.**

## Paket (30 Ekim 2026)

**Kayıt:** [`evidence/v02-kurulum/paket/`](../evidence/v02-kurulum/paket/).
- `build.json`: adım adım hazırlama süreleri.
- `manifest.json`: her dosyanın boyutu ve SHA-256 özeti.

Paketin kendisi Git'e girmez; bu makinede `.runtime\offline-bundle` klasöründe duruyor. Toplam 149 dosya, 7,87 GB. Hazırlanması 4,5 dakika sürdü; bunun yaklaşık 3,5 dakikası indirmeydi (kurulum dosyaları, Python ve Linux paketleri, Debian paketleri).

| Bölüm | İçerik | Nereden |
|---|---|---|
| `windows/` | Python 3.12.10, Git for Windows 2.55.0.windows.5, Amazon Corretto 17.0.20.10.1, Maven 3.9.16, WSL 2.7.12 kurulum dosyaları, Ollama 0.34.0 arşivi | İndirildi (proje liderinin onayı, 30 Ekim). Ollama arşivi buradan kopyalandı ve sabit özetle doğrulandı |
| `linux/` | Debian 13 WSL imajı v1.26.0.0 (özeti Microsoft'un dağıtım listesindeki özetle doğrulandı); Docker 26.1.5 ve 52 bağımlılığı (`.deb`); Semgrep için CPython 3.12.11; sandbox'ın iki imajı (`docker save`) | Debian imajı ve paketler indirildi; Python ve imajlar buradan |
| `wheels/` | SafePatch'in 30 Python paketi (Windows) ve Semgrep ortamının 46 paketi (Linux) | İndirildi. Sürümler `requirements.lock` dosyasından ve buradaki Semgrep ortamından |
| `models/` | Yalnız ürünün modeli: `qwen2.5-coder:7b-instruct-q4_K_M`. Deneyin embedding modeli girmedi | Buradan |
| `maven/`, `tools/` | Çevrimdışı Maven önbelleği, SpotBugs ve FindSecBugs | Buradan |
| `safepatch/` | Kaynak kod, `git bundle` olarak (`main`, `064ac25`) | Buradan |
| kök | `offline_install.ps1`, `manifest.json`, `build.json` | |

İndirilenlerin toplamı 755,0 MB; onaylanan listeyle aynı.

**Paket hiçbir sır içermez.** Anahtarlar kurulumda temiz makinede üretilir (`init_config.py`).

**Sandbox imajları özetleriyle sabit kalıyor.** `docker load`, imajın kayıt defterindeki özetini (runner'ın `maven:…@sha256:…` sabitlemesi) korumuyor; imaj kimliğini (bir içerik özeti) ise koruyor. Kurulum, `SANDBOX_IMAGE` ve `SANDBOX_IMAGE_8` değişkenlerini aynı içeriğin imaj kimliğine ayarlıyor:
- JDK 17: `sha256:caa1c994…`
- JDK 8: `sha256:09448651…`

## Temiz makinede yapılacaklar

**Ön koşullar**
- Windows 11, yönetici hesabı.
- Paket ve kurulum için en az 30 GB boş disk.
- GPU varsa NVIDIA sürücüsü kurulu olmalı. GPU yoksa model işlemcide çalışır; daha yavaş olur, betik bunu da kaydeder.
- Makinede daha önce SafePatch, WSL'de bir `Debian` dağıtımı ya da Python 3.12 kurulmamış olmalı.

**Adımlar**
1. `.runtime\offline-bundle` klasörünü harici bir diskle temiz makineye kopyalayın, ör. `D:\offline-bundle`.
2. **Ağı kapatın:** kablo, Wi-Fi.
3. Yönetici olarak bir PowerShell açın ve çalıştırın:

   ```powershell
   cd D:\offline-bundle
   powershell -ExecutionPolicy Bypass -File .\offline_install.ps1
   ```

4. WSL'yi açmak için yeniden başlatma gerekirse betik bunu söyler. Bilgisayarı yeniden başlatın ve 3. adımdaki komutu tekrar çalıştırın; betik kaldığı yerden devam eder.
5. Betik bitince `C:\SafePatch\install-timing.json` dosyasını geri gönderin. Sonuç [OLCUM_KURULUM.md](OLCUM_KURULUM.md) olarak raporlanır ve kayıt `evidence/v02-kurulum/` altına girer.

Önce sistemi değiştirmeden denemek isterseniz: `.\offline_install.ps1 -DryRun`. Bu kip yalnız paketi doğrular ve adımları listeler; yönetici yetkisi istemez. Bu makinede 149 dosyayı 7,6 saniyede doğruladı.

**Betiğin adımları** (her birinin süresi ve sonucu kayda girer)

| # | Adım | Ne yapar |
|---|---|---|
| 1 | paket doğrulama | Her dosyayı manifestteki SHA-256 ile karşılaştırır |
| 2–5 | Python, Git, Java, Maven | Sessiz kurulum. Java'nın ve Maven'ın `PATH` ayarı denetlenir |
| 6 | WSL | WSL MSI ve VirtualMachinePlatform. Gerekirse yeniden başlatma, ardından devam |
| 7 | Debian 13 | `wsl --import`, systemd açık |
| 8 | Docker | Eksik `.deb` paketleri kurulur, servis başlatılır |
| 9 | sandbox imajları | `docker load`, imaj kimlikleri denetlenir, ortam değişkenleri yazılır |
| 10 | Semgrep 1.136.0 | Paketteki Python ve çevrimdışı paketlerle `/opt/safepatch` altına kurulur |
| 11 | Ollama ve model | Arşiv açılır, model kopyalanır |
| 12 | SafePatch | `git clone`, sanal ortam, çevrimdışı `pip install`, `init_config`, `seed`, Maven önbelleği |
| 13 | Docker sandbox | `prepare_sandbox.py` (yalıtım sınaması) ve 20 GB'lık sınırlı çalışma alanı |
| 14 | birim testleri | `run-tests.ps1` |
| 15 | servisler ve duman testi | Ollama ve servisler başlatılır. Model özeti denetlenir (`dae161e2…`). `sql-01` işi ürün profilinde, Docker sandbox'ında, modelle; beklenen sonuç `awaiting_review` |

**Kayıtta neler var:**
- makine bilgisi: işletim sistemi, işlemci, RAM, GPU, boş disk;
- başlangıçta ağın açık olup olmadığı;
- her adımın başlangıcı, süresi ve sonucu;
- toplam adım süresi.

Bekleme süresi, yani yeniden başlatma, toplam adım süresinin dışında kalır; başlangıç ve bitiş zamanlarından ayrıca görülür.

## Sınırlar

- **Kurulum betiği temiz bir makinede henüz çalışmadı.** Bu makinede yalnız `-DryRun` kipi ve PowerShell 5.1 ayrıştırıcısıyla denetlendi. İlk gerçek koşu bir adımda takılırsa betik düzeltilir; o koşunun kaydı da saklanır.
- **Docker paketleri buradaki Debian 13'ün güncel sürümleri.** Temiz imajda daha yeni bir sürümü kurulu olan bağımlılıklar atlanır. Bir sürüm çatışması çıkarsa 8. adım bunu gösterir.
- **Python sürümü farklı.** Python 3.12.10, 3.12'nin son Windows kurulum dosyası; geliştirme makinesinde 3.12.14 çalışıyor. Paketler `cp312` olduğu için aynı.
- **Ölçüm tek bir makinede yapılacak.** Kurulum süresi büyük ölçüde diske ve işlemciye bağlı.
