# Egress testi (30 Ekim 2026, Hafta 10)

**Soru:** SafePatch bütün işini yaparken, süreçlerinden herhangi biri bu makinenin dışına bağlanıyor mu?

**Kanıt**
- Kayıtlar [`evidence/v02-egress/olcum/`](../evidence/v02-egress/olcum/) altında:
  - `protocol.json`: iz penceresi, sağlayıcılar, kök süreçler, ham dosyaların özetleri;
  - `workload.json`: iş akışının adımları;
  - `result.json`: sonuç.
- Betikler: `scripts/egress_trace.ps1` (yönetici) ve `scripts/egress_check.py`. Testleri `tests/test_egress_check.py`.

**Ham iz Git'e girmedi.** İz, makinenin bütün trafiğini tutuyor; bu yüzden `.runtime/egress` altında kaldı. Kanıta yalnız SafePatch'in kendi süreçleri yazıldı; makinenin geri kalanı yalnız sayı olarak geçiyor. Ham dosyaların SHA-256 özetleri `protocol.json` içinde.

## Sonuç

**Koşu sırasında SafePatch'in hiçbir süreci makinenin dışına bağlanmadı.**
- SafePatch'in süreç ağacında makine dışına giden bağlantı ya da datagram yok.
- Makine dışına sorulan DNS adı da yok. Tek ad `localhost`; onu Ollama sordu ve yerelde cevaplandı.
- WSL tarafında, koşu sırasında kontrol dışında dışarıya açılan soket yok.

**Ölçüm araçlarının altısı da kontrolle kanıtlandı:**
- Windows'ta TCP, UDP ve DNS;
- WSL'de TCP ve UDP;
- WSL'nin DNS sorgularının Windows izinde görünmesi.

İzde kayıp yok: `EventsLost` 0, `BuffersLost` 0.

**Koşudan önce bir bulgu var:** WSL açılırken sanal makinenin içinden `www.msftconnecttest.com` adresine, 80 portundan bir bağlantı kuruldu. Aşağıda, "WSL'nin açılış bağlantısı".

| Ölçüm | Sonuç |
|---|---|
| SafePatch süreç ağacı | 513 süreç: beş servis, Ollama (`llama-server` dahil), işi süren betik ve hepsinin çocukları (`git`, `java`, `wsl`, `sh`, `taskkill`) |
| SafePatch'in ağ olayları | 10.027; hepsi loopback. Makine dışına giden yalnız Windows kontrolünün 3 olayı |
| Makinenin öbür süreçleri | 69.160 ağ olayı; 50.093'ü makine dışına. Adres ya da ad kaydedilmedi |
| DNS | SafePatch adına makine dışına sorulan ad 0. Makinenin öbür 1.205 DNS olayı yalnız sayıldı |
| WSL gözlemcisi | 5.560 örnek, 50 ms aralıkla. Koşu sırasında kontrol dışında soket 0 |

## Nasıl ölçüldü

**İş akışı.** Gerçek servisler, ürün profilinde ve Docker sandbox'ıyla, iş başına 3 denemelik bütçe ve `guided+context` stratejisiyle çalıştı. HTTP üzerinden şu akış koşturuldu:
1. sentetik `sql-01` işi, Semgrep taramasıyla; incelemeye hazır hâle geldi;
2. onay, hafızaya alma ve staging'e dağıtım;
3. ikinci iş: aynı vaka, hafızadan birebir tekrar; incelemeye hazır, onay ve dağıtım;
4. staging'de geri alma;
5. bir dakika boş bekleme.

Adımların hepsi başarılı (`workload.json`). Onaylar yalnız bu koşu için üretilmiş test kimlikleriyle simüle edildi.

**Açılış da izin içinde.** İz başladıktan sonra Ollama ve beş servis yeniden başlatıldı; açılış sırasındaki davranış da ölçüme girdi.

**Üç ölçüm aracı**

1. **Windows çekirdek izi (ETW).** Operatör `scripts/egress_trace.ps1` dosyasını yönetici olarak başlattı. İz, bu sürede makinedeki her şeyi kaydetti:
   - her süreç başlangıcı, ebeveyniyle (Microsoft-Windows-Kernel-Process);
   - her TCP ve UDP olayı, işlem kimliğiyle (Microsoft-Windows-Kernel-Network);
   - her DNS sorgusu, soran süreçle (Microsoft-Windows-DNS-Client).

   Bu araç örnekleme yapmadığı için çok kısa bir bağlantı da kaçmıyor. Süreç ağacı, servislerin ve Ollama'nın işlem kimliklerinden başlayarak çocuklarıyla kuruldu. Bir işlem kimliğinin başka bir süreçte yeniden kullanılması, başlangıç ve bitiş zamanlarıyla ayrıldı.
2. **WSL gözlemcisi.** Semgrep ve Docker WSL'nin içinde çalışıyor. WSL sanal makinesinin trafiği Windows'un ağ yığınından geçmediği için Windows izinde görünmüyor; kontrol bunu doğruladı.
   - Bu yüzden WSL'nin içinde root olarak bir gözlemci `/proc/net` tablolarını 50 ms'de bir okudu.
   - Gözlemci soketin sahibini (kullanıcı ve süreç) de kaydetti.
   - WSL'nin DNS sorguları ise Windows'un DNS istemcisinden geçiyor (DNS tüneli). Bu yüzden Windows izinde, soran WSL hizmetiyle birlikte tam olarak görünüyor.
3. **Kontroller.** Her iki tarafta bir süreç üç şey yaptı:
   - kimsenin sahibi olmadığı bir `.invalid` adını çözmeye çalıştı;
   - `192.0.2.1:9` adresine bir TCP bağlantısı denedi. Bu adres belgeler için ayrılmıştır (TEST-NET-1) ve yönlendirilmez;
   - aynı adrese bir UDP datagramı gönderdi.

   Altı kontrolün hepsi ilgili araçta, doğru süreçle göründü. Görünmeseydi o araç "kanıtlanmadı" sayılacaktı.

**Saat düzeltmesi.** `tracerpt`, olay zamanlarını yerel saatle ama yanlış bir saat dilimi farkıyla (+02:59) yazıyor. Zamanlar, süreç olaylarının taşıdığı UTC oluşturma ve bitiş zamanlarıyla düzeltildi (10.800 sn).

**Durağan denetimler** (kodda, bu koşudan bağımsız)
- **Semgrep:** `--metrics=off` ve `--disable-version-check` ile, ayrıca `SEMGREP_SEND_METRICS=off` ortamıyla çalışıyor (`safepatch/runner.py`, `process.py`).
- **Sandbox:** `--network none` ile açılıyor; Hafta 8'deki ölçüm: [SANDBOX.md](SANDBOX.md).
- **Ollama:** `127.0.0.1` adresine bağlı ve bulut özellikleri kapalı (`OLLAMA_NO_CLOUD=1`).
- **Arayüz:** içerik güvenlik politikası `default-src 'self'`; dış kaynak yüklemez.

## WSL'nin açılış bağlantısı

**Ne görüldü.** Gözlemci WSL'yi başlattığında, iş akışından 25 saniye önce, root kullanıcısına ait bir TCP bağlantısı `2.16.168.61:80` adresine kurulup kapanmıştı (`TIME_WAIT`).
- Aynı anda Windows'un WSL hizmeti (`wslservice.exe`), sanal makine adına `www.msftconnecttest.com` adını çözdü. Bu ad Windows'un ağ bağlantısı denetiminin adı.
- Deneme koşusunda, ayrı bir WSL açılışında da aynı türden bir bağlantı görüldü: yine 80 portuna, başka bir adrese (`95.101.9.148`).

**Değerlendirme**
- Bağlantı `TIME_WAIT` durumunda yakalandığı için hangi sürecin kurduğu görülemedi. Zamanlaması ve adı, WSL'nin kendi açılışındaki bağlantı denetimine işaret ediyor; bu doğrulanmadı.
- SafePatch'in kodundan gelmiyor.
- Ama runner, WSL'yi ilk kullandığında WSL'yi açar; bu durumda bu bağlantı da kurulur.
- **Kapalı ağ kurulumu için açık iş:** bu bağlantıyı ya WSL ayarıyla kapatmak ya da ağ düzeyinde engellemek. Hangi ayarın kapattığı bu testte araştırılmadı.

## Sınırlar

- **İnternet açık bir makinede ölçüldü.** Sonuç "SafePatch dışarıya bağlanmadı" demek; "bağlanamaz" demek değil. Ağın kendisi yalnız Docker sandbox'ında kapalı.
- **WSL'de TCP ve UDP örneklemeyle izlendi** (50 ms). 50 ms'den kısa süren bir bağlantı kaçabilir.
  - Ama böyle bir bağlantı için önce DNS sorusu gerekir; WSL'nin DNS soruları Windows izinde tam görünüyor ve koşu sırasında hiç yoktu.
  - Adres doğrudan yazılmış bir bağlantıyı bu ölçüm dışlamıyor.
- **Docker konteynerleri gözlemcinin dışında.** Konteynerler kendi ağ ad alanında çalıştığı için gözlemci içlerini görmüyor. Sandbox `--network none` ile açılıyor; içeriden dışarı çıkılamadığı Hafta 8'de ölçüldü.
- **Kapsam tek bir koşu ve tek bir vaka:** sentetik `sql-01`, Semgrep tarayıcısı. Bu koşuda kullanılmayanlar:
  - FindSecBugs, bilinen bulgu kipi, L3 vakaları, L2 içe alma;
  - tarayıcıdan arayüz.
- **Ön koşullar hazırdı.** Model ve Maven önbelleği önceden indirilmişti; bu koşuda indirme olmadı ve olmaması gerekiyordu.
- **Yönetici yetkisi.** ETW izi için yönetici yetkisi gerekti; izi operatör başlattı.

## Yeniden koşmak

1. `python scripts/egress_check.py users`: yalnız bu koşu için test kimlikleri. Anahtarlar `.runtime/egress` içinde kalır, ekrana yazılmaz.
2. Yönetici PowerShell'de `./scripts/egress_trace.ps1`.
3. WSL'de, arka planda: `wsl -d Debian -u root --exec python3 <repo>/scripts/egress_check.py probe <repo>/.runtime/egress/wsl.json <repo>/.runtime/egress/stop`.
4. Ollama'yı ve servisleri yeniden başlat. Servisler için ortam:
   - `USERS_FILE=.runtime/egress/users.json`;
   - ayrı bir `DATABASE_URL`;
   - `RUNNER_SANDBOX=docker`.
5. `python scripts/egress_check.py run`. Kontroller ve iş akışı çalışır; sonunda iz ve gözlemci kendiliğinden durur.
6. `EVIDENCE_DIR=evidence/v02-<ad> python scripts/egress_check.py analyze`.
