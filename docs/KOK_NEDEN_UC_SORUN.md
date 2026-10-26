# Üç sorunun kök neden analizi (26 Ekim 2026)

**Kaynak:** L3'teki ilk model ölçümü ([OLCUM_L3_MODEL.md](OLCUM_L3_MODEL.md)) ve o koşunun kayıtlı model cevapları (`.runtime/l3-measure/l3-model-1/jobs.db`).

**Kayıtlar:** [evidence/v02-kok-neden/](../evidence/v02-kok-neden/)
- `once/`: değişiklikten önceki test sonuçları;
- `sonra/`: değişiklikten sonraki test sonuçları;
- `butce/`: istem bütçesinin canlı ölçümü.

**Dallar:**
- `hafta6-kok-neden`: düzeltmeler.
- `hafta6-politika-onerisi`: politika önerisi. Ayrı tutuldu; politika sahibinin onayı olmadan birleştirilmemeli.

| Sorun | Kök neden | Nereden kaynaklanıyor | Durum |
|---|---|---|---|
| 1. Politika reddi (01643) | Değiştirilen bir satırda dosyada zaten olan bir yasak ifade "eklenmiş" sayılıyor | Politika motoru | Öneri hazır, uygulanmadı (politika sahibinin kararı) |
| 2. Küçük dosyalarda bölge kipi | Tüm dosya bütçesi her baytı bir token sayıyor; gerçekte bir token 3,3 bayttan fazla | worker1'in bütçe hesabı (kod) | Düzeltildi |
| 3. Kodu değiştirmeyen cevaplar | Model gösterilen kodu harfi harfine geri döndürüyor; uygulama katmanında kayıp yok | Model | Nedeni artık her denemede kayıtlı; modelin davranışı değişmedi |

Bir ek bulgu daha düzeltildi: bağlam dosyası seçimi Benchmark'ta iş başına 97 saniye sürüyordu (aşağıda, 2. sorunun sonunda).

## 1. Politika reddi

### Gözlenen

İki ret de kayıtlı cevaplarla yeniden üretildi:

| Vaka | Adayın değişikliği | Dosyadaki sayım | Reddeden kural |
|---|---|---|---|
| 01643 | İki `java.net.URI` kullanımını kaldırıyor; var olan `catch (java.net.URISyntaxException e)` satırına `java.io.IOException` ekliyor | `java.net`: 4 → 2 | Eklenen satırda `java.net` geçiyor |
| 01066 | `Runtime r = Runtime.getRuntime();` satırını kaldırıp `Runtime.getRuntime().exec("/path/to/fixed/executable", ...)` yazıyor | `Runtime.getRuntime`: 1 → 1 | Eklenen satırda `Runtime.getRuntime` geçiyor |

- **Kural** (`safepatch/policy.py`, `introduces_forbidden`): diff'in eklenen satırlarında yasak bir ifade varsa ret. Unified diff değişen bir satırı "silme + ekleme" olarak gösterir. Bu yüzden dosyada zaten olan bir ifadeyi taşıyan satıra yapılan her düzenleme, ifadeyi "eklemek" sayılıyor.
- **Ret işi bitiriyor.** `rejected` durumuna geçiliyor, kalan denemeler kullanılmıyor (`engine.run`).
- **Ölçek.** Önerilen kural bütün kayıtlı model cevaplarına uygulandı (90 cevap). Yalnız bir kararı değiştiriyor: 01643'ün ilk denemesi.

### Neden basit bir gevşetme güvensiz

`java.net` bir paket önekidir. `java.net.URISyntaxException` (bir istisna tipi) ile `java.net.URL` (ağ bağlantısı) aynı ifadeye eşleşir. "Sayı artmadıysa geçir" kuralıyla bir aday `URISyntaxException`'ı silip yerine `new java.net.URL(...).openStream()` yazabilir; sayım aynı kalır, ağ yeteneği eklenmiş olur.

### Öneri (uygulanmadı, `hafta6-politika-onerisi` dalında)

- Bastırma ve test/derleme işaretleri (`NOSONAR`, `nosemgrep`, `SuppressWarnings`, `surefire`, `org.junit`, `.m2`, `.github`, `sonar.exclusions`) bugünkü gibi katı kalır: hiçbir eklenen satırda geçemez.
- Yetenek ifadeleri **tam başvurularıyla** sayılır: `java.net.URISyntaxException`, `java.net.URL`, `Runtime.getRuntime().exec` ayrı başvurulardır.
- Hiçbir başvuru dosyada öncekinden sık geçemez. Sayım dosyanın tamamında yapılır, böylece satırlara bölünmüş bir ifade de yakalanır.

| Durum | Bugün | Öneriyle |
|---|---|---|
| Düzenlenen satır var olan başvuruyu koruyor (01643) | ret | geçer |
| Var olan `Runtime.getRuntime()` olduğu gibi başka yere taşınıyor | ret | geçer |
| Aynı sayıyla başka sınıf (`URISyntaxException` → `URL`) | ret | ret |
| Yeni ağ başvurusu, `import java.net.*;` | ret | ret |
| Var olan `Runtime.getRuntime` artık `.exec` çağırıyor | ret | ret |
| `System.exit` ekleniyor; satırlara bölünmüş `System`/`.exit` | ret | ret |
| Var olan satıra `NOSONAR` ekleniyor | ret | ret |

**Önerinin riskleri:**
- Dosyada zaten olan bir yeteneğin dosya içinde taşınmasına izin verir. Davranış testi ve tanık yine karar verir.
- İfade temelli denetimin bilinen bir sınırı değişmiyor: dosya `import java.net.*;` içeriyorsa sınıfın basit adıyla (`new URL(...)`) kullanımı ne bugün ne öneriyle yakalanır.

**Alternatif B (ayrı karar):** Politika reddi işi bitirmesin. Deneme başarısız sayılsın ve modele hangi yasak ifadenin eklendiği söylensin. Bu, motorun davranışını ve modele giden metni değiştirir.

### Bu dalda değişen

Politika kodu değişmedi. `tests/test_policy.py` dosyasına eklenenler:
- **Dört koruma testi:** aynı sayıyla `URL`'ye geçiş, joker `import`, `.exec` kazanan `Runtime.getRuntime`, var olan satıra `NOSONAR`. Bugün de, öneriyle de ret.
- **Bir yeniden üretme testi:** 01643 kalıbı. Beklenen davranışı (geçmesi) sınıyor ve `xfail(strict=True)` ile işaretli. Bugün başarısız oluyor. Politika gevşetilirse test geçmeye başlar ve işaret kaldırılmadan paket kırmızıya döner; böylece değişiklik fark edilmeden olamaz.

## 2. Küçük dosyalarda bölge kipi

### Gözlenen

- **Bütçe** (`safepatch/worker1.py`, `compose_mode`): 8 192 − 2 048 (çıktı) − 512 = 5 632 token.
  - Tüm dosya kipi her UTF-8 baytı bir token sayıyordu; JSON şeması da bu hesaba dahildi.
  - Bölge kipi iki baytı bir token sayıyor ve üretimden sonra modelin ölçtüğü sayıyı denetliyor. Tüm dosya kipinde bu denetim yoktu.
- **L3 koşusunda ölçülen istem uzunlukları:**

| Kip | Deneme | Ölçülen istem (token) | Bayt/token (alt sınır) | Bağlam dosyası düşen deneme |
|---|---|---|---|---|
| Tüm dosya | 16 | 1 050–1 284 | 3,3–4,0 | 16 / 16 |
| Bölge | 62 | 1 695–2 617 | 3,5–4,4 | 62 / 62 |

  En uzun istem 5 632'nin 2 617'siydi.
- **Bağlamın düşmesi yalnız L3'te değil.** Önceki ölçümlerde de bağlam düştü: `v02-retry` 18/211, `v02-genel-talimat` 18/114, `v02-bolge-sentetik` 18/116, `v02-faz1` 6/28, `v02-w3-dogrulama` 6/36, VUL4J-79 9/9.

### Kök neden

Tüm dosya tahmini gerçeğin 3–4 katı. "Tüm dosya sığıyorsa tüm dosya" kuralı yanlış hesaplanan bir "sığıyor mu" sorusuyla çalışıyordu. Bu yüzden 70 satırlık servlet'ler bölge kipine düştü ve `guided+context`'in salt okunur bağlamı her denemede düştü. Sorun yapılandırmada değil, koddaki tahminde.

### Kip kararı neye dayanıyor

Karar kuralı değiştirilmedi: kip, istemin sığıp sığmadığına göre seçiliyor. Değişen tek şey, bu sorunun doğru hesaplanması. 70 satır özel bir eşik değil. Gerekçe:
- **Güvenlik.** Politika ve doğrulama iki kipte de bütün dosyayı yargılar. Tüm dosya kipinde de tek dosya, 200 satır ve yasak ifade sınırları geçerli. Bölge kipi modelin dokunabileceği yeri daraltır, ama bir güvenlik sınırı olarak tasarlanmadı; büyük dosyalar için getirildi (Hafta 5).
- **Bağlam ve değişiklik kapsamı.** Tüm dosya, modelin bulguyu tutan metodun dışındaki yardımcıları ve alanları görmesini sağlar. Benchmark'ta veri `doSomething` gibi ayrı metotlardan geçiyor; kabul edilen bir aday (02091) bu yardımcıyı kaldırdı. Bölge görünümü yalnız bulguyu tutan metotları içerir.
- **Sonuçlar bir kip lehine net değil.** İlk denemelerde tüm dosya 14 denemede 3 doğrulama, bölge 16 denemede 1 doğrulama verdi. Ama vakalar farklı ve sayılar küçük; bu fark kanıt sayılmadı.

### Düzeltme

- İki kip de iki baytı bir token sayıyor; şema hesaba dahil kalıyor.
- Tüm dosya kipi yalnız **cevap da sığıyorsa** seçiliyor (`answer_fits`). Bu kural geliştirme ölçümünde ortaya çıktı (aşağıda). Tüm dosya cevabı dosyayı tekrarlar ve çıktı bütçesi 2 048 token. Tahmin: (JSON'a kaçırılmış dosya + 1 200 bayt) / 3.
  - Kayıtlı 98 tüm dosya cevabında, 2 KB'ı geçen cevaplar token başına 3,6 bayttan az değil.
  - Cevapta dosyanın dışında en çok 1 116 bayt var (gerekçe ve anahtarlar).
  - Tahmin bu 98 cevabın hiçbirinde gerçeğin altında kalmıyor.
- Modelin ölçtüğü sayılar iki kipte de denetleniyor.
  - Tüm dosyanın istemi sınırı aşar ya da cevabı kesilirse iş başarısız olmuyor; istem bölgeleriyle yeniden üretiliyor. Metrik: `whole_file_fallback` (`prompt_over_budget` / `answer_cut_off`).
  - Bölge görünümü yoksa eskisi gibi hata.
- **Kip seçiminin sonucu** (ilk deneme, motorun gerçek bağlamıyla):

| Taraf | Tüm dosya | Bölge | Bölgeye düşenler |
|---|---|---|---|
| Geliştirme | 16 | 4 | Dört bölge vakası (5,6–6,4 KB) |
| Değerlendirme | 40 | 5 | En büyük üç servlet (~5 KB), VUL4J-41, VUL4J-79 |

  L3 ölçümünde ilk denemelerin 16'sı bölge, 14'ü tüm dosya kipindeydi.

### Canlı doğrulama

**Betik:** `scripts/prompt_budget_check.py`. **Kayıt:** [butce/prompt-budget.json](../evidence/v02-kok-neden/butce/prompt-budget.json).

worker1'in kendi koduyla kurulmuş 112 istemin uzunluğunu model ölçtü. Onarım yapılmadı. İstemler şunlardan kuruldu:
- geliştirme kaynakları;
- 42 Benchmark servlet'i, motorun seçtiği bağlamla;
- zor bir durum: Türkçe yorumlarla dolu bir dosya.

Sonuç:
- Tahmini aşan istem yok, sınırı aşan istem yok.
- En düşük oran 3,35 bayt/token, Türkçe dosyada. En uzun istem 5 632'nin 2 569'u.
- İstemlerin hepsi tüm dosya olarak sığıyor. Bu ölçüm yalnız istemi sınıyor; kip kararı artık cevabın da sığmasına bakıyor (Düzeltme).

Benchmark'ın ağır yeniden denemelerinde iki kardeş dosyadan biri ya da ikisi hâlâ düşüyor: tahmin gerçeğin en az 1,6 katı. Oran bilinçli olarak 2'de bırakıldı; 3 olsaydı Türkçe dosyada pay yalnız %10 kalırdı.

### Önceden çalışan davranış

- **Aynı kalan istemler.** Eski kuralla sığan ve hiçbir şey düşürmeyen bir istem aynen aynı kalır. Eski koşul (bayt ≤ sınır) yeni koşulu (bayt/2 ≤ sınır) zaten sağlar; istem metni de bütçeye bağlı değildir.
- **Değişen istemler.** Eskiden bölgeye düşen dosyalar ve eskiden bağlamı düşen denemeler.

### Geliştirme setinde önce/sonra ölçümü

**Kayıtlar:** [evidence/v02-butce-gelistirme/](../evidence/v02-butce-gelistirme/): `once/`, `sonra/`, `son/`, her biri `protocol.json`, `summary.json` ve `jobs/`. **Betik:** `scripts/l3_measure.py --split development`.

20 geliştirme vakası koşuldu: seed 42, `guided+context`, hafıza kapalı, 3 deneme, yerel runner. Koşular arasında değişen tek dosya `worker1.py`; her koşunun protokolü dosyanın özetini kaydediyor.

| Koşu | worker1 | Doğrulanan | Model süresi | Toplam süre |
|---|---|---|---|---|
| `once` | Değişiklikten önce (`83076cf`, 1 bayt/token) | 11 / 20 | 332 sn | 1 143 sn |
| `sonra` | Yalnız istem tahmini düzeltilmiş (`9293c09`) | 12 / 20 | 730 sn | 2 107 sn |
| `son` | İstem ve cevap birlikte (`024338a`) | 11 / 20 | 327 sn | 1 089 sn |

**Ara sürüm (`sonra`) neyi gösterdi:**
- Dört bölge vakası (5,6–6,4 KB) tüm dosya kipine geçti. Cevaplar dosyayı yeniden yazdığı için iş başına çıktı ~800 token'dan ~5 000 token'a çıktı; bu vakalarda model süresi 11–21 sn'den 112–145 sn'ye yükseldi.
- En büyük cevap, 2 048 token'lık çıktı bütçesinin 1 892'sini kullandı. Biraz daha büyük bir dosyanın cevabı kesilir ve iş hata ile biterdi. Eski 1 bayt/token sayımı bu riski tesadüfen saklıyordu.
- Bu yüzden cevap kuralı eklendi.
- Ara sürümdeki fazladan bir doğrulama (region-path-read) tek seed'de tek vaka; kanıt sayılmadı. Kip kararı sonuca göre değil, cevabın sığmasına göre verildi.
- Toplam süredeki farkın geri kalanı (~570 sn), istemi ve model süresi aynı kalan vakalarda (path-01..03'te 118 sn'den 220–230 sn'ye). Bu, makinedeki doğrulama hızının değişmesi; düzeltmeyle ilgisi yok.

**Son sürüm:**
- 20 vakanın 20'sinde ilk istem önceki sürümle bayt bayt aynı. Bölge vakaları yine bölge kipinde.
- Değişen tek şey command-01..03'ün yeniden denemelerinde bağlam dosyasının artık düşmemesi. Bu, sonucu değiştirmedi.
- **Gürültü:** iki varyant komut vakası üçüncü denemede ters yönde sonuç değiştirdi (biri doğrulandı → başarısız, öteki tersi). Yeniden denemeler 0,4 sıcaklıkla koşuyor ve rehber notu her istekte rastgele bir etiket taşıyor; bu yüzden aynı ayarlarla bile cevap ayrışabiliyor.
- **Sonuç:** tek seed'li bir koşu 20 vakada ±1–2 vaka oynuyor. Geliştirme setinde düzeltmenin sonuca ölçülebilir bir etkisi yok, gerileme de yok.
- **Etki nerede beklenmeli:** düzeltmenin asıl etkisi, L3'teki küçük servlet'lerin tüm dosya ve bağlamla gitmesinde. Geliştirme setinde bu durumu sınayan bir vaka yok.

### Riskler

- **Önceki ölçümler bu commit'le aynen tekrarlanamaz.** Yukarıda sayılan denemelerde istem değişir; eski davranış önceki commit'le tekrarlanır.
- **L3'te bağlam artık modele gidiyor.** Motorun seçtiği bağlam, aynı paketteki kardeş dosyalardır (alfabetik). Benchmark'ta bunlar ilgisiz ve kendileri de açık içeren servlet'ler (`BenchmarkTest00001`, `00004`).
  - İlk L3 ölçümü fiilen bağlamsız koştu. Bir sonraki L3 koşusu onunla doğrudan karşılaştırılamaz.
  - Bağlam seçimi değiştirilmedi. Sentetik laboratuvarda kardeş dosya düzeltme için gerekiyor (komut vakasında `EchoMain`); "yalnız başvurulan dosyalar" gibi basit bir kural bunu bozar ve elimizde kanıt yok.

### Ek bulgu: bağlam seçimi 97 saniye sürüyordu

`engine.read_only_context`, bir dosyanın sığıp sığmadığına bakmadan önce içeriğini okuyordu. Benchmark'ın paketinde 2 740 kardeş dosya var; seçim iş başına 97 saniye sürdü. Bu, Benchmark işlerinin süresinin (113–225 sn) kabaca yarısı.

Düzeltme: Git'in tuttuğu boyutla, sığamayacağı kesin olan dosya okunmuyor. Bir karakter en çok 4 bayt olduğu için ön eleme seçimi değiştirmez.

| Vaka | Süre | Okunan dosya | Seçim |
|---|---|---|---|
| owasp-benchmark-00011 | 97 sn → 0,36 sn | 2 740 → 4 | Aynı iki dosya, 7 532 karakter |
| vul4j-79, 41, 43 | 0,5 sn civarı | — | Bütün kardeşleri okuyan eski yolla aynı (6, 12, 3 dosya) |

## 3. Kodu değiştirmeyen cevaplar

### Gözlenen

L3 koşusunda 13 boş cevap vardı: 9'u komut, 4'ü SQL vakalarında. Her biri modele gösterilen kodla karşılaştırıldı.
- **13'ünün 13'ü gösterilen kodun aynısı.** 9'u birebir aynı. 4'ünde yalnız son satır sonu eksik; birleştirme bunu zaten geri ekliyor.
- **Kipe göre:** 4'ü tüm dosya, 9'u bölge kipinde.
- **Uygulama katmanında kayıp yok.** Geçersiz bölge kimliği, bölge dışına taşan değişiklik ya da içe aktarma hatası görülmedi; bunlar ayrı hata kodlarıyla raporlanır ve koşuda hiç çıkmadı.
- **Modelin gerekçesi bir düzeltme anlatıyor.** Örneğin "girdiyi temizleyerek açığı kapatıyoruz".
- **Geri bildirim işe yaramadı.** İlk cevabı boş olan 7 vakadan 6'sı, ikinci denemede "kod değişmedi" geri bildirimine rağmen aynı kodu yine döndürdü. Üçüncü denemede, rehberle, hepsi bir değişiklik yaptı; 02414 bu yolla doğrulandı.
- **Değişiklik gerekliydi.** 13'ünün hepsinde taban güvenlik tanığı başarısızdı.

### Kök neden

Model, 7B olan yerel model, gösterilen kodu kopyalıyor. Bu, değişikliğin uygulanamaması değil; model gerçekten değişiklik yapmıyor. Neden kopyaladığı bir varsayım olarak kalıyor. Örneğin CWE-78 notunun Benchmark'ın "girdi betiğe ortam değişkeni olarak gidiyor" kalıbına uymaması olabilir; bu sınanmadı.

### Değişiklik

Kod değişmeyen her denemeye bir `no_change` kaydı ekleniyor (`safepatch/engine.py`, `no_change`). L3 ölçüm satırları da bu kaydı taşıyor.

| Alan | Değerler | Anlamı |
|---|---|---|
| `answer` | `repeats_shown_code` | Model gösterilen kodu geri verdi |
| | `edits_made_no_difference` | Model değişiklik yaptı ama dosyada fark oluşmadı. Uygulama katmanında bir kayıp olduğunu gösterir; bugüne kadar görülmedi |
| `shown` | `whole_file` / `regions` | Modele ne gösterildi |
| `change_required_by` | `failing_security_witness` | Tanık açığı kanıtlıyor: değişiklik gerekli |
| | `finding_without_security_witness` | Yalnız bir bulgu var: yanlış pozitif olabilir, değişiklik gerekmeyebilir |

- **İş akışı değişmedi.** Boş cevap hâlâ başarısız bir deneme sayılıyor; modele giden geri bildirim, yani istem, aynı.
- **Neden akış değişmedi.** Tabanı geçersiz olan iş zaten modele gitmiyor; L3'teki 15 güvenli vaka böyle döndü. Modele giden işte değişiklik ya bir tanıkla kanıtlı ya da yalnız bir bulguya dayalı. Bu ikinci durum bu ölçümde hiç görülmedi; akışı onun için değiştirmek kanıtsız olurdu.
- **Gerçek kayıtlarla sınama.** Kayıt 13 gerçek boş deneme üzerinde yeniden oluşturuldu: 13'ü de `repeats_shown_code` ve `failing_security_witness`.

### Çözülemeyen

Modelin kodu kopyalaması çözülmedi. Denenecek iki öneri var; ikisi de modele giden metni değiştirdiği için önce geliştirme setinde ölçülmeli:
- (a) Boş cevabın geri bildirimine bulgunun satırını ve "cevabın gösterilen kodla birebir aynı" bilgisini eklemek.
- (b) CWE-78 notunu, girdinin ortam değişkeni olarak gittiği kalıbı da kapsayacak şekilde genişletmek.

## Testler

| | Önce | Sonra |
|---|---|---|
| Tam paket: birim, Java ve Docker sandbox testleri | **530 geçti** ([once/tests-all.xml](../evidence/v02-kok-neden/once/tests-all.xml)) | **543 geçti, 1 beklenen başarısızlık** (`xfail`, 1. sorun) ([sonra/tests-all.xml](../evidence/v02-kok-neden/sonra/tests-all.xml)) |
| Cevap kuralından sonra (`024338a`) | | **551 geçti, 1 beklenen başarısızlık** ([son/tests-all.xml](../evidence/v02-kok-neden/son/tests-all.xml)) |

Değişiklikten sonraki ilk koşuda bir test başarısız oldu ([sonra/tests-all-ilk.xml](../evidence/v02-kok-neden/sonra/tests-all-ilk.xml)). `test_ranking.py` içindeki bu test de eski eşiğe bağlıydı: sınanan davranış, başarısız aday uyarılarının önceki diff'ten önce düşmesi. Testin girdisi motorun gönderebileceği en büyük uyarılara (2 × 1 500 karakter) çıkarıldı; davranış aynı. Ardından paket yeniden koşuldu.

**Yeni testler:**
- **3. sorun, `tests/test_engine.py`:**
  - Boş cevabın neyi tekrarladığı ve değişikliği neyin istediği: tanık, tanıksız bulgu, bilinmiyor.
  - Bölge cevabı: son satır sonu eksik.
  - Kardeş dosya ön elemesi: seçim aynı kalıyor, sığmayan dosya okunmuyor.
- **2. sorun, `tests/test_worker1.py`:**
  - Servlet boyutlu bir dosya, yeniden deneme bağlamıyla tüm dosya olarak gidiyor.
  - Modelin ölçtüğü sayı sınırı aşarsa istem bölgeleriyle yeniden üretiliyor.
  - Bölge görünümü yoksa ret.
  - Sınırın tam altındaki istem tek çağrıyla cevaplanıyor.
  - Cevabı çıktı bütçesine sığmayacak bir dosya bölge kipinde gidiyor; bölge görünümü yoksa tüm dosya deneniyor.
  - Cevap tahmininin sınırları (3 500 / 4 900 karakter sığar, 5 000 sığmaz).
  - Kesilen bir tüm dosya cevabı bölgeleriyle yeniden üretiliyor; bölge görünümü yoksa ret.
  - Eski eşiğe bağlı beş test (dördü `test_worker1.py`'de, biri `test_ranking.py`'de) bütçeden türetilen boyutlarla yeniden yazıldı: sınadıkları davranış aynı (düşürme sırası, ret, bölgeye geçiş).
- **1. sorun, `tests/test_policy.py`:** 4 koruma testi ve 1 `xfail(strict=True)` yeniden üretme testi.

## Karar bekleyenler

1. **Politika önerisi** (`hafta6-politika-onerisi`): politika sahibi.
2. **Politika reddinin işi bitirmesi** (alternatif B): politika sahibi.
3. **Bütçe düzeltmesinin önceki ölçümlere etkisi.** Geliştirme setinde ölçüldü: 11/20 → 11/20 (yukarıda). Ama düzeltmenin asıl etkisi L3'te; bunu sınayacak bir geliştirme vakası yok. Küçük dosyayı geniş bir pakette tutan bir geliştirme vakası eklensin mi?
4. **L3'te bağlam seçimi.** Benchmark'ta ilgisiz kardeş dosyalar seçiliyor. Bir sonraki L3 koşusundan önce karar verilmeli; seçenekler: bağlam kapalı, seçim kuralı değişsin ya da olduğu gibi kalsın.
5. **Boş cevaplar için istem değişiklikleri** (a, b): geliştirme setinde ölçüm.
