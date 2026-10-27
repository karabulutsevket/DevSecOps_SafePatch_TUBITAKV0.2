# FindSecBugs adaptörü (27 Ekim 2026, Hafta 7)

**Kod:**
- `safepatch/scanner.py`: `parse_spotbugs`, SARIF'i ortak bulgu modeline çevirir.
- `safepatch/runner.py`: `findsecbugs_scan`, taramayı çalıştırır.
- `safepatch/weakness.py`: `SUPPORTED`, desteklenen aileler.

**Hazırlık:** `scripts/prepare_findsecbugs.py`, ardından `scripts/prepare_sandbox.py` ([KURULUM_V02.md](KURULUM_V02.md)).

**Testler:**
- `tests/test_scanner.py`: SARIF ayrıştırma.
- `tests/test_java_integration.py`: yerel çalışan laboratuvar vakaları.
- `tests/test_sandbox.py`: sandbox.

**Kayıtlar:** [evidence/v02-findsecbugs/](../evidence/v02-findsecbugs/).

## Ne yapıyor

- **Tarayıcı seçenekleri.** İki yeni seçenek var: `findsecbugs` ve `semgrep+findsecbugs`. İş isteğinde, doğrulama isteğinde ve komut satırında kullanılabilir.
- **Ne üzerinde çalışıyor.** SpotBugs 4.9.8 ve FindSecBugs 1.14.0, derleme bittikten sonra projenin derlenmiş sınıfları üzerinde çalışıyor. Projenin sınıf yolunu `maven-dependency-plugin` 3.8.1 çevrimdışı çıkarıyor.
- **Hangi sınıflar taranıyor.** Proje tanımındaki tarama yolu tek bir dosyaysa yalnız o sınıf ve iç sınıfları analiz ediliyor. Bu, Benchmark'ta 2 740 servlet'lik paketin tamamını taramayı önlüyor. Tarama yolu bir klasörse modülün bütün sınıfları taranıyor.
- **Nerede çalışıyor.** Gerçek projeler derlendikleri gibi sandbox içinde analiz ediliyor: ağ yok, kök dosya sistemi salt okunur, araçlar salt okunur bağlı. SpotBugs Java 11 ve üstünü istediği için JDK 17 imajında koşuyor; JDK 8 projelerinin sınıfları da orada analiz ediliyor (VUL4J-79). Sentetik vakalar yerel çalışıyor.
- **Sürüm sabit.** SARIF'teki SpotBugs sürümü 4.9.8 değilse tarama reddediliyor. FindSecBugs SARIF'e kendi sürümünü yazmıyor; bu yüzden eklenti dosyası her taramada SHA-256 özetiyle doğrulanıyor.

## Hangi sonuç bulgu sayılıyor

- **Yalnız güvenlik sonuçları.** Bir sonuç, ancak SECURITY etiketli ve bir CWE'ye bağlıysa bulgu sayılıyor.
  - CWE önce SARIF'in kendisinden okunuyor (FindSecBugs kural ilişkilerinde yazıyor). Orada yoksa Hafta 4 tablosuna (`TOOL_RULES`) bakılıyor.
  - Bilgi notları (ör. `SPRING_ENDPOINT`) ve stil sonuçları bulgu değil.
- **Desteklenen aileler.** İş açan ve yamanın kabulünü etkileyen bulgular yalnız sınıf paketi tamamlanmış ailelerden: CWE-89, CWE-22, CWE-78. Diğerleri raporda `other_findings` olarak duruyor.
  - Bu ayrım olmasaydı, aynı dosyadaki ilgisiz bulgular her düzeltmeden sonra da kalır ve hiçbir yama kabul edilmezdi.
  - Örnekler: VUL4J-79'daki 39 log injection (CWE-117), Benchmark'taki "güven sınırı" uyarıları (CWE-807).
- **Dosya eşleştirme.** SARIF'teki dosya yolu kaynak köküne göre (`demo/DemoService.java`). Tarama yolları içinde bu yolla biten tek depo dosyasına bağlanıyor. Böyle bir dosya yoksa ya da birden fazlaysa sonuç `unmapped_results` olarak sayılıyor.

## İlk taramalar

Taban tarama, her vakanın başlangıç sürümünde yapıldı. Bu, birkaç vakalık bir deneme; bir tespit oranı değil. Karşılaştırmalı tespit ölçümü sıradaki iş.

| Vaka | Bulgu (desteklenen aile) | Diğer bulgu | Taban geçerli | Süre |
|---|---|---|---|---|
| sql-01 | `SQL_INJECTION_JDBC` ve `SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE` (CWE-89) | 0 | evet | 22 sn |
| command-01 | `COMMAND_INJECTION` (CWE-78) | 0 | evet | 25 sn |
| path-01 | yok | 0 | **hayır** | 23 sn |
| owasp-benchmark-00011 | `PATH_TRAVERSAL_IN` (CWE-22) | 0 | evet | 54 sn |
| owasp-benchmark-00196 | `SQL_INJECTION_SPRING_JDBC` (CWE-89) | 2 (CWE-807) | evet | 52 sn |
| owasp-benchmark-00306 | `COMMAND_INJECTION` (CWE-78) | 0 | evet | 49 sn |
| vul4j-79 | 15 × `PATH_TRAVERSAL_IN` (CWE-22), 5 dosyada | 39 (CWE-117) | evet | 36 sn |

- **VUL4J-79.** Cevap anahtarının dört satırının dördü de (`ZipUtil.java` 1152, 1220, 1225, 1260) bulunanlar arasında.
- **path-01.** Laboratuvarın path vakası girdiyi `Path.resolve(input)` ile çözüp `Files.readString` ile okuyor. Bu çağrılar FindSecBugs 1.14'ün havuz (sink) listesinde yok; bulgu çıkmıyor ve iş açılmıyor.
- **Süreler.** Taramanın tek başına süresi değil; derleme, testler ve tarama birlikte.

## Karar gereken: doğru komut düzeltmesinden sonra kalan bulgu

Laboratuvarın doğru komut düzeltmesi sabit bir programı çalıştırıyor ve girdiyi kabuk olmadan, ayrı bir argüman olarak veriyor. FindSecBugs bu düzeltmeden sonra da `COMMAND_INJECTION` raporluyor. Kuralı kabuk olup olmadığına bakmıyor; istekten gelen verinin `ProcessBuilder`'a ulaşmasına bakıyor.

Bugünkü kabul kuralı "tarayıcı bulguyu artık raporlamamalı" diyor. Bu yüzden tarayıcı FindSecBugs iken doğru bir komut düzeltmesi reddediliyor (`finding_remaining`). `semgrep+findsecbugs` seçeneğinde de durum aynı. Bu durum testlerde sabit (`test_findsecbugs_after_the_reference_fix`).

Seçenekler:
- **(a) Kabul kuralı aynı kalsın.** Komut sınıfında tarayıcı olarak FindSecBugs kullanılmaz; kendi kuralımızla Semgrep kullanılır.
- **(b) Kalan bulgu insana gitsin.** Tanığı ve davranış testleri geçen bir düzeltmede tek eksik bu tarayıcının kalan bulgusuysa, aday otomatik reddedilmez; "tarayıcı hâlâ raporluyor" notuyla insan incelemesine gider. Bu, kabul kuralını değiştirir.

Kabul kuralı politika ve doğrulayıcının konusu; karar proje lideri ve politika sahibinde.

## Testler

| | Sonuç |
|---|---|
| Tam paket: birim, Java ve Docker sandbox | **570 geçti** ([kayıt](../evidence/v02-findsecbugs/testler/tests-all.xml)) |
| Yeni testler | 8 SARIF ayrıştırma testi, 5 Java entegrasyon testi, 1 Docker sandbox testi |
