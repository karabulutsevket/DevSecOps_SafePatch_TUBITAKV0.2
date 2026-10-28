# Ana deney protokolü: A / B / C / C+L2 (27 Ekim 2026, Hafta 9)

**Durum: kararlar verildi (27 Ekim, proje lideri), asıl koşu tamamlandı (`ana-1`, 28 Ekim; aşağıda "Koşu kaydı"). Analiz: [OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md).** Bu belge deney koşulmadan önce sabitlenir (ROADMAP.md Hafta 9). Koşu başladıktan sonra protokol de ürün kodu da değişmez. Değişirse koşu baştan alınır ve iki kayıt birlikte raporlanır. Betik bunu denetler: `safepatch/` değişmişse devam reddedilir.

**Betik:** `scripts/main_experiment.py`:
- `l2` alt komutu L2 paketini üretir;
- `run` alt komutu kolları koşar.

**Ön analiz:** [`evidence/v02-benchmark/kapsam/coverage.json`](../evidence/v02-benchmark/kapsam/coverage.json) (`scripts/experiment_coverage.py`). Bu analiz statiktir: model çağrısı, doğrulama ya da gizli test kullanmaz.

## Soru

ROADMAP.md, Bölüm 1:
- **H1:** Uygunluğu denetleyen ve kanıtla sıralayan hafıza (C), aynı model ve bütçede hafızasız modele (A) ve yalnız benzerliğe dayalı hafızaya (B) göre güvenli onarım oranını artırır, yanlış aktarımı azaltır, yanlış kabulü artırmaz.
- **H3:** L2 paketi, L1 boşken (soğuk başlangıç) güvenli onarım oranını artırır.

## Kollar

| Kol | Hafıza | Kayıt seçimi |
|---|---|---|
| **A** | kapalı | — |
| **B** | kolun kendi L1'i (aşağıda "Öğrenme") | aynı CWE ailesindeki kayıtlardan, bulgunun bulunduğu metoda **embedding benzerliği en yüksek** olan. Uygunluk kuralı yok; yalnız örnek, birebir tekrar yok |
| **C** | kolun kendi L1'i | SafePatch'in kuralları (`memory_mode=guarded`, `safepatch/memory.py`): birebir tekrar ya da uygun örnek, sıralama, başarısızlık uyarıları |
| **C+L2** | C + deneyden önce kurulan L2 paketi | C'nin kuralları; L2 yalnız L1'de uygun kayıt yoksa ve yalnız örnek olarak (`safepatch/l2.py`) |

**Öğrenme.** Her kol ve seed kendi boş veritabanıyla başlar; her biri ayrı bir "kurum" gibidir. Vakalar sırayla çözülür. Doğrulayıcının kabul ettiği her aday `SIMULATED-EXPERIMENT-REVIEWER` tarafından **simüle onayla** o kolun L1'ine alınır (karar 2). Böylece sonraki vakalar ondan yararlanabilir. A kolu da aynı sırayla koşar, ama hafızası kapalıdır.

**L2 paketi** (C+L2; karar 3). Geliştirme tarafındaki 16 referans düzeltmesinden oluşan bir deney paketi:
- `samples/variants/fixed`: 7;
- `samples/package/fixed`: 6;
- üç `-01` laboratuvarı: 3.

Düzeltmeler uzman yaması yoluyla doğrulanır, simüle onayla laboratuvar L1'ine alınır, `scripts/l2_build.py --experiment` ile imzalanır. Değerlendirme vakası pakete girmez; üretici bunu reddeder.

## Koşullar (bütün kollarda aynı)

- Model: `qwen2.5-coder:7b-instruct-q4_K_M` (özeti `worker1.py`'de sabit).
- Strateji `guided+context`; en çok 3 deneme; iş süresi 1800 sn; token bütçesi bugünkü.
- Bulgu cevap anahtarından ("bilinen bulgu", `scanner: known`). Tarayıcının kaçırdığı vakalar da onarım ölçümüne girer; tespit ayrı raporlandı ([OLCUM_TESPIT.md](OLCUM_TESPIT.md)).
- Doğrulama Docker sandbox'ında ([SANDBOX.md](SANDBOX.md)), değerlendirme profili.
- **Vakalar:** hazır 45 değerlendirme vakası: 30 gerçek açık, 15 güvenli kod. Güvenli vakaların her kolda modele gitmeden tanık kapısında durması beklenir. Bu bir denetimdir; durmazsa raporlanır.
- **Seed'ler:** 42, 43, 44.
- **Sıra:** her seed için vakalar seed'den türetilen rastgele bir sırayla çözülür. Bir seed'in sırası dört kolda aynıdır.
- **Kolların koşu sırası:** seed'den seed'e döndürülür (42: A, B, C, C+L2; 43: B, C, C+L2, A; 44: C, C+L2, A, B). Böylece makinenin ısınması ya da önbelleği bir kolu kayırmaz.

## Ölçütler

- **Birincil: doğru onarım.** Doğrulayıcı kabul etti ve gizli testler geçti. Her (vaka, seed, kol) için bir sonuç.
- **Yanlış kabul:** kabul edildi ama gizli testler başarısız.
- **Yanlış aktarım:** hafızadan örnek alan ve yanlış kabulle biten iş. Ayrıca B'de seçilen kaydın yapısal imzası bulguyla uyuşuyor muydu; bu, hafızanın yanlış bağlama taşınmasının ölçüsüdür.
- **İkincil:** kabul edilen deneme numarası, süre, hafıza kullanımı (kayıt, seviye, kullanım biçimi), aile bazında sonuçlar.
- **Altyapı hatası:** iş altyapı hatasıyla biterse bir kez yeniden koşulur ve iki kayıt da saklanır. Başarısız koşular paydadan çıkarılmaz.

## Analiz (Hafta 10)

- **Eşleştirilmiş karşılaştırmalar:** C–A, C–B, C+L2–C. McNemar testi (vaka × seed çiftleri), seed'ler ayrıca da gösterilir. Vakalar üzerinden bootstrap ile %95 güven aralığı.
- Toplam ve **aile bazında** (CWE-89, 22, 78) raporlanır.
- Sonuç olumlu ya da olumsuz raporlanır. Ham sonuçlar `evidence/v02-benchmark/` altına gider.

## Ön analizin söyledikleri (beklenti, sonuç değil)

30 gerçek açık için:

| | Toplam | CWE-22 | CWE-78 | CWE-89 |
|---|---|---|---|---|
| Vaka | 30 | 13 | 7 | 10 |
| L2'de aynı biçimli referans düzeltmesi olan | 5 | 3 | 1 | 1 |
| Aynı projede aynı biçimli kardeşi olan (L1'in ulaşabileceği) | 21 | 9 | 6 | 6 |

- **L2 en çok 5 vakaya ulaşabilir.** Benchmark'taki kalıpların çoğunun geliştirme tarafında aynı biçimde karşılığı yok: `File.<init>` "literal", `Runtime.exec`, Spring JDBC çağrıları. Üç Vul4J vakası ise JDK 8.
- **L1, kardeşi olan 21 vakaya** ancak sırada önce gelen bir kardeş kabul edilip onaylandıysa ulaşır. Önceki L3 koşularında doğru onarım 7–8/30 idi; bu yüzden C'nin yardım edebileceği vaka sayısı küçük olacak.
- **Kardeşlerin neredeyse hepsi OWASP Benchmark'ta.** Benchmark tek bir proje ve servletleri birbirine çok benziyor. Kurum içi hafıza için olağandan elverişli olabilir; raporda ayrıca belirtilecek.
- **İstatistiksel güç düşük.** Kollar arasındaki fark birkaç vaka düzeyinde kalabilir; anlamlı bir fark çıkmaması olası bir sonuçtur.

## Süre

Önceki L3 koşusu 45 vakada 68 dakika sürdü. 4 kol × 3 seed = 12 koşu, yaklaşık 14 saat GPU; birkaç geceye bölünür. Koşu kaldığı yerden devam edebilir.

## Kararlar (27 Ekim 2026, proje lideri)

1. **B kolunun embedding modeli:** `nomic-embed-text:v1.5`. Onayla indirildi:
   - kaynak: Ollama kütüphanesi;
   - boyut: 274 MB;
   - lisans: Apache-2.0;
   - tam özet `0a109f422b47e3a30ba2b10eca18548e944e8a23073ee3f3e947efcf3c45e59f`; özet `worker1.EMBED_MODEL`'de sabit.

   **Kullanım:**
   - Sorgu: bulgunun bulunduğu metot (`search_query:` önekiyle). Metot bulunamazsa bulgunun çevresindeki 50 satır kullanılır.
   - Belge: kaydın farkındaki özgün kod, yani bağlam ve silinen satırlar (`search_document:` önekiyle).
   - Benzerlik ölçüsü kosinüs; en yüksek benzerlik seçilir, eşitlikte en yeni kayıt.
2. **L1'e alma kuralı: (a).** Doğrulayıcının kabul ettiği her aday, gizli testlerin sonucundan bağımsız olarak simüle onayla kolun hafızasına girer. (b) seçilmedi: gizli testleri onay kapısı yapmak C'ye gerçek kurumda olmayan bir bilgi verirdi.
3. **L2 içeriği:** geliştirme tarafındaki 16 referans düzeltmesi. Her biri uzman yaması yoluyla doğrulanır, `SIMULATED-EXPERIMENT-REVIEWER` onaylar, deneye özel anahtarla imzalı deney paketine girer.

## Değerlendirme setinden önce

Betik, geliştirme vakalarında bir mekanik denemeden geçer. Bu deneme bir ölçüm değildir; değerlendirme setinde yalnız asıl koşu yapılır.

## Koşu kaydı: `ana-1`

**Ham kayıtlar** [`evidence/v02-benchmark/experiment/`](../evidence/v02-benchmark/experiment/) altında:
- `protocol.json`: koşunun sabitleri;
- `runs/<seed>-<kol>/<vaka>.json`: her satırın ham kaydı;
- `summary.json`: özet sayılar.

**Koşunun kendisi**
- Başlangıç 27 Ekim 2026 21:51, bitiş 28 Ekim 12:47; yaklaşık 15 saat.
- Satır sayısı 540: 4 kol × 3 seed × 45 vaka.
- Altyapı hatası yüzünden yeniden koşu gerekmedi.
- Kod koşu boyunca değişmedi: commit `166aeb8`, `code_sha256` `39cf00e2…9357`, başta ve sonda aynı.
- 15 güvenli vaka her kolda ve her seed'de modele gitmeden tanık kapısında durdu: 180/180, gerekçe `baseline_missing_expected_failing_security_assertion_or_finding`.
- Kabul edilen her adayda gizli testler koşuldu.

**Ham sayılar.** 30 gerçek açık × 3 seed = kol başına 90 iş. Bu tablo yalnız sayıları verir; anlamlılık sınaması ve güven aralıkları Hafta 10 analizinin işidir.

| Kol | Doğru onarım | Kabul | Yanlış kabul | Hafıza kullanılan iş | CWE-22 | CWE-78 | CWE-89 |
|---|---|---|---|---|---|---|---|
| A | 30/90 | 30 | 0 | 0 | 5/39 | 7/21 | 18/30 |
| B | 35/90 | 36 | 1 | 58 | 4/39 | 12/21 | 19/30 |
| C | 29/90 | 29 | 0 | 17 | 5/39 | 7/21 | 17/30 |
| C+L2 | 29/90 | 29 | 0 | 35 | 3/39 | 9/21 | 17/30 |

- B'deki yanlış kabul: `vul4j-43`, seed 42.
  - Seçilen L1 kaydı yapısal imzası bulguyla uyuşmayan bir örnekti; kosinüs benzerliği 0,627.
  - Gizli testte `BEHAVIOR_REGRESSION` ile kaldı.

**Koşu sırasındaki operasyonel müdahale (ölçümü etkilemez)**
- **Sorun.** Runner her doğrulama denemesinde projeyi `.runtime/runner-work` altına kopyalıyor ve iş bitince kopyayı silmiyordu. Bu V0.1'den kalma bir davranış. OWASP Benchmark'ta her kopya 228 MB; klasör koşu sırasında 163 GB'a ulaştı ve disk koşu bitmeden dolabilirdi.
- **Neden kod düzeltilmedi.** Koşu sürerken ürün kodu değiştirilemez.
- **Yapılan.** Proje liderinin onayıyla, 28 Ekim 02:40'tan itibaren koşunun dışında çalışan bir temizleyici kullanıldı:
  - yalnız bu klasördeki 2 saatten eski kopyaları 30 dakikada bir sildi;
  - bir iş en fazla 1800 sn sürdüğü için kullanımda olan bir kopyaya dokunmadı;
  - ölçüm kayıtlarına, hafızaya, review kopyalarına ve doğrulanmış artifact'lere dokunmadı;
  - 20 turda silme hatası olmadı.
- **Kayıt.** Temizleyicinin günlüğü `.runtime/runner-work-cleaner.log` dosyasında; Git'e girmez.
- **Kalıcı düzeltme.** Runner kendi kopyasını iş sonunda silecek; bu ayrı bir dalda yapılır.
