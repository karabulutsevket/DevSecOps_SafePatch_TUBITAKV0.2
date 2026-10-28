# V0.2 ana deney sonuçları (28 Ekim 2026, Hafta 10)

**Ham kayıtlar:** [`evidence/v02-benchmark/experiment/`](../evidence/v02-benchmark/experiment/):
- `protocol.json`;
- `runs/<seed>-<kol>/<vaka>.json`;
- `summary.json`.

**Analiz kaydı:** [`evidence/v02-benchmark/analiz/analysis.json`](../evidence/v02-benchmark/analiz/analysis.json). Kayıt, okuduğu 540 satırın baytlarına özetle bağlı (`runs_sha256` `d4076da1…`).

**Betik:** `scripts/experiment_analysis.py`. Hiçbir şeyi yeniden koşmaz; bütün sayılar kayıtlı satırlardan gelir.

**Protokol:** [DENEY_PROTOKOLU.md](DENEY_PROTOKOLU.md). Koşudan önce sabitlendi; koşunun kaydı oradaki "Koşu kaydı" bölümünde.

## Özet

- **H1 bu deneyde desteklenmedi.** SafePatch hafızası (C), doğru onarım oranını ne hafızasız modele (A) ne de yalnız benzerliğe dayalı hafızaya (B) göre artırdı.
  - C–A farkı **−1,1 puan**: %95 güven aralığı −8,9 ile +5,6 arası, McNemar p = 1,0.
  - C–B farkı **−6,7 puan**: aralık −14,4 ile 0,0 arası, p = 0,18.
- **Yanlış kabul artmadı.** C'de 0/29, A'da 0/30. Bir hafıza kaydının yanlış bağlama taşındığı tek yanlış kabul B'de oldu: 1/36. Olay sayısı karşılaştırma yapmaya yetmiyor.
- **H3 desteklenmedi.** L2 paketi doğru onarımı değiştirmedi: C+L2–C farkı **0,0 puan**, aralık −4,4 ile +4,4 arası. L2 örneği 15 işe gitti; hiçbiri doğru onarımla bitmedi.
- **Keşifsel bulgu.** Protokolde yoktu; sonuçlar görüldükten sonra arandı. C'nin işleri modele ne gönderildiğine göre ayrılınca birbirini götüren iki etki görünüyor:
  - hafızadan örnek giden işlerde C, aynı vaka ve seed'de A'dan iyi: 6'ya 1;
  - örnek gitmeyip yalnız başarısızlık uyarısı giden işlerde A'dan kötü: 0'a 7.

  Bu bir doğrulama değil, sınanacak bir hipotezdir (aşağıda "Sonraki adım").

## Kurulum (protokolden)

| Alan | Değer |
|---|---|
| Kollar | **A** hafıza kapalı. **B** aynı ailedeki kayıtlardan embedding benzerliği en yüksek olan, yalnız örnek olarak. **C** SafePatch'in uygunluk kuralları. **C+L2** C ve önceden kurulmuş, 16 kayıtlı L2 deney paketi |
| Vakalar | 45 değerlendirme vakası: 30 gerçek açık (27 OWASP Benchmark, 3 Vul4J) ve 15 güvenli kod |
| Seed'ler | 42, 43, 44. Vaka sırası seed'den türetilir ve dört kolda aynıdır; kolların koşu sırası seed'den seed'e döner |
| İş | `qwen2.5-coder:7b-instruct-q4_K_M`, `guided+context`, en çok 3 deneme, 1800 sn. Bulgu cevap anahtarından |
| Hafızaya alma | Doğrulayıcının kabul ettiği her aday, kolun kendi L1'ine **simüle onayla** girer (karar 2a) |
| Birincil ölçüt | **Doğru onarım:** doğrulayıcı kabul etti ve gizli testler geçti |
| Doğrulama | Docker sandbox'ı, değerlendirme profili. Kabul edilen her adaya, doğrulayıcının görmediği gizli testler uygulanır |
| Koşu | 27 Ekim 21:51 – 28 Ekim 12:47. 540 satır. Altyapı hatası yüzünden yeniden koşu gerekmedi; gizli test hatası olmadı |

## Kollar

Her kolda 30 gerçek açık × 3 seed = 90 iş. Güven aralıkları %95, bootstrap ile: 10.000 yeniden örnekleme. Yeniden örneklenen birim vaka; her vaka üç seed'iyle birlikte çekilir.

| Kol | Doğru onarım | Oran [%95 GA] | Kabul | Yanlış kabul | Hafıza kullanılan iş | CWE-22 | CWE-78 | CWE-89 |
|---|---|---|---|---|---|---|---|---|
| A | 30 | %33,3 [18,9; 48,9] | 30 | 0 | 0 | 5/39 | 7/21 | 18/30 |
| B | 35 | %38,9 [23,3; 54,4] | 36 | 1 | 58 | 4/39 | 12/21 | 19/30 |
| C | 29 | %32,2 [18,9; 46,7] | 29 | 0 | 17 | 5/39 | 7/21 | 17/30 |
| C+L2 | 29 | %32,2 [17,8; 47,8] | 29 | 0 | 35 (20 L1, 15 L2) | 3/39 | 9/21 | 17/30 |

- **Güvenli kod.** 15 vaka her kolda ve seed'de modele gitmeden tanık kapısında durdu (180/180).
- **Hafıza kullanımı.**
  - Hiçbir kolda birebir tekrar olmadı; hafıza her seferinde yalnız örnek olarak kullanıldı.
  - Benchmark servletlerinin kaynakları birbirinden farklı. Bu yüzden C'nin birebir tekrar kuralı hiç devreye girmedi.
  - B'nin seçtiği örneklerin 38/58'inin yapısal imzası bulguyla uyuşmuyordu. C bu kayıtları uygunluk kurallarıyla eliyor.
- **Yanlış kabul** (`runs/42-B/vul4j-43.json`): B, seed 42'de vul4j-43 için imzası farklı bir L1 kaydını örnek seçti (kosinüs 0,627). Aday doğrulayıcıdan geçti, gizli testte `BEHAVIOR_REGRESSION` ile kaldı. Bu, protokoldeki tanımıyla bir **yanlış aktarım**. C ve C+L2'de yanlış aktarım olmadı.
- **Politikanın reddettiği işler:** A 5, B 3, C 4, C+L2 2. Kalan kabul edilmeyen işlerin hepsinde deneme hakkı bitti; A'da bir iş ayrıca dosya sonu satırı nedeniyle reddedildi.

## Önceden tanımlı karşılaştırmalar

İş çiftleri aynı vaka ve aynı seed'den oluşur; her karşılaştırmada 90 çift var. Test, kesin McNemar testi: uyuşmayan çiftler üzerinde iki yönlü binom testi. Holm düzeltmesi bu üç karşılaştırmaya uygulandı.

| Karşılaştırma | İkisi de doğru | Yalnız ilki | Yalnız ikincisi | Fark (puan) [%95 GA] | McNemar p | Holm p |
|---|---|---|---|---|---|---|
| **C – A** | 22 | 7 | 8 | −1,1 [−8,9; +5,6] | 1,00 | 1,00 |
| **C – B** | 25 | 4 | 10 | −6,7 [−14,4; 0,0] | 0,18 | 0,54 |
| **C+L2 – C** | 27 | 2 | 2 | 0,0 [−4,4; +4,4] | 1,00 | 1,00 |

**Aile bazında** (uyuşmayan çiftler, fark ve %95 GA):

| Karşılaştırma | CWE-22 (39 çift) | CWE-78 (21 çift) | CWE-89 (30 çift) |
|---|---|---|---|
| C – A | 2/2; 0,0 [−10,3; +10,3] | 4/4; 0,0 [−14,3; +14,3] | 1/2; −3,3 [−20,0; +10,0] |
| C – B | 4/3; +2,6 [−5,1; +10,3] | **0/5; −23,8 [−42,9; −9,5]**, p = 0,06 | 0/2; −6,7 [−16,7; 0,0] |
| C+L2 – C | 0/2; −5,1 [−12,8; 0,0] | 2/0; +9,5 [0,0; +19,0] | 0/0; 0,0 |

**Seed bazında** doğru onarım sayıları (30 iş üzerinden; seed başına p'ler `analysis.json`'da, hiçbiri 0,2'nin altında değil):

| Karşılaştırma | 42 | 43 | 44 |
|---|---|---|---|
| C – A | 12 – 10 | 9 – 10 | 8 – 10 |
| C – B | 12 – 11 | 9 – 12 | 8 – 12 |
| C+L2 – C | 11 – 12 | 9 – 9 | 9 – 8 |

**Okuma**
- Önceden tanımlı üç karşılaştırmanın hiçbirinde anlamlı fark yok.
- **CWE-78'de B, C'den iyi görünüyor:** 5 uyuşmayan çiftin beşi de B lehine. Ama dikkat edilmesi gerekenler:
  - beş çiftte ulaşılabilecek en küçük p 0,06;
  - bu sonuç, aile bazındaki dokuz karşılaştırmadan yalnız biri;
  - komut ailesinde yalnız 7 vaka var ve bu kadar az vakayla bootstrap aralığı olduğundan dar çıkar.

  Bu yüzden bir bulgu değil, bir işaret olarak okunmalı.
- **Güven aralıkları, küçük bir etkiyi dışlamaya yetmiyor.** Veri, C'nin A'ya göre birkaç puanlık bir yararıyla da zararıyla da uyumlu.

## Ek karşılaştırmalar (keşifsel)

Bunlar protokolde yoktu; Holm düzeltmesine katılmadı.

| Karşılaştırma | Uyuşmayan çiftler | Fark (puan) [%95 GA] | McNemar p | Not |
|---|---|---|---|---|
| B – A | 9/4 | +5,6 [−2,2; +13,3] | 0,27 | CWE-78'de 5/0 (+23,8) |
| C+L2 – A | 5/6 | −1,1 [−7,8; +5,6] | 1,00 | |

## Hafızanın modele gönderdikleri: C'nin işleri dörde ayrılınca (keşifsel)

**Ne yapıldı.** C ve C+L2'de her iş iki şeye göre ayrıldı:
- hafızadan bir **örnek** gitti mi;
- yalnız **başarısızlık uyarısı** gitti mi. Uyarı, Hafta 5'ten beri var: aynı projede aynı yapısal biçimdeki başka bir vakada başarısız olmuş adayların değişen satırları, "burada işe yaramadı" notuyla gösteriliyor; en çok iki tane.

Her iş, A'nın aynı vaka ve seed'deki işiyle eşleştirildi.

| Kol | İşe giden | İş | Kol doğru | A doğru | Yalnız kol / yalnız A | McNemar p |
|---|---|---|---|---|---|---|
| C | örnek ve uyarı | 9 | 6 | 2 | 5 / 1 | 0,22 |
| C | yalnız örnek | 8 | 7 | 6 | 1 / 0 | 1,00 |
| C | **yalnız uyarı** | 25 | 3 | 10 | **0 / 7** | 0,016 |
| C | hiçbiri (prompt A ile aynı) | 48 | 13 | 12 | 1 / 0 | 1,00 |
| C+L2 | örnek ve uyarı | 18 | 6 | 4 | 4 / 2 | 0,69 |
| C+L2 | yalnız örnek | 17 | 7 | 6 | 1 / 0 | 1,00 |
| C+L2 | **yalnız uyarı** | 16 | 4 | 8 | **0 / 4** | 0,13 |
| C+L2 | hiçbiri | 39 | 12 | 12 | 0 / 0 | 1,00 |
| B | örnek (B uyarı göndermez) | 58 | 26 | 20 | 8 / 2 | 0,11 |
| B | hiçbiri | 32 | 9 | 10 | 1 / 2 | 1,00 |

**Örneğin kaynağına göre** (aynı eşleştirmeyle):
- C'nin L1 örnekleri: 17 işte 6'ya 1.
- C+L2'nin L1 örnekleri: 20 işte 5'e 1.
- C+L2'nin L2 örnekleri: 15 işte 0'a 1. Bu 15 işin:
  - 14'ünü A da çözemedi;
  - 9'u CWE-22 vakası;
  - 9'u, hiçbir kolun hiçbir seed'de çözemediği vakalarda.

**Okuma**
- **"Hiçbiri" satırı bir sağlama.** Prompt A ile aynıyken sonuç da neredeyse aynı: 48 çiftte 1 uyuşmazlık. Model gürültüsü bu kurulumda küçük. Diğer satırlardaki farklar yalnız rastgelelikle açıklanamaz.
- **Örnek gittiğinde C ve C+L2, A'dan iyi:** toplam 11'e 3. B'de de aynı yön var: 8'e 2.
- **Yalnız uyarı gittiğinde C ve C+L2, A'dan kötü:** toplam 0'a 11.
- **Toplam sonuç bu ikisinin toplamı.** C'nin genel sonucu (7'ye 8), örneklerin kazancı ile uyarıların kaybının birbirini götürmesiyle açıklanabilir.
- **Uyarı giden işlerde denemeler farklı biçimde başarısız oluyor.** C'nin yalnız uyarı giden 25 işinde denemeler A'nın aynı işlerine göre şöyle dağılıyor:

  | Deneme sonucu | C | A |
  |---|---|---|
  | Boş yama | 1 | 13 |
  | Aynı yamayı tekrar (`duplicate_patch`) | 17 | 9 |
  | Derleme hatası | 24 | 18 |
  | Geçen | 3 | 10 |

  Gönderilen 47 uyarının hepsi `same_shape` ilişkisindeydi:
  - derleme hatası 21;
  - tanık başarısızlığı 14;
  - davranış bozulması 12.

  Kaynak: kolların yerel veritabanları. Kayda yalnız sayılar ve veritabanı özetleri girdi.
- **Olası açıklama** (doğrulanmadı): başka bir vakada başarısız olmuş kodu görmek, 7B modeli doğru yaklaşımdan uzaklaştırıyor ya da gösterilen kodu taklit ettiriyor olabilir.
  - Benzer bir eğilim daha önce görülmüştü: boş cevapların 13/13'ü, modelin kendisine gösterilen kodu tekrarlamasıydı ([KOK_NEDEN_UC_SORUN.md](KOK_NEDEN_UC_SORUN.md)).
  - Başarısızlık nedeni derleme hatası olan bir aday doğru yaklaşımı içerebilir; ama uyarı, bu yaklaşımı da "işe yaramadı" diye gösteriyor.

**Bu bölüm neden yalnız bir hipotez**
- Ayrım sonuçlar görüldükten sonra yapıldı.
- Çoklu bakış düzeltmesi yapılmadı.
- Gruplar rastgele atanmadı: uyarının gidip gitmemesi, sırada daha önce aynı biçimde bir başarısızlık olup olmamasına bağlı.

A ile aynı vaka ve seed üzerinden eşleştirme vaka zorluğunu dengeliyor. Ama nedensellik ancak uyarının tek fark olduğu bir denemeyle gösterilebilir.

## Etki alanının sınırı

- 30 gerçek açığın 13'ünü hiçbir kol, hiçbir seed'de çözemedi.
- 5'ini her kol her seed'de çözdü: Benchmark 00678, 01087, 01964, 02091, 02181.
- Hafızanın sonucu değiştirebileceği **yalnız 12 vaka** var. Ön analiz bunu bekliyordu: L1'in ulaşabileceği 21 vakanın çoğu ancak kardeşi önceden çözülürse yararlanabiliyordu.
- Tavanı belirleyen 7B modelin kendisi.

## İkincil ölçütler

| | A | B | C | C+L2 |
|---|---|---|---|---|
| Kabul edilen adayların ilk denemede gelenleri | 17/30 | 28/36 | 24/29 | 24/29 |
| İş süresi, medyan (açık vakalar) | 133 sn | 127 sn | 129 sn | 122 sn |

- **Hafızalı kollarda kabul daha çok ilk denemede geliyor.** Bu fark sınanmadı; yalnız betimleyici.
- **İş süresinin medyanı** başarısız işlerin üç denemesine bağlı; kollar arasında belirgin bir fark yok.

## Sınırlar

- **Güç düşük.** 30 vaka, 3 seed. Güven aralıklarının genişliği 15 puan civarında. Birkaç puanlık bir etki ne gösterilebilir ne de dışlanabilir.
- **Benchmark tek bir proje.** 30 vakanın 27'si Benchmark'tan ve servletleri birbirine çok benziyor. Protokol bunun kurum içi hafızayı kayırabileceğini önceden yazmıştı; buna rağmen C kazanmadı.
- **Onaylar simüle.** Hafızaya alma `SIMULATED-EXPERIMENT-REVIEWER` ile yapıldı; gerçek insan onayı ve müşteri doğrulaması yok.
- **Bulgu cevap anahtarından geldi.** Tespit bu ölçüme girmedi; ayrı raporlandı ([OLCUM_TESPIT.md](OLCUM_TESPIT.md)).
- **Koşu sırasında operasyonel bir müdahale oldu.** Runner'ın Windows tarafındaki geçici kopyaları dışarıdan temizlendi. Kod ve ölçüm çıktıları etkilenmedi ([DENEY_PROTOKOLU.md](DENEY_PROTOKOLU.md), "Koşu kaydı").

## Sonraki adım (öneri; proje liderinin kararı)

Değerlendirme seti ayar için kullanılmaz. Uyarıları kapatıp aynı sette yeniden koşmak ve oradan "düzeldi" sonucu çıkarmak kural dışı. Önerilen yol:

1. **Geliştirme setinde uyarı denemesi.** Proje lideri 28 Ekim'de onayladı; protokol: [DENEY_UYARI.md](DENEY_UYARI.md).
   - Kollar: C ve "C, uyarısız".
   - Fark yalnız başarısızlık uyarısının gönderilmesi; uyarısız kol yalnız deney profilinde açılan bir seçenekle kurulur.
   - Öbür koşullar ana deneyle aynı: 26 geliştirme vakası (L3 geliştirme 20 ve paket 6), seed 42–44.
   - Önce geliştirme setinde kaç işe uyarı gideceği statik olarak sayılır. Çok azsa bu deneme de güçsüz kalır ve bu önceden yazılır.
   - Tahmini süre: 3–5 saat GPU.
   - **Sonuç (29 Ekim, `uyari-1`):** uyarısız kol, C'ye yalnız uyarı giden 24 çiftte 12'ye 2 öndeydi (p = 0,013); bütün çiftlerde +10,3 puan (p = 0,077). Fark büyük ölçüde komut ailesinde. Ayrıntı ve sınırlar: [DENEY_UYARI.md](DENEY_UYARI.md), "Sonuç: `uyari-1`".
2. **Uyarı politikası sonuca göre seçilir.** Seçenekler: uyarıyı kaldırmak, yalnız aynı kaynağa ait başarısızlıklarla sınırlamak, metnini değiştirmek. Bu seçim ancak geliştirme setindeki sonuçla yapılır.
   - **Karar (29 Ekim, proje lideri):** uyarı modele gönderilmez; yalnız kaydedilir.
3. **Gerekirse değerlendirmede yeni bir koşu.** Koşunun adı `ana-2` olur ve önceden sabitlenmiş bir protokolle yapılır. İki koşu birlikte raporlanır; `ana-1` geçerliliğini korur.
   - Protokol taslağı: [DENEY_ANA2.md](DENEY_ANA2.md). Proje liderinin onayını bekliyor.

**Ayrıca açık soru.** B'nin komut ailesindeki işareti, C'nin örnek uygunluk kuralının komut ailesi için fazla katı olabileceğini düşündürüyor. Ama B'nin tek yanlış kabulü de imzası uyuşmayan bir örnekten geldi. Bu dengeyi de ancak geliştirme setinde ölçmek doğru olur.
