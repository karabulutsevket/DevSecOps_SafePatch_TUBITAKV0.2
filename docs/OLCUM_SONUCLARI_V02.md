# V0.2 ana deney sonuçları (Hafta 10): `ana-1` ve `ana-2`

İki koşu var ve birlikte raporlanır:
- **`ana-1`** (28 Ekim): protokolün ilk koşusu. Başarısızlık uyarıları modele gidiyordu.
- **`ana-2`** (29 Ekim): aynı koşullar. Tek fark, uyarıların artık modele gönderilmemesi. Bu karar geliştirme setinde verildi ([DENEY_UYARI.md](DENEY_UYARI.md)); protokol [DENEY_ANA2.md](DENEY_ANA2.md).

`ana-1` geçerliliğini korur. Önce `ana-2` gelir, ardından `ana-1`. En sondaki "Sonraki adım" bölümü iki koşu için ortaktır.

**Durum: V0.2'nin hafıza ölçümü bu iki koşuyla kapandı** (30 Ekim, proje lideri).
- Sunumda ve başvuruda bu rapordaki rakamlar kullanılır.
- Daha büyük bir değerlendirme seti proje sonrasına bırakıldı ([BACKLOG.md](BACKLOG.md)).

## İkinci koşu: `ana-2` (29 Ekim 2026)

**Kayıtlar**
- **Ham kayıtlar:** [`evidence/v02-benchmark-2/experiment/`](../evidence/v02-benchmark-2/experiment/). `protocol.json` commit'i (`90b120e`) ve `safepatch/` özetini (`833658cb…`) kaydeder; çalışma ağacı temizdi.
- **Analiz:** [`evidence/v02-benchmark-2/analiz/analysis.json`](../evidence/v02-benchmark-2/analiz/analysis.json).
  - Okuduğu 540 satıra `runs_sha256` `f7810cf0…` ile bağlı.
  - Koşular arası bölüm, `ana-1`'in satırlarına `d4076da1…` ile bağlı.
- **Keşifsel ek:** [`exploratory.json`](../evidence/v02-benchmark-2/analiz/exploratory.json) (`experiment_analysis.py --explore`).
- **Koşu:** 29 Ekim 03:03 – 17:34. 540 satır; altyapı yüzünden tekrar ve gizli test hatası yok ([DENEY_ANA2.md](DENEY_ANA2.md), "Koşu kaydı").

### Özet

- **H1 yine desteklenmedi, ama C bu kez A'nın önünde.**
  - **C–A:** +5,6 puan [%95 GA +1,1; +10,0]. Uyuşmayan 5 çiftin beşi de C lehine. Önceden tanımlı test yine anlamlı değil: McNemar p = 0,063, Holm p = 0,19. Beş uyuşmazlıkla McNemar'ın verebileceği en küçük p zaten 0,0625.
  - **C–B:** −2,2 puan [−7,8; +2,2], p = 0,69. B'nin `ana-1`'deki komut ailesi üstünlüğü (0'a 5) bu koşuda yok (0'a 0).
- **H3 yine desteklenmedi.** C+L2–C −1,1 puan [−4,4; +2,2]. L2 örneği yine 15 işe gitti; hiçbiri doğru onarımla bitmedi.
- **Yanlış kabul yalnız B'de, 1/37.** `ana-1`'deki işin aynısı: seed 42, vul4j-43, imzası farklı bir örnek. C ve C+L2'de 0.
- **Koşular arası karşılaştırma (ikincil, düzeltmesiz).**
  - Doğru onarımlar: C 29'dan 34'e, C+L2 29'dan 33'e çıktı. Değişmeyen kollarda A 30'dan 29'a, B 35'ten 36'ya.
  - Yeniden koşmak tek başına A'da ve B'de 90 çiftten yalnız 3'ünün sonucunu değiştirdi. C'de 9 çift değişti, 7'si `ana-2` lehine (p = 0,18).
  - Okuma kuralına göre fark uyarı kararıyla tutarlı, ama istatistiksel olarak gösterilmiş değil.
- **Keşifsel bulgu.**
  - `ana-1`'de modele yalnız uyarı giden işler, A'ya göre 0'a 11 kötüydü.
  - `ana-2`'de uyarı bulunup modele gönderilmeyen işlerde bu fark yok: 1'e 0.

### Kollar (`ana-2`; `ana-1` karşılığıyla)

| Kol | Doğru onarım `ana-1` → `ana-2` | Oran [%95 GA] | Yanlış kabul | Hafıza kullanılan iş | Uyarısı tutulan iş | CWE-22 | CWE-78 | CWE-89 |
|---|---|---|---|---|---|---|---|---|
| A | 30 → 29 | %32,2 [17,8; 47,8] | 0 | 0 | 0 | 4/39 | 8/21 | 17/30 |
| B | 35 → 36 | %40,0 [24,4; 56,7] | 1 | 58 | 0 | 5/39 | 11/21 | 20/30 |
| C | 29 → 34 | %37,8 [21,1; 54,4] | 0 | 22 | 31 | 5/39 | 11/21 | 18/30 |
| C+L2 | 29 → 33 | %36,7 [21,1; 53,3] | 0 | 37 (22 L1, 15 L2) | 34 | 4/39 | 11/21 | 18/30 |

- **Güvenli kod.** 180/180 iş, modele gitmeden tanık kapısında durdu.
- **Hafıza.** Birebir tekrar yine hiç olmadı. B'nin örneklerinin 38/58'i yine imzası uyuşmayan kayıtlardan geldi.
- **Uyarılar.** C ve C+L2'de modele hiç uyarı gitmedi; bulunan uyarılar yalnız kayda girdi (`warnings_withheld`).
- **Reddedilen işler.**
  - Politika reddi: A 4, B 1, C 0, C+L2 2.
  - Dosya sonu satırı nedeniyle red: A'da ve C'de birer iş.
  - Kalanların hepsinde deneme hakkı bitti.
- **Kabulün ilk denemede geldiği işler:** A 17/29, B 29/37, C 25/34, C+L2 24/33.
- **İş süresi, medyan:** A 133 sn, B 128 sn, C 126 sn, C+L2 122 sn.

### Önceden tanımlı karşılaştırmalar (`ana-2`)

Her karşılaştırmada 90 çift var; çift, aynı vaka ve aynı seed'den oluşur. Test kesin McNemar, düzeltme bu üç karşılaştırma üzerinde Holm.

| Karşılaştırma | İkisi de doğru | Yalnız ilki | Yalnız ikincisi | Fark (puan) [%95 GA] | McNemar p | Holm p | `ana-1`'de fark |
|---|---|---|---|---|---|---|---|
| **C – A** | 29 | 5 | 0 | +5,6 [+1,1; +10,0] | 0,063 | 0,19 | −1,1 |
| **C – B** | 32 | 2 | 4 | −2,2 [−7,8; +2,2] | 0,69 | 1,00 | −6,7 |
| **C+L2 – C** | 32 | 1 | 2 | −1,1 [−4,4; +2,2] | 1,00 | 1,00 | 0,0 |

**Aile bazında** (yalnız ilki / yalnız ikincisi; fark ve %95 GA):

| Karşılaştırma | CWE-22 (39 çift) | CWE-78 (21 çift) | CWE-89 (30 çift) |
|---|---|---|---|
| C – A | 1/0; +2,6 [0,0; +7,7] | 3/0; +14,3 [+4,8; +28,6], p = 0,25 | 1/0; +3,3 [0,0; +10,0] |
| C – B | 2/2; 0,0 [−7,7; +7,7] | 0/0; 0,0 (`ana-1`'de 0/5) | 0/2; −6,7 [−20,0; 0,0] |
| C+L2 – C | 0/1; −2,6 [−7,7; 0,0] | 0/0; 0,0 | 1/1; 0,0 [−10,0; +10,0] |

**Seed bazında** doğru onarım sayıları (30 iş üzerinden):

| Karşılaştırma | 42 | 43 | 44 |
|---|---|---|---|
| C – A | 12 – 8 | 11 – 11 | 11 – 10 |
| C – B | 12 – 12 | 11 – 13 | 11 – 11 |
| C+L2 – C | 11 – 12 | 11 – 11 | 11 – 11 |

**Ek karşılaştırmalar** (keşifsel, Holm'a girmedi):

| Karşılaştırma | Uyuşmayan çiftler | Fark (puan) [%95 GA] | McNemar p | `ana-1`'de |
|---|---|---|---|---|
| B – A | 8/1 | +7,8 [+2,2; +14,4] | 0,039 | 9/4, p = 0,27 |
| C+L2 – A | 4/0 | +4,4 [+1,1; +8,9] | 0,13 | 5/6, p = 1,00 |

**Okuma**
- **Önceden tanımlı üç karşılaştırmanın hiçbiri anlamlı değil.** Protokol de bunu bekliyordu ([DENEY_ANA2.md](DENEY_ANA2.md), "Beklenti").
- **C–A'nın yönü değişti.** `ana-1`'de 7'ye 8 olan uyuşmazlıklar `ana-2`'de 5'e 0. Ama bu kadar az uyuşmayan çiftle test 0,05'in altına inemez.
- **Komut ailesindeki işaret kayboldu.** `ana-1`'de B, C'nin önündeydi (0'a 5). `ana-2`'de C bu ailede B ile eşit, A'nın ise önünde (3'e 0). Uyarı denemesinde de uyarıların zararı büyük ölçüde komut ailesindeydi ([DENEY_UYARI.md](DENEY_UYARI.md)). Bu, `ana-1`'deki işaretin uyarılardan geldiği açıklamasıyla tutarlı; ama ayrıca sınanmadı.
- **Örnek alan iki kol da A'nın önünde.** B ile C, örnek alan işlerde A'yı geçti (aşağıda, keşifsel bölüm). B–A anlamlılığa en yakın karşılaştırma; ama önceden tanımlı değildi.

### Koşular arası karşılaştırma (ikincil; düzeltmesiz)

Her kol, `ana-1`'deki aynı kolla, aynı vaka ve seed üzerinden eşleştirildi. "Aynı yama dizisi": iki koşuda bütün denemelerin yama özetleri aynı olan çiftler.

| Kol | Doğru `ana-1` → `ana-2` | Yalnız `ana-2` / yalnız `ana-1` | Fark (puan) [%95 GA] | McNemar p | Aynı yama dizisi |
|---|---|---|---|---|---|
| A | 30 → 29 | 1 / 2 | −1,1 [−4,4; +2,2] | 1,00 | 43/90 |
| B | 35 → 36 | 2 / 1 | +1,1 [−2,2; +4,4] | 1,00 | 42/90 |
| **C** | 29 → 34 | **7 / 2** | +5,6 [−1,1; +13,3] | 0,18 | 27/90 |
| **C+L2** | 29 → 33 | **4 / 0** | +4,4 [+1,1; +8,9] | 0,13 | 33/90 |

**Okuma** (protokolün okuma kuralıyla)
- **Tekrarlanabilirlik.** Kodu ve istemi değişmeyen A ve B'de, yeniden koşmak 90 çiftin yalnız 3'ünde sonucu değiştirdi.
  - Yamaların kendisi ise çiftlerin yarısından fazlasında farklı: A'da 47/90, B'de 48/90. Yani model aynı istemde her seferinde aynı yamayı üretmiyor; ama sonuç büyük ölçüde aynı kalıyor.
  - Bu farkın nedeni bu koşuda ayrıştırılmadı: model, donanım ya da zamanlama olabilir.
- **A'daki rerun etkisi küçük olduğu için koşular arası karşılaştırma okunabilir.** C'de 9 çift değişti, C+L2'de 4; ikisinde de çoğunluk `ana-2` lehine.
- **Bu fark uyarı kararıyla tutarlı, ama gösterilmiş değil.**
  - İkisinde de McNemar p 0,1'in üstünde ve düzeltme yapılmadı.
  - C+L2'nin bootstrap aralığı sıfırı dışarıda bırakıyor; ama 4 uyuşmazlıkla bu aralık olduğundan dar çıkar.
- **Fark tek bir nedene bağlanamaz.** C'de fark yalnız uyarının gitmemesinden gelmez: kabul edilen her aday kolun hafızasına girdiği için sonraki işlerin örnekleri de değişti (zincirleme etki). C'de yama dizilerinin daha azının (27/90) aynı kalması da bunu gösteriyor.

### Hafızanın modele gönderdikleri: aynı ayrım iki koşuda (keşifsel)

`ana-1`'in ayrımı tekrarlandı. Tek fark: `ana-2`'de "uyarı", hafızanın bulup modele göndermediği uyarı demek. Böylece `ana-1`'de uyarı giden işlerin karşılığı görülebiliyor. Bu ayrım sonuçlar görüldükten sonra seçildi; kaynağı [`exploratory.json`](../evidence/v02-benchmark-2/analiz/exploratory.json).

Her hücre üç sayı verir: iş sayısı; yalnız kolun doğru olduğu çiftler / yalnız A'nın doğru olduğu çiftler.

| Kol | Hafızanın bulduğu | `ana-1` (uyarı gönderildi) | `ana-2` (uyarı tutuldu) |
|---|---|---|---|
| C | örnek ve uyarı | 9 iş; 5 / 1 | 12 iş; 2 / 0 |
| C | yalnız örnek | 8 iş; 1 / 0 | 10 iş; 1 / 0 |
| C | **yalnız uyarı** | 25 iş; **0 / 7** (p = 0,016) | 19 iş; 1 / 0 |
| C | hiçbiri | 48 iş; 1 / 0 | 49 iş; 1 / 0 |
| C+L2 | örnek ve uyarı | 18 iş; 4 / 2 | 20 iş; 3 / 0 |
| C+L2 | yalnız örnek | 17 iş; 1 / 0 | 17 iş; 1 / 0 |
| C+L2 | **yalnız uyarı** | 16 iş; **0 / 4** | 14 iş; 0 / 0 |
| C+L2 | hiçbiri | 39 iş; 0 / 0 | 39 iş; 0 / 0 |

- **Yalnız uyarı satırları.** `ana-1`'de C ve C+L2 bu işlerde A'ya 0'a 11 kaybediyordu. Uyarı modele gitmeyince bu fark 1'e 0 oldu.
- **Örnek alan işler.** C ve C+L2, A'nın önünde: `ana-2`'de toplam 7'ye 0. B'de de aynı yön var: örnek alan 58 işte 7'ye 0, p = 0,016 (`ana-1`'de 8'e 2). B'nin rakamları `analysis.json`'da, `memory_split_exploratory` altında.
- **Gruplar aynı işler değil.** Hangi işin bu gruplara düştüğü, sıradaki önceki sonuçlara bağlı ve iki koşuda farklı. Bu tablo bir doğrulama değil.

### Etki alanı ve sınırlar (`ana-2`)

- **Tavan.** 30 açığın 16'sını `ana-2`'de hiçbir kol hiçbir seed'de çözemedi. 7'sini her kol her seed'de çözdü. Hafızanın değiştirebileceği 7 vaka kaldı. `ana-1`'de bu sayılar 13, 5 ve 12 idi; fark da yeniden koşmanın oynaklığından geliyor.
- **Güç yine düşük.** Önceden tanımlı karşılaştırmalardaki birkaç puanlık farklar ne gösterilebiliyor ne de dışlanabiliyor.
- **Ayar yapılmadı.** Uyarı kararı geliştirme setinde verildi. `ana-2` bu kararın değerlendirme setindeki ilk ve tek ölçümü; değerlendirme sonucuna göre yeni bir ayar yapılmayacak.
- **Onaylar simüle**, bulgular cevap anahtarından; `ana-1` ile aynı.

## İlk koşu: `ana-1` (28 Ekim 2026)

**Ham kayıtlar:** [`evidence/v02-benchmark/experiment/`](../evidence/v02-benchmark/experiment/):
- `protocol.json`;
- `runs/<seed>-<kol>/<vaka>.json`;
- `summary.json`.

**Analiz kaydı:** [`evidence/v02-benchmark/analiz/analysis.json`](../evidence/v02-benchmark/analiz/analysis.json). Kayıt, okuduğu 540 satırın baytlarına özetle bağlı (`runs_sha256` `d4076da1…`).

**Betik:** `scripts/experiment_analysis.py`. Hiçbir şeyi yeniden koşmaz; bütün sayılar kayıtlı satırlardan gelir.

**Protokol:** [DENEY_PROTOKOLU.md](DENEY_PROTOKOLU.md). Koşudan önce sabitlendi; koşunun kaydı oradaki "Koşu kaydı" bölümünde.

### Özet

- **H1 bu deneyde desteklenmedi.** SafePatch hafızası (C), doğru onarım oranını ne hafızasız modele (A) ne de yalnız benzerliğe dayalı hafızaya (B) göre artırdı.
  - C–A farkı **−1,1 puan**: %95 güven aralığı −8,9 ile +5,6 arası, McNemar p = 1,0.
  - C–B farkı **−6,7 puan**: aralık −14,4 ile 0,0 arası, p = 0,18.
- **Yanlış kabul artmadı.** C'de 0/29, A'da 0/30. Bir hafıza kaydının yanlış bağlama taşındığı tek yanlış kabul B'de oldu: 1/36. Olay sayısı karşılaştırma yapmaya yetmiyor.
- **H3 desteklenmedi.** L2 paketi doğru onarımı değiştirmedi: C+L2–C farkı **0,0 puan**, aralık −4,4 ile +4,4 arası. L2 örneği 15 işe gitti; hiçbiri doğru onarımla bitmedi.
- **Keşifsel bulgu.** Protokolde yoktu; sonuçlar görüldükten sonra arandı. C'nin işleri modele ne gönderildiğine göre ayrılınca birbirini götüren iki etki görünüyor:
  - hafızadan örnek giden işlerde C, aynı vaka ve seed'de A'dan iyi: 6'ya 1;
  - örnek gitmeyip yalnız başarısızlık uyarısı giden işlerde A'dan kötü: 0'a 7.

  Bu bir doğrulama değil, sınanacak bir hipotezdir (aşağıda "Sonraki adım").

### Kurulum (protokolden)

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

### Kollar

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

### Önceden tanımlı karşılaştırmalar

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

### Ek karşılaştırmalar (keşifsel)

Bunlar protokolde yoktu; Holm düzeltmesine katılmadı.

| Karşılaştırma | Uyuşmayan çiftler | Fark (puan) [%95 GA] | McNemar p | Not |
|---|---|---|---|---|
| B – A | 9/4 | +5,6 [−2,2; +13,3] | 0,27 | CWE-78'de 5/0 (+23,8) |
| C+L2 – A | 5/6 | −1,1 [−7,8; +5,6] | 1,00 | |

### Hafızanın modele gönderdikleri: C'nin işleri dörde ayrılınca (keşifsel)

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

### Etki alanının sınırı

- 30 gerçek açığın 13'ünü hiçbir kol, hiçbir seed'de çözemedi.
- 5'ini her kol her seed'de çözdü: Benchmark 00678, 01087, 01964, 02091, 02181.
- Hafızanın sonucu değiştirebileceği **yalnız 12 vaka** var. Ön analiz bunu bekliyordu: L1'in ulaşabileceği 21 vakanın çoğu ancak kardeşi önceden çözülürse yararlanabiliyordu.
- Tavanı belirleyen 7B modelin kendisi.

### İkincil ölçütler

| | A | B | C | C+L2 |
|---|---|---|---|---|
| Kabul edilen adayların ilk denemede gelenleri | 17/30 | 28/36 | 24/29 | 24/29 |
| İş süresi, medyan (açık vakalar) | 133 sn | 127 sn | 129 sn | 122 sn |

- **Hafızalı kollarda kabul daha çok ilk denemede geliyor.** Bu fark sınanmadı; yalnız betimleyici.
- **İş süresinin medyanı** başarısız işlerin üç denemesine bağlı; kollar arasında belirgin bir fark yok.

### Sınırlar

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
   - Protokol: [DENEY_ANA2.md](DENEY_ANA2.md). Proje lideri 29 Ekim'de dört kolla onayladı.
   - **Sonuç (29 Ekim, `ana-2`):** önceden tanımlı karşılaştırmaların hiçbiri anlamlı değil. C–A +5,6 puan (5'e 0, p = 0,063, Holm p = 0,19). Koşular arası karşılaştırmada C 29'dan 34'e çıktı, A ve B ise neredeyse yerinde kaldı. Ayrıntı yukarıda, "İkinci koşu: `ana-2`".
4. **Ölçüm kapandı.** Proje liderinin kararı (30 Ekim): "Olur, ölçümü kapat ve BACKLOG'a yaz".
   - **Sonuç:** V0.2'nin hafıza ölçümü `ana-1` ve `ana-2` ile kapandı. H1 ve H3 desteklenmedi; `ana-2`'de C, A'nın yalnız yön olarak önünde.
   - **Değerlendirme seti kapalı kalır.** 30 açık vakaya bakarak ayar yapılmaz ve bu vakalar V0.2'de yeniden koşulmaz.
   - **Daha büyük set proje sonrasında** ([BACKLOG.md](BACKLOG.md)). Yeni vakalar ve önceden sabitlenmiş yeni bir protokol gerekir; aynı 30 vakayı yeniden koşmak gücü artırmaz.

**Ayrıca açık soru.** `ana-1`'de B'nin komut ailesindeki işareti, C'nin örnek uygunluk kuralının bu aile için fazla katı olabileceğini düşündürmüştü.
- `ana-2`'de bu işaret yok: C ile B komut ailesinde eşit (0'a 0).
- Ama B, örnek alan işlerde A'nın önünde. B'nin tek yanlış kabulü ise iki koşuda da imzası uyuşmayan bir örnekten geldi.

Bu dengeyi ölçmek gerekirse, yeri geliştirme seti.
