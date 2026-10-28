# Uyarı denemesi protokolü: C ile uyarısız C (28 Ekim 2026, Hafta 10)

**Durum: koşudan önce sabitlendi; koşu (`uyari-1`) 29 Ekim'de bitti.** Sonuç en altta, "Sonuç: `uyari-1`" bölümünde.

**Karar (29 Ekim, proje lideri): 1. seçenek.** "Olur, 1. seçenekle ilerle." Uyarılar artık modele gönderilmiyor; yalnız kaydediliyor ([HAFIZA_UYGUNLUK.md](HAFIZA_UYGUNLUK.md)). Değerlendirmedeki yeni koşunun taslağı: [DENEY_ANA2.md](DENEY_ANA2.md).
- Proje liderinin onayı: 28 Ekim, "Olur, uyarı denemesiyle devam et".
- Koşu başladıktan sonra protokol de ürün kodu da değişmez. Betik bunu denetler: `safepatch/` değişmişse devam reddedilir.

**Betik:** `scripts/warning_experiment.py`. İki adımı var:
- `exposure`: koşudan önce statik sayım;
- `run`: kollar.

**Kanıt:** [`evidence/v02-uyari/deney/`](../evidence/v02-uyari/deney/).

## Neden

Ana deneyde ([OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md)), modele yalnız başarısızlık uyarısı giden işler, aynı vaka ve seed'deki hafızasız işlere göre daha kötüydü:
- C'de uyuşmayan çiftler 0'a 7;
- C+L2'de 0'a 4.

Bu bulgu keşifseldi: sonuçlar görüldükten sonra arandı.

**Hipotez:** başarısızlık uyarıları yerel 7B modelin kabul oranını düşürüyor.

Değerlendirme seti ayar için kullanılmaz. Bu yüzden hipotez geliştirme setinde sınanır.

## Kollar

| Kol | Ne yapar |
|---|---|
| **C** | SafePatch hafızası, ana deneydeki gibi (`memory_mode=guarded`) |
| **C-W** | C ile aynı; tek fark, başarısızlık uyarılarının modele gitmemesi |

**C-W'de uyarıya ne oluyor**
- Başarısızlıklar her zamanki gibi bulunup kaydediliyor.
- Modele gönderilmeyen uyarılar işin kaydına `warnings_withheld` olarak yazılıyor.
- Anahtar `experiment_failure_warnings=false` adlı bir iş alanı. Motor bunu yalnız lab ve değerlendirme profilinde dikkate alıyor; API bu alanı sunmuyor.

**Değişmeyenler:** örnek seçimi, birebir tekrar ve sıralama iki kolda aynı.

## Koşullar

- **Vakalar:** L3 kataloğundaki 26 hazır geliştirme vakası: 9 SQL, 9 path, 8 komut. Hepsi bizim yazdığımız sentetik vakalar.
- **Seed'ler:** 42, 43, 44.
  - Vaka sırası seed'den türetiliyor ve iki kolda aynı.
  - Kolların koşu sırası seed'den seed'e değişiyor: 42'de C, C-W; 43'te C-W, C; 44'te C, C-W.
- **Öğrenme:** her (seed, kol) boş bir veritabanıyla başlıyor. Doğrulayıcının kabul ettiği her aday simüle onayla kolun L1'ine giriyor (karar 2a, ana deneyle aynı).
- **Model ve bütçe ana deneyle aynı:** `qwen2.5-coder:7b-instruct-q4_K_M`, `guided+context`, en çok 3 deneme, 1800 sn.
- **Ortam:** lab profili, `PROJECTS_DIR=.runtime/dev-all/projects`. Sentetik vakalar yerel olarak derleniyor; lab profilinde yalnız onlara izin var.

## Ölçütler ve önceden tanımlı analiz

- **Birincil ölçüt: doğrulayıcının kabulü.** Geliştirme vakalarında gizli test yok. Bu yüzden yanlış kabul ölçülemiyor ve sonuç "doğru onarım" diye değil, "kabul" diye raporlanıyor.
- **Karşılaştırmalar.** Hepsi aynı vaka ve seed'den oluşan çiftler üzerinde: kesin McNemar testi ve vakaları yeniden örnekleyen %95 bootstrap aralığı.
  1. **Birincil:** C-W – C, bütün çiftler (26 × 3 = 78).
  2. **İkincil (a):** C'nin örneksiz, yalnız uyarı aldığı çiftler. Ana deneydeki bulgu bu alt grupta görülmüştü.
  3. **İkincil (b):** C'nin herhangi bir uyarı aldığı çiftler.
- **Alt grupların tanımı.** Alt gruplar C'nin kendi işine, yani modelin uyarıyı gerçekten gördüğü işe göre tanımlanıyor.
- **Ayrıca raporlananlar.**
  - C-W'de kaç işte uyarı tutulduğu.
  - Aile bazındaki sayılar; bunlar yalnız betimleyici.

## Uyarıya açıklık (koşudan önce, statik)

**Kaynak:** [`exposure.json`](../evidence/v02-uyari/deney/exposure.json). 26 vakanın 20'sinin aynı projede aynı aile, JDK ve imza biçiminde bir kardeşi var:

| Aile | Kardeşi olan vaka |
|---|---|
| CWE-22 | 7/9 |
| CWE-78 | 6/8 |
| CWE-89 | 7/9 |

**Ne zaman uyarı gider.** Uyarı ancak sırada önce gelen bir kardeş başarısız olduysa gider. Geliştirme vakalarında kabul daha sık olduğu için başarısızlık, dolayısıyla uyarı, ana deneydekinden az olabilir. Ana deneyde C'nin 90 işinin 25'ine yalnız uyarı gitmişti.

## Güç ve karar

- **Gücün sınırı.** İki yönlü kesin testte p < 0,05 için uyuşmayan çiftlerin en az 6'sının, hepsi aynı yönde olması gerekiyor. 5'e 0 bile p = 0,06 verir. İkincil (a)'da 10'dan az çift kalırsa sonuç **belirsiz** olarak raporlanır.
- **Sonuca göre öneri.** Bunlar koşudan önce yazıldı; karar proje liderinin.
  - **İkincil (a)'da C-W lehine açık bir fark varsa ve birincilde C-W, C'den kötü değilse:** uyarı politikasının değişmesi önerilir. Seçenekler: uyarıyı kaldırmak, yalnız aynı kaynağın başarısızlıklarıyla sınırlamak ya da metnini değiştirmek. Ardından değerlendirmede önceden sabitlenmiş yeni bir koşu (`ana-2`) yapılır ve `ana-1` ile birlikte raporlanır.
  - **Fark yoksa ya da fark C lehineyse:** hipotez geliştirme setinde desteklenmemiş olur. Uyarılar kalır; ana deneydeki bulgu keşifsel olarak raporlanmaya devam eder.
  - **Sonuç belirsizse:** belirsiz olarak raporlanır. Ek seed ya da başka bir yol proje liderine sorulur.

## Süre

Toplam 156 iş: 2 kol × 3 seed × 26 vaka. Önceki mekanik denemede geliştirme işleri 30–120 sn sürmüştü; toplam yaklaşık 3 saat bekleniyor. Koşu kaldığı yerden devam edebilir.

## Sonuç: `uyari-1` (29 Ekim 2026)

**Kayıtlar** ([`evidence/v02-uyari/deney/`](../evidence/v02-uyari/deney/)):
- `protocol.json`: commit `e2ff4a3`, çalışma ağacı temiz, `safepatch/` özeti `af6e24d4…`;
- `runs/<seed>-<kol>/<vaka>.json`: 156 satır;
- `summary.json`, `analysis.json`: koşunun sonunda betiğin yazdığı önceden tanımlı analiz;
- `exploratory.json`: sonradan, `explore` adımıyla yazılan keşifsel kırılımlar. Karara girmez.

**Koşu.** 28 Ekim 22.53'te başladı, 29 Ekim 01.13'te bitti.
- Altyapı kaynaklı yeniden deneme yok.
- Her kolda bir iş politika gereği reddedildi: `variant-command-list`, seed 42, `source_requires_final_newline`. Aynı vaka ve seed iki kolda da reddedildi.

### Kollar

| Kol | İş | Kabul | Örnekli iş | Uyarı gönderilen / tutulan iş |
|---|---|---|---|---|
| C | 78 | 47 (%60,3) | 29 | 38 gönderildi |
| C-W | 78 | 55 (%70,5) | 32 | 38 tutuldu |

### Önceden tanımlı karşılaştırmalar (C-W – C, kabul)

| Karşılaştırma | Çift | Yalnız C-W / yalnız C | Fark | McNemar p | %95 bootstrap |
|---|---|---|---|---|---|
| **Birincil:** bütün çiftler | 78 | 12 / 4 | +10,3 puan | 0,077 | [0,0; +21,8] |
| **İkincil (a):** C'ye örneksiz, yalnız uyarı gitti | 24 | 12 / 2 | +41,7 puan | 0,013 | [+11,5; +73,1] |
| **İkincil (b):** C'ye herhangi bir uyarı gitti | 38 | 12 / 3 | +23,7 puan | 0,035 | [+2,6; +45,7] |

- İkincil (a)'da 24 çift var. Protokoldeki "10'dan az çift belirsiz" sınırının üstünde.
- Protokol çoklu karşılaştırma düzeltmesi tanımlamamıştı. Bilgi için: üç karşılaştırmaya Holm uygulansa (a) 0,039, (b) 0,070, birincil 0,077 olur.

**Aile bazında (betimleyici).**

| Aile | Çift | Yalnız C-W / yalnız C | C-W kabul | C kabul |
|---|---|---|---|---|
| CWE-22 | 27 | 1 / 3 | 14 | 16 |
| CWE-78 | 24 | 11 / 1 | 15 | 5 |
| CWE-89 | 27 | 0 / 0 | 26 | 26 |

### Protokole göre okuma

Protokolün ilk koşulu sağlandı:
- İkincil (a)'da C-W lehine açık bir fark var: 12'ye 2, p = 0,013, aralık sıfırı içermiyor.
- Birincilde C-W, C'den kötü değil: +10,3 puan, aralık [0,0; +21,8].

Protokolün önceden yazdığı öneri bu durumda: **uyarı politikası değişsin**, ardından değerlendirmede önceden sabitlenmiş yeni bir koşu (`ana-2`) yapılsın. Karar proje liderinin.

### Sınırlar ve keşifsel ayrıntı (`exploratory.json`)

- **Geliştirme seti, sentetik vakalar.** Gizli test yok; ölçülen kabul, doğru onarım değil.
- **Fark tek aileye ve sınırlı vakaya yığılıyor.**
  - 12 kazanımın 11'i CWE-78'de; CWE-22'de işaret ters (1'e 3), CWE-89'da kabul zaten tavanda.
  - (a)'daki 14 uyuşmayan çift 8 vakadan geliyor.
  - Seed'lere göre (a): 42'de 1'e 1, 43'te 4'e 0, 44'te 7'ye 1.
- **Farkın yarısı zincirleme etkiden.** C-W önceki bir kardeşi kabul edince sonraki işte onu örnek olarak alabiliyor. (a)'nın 24 çiftini buna göre ayırınca:

  | (a) içinde | Çift | Yalnız C-W / yalnız C | McNemar p |
  |---|---|---|---|
  | C-W de örneksiz (doğrudan etki) | 18 | 6 / 2 | 0,29 |
  | C-W örnek aldı (zincirleme) | 6 | 6 / 0 | 0,031 |

  - Zincirleme etki politikanın gerçek bir sonucudur: uyarı politikası, hafızanın sonraki işlere ne bıraktığını da etkiliyor. Önceden tanımlı analiz bu yüzden kolun tamamını karşılaştırıyor.
  - Ama uyarının tek bir işe doğrudan etkisi tek başına daha zayıf görünüyor (6'ya 2).
- **Uyarı gitmeyen çiftlerde fark yok.**
  - C'ye hiç uyarı gitmeyen 40 çiftte: 0'a 1.
  - Örnekle birlikte uyarı giden 14 çiftte: 0'a 1.
- **Denemeler (a) çiftlerinde.**
  - C'nin 71 denemesinin 27'si güvenlik tanığında, 19'u yinelenen yamada kaldı; 4'ü geçti.
  - C-W'nin 57 denemesinin 11'i güvenlik tanığında, 8'i yinelenen yamada kaldı; 14'ü geçti.
  - Uyarı, modeli başarısız adayın etrafında tutuyor gibi görünüyor. Bu bir yorum; ölçülmedi.
- **Uyarının türü ana deneyden farklı.**
  - Bu koşuda C'ye giden 69 uyarının 65'i `same_context`, 4'ü `same_shape`. Çoğu bir kardeşin güvenlik tanığı başarısızlığı (53).
  - Ana deneyde 47 uyarının hepsi `same_shape` idi.
  - İki koşuda da hiç `same_source` uyarısı olmadı. "Yalnız aynı kaynağın başarısızlıkları" seçeneği bu iki sette uyarıyı fiilen tamamen kaldırırdı.

### Proje liderinin kararı için seçenekler

Önceden yazılan seçenekler ve bu sonuçla ilişkileri:

1. **Uyarıyı modele göndermemek.**
   - En doğrudan desteklenen seçenek: C-W tam olarak bu.
   - Başarısızlıklar kaydedilmeye ve incelemecilere gösterilmeye devam eder.
2. **Uyarıyı yalnız `same_source` başarısızlıklarıyla sınırlamak.**
   - Bu iki sette 1. seçenekle aynı sonucu verirdi.
   - Aynı kaynağa tekrar gelen işte "bu denendi, olmadı" bilgisini korur. Ama bu durum ölçülmedi.
3. **Uyarının metnini değiştirmek.**
   - Ölçülmemiş bir değişiklik olur.
   - Değerlendirmeden önce geliştirme setinde ayrı bir deneme ister.

Hangisi seçilirse seçilsin, değerlendirmede sabitlenmiş yeni bir koşu (`ana-2`) yapılır. `ana-1` ile birlikte raporlanır; `ana-1` geçerliliğini korur.
