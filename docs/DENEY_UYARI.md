# Uyarı denemesi protokolü: C ile uyarısız C (28 Ekim 2026, Hafta 10)

**Durum: koşudan önce sabitlendi.**
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
