# Path güvenlik tanığı ölçümü (Hafta 3)

**Tarih:** 25 Ekim 2026 · **Ürün kodu:** tanık ve yeniden doğrulama commit `dc8a594`, model ölçümü commit `641a978` · **Ham kanıt:** [`evidence/v02-path-tanigi/reverify/`](../evidence/v02-path-tanigi/reverify/) (model yok) ve [`evidence/v02-path-tanigi/retry/`](../evidence/v02-path-tanigi/retry/) (model) · **Önceki ölçüm:** [OLCUM_V02_YENIDEN_DENEME.md](OLCUM_V02_YENIDEN_DENEME.md) (H2)

## Soru

H2 deneyinde path ailesi 0/9'dan 9/9'a çıktı. Ancak güvenlik tanığı yalnız `../secret.txt` girdisini deniyordu ve `guided` stratejisinin kabul edilen 9 path düzeltmesinin 6'sı yalnız `normalize()` kullanıyordu. İki soru:

1. H2'de kabul edilen path yamalarından kaçı daha güçlü bir tanığı geçiyor?
2. Güçlü tanık ve `toRealPath()` zorunlu reçeteyle model path vakalarını çözebiliyor mu?

## Değişenler

| | H2 | Hafta 3 |
|---|---|---|
| Güvenlik tanığı | `../secret.txt` | + kök dışındaki dosyanın mutlak yolu; + kök içinde, dışarıyı gösteren dizin bağlantısı |
| Davranış testi | Düz ve iç içe dosya okuma | + bağlantı üzerinden verilen kökten okuma |
| Path reçetesi | Hedef için "`toRealPath()` veya `normalize()`" | Kök ve hedef için `toRealPath()` zorunlu; `normalize()`'ın bağlantıları izlemediği açıkça yazılı |

Bağlantı Linux'ta sembolik bağlantıdır. Windows'ta sembolik bağlantı yetkisi yoksa dizin bağlantısı (junction) kullanılır. İkisini de `toRealPath()` çözer, `normalize()` çözmez; bu makinede ayrıca denendi. SQL ve command vakaları değişmedi, commit'leri aynı.

## 1. H2 kabullerinin yeniden doğrulanması (model yok)

H2'de kabul edilen 18 path işinin yaması (17 farklı yama), path vakalarının güncel commit'inde gerçek runner ve H2'deki tarayıcıyla (Semgrep) yeniden çalıştırıldı. Kaynak dosya değişmedi; her yamanın taban özeti güncel kaynakla eşleşti.

| Strateji | H2'de kabul | Güçlü tanığı geçen | Düşen | Geliştirme | Değerlendirme |
|---|---|---|---|---|---|
| `guided` | 9 | **3** | 6 | 2/3 | 1/6 |
| `guided+context` | 9 | **9** | 0 | 3/3 | 6/6 |

- Düşen 6 yamanın hepsi yalnız `normalize()` kullanıyor ve hepsi aynı testte düşüyor: kök içinden dışarıyı gösteren bağlantı.
- Geçen 12 yamanın hepsi `toRealPath()` kullanıyor.
- Mutlak yol testi ve bağlantılı kök davranış testi hiçbir yamayı düşürmedi.
- **Nedeni:** H2'de `guided`'ın 2. denemede kabul edilen 6 yamasının altısı da güvensiz. 2. denemede model yalnız teşhis görür, reçeteyi görmez. Reçetenin verildiği 3. denemede kabul edilen 3 yamanın üçü de güvenli. Zayıf tanık, model reçeteye ulaşmadan zayıf düzeltmeyi kabul etti.

### H2 karşılaştırmasına etkisi

Güçlü tanığı geçmeyen path kabulleri çıkarıldığında H2 tabloları şöyle değişiyor. SQL ve command tanıkları değişmediği için o kabuller aynı kalıyor.

| Strateji | H2 kabul | Güçlü path tanığıyla |
|---|---|---|
| `v01` | 9/27 | 9/27 |
| `sampling` | 9/27 | 9/27 |
| `guided` | 19/27 | **13/27** |
| `guided+context` | 19/27 | **19/27** |

| Karşılaştırma (kesin McNemar) | H2 | Güçlü path tanığıyla |
|---|---|---|
| `v01` → `guided` | 10–0, p = 0,002 | **4–0, p = 0,125** |
| `v01` → `guided+context` | 10–0, p = 0,002 | **10–0, p = 0,002** |
| `guided` → `guided+context` | 1–1, p = 1,0 | 7–1, p = 0,070 |

`v01`'e karşı anlamlı fark yalnız `guided+context` için ayakta kalıyor. Yeni işlerin varsayılanı zaten `guided+context`; bu karar artık daha sağlam bir dayanağa sahip. Bu tablo, H2 sırasında tanık güçlü olsaydı `guided`'ın ne yapacağını göstermez: o durumda döngü başarısızlık geri bildirimi alıp yeniden denerdi. Bunu ikinci ölçüm ölçüyor.

## 2. Model ile yeniden ölçüm

3 path vakası × 3 strateji × 3 seed = 27 iş. Model, sıcaklık ve deneme bütçesi H2 ile aynı. **Tanık ve reçete birlikte değişti**, bu yüzden ikisinin etkisi ayrı ayrı okunamaz.

| Strateji | Kabul | Geliştirme | Değerlendirme | Kabul edilenlerin deneme sayısı | Kabul edilmeyenler |
|---|---|---|---|---|---|
| `v01` | 0/9 | 0/3 | 0/6 | — | ilerleme yok 9 |
| `guided` | **8/9** | 3/3 | 5/6 | 3 denemede: 8 | deneme bütçesi bitti 1 |
| `guided+context` | **8/9** | 3/3 | 5/6 | 3 denemede: 8 | deneme bütçesi bitti 1 |

- Kabul edilen 16 yamanın hepsi `toRealPath()` kullanıyor ve güçlü tanığı geçti.
- Hepsi, reçetenin verildiği 3. denemede kabul edildi.
- **Kabul edilmeyen iki iş** (ikisi de `path-02`, seed 44): 3. denemede model girdiyi kök yerine çalışma dizinine göre çözdü (`Paths.get(input)`). Üç davranış testinin üçü de düştü. Yeni bağlantılı kök testi tek başına hiçbir yamayı düşürmedi.
- Yeni reçeteyle `guided` 3 güvenli path düzeltmesinden 8'e çıktı. H2'deki `guided` / `guided+context` farkı zayıf reçeteden geliyordu; reçete düzelince kalmadı. Ek bağlamın path üzerindeki faydası bu ölçümde görünmüyor.
- **Süre:** bu koşuda bütün bileşenler daha yavaş çalıştı (ortanca model 5,2→7,1 sn, derleme 4,6→6,8 sn, runner toplamı 23,3→44,7 sn; `v01` path işleri). Yeni testlerin payı küçük: test koşuları 3,4→4,1 sn. Süreler H2 ile karşılaştırılmamalı. Koşunun toplam süresi 72 dakika.

## Sınırlar

- Reçete, H2'de kabul edilen bütün path yamalarına (değerlendirme vakaları dahil) bakılarak değiştirildi. Bu yüzden buradaki değerlendirme vakası sonuçları H2'dekinden daha az bağımsız. Değişiklik standart bir güvenlik özelliğidir (CWE-22 için yolu dosya sistemi üzerinden kanonikleştirmek), vaka ayrıntısı içermez.
- 3 sentetik vaka, 3 seed, tek koşu. Yerel model aynı istemde bile her zaman aynı yamayı üretmiyor.
- Tanık hâlâ bir test kümesi. Kapsamadıkları: denetim ile okuma arasında bağlantının değiştirilmesi (TOCTOU), Windows'a özgü yol biçimleri (UNC, kısa adlar, büyük-küçük harf), dosya izinleri.
- Linux'ta sembolik bağlantıyla koşu yapılmadı; Docker sandbox ile (Hafta 5–6) yapılacak.

## Yeniden üretim

```powershell
$env:MAVEN_CACHE = '<maven önbelleği>'; $env:SEMGREP_WSL = '<WSL içindeki semgrep yolu>'
$env:EVIDENCE_DIR = 'evidence/v02-path-yeni'          # yeni klasör; mevcut kanıt üzerine yazılmaz
.venv/Scripts/python.exe scripts/seed.py              # path depoları güçlü tanıkla yeniden kurulur
.venv/Scripts/python.exe scripts/reverify_accepted.py --source evidence/v02-retry/retry --cases path-01,path-02,path-03
.venv/Scripts/python.exe scripts/retry_experiment.py --cases path-01,path-02,path-03 --strategies v01,guided,guided+context   # Ollama ve servisler çalışırken
```
