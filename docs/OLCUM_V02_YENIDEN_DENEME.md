# SafePatch V0.2 — Yeniden deneme stratejisi deneyi (H2)

**Tarih:** 24 Ekim 2026 · **Ürün kodu:** commit `3d0f54f` (işlerin ilk 50'si) ve `216b732` (kalan 58; `safepatch/` aynı, yalnız deney betiğine devam özelliği eklendi) · **Ham kanıt:** [`evidence/v02-retry/retry/`](../evidence/v02-retry/retry/) · **Sayıların kaynağı:** [`analysis.json`](../evidence/v02-retry/retry/analysis.json) (`scripts/analyze_retry.py` ham iş dosyalarından üretir)

## Soru

V0.1'in yeniden deneme döngüsü, path ve command zafiyet ailelerinde hiç başarılı olmuyordu. Model ikinci denemede aynı yamayı üretiyor ve iş `duplicate_patch` ile duruyordu. Hipotez **H2:** başarısızlık türüne göre geri bildirim veren yeniden deneme, sabit V0.1 döngüsüne göre daha fazla vakayı çözer.

## Yöntem

- **Vakalar:** 9 sentetik Java vakası, 3 aile (SQL, path, command). `-01` geliştirme, `-02` ve `-03` değerlendirme vakası.
- **Stratejiler** (yalnız yeniden deneme davranışı farklı; hafıza kapalı):

| Strateji | Ne değişiyor? |
|---|---|
| `v01` | V0.1 döngüsünün aynısı |
| `sampling` | Yeniden denemelerde sıcaklık 0,4 |
| `guided` | + sınıflandırılmış başarısızlık, önceki denemenin değişen satırları, kademeli rehber (seviye 0: teşhis, seviye 1: teşhis + zafiyet reçetesi) |
| `guided+context` | + projenin diğer kaynak dosyaları, salt okunur bağlam olarak |

- **Tekrar:** 3 seed (42, 43, 44); toplam 9 × 4 × 3 = **108 iş**, en fazla 3 deneme.
- **Model ve doğrulama:** Yerel Qwen2.5-Coder 7B Q4_K_M (Ollama 0.34.0, RTX 4070 Laptop 8 GB). Her aday gerçek Maven derlemesi, davranış testi, güvenlik tanığı ve Semgrep 1.136.0 taramasından geçti. İnsan onayı yok; kabul = "incelemeye hazır".
- **Rehberin kaynağı:** Rehber metinlerini ekip, V0.1'in **geliştirme vakalarındaki** (`-01`) hatalarına bakarak yazdı. Rehberin yeri ve yapısı da deneyden önce `path-01` ve `command-01` üzerindeki ön denemelerle belirlendi. Değerlendirme vakaları ayrıca raporlanıyor.
- **Ön deneme bulgusu:** Aynı rehber metni sistem talimatına konduğunda model onu yok saydı; sıcaklık 0,4'te iki seed'de birebir aynı yamayı üretti. Metin, kullanıcı mesajında verinin sonuna işaretli bir not olarak konunca model yamayı değiştirdi. Rehber bu yüzden verinin sonunda.
- **Kesinti:** İlk çalıştırma 50. işten sonra bilgisayar gözetimsizken durdu. Kalan 58 iş aynı plan ve sırayla `--resume` ile tamamlandı; yarıda kalan iş yeniden çalıştırıldı.

## Sonuçlar

### Kabul edilen işler

| Strateji | Toplam | SQL | Path | Command | Geliştirme | Değerlendirme | Seed 42 | Seed 43 | Seed 44 |
|---|---|---|---|---|---|---|---|---|---|
| `v01` | **9/27** | 9/9 | 0/9 | 0/9 | 3/9 | 6/18 | 3/9 | 3/9 | 3/9 |
| `sampling` | **9/27** | 9/9 | 0/9 | 0/9 | 3/9 | 6/18 | 3/9 | 3/9 | 3/9 |
| `guided` | **19/27** | 9/9 | 9/9 | 1/9 | 6/9 | 13/18 | 7/9 | 6/9 | 6/9 |
| `guided+context` | **19/27** | 9/9 | 9/9 | 1/9 | 6/9 | 13/18 | 7/9 | 6/9 | 6/9 |

### Vaka bazında (3 seed içinde kabul)

| Vaka | `v01` | `sampling` | `guided` | `guided+context` |
|---|---|---|---|---|
| sql-01, sql-02, sql-03 | 3/3 | 3/3 | 3/3 | 3/3 |
| path-01 | 0/3 | 0/3 | 3/3 | 3/3 |
| path-02 | 0/3 | 0/3 | 3/3 | 3/3 |
| path-03 | 0/3 | 0/3 | 3/3 | 3/3 |
| command-01 | 0/3 | 0/3 | 0/3 | 0/3 |
| command-02 | 0/3 | 0/3 | 0/3 | 1/3 |
| command-03 | 0/3 | 0/3 | 1/3 | 0/3 |

### Eşleştirilmiş karşılaştırma (aynı vaka ve seed; kesin McNemar testi)

| Karşılaştırma | Yalnız ikincinin çözdüğü | Yalnız birincinin çözdüğü | p (iki yönlü) |
|---|---|---|---|
| `v01` → `sampling` | 0 | 0 | 1,0 |
| `v01` → `guided` | 10 | 0 | 0,002 |
| `v01` → `guided+context` | 10 | 0 | 0,002 |
| `guided` → `guided+context` | 1 | 1 | 1,0 |

Eşler (vaka, seed) çiftleridir. 3 aileden 9 vaka, 3 seed'de tekrarlandığı için eşler bağımsız projeler değildir. İyileşmenin tamamı path ailesinin 3 vakasından ve command'daki 1 vakadan geliyor; p değeri bu sınırla okunmalı.

### Süre ve deneme sayısı

| Strateji | Ortanca toplam süre | Kabul edilenlerde ortanca | Kabul edilenlerin deneme sayısı | Durma nedenleri |
|---|---|---|---|---|
| `v01` | 63,0 sn | 55,8 sn | 1 deneme: 9 | aynı yama 13, ilerleme yok 5 |
| `sampling` | 67,4 sn | 55,3 sn | 1 deneme: 9 | ilerleme yok 9, aynı yama 9 |
| `guided` | 87,6 sn | 73,1 sn | 1: 9, 2: 6, 3: 4 | deneme bütçesi bitti 8 |
| `guided+context` | 64,8 sn | 86,7 sn | 1: 9, 3: 10 | deneme bütçesi bitti 8 |

Rehberli stratejiler path vakalarını 2. veya 3. denemede çözdüğü için kabul edilen işlerde daha uzun sürüyor. Bunun karşılığı, V0.1'in hiç çözemediği vakaların çözülmesi.

## Kalite incelemesi: kabul edilen path düzeltmeleri

Kabul edilen path düzeltmeleri iki gruba ayrılıyor:

| Strateji | Kabul edilen path düzeltmesi | Hedef yolu `toRealPath()` ile çözen | Yalnız `normalize()` kullanan |
|---|---|---|---|
| `guided` | 9 | 3 | 6 |
| `guided+context` | 9 | 9 | 0 |

`normalize()` yalnız metin üzerinde çalışır ve dosya sistemine bakmaz; kök dizin içindeki, dışarıyı gösteren bir sembolik bağlantıyı yakalamaz. Mevcut güvenlik tanığı yalnız `../secret.txt` girdisini denediği için bu düzeltmeler "doğrulandı" diye geçti. Daha güçlü bir tanıkla (sembolik bağlantı ve mutlak yol vakaları) `guided` stratejisinin 6 path düzeltmesi büyük olasılıkla reddedilirdi. Bu, sınanmadı.

İki not:
1. Ekibin yazdığı path reçetesi "`toRealPath()` **veya** `normalize()`" diyordu; yani zayıf düzeltmeye kendi rehberimiz izin verdi.
2. `guided+context`'in 9/9 sağlam sonuç vermesinin nedeni bu deneyle açıklanamaz. Kabul oranı farkı olmadığı için ek bağlamın faydası şu an kanıtlanmış değil.

Bu bulgu, "doğrulanmış düzeltme" ifadesinin tanık testinin gücü kadar anlamlı olduğunu gösteriyor.

## Yorum

**Gösterdiği:**
- Rehberli yeniden deneme, bu 9 vakada V0.1'in çözemediği 10 (vaka, seed) eşini çözdü; V0.1'in çözüp rehberlinin çözemediği eş yok.
- Path ailesi 0/9'dan 9/9'a çıktı; rehber yazılırken bakılmayan `path-02` ve `path-03` dahil.
- **Yalnız rastgeleliği artırmak hiçbir şey kazandırmadı.** Kazanç, modele doğru geri bildirimin doğru yerde verilmesinden geliyor.
- 7B yerel modelde geri bildirimin **yeri** sonucu belirliyor (sistem talimatı yerine verinin sonu).

**Göstermediği:**
- Gerçek projelerde ya da farklı zafiyet türlerinde aynı kazancın oluşacağı.
- Ek bağlam dosyalarının kabul oranına katkısı (19 = 19).
- Command ailesinin çözüldüğü: 1/9 ile hâlâ zayıf.
- İnsan zamanı tasarrufu: ölçülmedi.

## Sınırlar

- 3 sentetik aile ve 9 küçük vaka; değerlendirme vakaları aynı şablonların varyantları, bağımsız proje değil.
- Rehber ve yerleşimi geliştirme vakaları üzerinde ayarlandı; aşırı uyum riski var.
- Güvenlik tanığı zayıf (yukarıdaki kalite incelemesi). Kabul, "insan incelemesine hazır" demek; güvenlik garantisi değil.
- Tek model, tek donanım; native runner aynı kullanıcıyla çalışıyor.
- Sıcaklık 0'da bile ilk deneme yaması 3 seed'de her zaman aynı değil (`v01`'de 7/9 vakada aynı).

## Sonraki adımlar

1. **Path sınıf paketi (Hafta 3):** sembolik bağlantı ve mutlak yol tanıkları; reçetede `toRealPath()` zorunlu. Path vakaları yeniden ölçülür. Kaç kabulün daha güçlü tanığı geçtiği ayrıca raporlanır.
2. **Varsayılan strateji kararı:** ölçüm `guided` ailesini destekliyor. Ürünün varsayılanının `v01`'den `guided` ya da `guided+context`'e çekilmesi ekip kararı.
3. **Command ailesi:** reçete ve bağlam yetmiyor. Seçenekler: yardımcı sınıfın bulunmasına yönelik daha somut bağlam, daha büyük model (8 GB GPU sınırı), ya da iyi kanıtla insana devretme.
4. **Genelleme:** asıl ölçüm L3 setinde (OWASP Benchmark, Vul4J), Hafta 9.

## Yeniden üretim

```powershell
$env:EVIDENCE_DIR = 'evidence/v02-retry-yeni'   # yeni klasör; mevcut kanıt üzerine yazılmaz
.venv/Scripts/python.exe scripts/retry_experiment.py          # Ollama ve servisler çalışırken
.venv/Scripts/python.exe scripts/analyze_retry.py
```
