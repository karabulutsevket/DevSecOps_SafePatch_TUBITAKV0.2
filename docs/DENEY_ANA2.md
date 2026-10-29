# Ana deney, ikinci koşu: `ana-2` (29 Ekim 2026, Hafta 10)

**Durum: onaylandı ve koşudan önce sabitlendi.**
- Proje liderinin onayı: 29 Ekim, "Olur, dört kolla ana-2'yi başlat". Kapsam: dört kol.
- Koşu başladıktan sonra ne protokol ne ürün kodu değişir; betik bunu denetler (`safepatch/` değişmişse devam reddedilir).
- `ana-1` geçerliliğini korur ([DENEY_PROTOKOLU.md](DENEY_PROTOKOLU.md), [OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md)). İki koşu birlikte raporlanır.

## Neden

- **`ana-1`'de H1 ve H3 desteklenmedi.** Keşifsel analizde, modele yalnız başarısızlık uyarısı giden işler hafızasız kola göre daha kötüydü (C'de 0'a 7).
- **Bu bulgu geliştirme setinde sınandı** ([DENEY_UYARI.md](DENEY_UYARI.md)). Uyarısız kol, yalnız uyarı giden çiftlerde 12'ye 2 öndeydi (p = 0,013).
- **Proje lideri 29 Ekim'de karar verdi:** uyarılar artık modele gönderilmiyor; yalnız kaydediliyor ([HAFIZA_UYGUNLUK.md](HAFIZA_UYGUNLUK.md)).
- **`ana-2`, ürünün bu yeni hâlini değerlendirme setinde ölçer.** Karar geliştirme setinde verildi; değerlendirme seti ayar için kullanılmadı. `ana-2` yalnız kararın değerlendirmedeki sonucunu ölçer, ardından yeni bir ayar yapılmaz.

## `ana-1`'e göre ne değişiyor

`ana-1`'in kodu `166aeb8` idi. Bu koşunun kodu `hafta10-uyari-politikasi` dalının onay anındaki ucu olur; `protocol.json` commit'i ve `safepatch/` özetini kaydeder. `safepatch/` altında yalnız üç dosya değişti:

| Dosya | Değişiklik | Hangi kolu etkiler |
|---|---|---|
| `engine.py` | Başarısızlık uyarıları modele gönderilmiyor, `warnings_withheld` olarak kaydediliyor | C ve C+L2. A'da hafıza kapalı, B'de uyarı hiç yoktu; istemleri değişmez |
| `runner.py` | Runner, Windows tarafındaki kopyasını iş bitince siliyor (Hafta 9, `hafta9-runner-temizligi`) | Hiçbiri; yalnız disk. `ana-1`'deki dışarıdan temizliğe gerek kalmaz |
| `static/app.js` | İnceleme ekranı gönderilmeyen uyarıları listeliyor | Hiçbiri |

Betiklerde iki ek var:
- `main_experiment.py --protocol`: `protocol.json`'a bu belgeyi yazar.
- `experiment_analysis.py --previous`: koşular arası karşılaştırma (aşağıda).

## Aynı kalanlar

Hepsi `ana-1` ile aynı ([DENEY_PROTOKOLU.md](DENEY_PROTOKOLU.md), "Kollar" ve "Koşullar"):
- **Kollar:** A, B, C, C+L2.
- **Vakalar:** 45 değerlendirme vakası (30 gerçek açık, 15 güvenli kod). L3 kataloğu değişmedi (`catalog_sha256` `75841d71…`).
- **Seed'ler ve sıra:** 42, 43, 44. Vaka sırası seed'den türetildiği ve katalog aynı olduğu için `ana-1` ile birebir aynı. Kolların sırası da aynı biçimde döndürülür.
- **Model ve bütçe:**
  - model `qwen2.5-coder:7b-instruct-q4_K_M`;
  - B'nin embedding modeli `nomic-embed-text:v1.5`;
  - strateji `guided+context`, en çok 3 deneme, 1800 sn.
- **Bulgu ve doğrulama:** bulgu cevap anahtarından; doğrulama Docker sandbox'ında, değerlendirme profilinde.
- **Hafızaya alma:** karar 2a, simüle onay.
- **L2 paketi:** `ana-1`'in paketi bayt düzeyinde aynen (`l2_package_sha256` `f4975a6d…`). Yeniden üretilmez: `evidence/v02-benchmark/experiment/l2/` yeni kanıt klasörüne kopyalanır ve özeti koşudan önce denetlenir.
- **Ölçütler:** birincil doğru onarım (kabul ve gizli testler geçti); yanlış kabul, yanlış aktarım ve ikinciller aynı.

## Önceden tanımlı analiz

**1. `ana-2` içinde, `ana-1` ile aynı.**
- C–A, C–B, C+L2–C: kesin McNemar ve vakaları yeniden örnekleyen %95 bootstrap aralığı.
- Holm düzeltmesi bu üç karşılaştırma üzerinde.
- Toplam, aile ve seed bazında.

**2. Koşular arası (ikincil; düzeltmesiz, ayrıca etiketlenir).** Her kol, `ana-1`'deki aynı kolla, aynı vaka ve seed üzerinden eşleştirilir:
- **C(`ana-2`) – C(`ana-1`):** uyarı kararının değerlendirme setindeki etkisi. Ayrıca C+L2 için de aynı karşılaştırma yapılır.
- **A(`ana-2`) – A(`ana-1`) ve B(`ana-2`) – B(`ana-1`):** tekrarlanabilirlik denetimi.
  - Bu kolların kodu ve istemleri değişmedi.
  - Uyuşmayan çiftler ve farklı yama özetleri (`same_attempt_patches`) yalnız yeniden koşmanın etkisini gösterir: model, donanım ya da zamanlama.

**Okuma kuralı.** C'nin koşular arası farkı, A'nın tekrarlanabilirlik sonucuyla birlikte okunur:
- A'da uyuşmayan çift yoksa ya da çok azsa, C'deki fark uyarı kararına bağlanabilir.
- A'da da benzer sayıda uyuşmayan çift varsa, koşular arası karşılaştırma belirsiz sayılır ve öyle raporlanır.

**Keşifsel (sonuç görüldükten sonra seçilenler ayrıca etiketlenir):** `ana-1`'deki hafıza kırılımı ve tavan analizi tekrarlanır. Her kolda uyarısı tutulan iş sayısı (`warnings_withheld_jobs`) raporlanır.

**Komutlar:**
- `ana-2` içi analiz ve koşular arası karşılaştırma: `EVIDENCE_DIR=evidence/v02-benchmark-2 python scripts/experiment_analysis.py --previous evidence/v02-benchmark/experiment`.
- Çıktı `evidence/v02-benchmark-2/analiz/analysis.json`; eski kayıtların üzerine yazılmaz.

## Beklenti (sonuç değil) ve güç

- **Uyarı etkisinin ölçeği.** `ana-1`'de C'nin 90 işinin 25'ine yalnız uyarı gitti. Bu işlerde A, 7 çift öndeydi. Uyarı kaldırılınca bu farkın kapanması beklenir.
- **Örnek etkisinin ölçeği.** Örnek alan işlerde C, A'ya göre 6'ya 1 öndeydi.
- **Güç düşük.** İkisi birlikte bile C–A için birkaç vakalık bir fark eder. Bu yüzden C–A'da anlamlı bir sonuç beklenmez. Sonuç olumlu ya da olumsuz raporlanır.

## Süre ve işletim

- **Süre:** 540 iş; `ana-1` yaklaşık 14 saat sürdü. Koşu kaldığı yerden devam edebilir.
- **Disk:** runner artık kendi kopyasını siliyor. Worker2'nin inceleme kopyaları (`ana-1`'de yaklaşık 12 GB) tasarım gereği kalır; boş alan yeterli.
- **Adımlar (onaydan sonra):**
  1. Çalışma ağacı temiz olmalı; koşu dalın ucundan başlar.
  2. `evidence/v02-benchmark-2/experiment/l2/` içine `ana-1`'in L2 klasörü kopyalanır; paket özeti `f4975a6d…` ile karşılaştırılır.
  3. Servisler değerlendirme profilinde başlatılır: `PROJECTS_DIR=.runtime/l3/projects`, `SAFEPATCH_PROFILE=evaluation`, `RUNNER_SANDBOX=docker`, `SANDBOX_MAVEN_CACHE`.
  4. `EVIDENCE_DIR=evidence/v02-benchmark-2 python scripts/main_experiment.py run --run ana-2 --protocol docs/DENEY_ANA2.md`.
  5. Koşu bitince önceden tanımlı analiz; sonuçlar [OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md)'ye `ana-1` ile yan yana eklenir.

## Kararlar (29 Ekim 2026, proje lideri)

1. **Protokol onaylandı.**
2. **Kapsam: dört kolun hepsi yeniden koşar** (~14 saat).
   - Daha kısa seçenek (yalnız C ve C+L2, ~7 saat) seçilmedi.
   - Gerekçe: koşular arası eşleştirmenin geçerliliği tekrarlanabilirliğe bağlı ve bunu ancak A'yı yeniden koşmak gösterir.
