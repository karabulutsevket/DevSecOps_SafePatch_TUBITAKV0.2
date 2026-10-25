# Faz 1 geçiş koşulları ölçümü (Hafta 5)

**Tarih:** 25 Ekim 2026 · **Ürün kodu:** commit `910595b` · **Ham kanıt:** [`evidence/v02-faz1/faz1/`](../evidence/v02-faz1/faz1/) (`summary.json` koşulları ham kayıtlardan denetler) · **Betik:** `scripts/faz1_exit.py`

## Faz 1 geçiş koşulları (ROADMAP.md Hafta 5)

| Koşul | Sonuç | Kanıt |
|---|---|---|
| (1) Bir uzman yaması hafızaya girdi ve sonraki bir işte kullanılıp doğrulamadan geçti | **Gösterildi** (test kimlikleriyle) | [UZMAN_YAMASI.md](UZMAN_YAMASI.md#arayüz), [`evidence/v02-uzman-arayuzu/demo/`](../evidence/v02-uzman-arayuzu/demo/) |
| (2) Kaynak hash'i farklı bir varyant vakada hafıza kaydı yapısal imzayla seçildi ve doğrulamadan geçti | **Sağlandı:** 4 varyantta | bu ölçüm |
| (3) Uyumsuz bir kayıt doğru gerekçeyle elendi | **Sağlandı** | bu ölçüm |

## Yöntem

- **Hafıza kurma:** `sql-01`, `path-01`, `command-01` hafıza kapalı, `guided+context`, en çok 3 deneme ile koştu. Kabul edilen adaylar ayrı bir deney veritabanında **simüle bir inceleyiciyle** (`SIMULATED-EXPERIMENT-REVIEWER`) onaylanıp hafızaya alındı. Bu gerçek bir insan onayı değildir.
- **Değerlendirme:** 6 varyant (`sql-02/03`, `path-02/03`, `command-02/03`) ve `sql-execute`, hafıza kapalı (A) ve korumalı (C) olarak, seed 42, `guided+context`. Değerlendirme işleri hafızaya yazmaz.
- **`sql-execute`:** `sql-01` ile aynı kod ve testler; tek fark, sorgu `executeQuery(sql)` yerine `execute(sql)` + `getResultSet()` ile çalışıyor. Yalnız bu ölçüme özel; resmi 9 vakaya eklenmedi, deneylerin vaka listesi değişmedi.
- **Tarayıcı:** yerleşik demo tarayıcısı. Kendi Semgrep kuralımız `execute()` varyantını yakalamıyor. Model, tanıklar ve rehber metinleri önceki ölçümlerle aynı.
- **Ölçek:** 17 iş, 11 dakika.

## Sonuç

**Hafıza kurma:** `sql-01` (1. deneme) ve `path-01` (3. deneme) kabul edildi; `command-01` edilmedi. Hafızada 2 kayıt oldu.

| Varyant | A: hafıza kapalı | C: korumalı hafıza | C'de hafıza kararı |
|---|---|---|---|
| `sql-02`, `sql-03` | kabul (1 deneme) | kabul (1 deneme) | `sql-01` kaydı **örnek**; tek fark kaynak kod |
| `path-02`, `path-03` | kabul (**3** deneme, ~60 sn) | kabul (**1** deneme, ~29 sn) | `path-01` kaydı **örnek**; artı 2 başarısızlık uyarısı |
| `command-02`, `command-03` | kabul yok | kabul yok | kayıt yok (`command-01` çözülemedi); 2 başarısızlık uyarısı gitti |
| `sql-execute` | kabul (1 deneme) | kabul (1 deneme) | `sql-01` kaydı **elendi**: `source_sha256`, `signature.sink` (imzada hedef çağrı farklı) |

- **Koşul 2:** dört varyantta kayıt, kaynak kodu farklı olduğu hâlde yapısal imzayla örnek olarak seçildi. Dört aday da tam doğrulamadan geçti.
- **Koşul 3:** `sql-01` kaydı `sql-execute` için doğru gerekçeyle elendi. Model kaydı görmedi ve kendi düzeltmesi doğrulamadan geçti.
- **Gözlem (iddia değil):** path varyantlarında hafızalı kol ilk denemede kabul edildi. İlk yama doğrudan `toRealPath()` kullandı. Hafızasız kol ancak üçüncü denemede, reçete verildikten sonra kabul edildi. Süre yaklaşık yarıya indi. Bu yalnız 2 vaka ve tek seed; hafızanın etkisi H1 deneyinde ölçülecek (ROADMAP.md Hafta 9–10).
- **Command:** iki kolda da çözülemedi. Hafızada command kaydı yoktu.

## Sınırlar

- Onaylar simüle; hafıza kaydı sentetik vakalardan kurulu.
- Varyantlar aynı şablonun küçük değişiklikleri; `sql-execute` bu ölçüm için yazıldı. Bağımsız proje değil.
- Tek seed, tek koşu. Yerel model aynı istemde bile her zaman aynı yamayı üretmiyor.
- Tarayıcı yerleşik demo tarayıcısı; Semgrep ile koşulmadı.

## Yeniden üretim

```powershell
.venv/Scripts/python.exe scripts/faz1_exit.py --prepare            # ölçüme özel proje klasörü; yolunu yazar
$env:PROJECTS_DIR = (Resolve-Path .runtime\faz1\projects).Path    # servisler de bu klasörle başlatılır
./scripts/start-native.ps1 -Restart                                 # Ollama da çalışırken
$env:EVIDENCE_DIR = 'evidence/v02-faz1-yeni'
.venv/Scripts/python.exe scripts/faz1_exit.py
```
