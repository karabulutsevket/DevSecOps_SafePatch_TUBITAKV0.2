# Faz 2 geçiş koşulları (27 Ekim 2026, Hafta 7)

**Ürün kodu:** commit `2c399c1`. **Ham kanıt:** [`evidence/v02-faz2/faz2/`](../evidence/v02-faz2/faz2/); `summary.json` koşulu ham kayıtlardan denetler. **Betik:** `scripts/faz2_exit.py`.

## Faz 2 geçiş koşulları (ROADMAP.md, Faz 2)

| Koşul | Durum | Kanıt |
|---|---|---|
| L3'te en az 30 vaka çalışır durumda: derleniyor, başlangıçta güvenlik tanığı başarısız | **Sağlandı:** değerlendirmede 30 gerçek açık (45 vakanın 30'u) | [L3_SETI.md](L3_SETI.md) |
| L2 paketi imzalı olarak içeri alınabiliyor | **Sağlandı** (27 Ekim, deney paketiyle; simüle onaylar) | [OLCUM_L2.md](OLCUM_L2.md) |
| Sandbox'ta uçtan uca bir iş tamamlandı | **Sağlandı:** L3 model koşuları sandbox'ta, işler kabul ve gizli testlerle | [OLCUM_L3_MODEL.md](OLCUM_L3_MODEL.md) |
| Semgrep bulgusundan öğrenilmiş bir hafıza kaydı, aynı zafiyetin FindSecBugs bulgusunda seçildi ve doğrulamadan geçti | **Sağlandı** | bu ölçüm |

## Tarayıcıdan bağımsızlık: ölçüm

Gerçek yerel model ve gerçek Java doğrulaması, sentetik laboratuvarda. Ayarlar: seed 42, `guided+context`, en çok 3 deneme.

**1. Hafızaya kayıt.**
- `sql-01`, tarayıcı **Semgrep**: bulgu SafePatch'in kendi kuralı `bigg.java.sql-concatenation` (satır 17). Hafıza kapalı.
- Model ilk denemede doğrulanan bir düzeltme üretti.
- Bu aday, ayrı bir deney veritabanında `SIMULATED-EXPERIMENT-REVIEWER` tarafından **simüle edilmiş bir onayla** hafızaya alındı. Gerçek bir insan onayı değil.

| Kaydın alanı | Değeri |
|---|---|
| CWE ailesi | CWE-89 |
| Yapısal imza | havuz `java.sql.Statement.executeQuery`, kuruluş birleştirme, kaynak metot parametresi, kütüphane JDBC |
| Kural kimliği | `bigg.java.sql-concatenation`; yalnız iz için saklanıyor, eşleştirmede kullanılmıyor |

**2. Kullanım.** Üç iş, tarayıcı **FindSecBugs** (bulgu `SQL_INJECTION_JDBC`, satır 17), hafıza açık (`guarded`):

| Vaka | Hafızanın kullanımı | Sonuç | Deneme | Doğrulamadaki yeniden tarama |
|---|---|---|---|---|
| sql-01 | Aynı kayıt, **birebir tekrar** (kaynak aynı) | Kabul | 1 | FindSecBugs, kalan bulgu yok |
| sql-02 | Aynı kayıt, **örnek** (kaynak farklı) | Kabul | 1 | FindSecBugs, kalan bulgu yok |
| sql-03 | Aynı kayıt, **örnek** | Kabul | 1 | FindSecBugs, kalan bulgu yok |

Toplam süre 3 dakika 49 saniye.

**Neden çalıştı.** Hafıza kaydı tarayıcının kural adına değil, iki şeye bağlı:
- zafiyetin CWE ailesine;
- koddan okunan yapısal imzaya (`safepatch/memory.py`, `safepatch/signature.py`).

FindSecBugs bulgusunun CWE'si SARIF'ten geliyor (CWE-89), ve iki tarayıcı da aynı satırı gösteriyor. Bu yüzden Semgrep'le öğrenilen kayıt FindSecBugs bulgusunda da seçildi. Birebir tekrar da doğrulamadan geçti: derleme, davranış ve güvenlik testleri, ve FindSecBugs'la yeniden tarama.

## Sınırlar

- **Sentetik ve tek seed.** Bu, bir koşulun gösterimi; bağımsız bir benchmark değil. Tek aile (SQL), tek seed.
- **Simüle edilmiş onay.** Hafızaya alma onayı gerçek bir insan onayı değil.
- **Kapsam SQL ailesiyle sınırlı.** Komut ailesinde FindSecBugs, doğru bir düzeltmeden sonra da `COMMAND_INJECTION` raporluyor ([FINDSECBUGS.md](FINDSECBUGS.md)); bugünkü kabul kuralıyla orada doğrulama geçmez. Path ailesinde FindSecBugs laboratuvarın kalıbını hiç görmüyor.
- **L2 paketi koşulu** ayrı bir ölçümle sağlandı ([OLCUM_L2.md](OLCUM_L2.md)). Böylece Faz 2'nin dört geçiş koşulu da sağlanmış oldu. Hafta 8'in sandbox sertleştirme maddeleri ayrı iş olarak açık.
