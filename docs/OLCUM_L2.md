# L2 paketi: imzalı içeri alma ve güven seviyesi (27 Ekim 2026, Hafta 7)

**Ürün kodu:** commit `1815387`. **Ham kanıt:** [`evidence/v02-l2/l2/`](../evidence/v02-l2/l2/). **Betik:** `scripts/l2_exit.py`. **Tasarım:** [L2_PAKETI.md](L2_PAKETI.md).

Gösterim, bir kaydın yolculuğunu baştan sona izliyor:
- laboratuvarda doğrulanmış bir düzeltme imzalı pakete girer;
- paket, hafızası boş bir kurulumun veritabanına çevrimdışı alınır;
- başka bir projede bir işe örnek olur;
- oradan çıkan düzeltme kurumda doğrulanıp onaylanınca L1'e girer.

Gerçek yerel model ve gerçek Java doğrulaması kullanıldı, yalnız sahibi olduğumuz sentetik projelerde. Ayarlar: seed 42, `guided+context`, en çok 3 deneme. Toplam süre 5 dakika 25 saniye.

## Adımlar ve sonuçlar

| Adım | Ne oldu | Kanıt |
|---|---|---|
| 1. Laboratuvar | `path-01` (proje `owned-java-demo`), Semgrep, hafıza kapalı. Model üçüncü denemede doğrulanan bir düzeltme üretti. **Simüle onayla** (`SIMULATED-EXPERIMENT-REVIEWER`) laboratuvarın L1'ine alındı | `runs.json`, `lab-memory.json` |
| 2. Paket | Laboratuvarın onaylı kaydı `l2_build.py` ile tek kayıtlık bir **deney paketi** oldu (sürüm 1 ve 2). İmza: Ed25519, `ssh-keygen -Y sign`, bu koşu için üretilen anahtar | `package/` |
| 3. İçeri alma | Sürüm 1, boş bir kurulum veritabanına alındı. İmzalayan anahtar `SHA256:T1X+mEIe…`. Kayıt L2'de duruyor: `external_not_verified_here` | `import.json` |
| 4. Kullanım | `package-path-1` (proje `safepatch-package-dev`; başka kod, aynı zafiyet biçimi), bilinen bulgu, hafıza açık. L1 boştu; L2 kaydı **örnek** olarak seçildi (birebir tekrar değil). Model ilk denemede doğrulanan bir düzeltme üretti | `runs.json`, `jobs/` |
| 5. Terfi | Aday **simüle onayla** (`SIMULATED-CUSTOMER-REVIEWER`) kurumun L1'ine alındı. L1 kaydı `l2_origin` alanında kaynağını taşıyor: kayıt, özet, yayıncı, sürüm 1. L2 kaydının `validated_here` listesine bu L1 kaydı eklendi | `installation-memory.json` |
| 6. Sonraki iş | Aynı vakada yeni bir iş açıldı. Bu kez **L1 kaydı** seçildi: birebir tekrar, model çağrılmadan. Doğrulamadan yine geçti | `runs.json` |
| 7. Güncelleme | Sürüm 2 içeri alındı. Kaydın kurumdaki kullanım izi ve doğrulaması korundu | `import.json`, `summary.json` |

**Reddedilenler** (aynı paketin kopyalarında):

| Deneme | Sonuç |
|---|---|
| Kayıtta tek bayt değişikliği | `record_sha256_mismatch` |
| Kurulumun güvenmediği bir anahtarla doğrulama | `signature_invalid` |
| Güven dosyası olmadan | `l2_trust_not_configured` |
| Sürüm 2'den sonra sürüm 1'i yeniden alma | `package_downgrade` |

`summary.json` koşulu ham kayıtlardan denetliyor: `condition_met: true`. Paket kanıt klasöründen tek başına yeniden doğrulanabilir:

```powershell
.venv/Scripts/python.exe -m safepatch.l2 verify evidence/v02-l2/l2/package/safepatch-l2-v1.zip --trusted evidence/v02-l2/l2/package/allowed_signers
```

## Gözlem (ölçüm değil)

`package-path-1` 27 Ekim geliştirme koşusunda hafıza kapalıyken başarısız olmuştu: aynı seed (42), aynı strateji, aynı worker1 davranışı (o koşudan beri `worker1.py`'de yalnız bir yorum değişti). Üç denemenin üçü de geçmedi: iki kez güvenlik tanığı, bir kez derleme ([`evidence/v02-paket-gelistirme/yeni-baglamli-s42`](../evidence/v02-paket-gelistirme/yeni-baglamli-s42/l3-model/jobs/package-path-1.json)). Bu koşuda L2 örneğiyle ilk denemede geçti.

Bu **tek bir gözlemdir**: tek vaka, tek seed, kontrol kolu yok. L2'nin soğuk başlangıçtaki etkisi (H3) Hafta 9'daki A/B/C/C+L2 deneyinde ölçülecek.

## Sınırlar

- **Simüle onaylar.** Laboratuvar ve kurum tarafındaki onaylar gerçek insan onayı değil. Bu yüzden paket bir deney paketi. Deney paketleri ürün profilinde içeri alınamaz.
- **Deney anahtarı.** Anahtar parolasız ve yalnız bu koşu için üretildi; özel anahtar `.runtime` altında kaldı, depoya girmedi. Üretim anahtarının nasıl yönetileceği proje liderinin kararı ([L2_PAKETI.md](L2_PAKETI.md), "Karar bekleyenler").
- **Kapsam.** Tek kayıt, tek aile (path), iki proje. Kaynak yalnız kendi laboratuvarımız; CVE düzeltme commit'leri henüz yok.
- **Sonradan eklenen denetim.** Koşudan sonra bir denetim eklendi ve birim testiyle sınandı: bir yayıncı başka bir yayıncının kaydının üzerine yazamaz. Bu koşuda tek yayıncı vardı; sonucu etkilemez.
