# Başarısızlık hafızası

Doğrulamadan geçemeyen bir aday da bilgi taşır: "bu kodda, bu sözleşmede bu yama işe yaramadı". Bu belge Hafta 3'te eklenen başarısızlık hafızasını anlatır (ROADMAP.md Hafta 3; H1 hipotezindeki "başarısızlık bilgisi").

Kod: `safepatch/memory.py` (`record_failure`, `failures`, `failure_records`), `safepatch/feedback.py` (`patch_caused`), `safepatch/engine.py`. Testler: `tests/test_failure_memory.py`.

## Ne kaydedilir

Her başarısız doğrulamadan sonra kayıt yazılır: model yaması, hafızadan tekrar ya da uzman yaması. Yalnız **yamanın kendisinin** neden olduğu başarısızlıklar girer. Altyapı hatası düzeltme hakkında bir şey öğretmez. Sınıflandırıcı (`feedback.classify`) bu durumları ayrı bir `infrastructure` sınıfına ayırır. Model işi bu sınıfta yeniden denemeden `infrastructure_error` ile durur. Uzman yaması ise uzmana geri döner.

| Kaydedilir | Kaydedilmez |
|---|---|
| Derleyici tanısı olan derleme hatası | Tanısız derleme hatası (çevrimdışı Maven önbelleği, zaman aşımı) |
| Davranış testi gerilemesi | JUnit raporu oluşmayan test koşusu |
| Güvenlik tanığının yakaladığı açık | Güvenlik tanığı olmayan proje |
| Yeniden taramada kalan bulgu | Sınıflandırılamayan sonuç |
| | Politika reddi (yama hiç çalışmadı; ret işin kaydında kalır) |
| | Değerlendirme (deney) işleri: L3 verisi kurum hafızasına girmez |

## Kayıt şeması (`safepatch-failure/1`)

| Alan | İçerik |
|---|---|
| `context` | Onaylı kayıtlarla aynı bağlam: proje, CWE ailesi, kural (yalnız izlenebilirlik), JDK, dosya yolu, build ve test sözleşmesi özetleri, kaynak özeti ([uygunluk kararı](HAFIZA_UYGUNLUK.md)) |
| `context_sha256` | Bağlam imzası: zorunlu alanların özeti (kaynak özeti ve tarayıcı kuralı hariç); aynı sözleşmedeki farklı kod sürümlerini ve aynı zayıflığın farklı tarayıcı bulgularını gruplar |
| `patch_sha256`, `diff`, `changed_lines` | Başarısız aday |
| `origin`, `strategy`, `retry`, `model`, `author` | Adayı kim üretti: model modu ve özeti, yeniden deneme stratejisi ve seviyesi, uzman yazarı |
| `failure` | Başarısızlık sınıfı ve ayrıntısı: derleyici tanıları, düşen test adları, kalan kurallar |
| `occurrences` | Her görülüş: iş, deneme, sınıf, kanıt özeti (doğrulama sonucunun SHA-256'sı), zaman |
| `memory_ids` | Aday hafızadan geldiyse o kaydın kimliği (Hafta 5 geçersizleşmesi için) |

Aynı kaynakta aynı yama başka bir işte yine başarısız olursa yeni kayıt açılmaz, görülüş eklenir.

## Arama

Her yeni iş onaylı kayıtları ararken başarısızlık kayıtlarını da arar; sonuç işin kanıtında `memory_lookup.failures` alanındadır. Onaylı kayıtlardaki gibi yalnız `compatible` bağlamlar sayılır:

- `same_source`: aynı kaynak kod;
- `same_context`: aynı dosya, kural, build ve test sözleşmesi, farklı kaynak.

Sonuçta yalnız özet bulunur: kimlik, ilişki, sınıf, yama özeti, köken, görülüş sayısı. Hafızası kapalı işlerde (`memory_mode: off`) arama yapılmaz. Kayıtların listesi: `GET /v1/memory/failures` (kullanıcının projeleri).

## Şimdilik yapmadıkları

- Başarısız yama hiçbir zaman onaylı örnek olarak önerilmez; ayrı tabloda durur.
- Model başarısızlık kayıtlarını görmez. "Bu bağlamda şu kalıp çalışmadı" uyarısı Hafta 5'te (sıralama v1) eklenecek. O zamana kadar model istemleri ve H2 ölçümü değişmez. Uyarı eklenirken kayıttaki diff veri olarak kalmalı ve doğrulayıcı notu taklidi denetlenmeli.
  - *Güncelleme:* uyarı Hafta 5'te eklendi. 29 Ekim'den beri yine modele gönderilmiyor; yalnız kaydediliyor ve inceleyiciye gösteriliyor ([HAFIZA_UYGUNLUK.md](HAFIZA_UYGUNLUK.md), "Başarısızlık uyarıları").
- Kayıtların geçersizleşmesi Hafta 5'te.
