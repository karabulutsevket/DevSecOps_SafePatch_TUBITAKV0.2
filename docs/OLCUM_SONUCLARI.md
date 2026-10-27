# SafePatch V0.1 — ölçüm sonuçları

Sonuçlar bu makinede gerçekten çalıştırılan komutlardan üretilmiştir. Ham JSON/CSV ve JUnit dosyaları `evidence/` içindedir.

## Doğrulama testleri

| Paket | Geçen | Hata / başarısız | Kapsam |
|---|---:|---:|---|
| Birim / sözleşme | 87 | 0 | Yetki, politika, hafıza, bütçe, tarayıcı sözleşmeleri |
| Java entegrasyonu | 9 | 0 | Gerçek Maven/JUnit; elle yazılmış referans ve negatif yamalar |
| Staging / rollback | 1 | 0 | Gerçek JAR süreçleri; insan onayı simüle |

## Gerçek model karşılaştırması

18 değerlendirme koşusunda 6 aday insan incelemesine hazır oldu. Bu sayı 18 farklı zafiyet anlamına gelmez: 3 sentetik aile, aynı kaynak tekrarı ve küçük kaynak varyantları kullanıldı. Hafıza hazırlığı ayrıca 3 gerçek model koşusudur; yalnız SQL örneği geçti ve 1 hafıza kaydı oluşturuldu.

| Kapsam | Yaklaşım | Kabul / koşu | Tüm koşuların ortancası (sn) |
|---|---|---:|---:|
| recurrence | off | 1/3 | 56,9 |
| recurrence | naive | 1/3 | 60,6 |
| recurrence | guarded | 1/3 | 60,1 |
| variant | off | 1/3 | 67,8 |
| variant | naive | 1/3 | 69,7 |
| variant | guarded | 1/3 | 68,6 |

Aynı SQL kaynağında A hafızasız 56,9 sn, B örnekli 57,8 sn, C yeniden uygulama 46,7 sn sürdü. Bu tek eşleştirilmiş örnekte C toplam süresi A’dan %17,8 daha kısadır. C model çağrısı yapmadı; doğrulama yine çalıştı.

Varyantta hafıza örneği modele ek bağlam getirir; hız kazanımı otomatik değildir. Aynı kaynakta kaydedilmiş yamayı uygulamak ile yeni projeye genellemek farklı deneylerdir. Path ve command için hazırlıkta uygun hafıza oluşmadığı için bu kollarda hafıza boş kaldı. Bu nedenle üç aile için F1 üstünlüğü iddia edilemez.

Karşılaştırma tek seed ile yapıldı. Sıralama dengeli döndürüldü; model/GPU paylaşan başka benchmark çalıştırılmadı, ancak makine ayrılmış laboratuvar sunucusu değildir. Isınma, OS yükü, Semgrep süreç başlatma ve önbellek etkileri vardır. n=3/kol, bağımsız aile sayısı 3 olduğundan p95/popülasyon güven aralığı ve genel hız iddiası yayımlanmıyor. İnsan zamanı ölçülmedi.

İlk 18 koşu FastAPI 0.116.1 / Starlette 0.47.3 ortamında ölçüldü. Bağımlılık taraması sonrası teslim sürümü FastAPI 0.141.1 / Starlette 1.6.0 / pytest 9.1.1 ile tekrar test edildi. Aşağıdaki release smoke güncel ortamın gerçek onarım/hafıza akışıdır; eski ölçümler güncel ortam sonucu gibi etiketlenmez.

## Güncel teslim ortamı: gerçek uçtan uca kontrol

Yeni runtime ile SQL onarımı 67,2 sn, yeniden uygulama 50,9 sn. Model + HTTP worker servisleri + gerçek Java/Semgrep kullanıldı. Kontrol API’si in-process HTTP test istemcisiyle çağrıldı. İzole test DB’sinde reviewer rolü simüle edilerek onay, hafızaya alma ve geri çekme doğrulandı. Geri çekme sonrası durum: `needs_human`. Gerçek insan onayı veya üretim dağıtımı değildir.

## Kabul yöntemi karşılaştırması

| Kapı | İyi aday kabulü | Kötü adayın yanlış kabulü |
|---|---:|---:|
| V0_scanner_only | 3/3 | 6/6 |
| V1_build_and_scanner | 3/3 | 6/6 |
| V2_full_acceptance | 3/3 | 0/6 |

Aynı 9 adayın gerçek derleme/test/tarama sonuçları üç kapı için değerlendirildi. Adaylar elle yazılan 3 referans onarım ve 6 kasıtlı işlev bozma örneğidir. Bu sonuç, genel dünyada sıfır yanlış kabul garantisi değildir. Gerçek modelin path önerisinde tarama temizken güvenlik tanığının başarısız olması da ham koşularda görülebilir.

## Bağımlılık ve ağ kanıtı

İlk Python kilidinde 27 paketten 2 paket için OSV kaydı bulundu: Starlette ve pytest. Güncelleme sonrasında 28 paket için sorguda 0 eşleşme bulundu. Bu, sorgu tarihindeki Python kilidiyle sınırlıdır; Java/image/model taraması veya zafiyetsizlik garantisi değildir. Kaynak kod gönderilmedi; yalnız bu açık kaynak paket adları ve sürümleri internetli hazırlık aşamasında sorgulandı.

Linux `unshare -Urn` probunda boş route tablosu ve dış bağlantı denemesinde ENETUNREACH ölçüldü. Bu yalnız probun ağ ad alanını doğrular; Maven, model, bütün host veya airgap sertifikasyonu değildir. Native runner aynı kullanıcıyla çalışır.

## Yapılmayan ve ayrıca gereken ölçümler

Canlı SonarQube/CodeFix, Snyk, Trivy/Grype entegrasyonu, Docker kötü niyetli build testi, tüm sistem paket kaydı, yüksek yük/HA, bağımsız holdout corpus, farklı model/GPU kıyası, AppSec uzman doğrulaması, gerçek geliştirici süresi ve müşteri ödeme isteği ölçülmedi. Protokoller `ARGE_VE_TICARILESME.md` içinde.
