# Ar-Ge ve ticari doğrulama planı

## Savunulabilir hipotez

SafePatch'in araştırma konusu, sabit yerel modelin **hangi geçmiş düzeltmeyi hangi bağlamda yeniden kullanabileceği** ve **yanlış yamaların hangi bağımsız kontrollerle reddedileceğidir**. Yerel LLM, RAG, tekrar tarama veya CI bağlantısı tek başına yeni değildir. V0.1 bu iddiayı dar bir sentetik çalışma alanında ölçer; bilimsel yenilik veya ürün-pazar uyumu kanıtlanmış değildir.

## Yapılan ve yapılacak karşılaştırmalar

| Soru | V0.1 ölçümü | Ürün/pilot için gerekli ek çalışma |
|---|---|---|
| Hafıza süreyi azaltıyor mu? | Aynı model, seed ve bütçeyle A hafızasız / B kural bazlı örnek / C uygunluk kontrollü örnek veya exact replay | Farklı projeler, en az 3 seed, donanım tekrarları, p50/p95 ve güven aralıkları |
| Sonuç genelleniyor mu? | 3 sentetik aile, tekrar ve küçük varyantlar; bağımsız holdout değil | Proje/CVE/yama ailesine göre ayrılmış 20 geliştirme + en az 40 bağımsız değerlendirme vakası |
| Tarayıcı temizliği yeterli mi? | Aynı aday havuzunda yalnız tarama / derleme+tarama / tüm davranış ve güvenlik kontrolleri | Bağımsız uzman etiketleri, saldırı tanıkları ve kör değerlendirme |
| Yanlış hafıza kullanılıyor mu? | Uyuşmayan ve eksik önkoşullar, proje erişimi, geri çekme ve çalışan iş testleri | AST/veri akışı önkoşulları; yanlış kabul/yanlış ret maliyeti |
| İşletilebilir mi? | Yetki, idempotency, iptal, süre/deneme/token sınırı, kanıt hash'i, gerçek JAR staging/rollback | Yük, uzun süreli çalışma, çoklu replika, çökme kurtarma ve gerçek CI pilotu |
| Gerçekten kapalı ağ mı? | Sınırlı Linux ağ ad alanı probu; bütün sistem kanıtı değil | DNS/TCP/UDP/telemetri dahil tüm rollerden egress denemeleri; temiz restart; paket kaydı |
| Müşteri para öder mi? | Görüşme ve satış verisi yok | AppSec, Java ekip lideri, platform ekibi ve satın alma ile 8–12 görüşme; 2 ücretli pilot adayı |

Başarısız onarımlar ve altyapı hataları paydadan çıkarılmaz. Model üretim süresi, hafıza araması, toplam süre ve kabul oranı ayrı raporlanır. Birimler karıştırılmaz: unit test sayısı modelin doğru düzelttiği zafiyet sayısı değildir. Otomatik onay testleri gerçek insan onayı değildir.

## Pilot tasarımı

1. Kurum, kullanımına izin verdiği Java projeleri ve geçmişte uzman doğrulaması yapılmış bulguları seçer. Kaynak ve hafıza kurum içinde kalır.
2. İki hafta boyunca mevcut süreçte bulgu başına aktif mühendis ve inceleme süreleri ölçülür. Takvimde bekleme süresi ayrıca tutulur.
3. Benzer bulgular mevcut süreç ve SafePatch destekli süreç arasında dengeli atanır. Aynı kişi aynı yamayı iki kolda önceden görmez.
4. AppSec uzmanı yamaları araç kolunu bilmeden değerlendirir. Uygun olmayan öneri, yanlış güvenlik kabulü, normal davranış kaybı ve geri alma sayısı raporlanır.
5. 30 gün sonra tekrar açılan bulgu ve bakım maliyeti izlenir. Satın alma niyeti ve ücretli pilot kararı ayrı kanıttır.

Başarı eşikleri müşteriyle pilot öncesi sabitlenmelidir. Örnek hedef: yanlış güvenlik kabulü artmadan aktif mühendis süresinde en az %25 azalma. **Bu %25 ölçülmüş bir sonuç değildir.**

## Maliyet ve fiyatlama

Toplam maliyet = ilk kurulum/uyarlama + GPU ve sunucu amortismanı + bakım/enerji + gerekli üçüncü taraf lisansları + uzman inceleme süresi. API'nin yerel ağa çağrılması internet kullanımı demek değildir. Yerel model kullanmak da tek başına sıfır sızıntı garantisi vermez.

Başlangıç teklifi için “sınırlı sayıda Java reposu, belirli kural kapsamı, kurum içi kurulum, yıllık destek” modeli denenebilir. Kullanıcı başına, repo başına veya kurum lisansı fiyatları müşteri görüşmesiyle sınanmalıdır. Bu teslimde fiyat, tasarruf, satış olasılığı veya müşteri talebi uydurulmamıştır.

Finans ve savunma müşterisinde karar verici yalnız geliştirici değildir. AppSec hatalı onarım riskine, platform ekibi offline bağımlılık ve bakım yüküne, geliştirici doğru diff ve kolay incelemeye, satın alma lisans/yerinde destek ve sorumluluk paylaşımına bakar. Bunlar müşteri görüşmesinde doğrulanacak ihtiyaç hipotezleridir.

## Rekabeti nasıl değerlendireceğiz?

Sonar AI CodeFix, ayrı bir ürün olan [Sonar Remediation Agent](https://www.sonarsource.com/products/sonarqube/remediation-agent/), GitLab'ın zafiyet çözüm özellikleri, Semgrep'in geçmiş düzeltme kullanan özellikleri ve APR araştırmaları karşılaştırma kapsamına alınmalıdır. Sonar Remediation Agent kapalı döngü düzeltme ve doğrulama sunar; “Sonar yalnız önerir” iddiası bütün ürün ailesine genellenemez. Dağıtım ve lisans kapsamları [araştırma ön çalışmasında](ARASTIRMA_ONCALISMASI.md) ayrılmıştır. Güncel yetenekler ve paketler değiştiği için satın alma öncesi sağlayıcıyla doğrulanır. Hiçbiriyle bu donanımda lisanslı başa baş performans testi yapılmadı; “rakiplerden daha iyi” iddiası yoktur.

Farklılaşma hedefi: ölçülebilir önkoşul uygunluğu, yanlış yama kabulünü azaltan bağımsız testler, geri çekilebilir kurum hafızası ve kurumun offline işletme yükünün azaltılması. Müşteri bunları zaten kendi CI sisteminde kurmuşsa değer önerisi zayıflayabilir; pilot bunu da ölçmelidir.

## TÜBİTAK başvurusuna aktarılacak kanıt

- Teknolojik belirsizlik: benzer yamanın güvenle taşınabileceği koşulları çıkarmak ve eksik bilgide çekimser kalmak.
- Ar-Ge iş paketleri: uygunluk çıkarımı, bağımsız kabul tanıkları, geri çekme etkisi, bütçeli otomasyon ve kontrollü deney.
- Ölçülebilir çıktılar: doğru/yanlış kabul, kapsama, başarısızlık türleri, toplam süre, gerçek insan inceleme süresi ve yeniden açılan bulgu.
- Ön çalışma kanıtı: bu depodaki ham koşular, JUnit ve karşılaştırma raporları. Sentetik sonuçların gerçek kurum başarısı olmadığı başvuruda açık yazılır.
- Ticari kanıt: görüşme notu, pilot protokolü, ücretli pilot/niyet mektubu. Bu teslimde henüz yoktur.
