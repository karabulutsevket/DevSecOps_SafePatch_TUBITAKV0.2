# SafePatch: teknik yenilik ve ticari fizibilite

> Bu ön araştırma uygulama geliştirilmeden önce hazırlanmıştır. Eski prototip test sayıları tarihsel bağlamdır. Teslim sürümünün güncel kanıtları için [ölçüm sonuçları](OLCUM_SONUCLARI.md) ve [çalışan mimari](CALISAN_MIMARI.md) esas alınmalıdır.

**Karar: devam edin; ilk ürünü daraltın.** SafePatch, bütün güvenlik araçlarını birleştiren genel bir DevSecOps platformu yerine, kurum içinde çalışan **Java yama doğrulama ve güvenli yeniden kullanım ürünü** olarak konumlandırılmalı. Hedef, daha fazla yama üretmekten önce geliştiricinin güvenle kabul edebildiği düzeltme sayısını artırmak ve inceleme emeğini azaltmak olmalı. Bu, ticari olarak sınanmaya değer bir öneridir; bugün kanıtlanmış bir satın alma gerekçesi değildir.

**Doğrulanmış bulgu:** Yerel LLM, geçmiş düzeltme getirme, yeniden tarama ve insan onayı ayrı ayrı mevcut çözümlerde bulunuyor. Sonar AI CodeFix için tamamen yerel yapılandırma belgeleniyor. Ayrı bir ürün olan Sonar Remediation Agent ise kapalı döngü düzeltme ve doğrulama sunuyor. GitLab da self-hosted model altyapısında zafiyet çözümünü belgeliyor. “Sonar sadece önerir; biz ilk kez düzeltip yeniden tararız” iddiası ürün ailesinin tamamı için artık savunulamaz.[^6][^7][^8]

**Çıkarım:** Kurum için en anlamlı fark, bir yamanın başka bir projeye ne zaman aktarılabileceğini açıklamak, uygun örnek yoksa bunu bilmek ve tarayıcının kaçırdığı davranış kaybına karşı ek kanıt sunmaktır. Rakiplerden daha iyi olduğumuz ancak aynı iş yükünde, benzer maliyetle, doğru kabul edilen yamalar ve insan zamanı ölçülerek gösterilebilir.

| Öncelik | Önerilen yatırım | Başarı koşulu |
| --- | --- | --- |
| 1 - Ar-Ge | Geçerlilik koşullarını denetleyen düzeltme hafızası | Basit benzerlik aramasından daha az yanlış aktarım; daha çok doğru düzeltme. |
| 2 - Ar-Ge | Güvenlik davranışı ve işlev kaybını birlikte değerlendiren kabul yöntemi | Gizli değerlendirme testlerinde hatalı kabulü azaltırken faydalı yama üretimini koruma. |
| 3 - Ürün | Kurum içi kurulum ve commit/paket ile bağlı inceleme kanıtı | Kurulum ve inceleme yükünün ölçülmesi; ücretli pilot ve yenileme gerekçesi. |

**Mevcut kanıt:** Yerel prototipte bir SQL injection düzeltmesi gerçek modelle 118 saniyede incelemeye ulaşmış; diğer dar senaryolarda retler var. 69 başarılı sistem testi, 69 başarılı yapay zekâ düzeltmesi demek değildir. Canlı SonarQube, onaylı hafıza, kurumsal ağ izolasyonu ve müşteri pilotu tamamlanmış değil.[^1]

**Hipotez:** İlk erişilebilir müşteri, Java/Spring kullanan ve bir finans kuruluşuna yazılım sağlayan, çalışan CI hattı bulunan bir yazılım ekibi olabilir. Büyük bir bankaya veya savunma ana yüklenicisine doğrudan satıştan önce bu varsayım görüşmelerle sınanmalı. Sonuç başarısızsa kaynak kodu düzeltmesinden, dışarıdan üretilen yamaların doğrulanması ve inceleme kanıtı hizmetine geçmek değerlendirilmelidir.

Araştırma kesiti 12 Eylül 2026’dır. “Doğrulanmış bulgu”, atıf yapılan kaynağın veya proje kaydının desteklediği bilgidir; üretici beyanının bağımsız performans doğrulaması olduğu anlamına gelmez. “Çıkarım” analitik değerlendirmeyi, “hipotez” deney veya müşteri kanıtı gerektiren beklentiyi belirtir.

## 1. Müşteri ihtiyacı ve ilk pazar

**Doğrulanmış bulgu:** JPMorganChase kendi mühendislik anlatımında araç çoğalmasını azaltmayı, standart geliştirme kalıplarını ve güvenlik kontrollerini ortak bir geliştirici platformunda birleştirmeyi önemsiyor. Bu, büyük kurumlarda entegrasyon ve öngörülebilirliğin değerini destekler; yeni bir güvenlik ekranı satın alınacağını kanıtlamaz. Aynı zamanda güçlü bir “kurum içinde kendimiz yaparız” alternatifini gösterir.[^2]

DORA’nın teknik düzenlemesi, kapsama giren finansal kuruluşlarda zafiyet/yama yönetimi ile test, onay, değişiklik kaydı ve geri dönüş süreçlerini ele alır. NIST SSDF de zafiyetlerin nedenlerini giderip tekrarını önlemeyi güvenli geliştirmeye bağlar. Bunlar kanıt ve süreç ihtiyacını destekler; bütün Türk bankaları veya savunma tedarikçileri için mutlak internet yasağı çıkarılamaz. BDDK’nın ilgili yönetmelik listesi bulunmuş olsa da güncel konsolide metnine erişim doğrulanamadığından bu rapor BDDK adına özel bir air-gap yükümlülüğü ileri sürmez.[^3][^4]

| Öncelik / sorun | Satın alınabilecek sonuç | Sahada toplanacak kanıt |
| --- | --- | --- |
| P1 - İnceleme ve bağlam | Yamanın neyi değiştirdiğini ve hangi koşulları koruduğunu kısa kanıtla sunma | Son 20 bulguda aktif inceleme süresi; bekleme süresinden ayrı. |
| P1 - Hatalı düzeltme | Uyarıyı sustururken işlevi bozan yamayı eleme | Ret gerekçeleri, yeniden açılan bulgular, geri alınan değişiklikler. |
| P2 - Tekrarlayan kalıplar | Onaylı çözümü uygun Java/API bağlamında tekrar kullanma | Aynı neden ve düzeltme stratejisinin gerçek tekrar sıklığı. |
| P2 - Eski Java ve eksik test | Desteklenen JDK/bağımlılık matrisinde güvenilir derleme; eksik kanıtta insan kararı | Derlenebilir depo oranı, mevcut güvenlik testleri ve test kararsızlığı. |
| Koşullu - Veri yerleşimi | Kodun ve işlem verisinin izin verilen kurum ağında kalması | Yazılı veri sınıflandırması, izinli bağlantılar ve güncelleme prosedürü. |

**Segment seçimi - çıkarım:** İlk sırada erişilebilir bir Java yazılım tedarikçisi; ikinci sırada orta ölçekli finans/fintek kuruluşunun AppSec ekibi; üçüncü sırada büyük banka veya savunma ana yüklenicisi önerilir. Bu sıralama ölçülmüş satış süresi değildir. Savunmada hedef uygulamanın gerçekten Java olması, sınıflandırma seviyesi, tesis/tedarikçi koşulları ve modeli çalıştırma yetkisi erken doğrulanmalıdır.

Günlük kullanıcı Java geliştiricisi ve kod inceleyicisidir. Teknik değerlendirmeyi AppSec ve platform/DevOps lideri birlikte yapar. Bütçe sahibi kurumuna göre mühendislik yöneticisi, CISO veya BT yöneticisi olabilir; satın alma ve hukuk ayrıca etkiler. Onay beklemesi darboğazsa daha hızlı LLM tek başına değer üretmez. Yanlış pozitif oranı yüksekse ilk müdahale tarama profili ve triage sürecine olabilir.

Moderne’nin anonim banka vakası otomatik kod dönüşümüne ticari ilgi için bir üretici sinyalidir. SafePatch’e ödeme isteği, Türkiye’deki uygun müşteri sayısı ve savunma Java zafiyet hacmi henüz bilinmiyor. Pazar büyüklüğü için genel siber güvenlik harcaması yerine erişilebilir hesaplar, uygun depolar ve yıllık çözülebilir iş yükü sayılmalıdır.[^5]

## 2. Rakipler: kurulum, model ve lisans

Tablo, erişilen güncel ürün belgelerini karşılaştırır. **“Belgeli offline” üreticinin desteklediği yapılandırmadır; bağımsız ağ doğrulaması değildir.** “Doğrulanamadı” yokluk iddiası değildir. Tek bir markanın bulut ve yerel ürünlerinin yetenekleri birbirine aktarılmamıştır.

| Ürün / hedef / dil | Kurulum ve model | Lisans, kapsam ve kanıt |
| --- | --- | --- |
| SonarQube AI CodeFix<br>Mevcut Sonar müşterileri; Java dahil seçili diller | Server Enterprise / Data Center. Kurum içi OpenAI uyumlu gateway ve yerel model belgeli; tümü yerel kurulum outbound erişimsiz tasarlanmış. | CodeFix Community özelliği değil. Kurumsal bedel kapsam/teklife bağlı; seçilen gerçek sürümde doğrulama gerekir.[^6][^41] |
| Sonar Remediation Agent<br>Kurumsal geliştirme; desteklenen Sonar bulguları | İncelenen teklif SonarQube Cloud Enterprise; GitHub/Azure DevOps akışı. Tam yerel dağıtım doğrulanamadı. | Ayrı ürün/özellik. Sandbox ve kapalı döngü üretici beyanı; bu raporda bağımsız başarı deneyi yok.[^7] |
| GitLab Duo / Agent Platform<br>GitLab ekipleri; Java bulguları dahil | Self-Managed / Dedicated for Government; self-hosted gateway ve desteklenen modeller. Offline kurulum belgeli. | Vulnerability Resolution self-hosted: 18.1.2+, beta; ilgili Ultimate/Duo yetkileri. Agent Platform offline: ELA + Self-Hosted eklentisi; teklif.[^8][^9][^42] |
| Semgrep Assistant / Workflows<br>AppSec ekipleri; Java dahil | Assistant geçmiş teknik tasarımı bulut hizmeti; Workflows yönetilen altyapı sunar. Yerelde özel iş akışı çalışması tüm sistem için air-gap kanıtı değil. | Workflows beta. Bu tam kapalı kurulum için kapsam ve fiyat doğrulanamadı.[^10][^11] |
| CodeThreat GenAI<br>AppSec; Java desteği pilotta teyit edilmeli | Üretici kurum içi GenAI entegrasyonu tanımlar. Tam internet kesintisinde bütün bağımlılıklarıyla çalışma doğrulanamadı. | On-prem öneri üretimi doğrudan yakın alternatif. Türkiye Siber Güvenlik Kümelenmesi kataloğunda ürün kaydı var; fiyat teklifi gerekir.[^12][^13] |
| Mend SAST Gen 2<br>AppSec; Java dahil | Belgelenen AI akışında kod parçacıkları Mend tarafından yönetilen modele gider. Müşterinin yerel modeliyle tam offline akış doğrulanamadı. | SAST yetkisi ve AI koşulları geçerli; teklif. “On-prem platform” ifadesi AI işlevinin de offline olduğu anlamına gelmez.[^14] |
| Snyk<br>Geliştirici/AppSec; Java kaynak ve bağımlılıklar | Code Local Engine yeni kurulum almayan eski seçenek; sonuçlar SaaS’a aktarılır. Broker/yerel tarama tam air-gap sayılmaz. | Team kamuya açık başlangıcı ürün/geliştirici başına 25 USD/ay; Enterprise teklif. Bu, istenen kapalı ağ paketinin fiyatı değildir.[^15][^16] |
| OpenRewrite / Moderne<br>Java modernizasyon ve güvenlik dönüşümü | Tarifler Maven/Gradle içinde çalışabilir. Moderne CLI lisansını yerelde doğrulayabilir; tüm platform için offline kapsam ayrıca sınanmalı. | Açık kaynak araç ile özel tarif/DX/Connector lisansları ayrı. Özel depo için Moderne yetkisi gerekebilir.[^17][^18][^19] |
| Kurum içi LLM + mevcut CI<br>Platform ekibi; seçtiği Java kapsamı | Kurum kendi sunucusunu, modelini ve ağını seçer. Offline yeterlilik kendi kurulum testine bağlı. | Yazılım kadar geliştirme ve bakım emeği maliyeti var. Satın alma karşılaştırmasında mutlaka yer almalı. |

## 3. Rakipler: düzeltme ve doğrulama akışı

Kaynak kodu, bağımlılık sürümü ve konteyner imajı düzeltmeleri farklı işlerdir. Trivy/Grype gelecek tarama seçenekleridir; Java yama üreticisi olarak puanlanmamıştır.

| Ürün | Hafıza / düzeltme kapsamı | Kontrol, insan ve Git/CI |
| --- | --- | --- |
| Sonar AI CodeFix | Seçili kaynak kodu bulgularına öneri. Kurumun onaylı yamalarını getiren hafıza doğrulanamadı. | IDE üzerinde uygula/reddet akışı belgeli. Bu CodeFix belgesinde genel derleme + işlev testi + sınırlı tekrar yürütücüsü doğrulanamadı.[^6] |
| Sonar Remediation Agent | Kaynak kodu düzeltme ajanı. Kuruma ait onaylı yama hafızası doğrulanamadı. | Sandbox, tekrar tarama/iyileştirme ve incelemeye PR belgeli. Test kapsamının müşteri Java davranış sözleşmelerini ne ölçüde kapsadığı pilotta görülmeli.[^7] |
| GitLab Duo | Desteklenen SAST CWE bulguları için çözüm. Kurumsal onaylı yama RAG’i doğrulanamadı. | MR ve pipeline doğrulaması akışta yer alır. Self-hosted beta çözümleme ile genel Agent Platform GA durumu ayrıdır; her MR’da otomatik çalışan tüm test/retry ayrıntıları varsayılamaz.[^8][^9] |
| Semgrep | Assistant tasarımı önceki düzeltme difflerini getirir; kural ve veri akışından yararlanır. Bu, basit yama hafızasının doğrudan öncülüdür. | Öz inceleme ve yeniden Semgrep taraması belgeli. Genel derleme/güvenlik test döngüsünün tüm hazır iş akışlarında varlığı doğrulanamadı; Workflows ek otomasyon sunar.[^10][^11] |
| CodeThreat | Kaynak güvenliği için GenAI önerileri; onaylı kurum hafızası doğrulanamadı. | CI/CD entegrasyonu katalogda var. Yamanın otomatik uygulanması, izole derleme, davranış testi, tekrar ve onay kanıt zinciri bütünü doğrulanamadı.[^12][^13] |
| Mend | SAST düzeltme önerisi; Java dahil. Bu özellikte geçmiş kurum yamalarının getirilmesi doğrulanamadı. | Depo ve platform üzerinden düzeltme akışı. Tam yerel kabul kapısı ve bütün test/retry zinciri doğrulanamadı.[^14] |
| Snyk | Code ve Open Source farklı ürün kapsamlarıdır; kaynak kodu ile bağımlılık işlerini tek başarı metriğinde toplamayın. | Yerel tarama açıklaması SaaS bağımlılığını ortadan kaldırmaz. Bu araştırmada tam kapalı Java düzeltme/onay zinciri teyit edilmedi.[^15][^16] |
| OpenRewrite / Moderne | Belirli dönüşümler için tarifler; LLM bağlamına geçmiş yama getirme ile aynı mekanizma değil. | Tekrarlanabilir dönüşüm + Git farkı. İşlevin korunması için proje testleri ayrıca gerekir; tarif seçimi/önkoşul denetimi yakın alternatif.[^17][^18] |
| Kurum içi çözüm | Kurum kendi RAG’ini ve sabit modelini kurabilir. | CI, test, PR ve onay zaten mevcut olabilir. SafePatch’in bunları tekrar satması için daha az bakım veya daha iyi doğru-kabul sonucu göstermesi gerekir. |

**Olgunluk ve denetim notu:** Yerleşik bir şirketin varlığı belirli AI özelliğinin olgunluğunu kanıtlamaz. Karşılaştırılabilir bağımsız air-gap pilot verisi bulunamadı. Rol ayrımı, audit log kapsamı, saklama/aktarma politikası, onayın paket özetiyle bağlanması ve yeniden taramanın aynı commit’e ait olması her teklif için ayrıca test edilmelidir.

**Satın alma yaklaşımı:** Müşterinin uygun Sonar CodeFix yetkisi zaten varsa onu alternatif yama sağlayıcısı olarak aynı değerlendirmeye alın. CodeFix ile yerel LLM birbirinin zorunlu karşıtı değildir; CodeFix de yerel LLM kullanabilir. SafePatch’in değeri yama kaynağından bağımsız seçim, doğrulama ve kanıt olmalıdır.

## 4. Literatür ve özgünlük sınırı

| Çalışma / durum | Örtüşme | SafePatch için kalan soru |
| --- | --- | --- |
| RAP-Gen<br>FSE 2023 | Geçmiş düzeltme getirme, hibrit arama ve CodeT5 ince ayarıyla genel program onarımı; Java değerlendirmesi var.[^20] | Sabit yerel model + hafıza kavramı tek başına katkı sayılmaz. Kurumsal geçerlilik koşullarının yararı ayrıca ölçülmeli. |
| RAVEN<br>21 Haziran 2026; under review | Birden çok getirici, kod grafiği, örnek seçimi, bağlam toplama ve Semgrep geri bildirimiyle yama üretimi.[^21] | Son değerlendirmede bilinen referans düzeltme/commit bilgisine bakan LLM ve CodeBLEU kullanılıyor. Bu başarı ölçütü müşteride referans yama olmadan çalıştırılan güvenlik testleriyle eş tutulamaz. |
| InferFix<br>FSE 2023 | Getirme + LLM; Java/C#. Bölüm 8, Microsoft iç CI ortamında PR, build/test ve Infer ile yeniden analiz kullanımını anlatır.[^22] | “Akademi yalnız betiktir, CI entegrasyonu yoktur” doğru değil. Yazar anlatımı SafePatch’in ticari doğrulaması veya tüm kurulumların air-gap kanıtı değildir. |
| KeaRepair<br>1 Temmuz 2026; ön baskı | Geçmiş zafiyet/yama bilgisi, programdan doğrulanan bulgular ve derleme + PoC + test yürütülen kapalı döngü; 55 C/C++ vakası.[^23] | Hafıza + gerçek test de literatürde mevcut. Java ve küçük model uygulaması tek başına yeni algoritma değildir. |
| Shibboleth<br>ISSTA 2022 | Java APR yamalarının doğruluğunu üretim/test koduna etkisi üzerinden değerlendirme; testleri geçen hatalı yamalar temel problem.[^24] | Test yeterliliğini sorgulamak yeni değil. Güvenlik davranışı, kapsam ve maliyeti birleştiren yöntemin ek faydası gösterilmeli. |
| CodePoisonRAG<br>2 Eylül 2026; under review | Model ağırlıklarını değiştirmeden getirme havuzuna zehirli bilgi eklenmesinin etkisini inceler.[^25] | Onaylı hafıza da güven sınırıdır. Kaynak doğrulama ve iptal tasarımı gerekli; makalenin saldırı oranları doğrudan kurum içi ürün riskine taşınamaz. |

**Çıkarım:** Savunulabilir Ar-Ge iddiası, “bilinen bileşenleri bir araya getirdik” cümlesinden daha dar olmalıdır. Önerilen problem şudur: **Java güvenlik yamalarının aktarılabilirlik koşullarını ve mevcut testlerin ayırt etme gücünü birlikte kullanarak, sınırlı hesaplama bütçesinde doğru kabul edilen düzeltme sayısını artırabilir miyiz?** Bu birleşimin özgün olduğu henüz ispatlanmış değildir; en yakın yöntemlerle deney ve ek literatür takibi gerekir.

RAVEN’in referans düzeltmeli değerlendirmesi ile gerçek müşteri ortamındaki kabul kararı ayrılmalıdır. Buna karşılık KeaRepair’in yürütülen PoC/test döngüsü yok sayılmamalıdır. Her iki bulgu da aynı sonucu verir: başarı yüzdelerini farklı diller, veri kümeleri, modeller ve doğruluk tanımları arasında doğrudan sıralamak yanıltıcıdır.[^21][^23]

Vul4J güvenlik odaklı Java değerlendirmesine uygun bir başlangıç kaynağıdır. Güncel depo PoV içeren örnekleri yalnız statik uyarı kontrolü içeren örneklerden ayırıyor; hepsini “çalıştırılmış saldırı testi” saymayın. Defects4J genel hata onarımı için tamamlayıcı olabilir, güvenlik zafiyet başarısının yerine geçmez.[^26]

## 5. Yenilik fırsatları ve öncelikler

**Analitik puanlama:** Aşağıdaki 10 üzerinden puanlar müşteri araştırması veya hakem değerlendirmesi sonucu değildir. Müşteri faydası %35, önceki çalışmalara karşı araştırılabilir fark %30, dar MVP’de uygulanabilirlik %20 ve taklit direnci %15 ağırlıklıdır. Yükler, Java/AppSec yetkinliği olan bir ekip için takvim taahhüdü olmayan kişi-ay tahminleridir; birbiriyle örtüşür ve toplanarak proje süresi çıkarılamaz.

| Fırsat | Fayda | Fark | MVP | Direnç | Ağırlıklı | Yük |
| --- | --- | --- | --- | --- | --- | --- |
| F1 - Koşullu hafıza | 8 | 7 | 7 | 7 | 7,4 | 3-5 kişi-ay |
| F2 - Kanıtla yama kabulü | 9 | 7 | 6 | 7 | 7,5 | 4-7 kişi-ay |
| F3 - İptal ve olumsuz deneyim | 7 | 5 | 8 | 6 | 6,5 | 1-3 kişi-ay |
| F4 - Tarif/LLM seçimi | 7 | 5 | 7 | 5 | 6,1 | 2-4 kişi-ay |
| F5 - Bütçeli seçici otomasyon | 7 | 6 | 5 | 6 | 6,2 | 2-4 kişi-ay |
| F6 - Offline kanıt ve kurulum | 8 | 3 | 7 | 5 | 5,9 | 2-4 kişi-ay |

**Seçim:** Ar-Ge omurgası F1 + F2 olmalı. F6, daha düşük yenilik puanına rağmen kurumun ürünü değerlendirebilmesi için gerekli ürünleşme işidir; temel sürümü MVP’ye girer. F3’ün kayıt, yetki ve iptal bölümü F1’e zorunlu güven yönetimi olarak eklenir. F4 ve F5 önce basit kurallarla yürütülür; etkileri ölçülmeden ayrı Ar-Ge iş paketlerine genişletilmez.

| Katman | Bu projedeki örnek | Başvuruda nasıl anlatılmalı? |
| --- | --- | --- |
| Standart mühendislik | SAST API, Git/CI, deneme sınırı, sandbox, insan onayı, log | Gerekli altyapı ve teslimat; tek başına özgün katkı değil. |
| Ticari farklılaşma | Kurulum süresi, yerel destek, açıklanabilir kanıt, mevcut araçlarla uyum | Müşteri zamanı ve toplam maliyetle doğrulanır. |
| Ar-Ge adayı | Yama uygulanabilirliği, test yeterliliği ve yanlış kabulü birlikte ele alan karar yöntemi | Belirsizlik, karşılaştırma yöntemi ve ölçülebilir başarısızlık koşulları açık yazılır. |

F1’in en yakın karşılaştırmaları Semgrep’in geçmiş düzeltmeleri getirmesi ile RAP-Gen/RAVEN’in getirme ve örnek seçme yöntemleridir. F2’nin karşılaştırmaları Shibboleth gibi doğruluk değerlendirme yöntemleri ve gerçek test kullanan KeaRepair akışıdır. Bu kaynaklar yeniliğin hazır bir iddia değil, sınanacak bir fark olduğunu gösterir.[^10][^20][^21][^23][^24]

**Savunulabilirlik:** Müşteriye ait yamaları kurumlar arasında taşımadan avantaj kurulabilir. Hakları açık test/karşı örnek kütüphanesi, sürümlere göre geçerlilik çıkarma yöntemi, entegrasyon kalitesi ve kurulum deneyimi ürün varlığı olur. Kurum içi hafıza müşteriye özgü değer sağlar; tek başına üreticinin müşteriler arasında büyüyen veri avantajı değildir. Kod tabanı ve adlandırma için patent/marka temizliği bu araştırmayla yapılmış sayılmaz.

## 6. Koşullu hafıza ve güven yönetimi

### F1. Geçerlilik koşullarını denetleyen düzeltme hafızası

**Problem ve yakın yaklaşım:** Aynı CWE veya benzer metin, aynı yamanın uygun olduğunu göstermez. JDBC düzeltmesinin ORM sorgusuna, dosya yolu kontrolünün farklı işletim sistemi veya sembolik bağlantı davranışına taşınması sorun çıkarabilir. Semgrep, RAP-Gen ve RAVEN getirme/seçim için yakın öncüllerdir; fark yalnız daha fazla metadata tutmak olamaz.[^10][^20][^21]

**Yöntem ve belirsizlik:** Her onaylı kayda kaynak/sink, Java ve kütüphane sürümü, kullanılan güvenlik API’si, veri akışı varsayımları, izin verilen davranış değişikliği ve destekleyen testler eklenir. Önce açık uyumsuzlukları eleyen filtre, sonra uygun örneği sıralayan yöntem çalışır. Araştırma sorusu, bu koşulların koddan ne kadar doğru çıkarılabildiği ve eksik bilgi halinde getirmeden vazgeçmenin toplam doğru düzeltmeye etkisidir. LLM’in kendi uygunluk açıklaması tek kanıt kabul edilmez.

**Deney:** Aynı modelde hafızasız ve basit kural+benzerlik getirmesiyle karşılaştırın. Özellikle sürüm, API ve yetki sınırı değişmiş vakalar kullanın; yanlış örnek aktarımı, doğru kabul/başvuru sayısı ve maliyeti ölçün. Gerekli veri, lisansı uygun geçmiş yamalar ve uzmanların işaretlediği geçerlilik/uyumsuzluk çiftleridir. Java program analizi ve AppSec uzmanlığı gerekir; ilk çalışma mevcut yerel model donanımıyla başlayabilir.

**Yük, değer ve risk:** Dar kapsam için 3-5 kişi-ay tahmini. Başlıca risk kısmi veri akışından aşırı kesin koşul üretmektir. Müşteri daha az tekrar inceleme için ödeme yapabilir; bunun için tekrar hacmi ölçülmelidir. Metadata şeması kolay taklit edilir, değerlendirilmiş koşul çıkarma yöntemi ve karşı örnek koleksiyonu daha zordur. MVP’de yalnız iki Java zafiyet ailesi ve birkaç API ile başlayın.

### F3. İptal edilebilir hafıza ve olumsuz deneyim

**Problem ve yakın yaklaşım:** İnsan onayı kalıcı doğruluk belgesi değildir. Bir örnek sonradan güvensiz, sürüm açısından eski veya yanlış kapsamlı bulunabilir. CodePoisonRAG, getirme içeriğinin bir güven sınırı olduğunu gösteren yakın tehdit çalışmasıdır; saldırı koşulları onaylı kurum havuzuyla aynı varsayılmamalıdır.[^25]

**Yöntem ve deney:** Kayıtlar taslak, onaylı, karantinada, iptal edilmiş durumlarında tutulur. Yama özeti, test kanıtı, köken, lisans, onaylayan ve geçerlilik aralığı saklanır. Hangi işlerin hangi kaydı kullandığı izlenir; iptal yeni kullanımı durdurur ve etkilenmiş işleri incelemeye açar. Bir ret yalnız başarısız bağlama ilişkin veri olmalı; her bağlam için evrensel yasak olmamalıdır. Eski, bozuk ve çelişkili örnekler ekleyerek yetkisiz getirme, iptal gecikmesi ve yanlış eleme oranı ölçülür.

**Kaynak ve değer:** 1-3 kişi-ay; güvenli veri yönetimi ve Java inceleme becerisi gerekir, ek büyük GPU gerektirmez. Temel yetki/iptal takibi standart mühendisliktir. Olumsuz deneyimden bağlama göre seçim yapmak Ar-Ge adayıdır. Denetlenebilir geri çağırma müşteriye değer sağlayabilir; tek başına kopyalanması zor bir teknoloji değildir. Temel durum makinesi MVP’ye, gelişmiş olumsuz örnek seçimi sonraya alınır.

## 7. Yama kabulü ve sınırlı kaynakta karar

### F2. Referans yama olmadan güvenlik ve davranış kanıtı

**Problem ve fark:** Uyarı kaybolduğu ve testler geçtiği halde yama yetkili kullanımı engelleyebilir, veriyi değiştirebilir veya yalnız tarayıcıyı atlatabilir. Shibboleth yama doğruluğu/test yeterliliği için yakın öncü; KeaRepair çalıştırılan test döngüsü için karşılaştırmadır. Öneri, yeni müşteri kodunda doğru referans yamaya erişmeden, seçili Java güvenlik davranışları için kabul edilebilir değişimi tanımlamaktır.[^24][^23]

**Yöntem ve belirsizlik:** Korunan testler ve uzman onaylı güvenlik sözleşmeleri üreticiden bağımsız tutulur. Savunmasız sürümde tehlikeli davranışı gösteren tanık test, yamalı sürümde güvenli sonucu arar; ayrıca meşru girdilerin davranışı sınanır. Güvenlik kontrolünü kaldıran veya işlevi kapatan sınırlı negatif kontrol yamalarıyla testlerin bunları ayırt edip etmediği ölçülür. Belirsizlik, bu testlerin kapsamadığı davranışlar ve test üreticisiyle yama üreticisinin ortak hatalarıdır. Yüksek coverage tek başına yeterlilik değildir.

**Deney ve kaynak:** Aynı aday yama havuzunu standart derleme+test+rescan ve önerilen kapıdan ayrı geçirin. Son doğruluğu, kapının görmediği testler ve iki uzmanın kör incelemesi belirlesin. Gerçek Java güvenlik vakaları, başarısız yama örnekleri ve alan davranışını bilen geliştirici gerekir. Test altyapısı CPU/derleme maliyeti de doğurur; yalnız GPU süresini ölçmeyin.

**Yük ve ticari değer:** 4-7 kişi-ay tahmini. En büyük risk, işlev sözleşmesini çıkarmanın manuel düzeltmeden pahalı olmasıdır. İlk kullanım SQL injection ve path traversal gibi dar ailelerle sınırlandırılmalı; kimlik doğrulama/iş mantığı açıkları sonraya bırakılmalı. Satın alma gerekçesi daha az hatalı kabul ve daha kısa uzman incelemesidir. Genel test döngüsü kolay taklit edilir; ölçülmüş karşı örnekler ve bağlama bağlı kabul yöntemi daha savunulabilirdir. MVP’de F1 ile birlikte temel araştırma bileşenidir.

### F5. Bütçeli ve gerektiğinde vazgeçen otomasyon

**Problem ve yakın yaklaşım:** Küçük bir yerel model sürekli yanlış yama üreterek GPU ve inceleme zamanını tüketebilir. RAVEN’in sınırlı ajan adımları ve KeaRepair’in iteratif doğrulaması yakın yöntemlerdir; deneme sayısına sınır koymak zaten standarttır. Fark adım sayısından çok, bir sonraki denemenin beklenen değerini gözlenen kanıtlardan belirlemektir.[^21][^23]

**Yöntem ve deney:** Kural kapsamı, bağlam eksikliği, derleme hatası türü, tekrar eden diff ve önceki test sonucu ile dur/yeniden dene/insana aktar kararı verilir. Modelin sayısal özgüvenine güvenilmez. Kalibrasyon yalnız geliştirme verisinde yapılır; ağırlıkları sabit LLM şartı korunur. Sabit üç denemeyle aynı zaman/token tavanında karşılaştırın; bütün işleri reddederek düşük hata oranı elde etmek başarı sayılmaz.

**Kaynak, yük ve risk:** 2-4 kişi-ay; yeterli başarısız deneme kaydı ve istatistiksel değerlendirme gerekir. Risk, kolay projelerde öğrenilen kararın başka projelerde aşırı ret üretmesidir. Müşteriye sunucu kapasitesi ve kuyruk süresi kazancı ancak doğru kabul kaybıyla birlikte sunulmalıdır. Taklit direnci orta-düşük; MVP’de mevcut limitler ve tekrar duruşu yeterli, uyarlanabilir yöntem daha sonra denenmeli.

## 8. Dönüşüm tarifleri ve kurumsal teslimat

### F4. Belirli dönüşüm tarifi ile LLM arasında seçim

**Problem ve yakın yaklaşım:** Tekrarlayan, açıkça tanımlı bir kod dönüşümü için her defasında serbest yama üretmek pahalı ve değişkendir. OpenRewrite/Moderne tarifleri bu alanda yerleşik alternatiftir. Deterministik dönüşümün kendisini veya Java’ya uyarlanmasını yeni icat gibi sunmak uygun değildir.[^17][^18]

**Yöntem ve belirsizlik:** Önkoşulu doğrulanan dar vakada lisansı uygun tarif uygulanır; uygun değilse yerel LLM’ye geçilir. Kurumun onayladığı tekrarlayan düzeltmelerden tarif adayı çıkarılabilir, ancak uzman incelemesi ve karşı örneklerle sınanması gerekir. Araştırma sorusu, güvenli tarif uygulanabilirliğini doğru tanıyıp yanlış genellemeyi azaltmanın maliyet/fayda etkisidir. “Aynı diff daha önce işe yaradı” yeterli değildir.

**Deney:** Tarif-only, LLM-only ve seçici birleşimi aynı vakalarda karşılaştırın. API/sürüm uyumsuzluğu ve yalnız görünüşte benzer kodları özellikle ekleyin. Derleme, güvenlik, davranış ve harcanan insan dakikası birlikte ölçülür. Veri, onaylı dönüşümler ile hem uygulanabilir hem uygulanamaz örneklerdir; AST/Java uzmanlığı gerekir. Ek GPU gereksinimi sınırlı olabilir; kazanç deneyle görülür.

**Yük ve değer:** 2-4 kişi-ay tahmini. Müşterinin çok tekrar eden kalıpları varsa hız ve tutarlılık için değer yaratır; aksi halde yeni bir tarif bakım yükü olur. Hazır tarife sarıcı yazmak kolay taklit edilir. Otomatik tarif türetme MVP dışında; ilk aşamada bir veya iki açık önkoşullu tarif, karşılaştırma ve maliyet kontrolü için yeterlidir. Tariflerin lisansı çekirdek araç lisansından ayrı incelenmelidir.[^18]

### F6. Offline kurulum ve yama ile bağlı kanıt paketi

**Problem ve yakın yaklaşım:** Kapalı ağda modelin çalışması tek başına yeterli değildir; kod, paket, lisans, tarama kuralı ve onay zinciri birlikte işletilir. GitLab’ın offline kurulum belgeleri, hazır alternatiflerin de bu konuyu ele aldığını gösterir. DORA kapsamındaki değişiklik/test gereksinimleri kanıt ihtiyacına dayanak olur; bu paket kendiliğinden mevzuat uyumu veya sertifika sağlamaz.[^42][^3]

**Bileşen ve deney:** Sürümlü offline kurulum paketi, hash/imza manifesti, izinli servis listesi, güncelleme prosedürü ve değişmez kanıt kaydı hazırlanır. Kanıt; temel commit, diff, model/prompt/hafıza sürümleri, tarayıcı profil özeti, test sonuçları, paket özeti ve insan kararını bağlar. Ağ tamamen kesildikten sonra temiz makinede kurulum/yeniden başlatma, kimlik süresi dolması, eksik paket ve geri dönüş senaryoları test edilir. Dış çıkış denemeleri ile başarılı dış iletişim ayrı kaydedilir.

**Kaynak, yük ve risk:** 2-4 kişi-ay; platform mühendisliği, PKI/kimlik ve güvenlik incelemesi gerekir. Müşterinin onaylı işletim sistemi, registry ve kimlik altyapısı olmadan süre kesinleşmez. Tüm ağları kapatmak yerine kurum içi zorunlu servisler açıkça tanımlanmalıdır. Docker socket veya üretim sırrı çalışan teste verilmemelidir.

**Ticari sınıflandırma:** Temel değer daha kolay kabul, bakım ve denetimdir; Ar-Ge yeniliği düşüktür. Taklit engeli çoğunlukla entegrasyon kalitesi ve saha deneyimidir. MVP’ye temel kurulum/kanıt zinciri girer; çok bölgeli HA, Kubernetes operatörü ve her müşteri için farklı özel platform ilk ürüne girmez.

## 9. Güncellenmiş ürün ve MVP mimarisi

**Ürün tanımı:** SafePatch, seçili Java güvenlik bulguları için kurumun geçerli onarım bilgisini kullanan, yerel modelin veya başka bir yama sağlayıcısının ürettiği değişiklikleri bağımsız kontrollerden geçiren ve onay kararını test edilmiş kod/paketle ilişkilendiren kurum içi bir yazılım bileşenidir. İlk teslimat incelemeye hazır PR ve kanıt paketi olmalı; üretim dağıtımı müşterinin mevcut yetkili hattında kalmalıdır.

| Adım | İşlev ve güven sınırı |
| --- | --- |
| 1. Başlangıç | Sabit commit ve hedef modül; scanner/Java/sürüm profili; önce derleme ve temel test durumu. Mevcut hata ile yamadan kaynaklanan hata ayrılır. |
| 2. Bulgu seçimi | Desteklenen kural ve veri akışı; hotspot ile doğrulanmış vulnerability ayrımı. Kapsam dışı veya eksik taramada “temiz” kararı verilmez. |
| 3. Hafıza ve öneri | Yetkili/onaylı kayıtları koşul filtresinden geçir; uygun örnek yoksa hafızasız çalış. Sabit yerel LLM veya uygun lisanslı alternatif yama sağlayıcısı. |
| 4. İzole yürütme | Geçici çalışma alanında diff sınırı; korunan testler; kaynak/süre sınırları; üretim sırları olmadan derleme ve uygulama testleri. |
| 5. Kabul değerlendirmesi | Güvenlik tanık testi, meşru davranış testleri ve yeniden tarama. Aynı analiz/commit eşleşmesi; eksik çıktı veya zaman aşımı onay sayılmaz. |
| 6. Sınırlı tekrar | En çok 3 deneme; toplam süre/token/diff bütçesi. Tekrarlayan yama, ilerleme yokluğu veya kapsam dışı değişiklikte dur. |
| 7. İnsan ve dağıtım | Diff, gerekçe, kalan belirsizlikler ve test kanıtı; yetkili insan kararı tam commit/paket özetine bağlanır. Değişiklik onayı geçersiz kılar. |
| 8. Hafızaya terfi | İnsan onayı + gerekli testler + birleşen commit eşleşmesiyle geçerli kayıt; dağıtım/geri dönüş sonucu sonradan eklenir. Hatalı örnek karantinaya alınır. |

**MVP sınırı:** Java 17, Maven ve seçili Spring/JDBC kullanım biçimleri; SQL injection ile path traversal için destek matrisi; tek kurum, tek kuyruk, mevcut Git/CI ile bir entegrasyon. Hafızada önce kural+API+sürüm gibi açık alanlar ve basit getirici yeterli; vektör veritabanı veya çok ajanlı yapı zorunlu değil. Yeni ikinci model, ilk yöntemi ölçmek için gerekli değil.

**Sonar kararı:** Community Build ücretsiz bir başlangıç adayıdır, hedef injection kurallarının varlığı garanti değildir. Gerçek savunmasız ve düzeltilmiş örneklerde kuralın etkinliğini, analiz kapsamını ve API sonucunu doğrulayın. Başarısızsa müşterinin uygun mevcut ücretli Sonar yetkisini kullanın veya pilot için daha uygun, lisansı açık bir tarama kaynağı seçin. Dar sentetik Semgrep kuralını kurumsal SAST kapsamı gibi sunmayın.[^27][^1]

**Sonraya bırakılacaklar:** Snyk/Trivy/Grype orkestrasyonu, bütün Java frameworkleri, kimlik doğrulama/iş mantığı açıklarının otonom onarımı, otomatik üretim dağıtımı, otomatik model eğitimi, kurumlar arası yama havuzu ve HA. Boş hafızada değer, korunan doğrulama ve inceleme kanıtından gelmeli; lisansı uygun başlangıç örnekleri yalnız ek destek olmalıdır.

## 10. Lisanslar ve kapalı ağ işletimi

**Tek lisansla bütün müşterilere kurulum varsayımı yapılmamalı.** İlk ticari modelde SafePatch kendi lisansını satar; müşteri gerekli üçüncü taraf haklarını kendi adına sağlar. Bu yaklaşım yeniden satış/OEM hakkı yerine geçmez. Ürün içine dağıtma, müşteriye hizmet olarak sunma, uyarıları kullanma ve bir rakip ürün için kıyaslama farklı izin sorularıdır.

| Bileşen | Doğrulanan durum ve satın alma sonucu |
| --- | --- |
| Sonar Community | Ücretsiz yapı; depodaki çekirdek lisans LGPL v3. Ticari kurulum hizmeti verebilmek, dağıtılan bileşenlerin bildirim/kaynak ve diğer lisans yükümlülüklerini ortadan kaldırmaz.[^27][^28] |
| Ücretli Sonar / CodeFix | 27 Ağustos 2026 Primary Agreement iç kullanım ve devredilemez/alt lisans verilemez haklar tanımlar. Yetkili reseller düzenlemesi ayrıdır. Kendi tek lisansınızı bağımsız müşterilere çoğaltmayın; kapsam için yazılı teklif/sözleşme gerekir.[^29][^43] |
| Sonar çıktısı ve hafıza | AI Annex müşteri kodu/düzeltmesini, Sonar’ın kural/prompt gibi özel mantığından ayırır. Müşteri yamasını tutmak ile üreticinin özel mantığını derlemek aynı hak değildir. Alerts, öneriler, yerel model logları ve RAG kullanımı için geçerli ürün eki/AUP birlikte incelenmeli.[^30] |
| Snyk | Hizmet şartlarında yeniden satış, service bureau, rakip kullanım ve belirli kıyaslama kısıtları vardır. Müşterinin lisans sahibi olması her entegrasyon/benchmark kullanımını otomatik izinli yapmaz; uygun yazılı ticari düzenleme gerekir.[^31] |
| Qwen2.5-Coder-7B-Instruct | İncelenen model Apache 2.0. Ticari kullanım/dağıtım seçeneği lisans koşullarıyla değerlendirilebilir. Paketlenen gerçek checkpoint, quantization kökeni ve bildirimler kaydedilmeli; bütün Qwen ailesi için genelleme yapılmaz.[^32] |
| DeepSeek-Coder-V2 | Model lisansının Attachment A bölümünde “For military use in any way” kısıtı var. Savunma kullanımına varsayılan seçenek yapılamaz; kullanım bağlamı ve haklar netleşmeli. Bu bulgu bütün DeepSeek modellerine uygulanamaz.[^33] |
| Trivy / Grype / tarifler | Trivy ve Grype kod lisansları Apache 2.0; veri kaynakları ve paketlenen bileşenler ayrıca incelenir. Moderne’nin bazı tarifleri ve ürünleri özeldir; hepsini açık kaynak saymayın.[^34][^36][^18] |

**Ağ mimarisi:** API çağrısı internet kullanımı demek değildir; kurum içi LLM servisine çağrı yerel ağda kalabilir. Tersine, on-prem kurulum tek başına internetsiz çalışma demek değildir. Çalışan sandbox için uygun ağ kısıtı; orkestratör için yalnız gerekli Git, model, tarayıcı, registry ve kimlik servislerine izin verilmelidir. **network none bütün sistemin veri sızıntısı riskini sıfırlamaz.** Yönetim arayüzü, loglar, paylaşılan diskler ve güncelleme kanalı da güven sınırıdır.

Maven/Gradle bağımlılıkları, container imajları, model dosyaları, tarayıcı kuralları ve zafiyet veritabanları kuruma kontrollü alınır. Kaynak/doğrulama manifesti, onaylı aktarım, güncellik yaşı, geri dönüş ve sorumlu kişi belirlenir. Trivy belgesi offline taramanın ayrıca veritabanı ve bağlantı ayarı gerektirdiğini gösterir. İnternet kesikken yeniden başlatma ve yeni iş tamamlanması ayrıca denenmelidir.[^35]

Lisans değerlendirmesi erişilen kamuya açık şartlara dayanır; müşterinin imzaladığı sözleşmenin yerini almaz. Belirli kurulum için sürüm, eklenti, kullanıcı/LOC kapsamı, offline lisans, destek erişimi ve veri kullanım hakları satın alma dosyasında yazılı olmalıdır.

## 11. Ticari model ve toplam maliyet

**Önerilen model - hipotez:** Sabit kapsamlı ücretli pilot; ardından kurum/kurulum başına yıllık yazılım ve bakım bedeli, ayrı ilk kurulum ücreti. Kapasite paketleri eşzamanlı iş/runner ve destek kapsamına bağlanabilir. Bulgu başına ücret, daha fazla uyarı üretmeyi ödüllendirebilir; ilk model olarak uygun değil. Süresiz lisans bazı satın almalara uyabilir fakat offline güncelleme ve destek için devam eden bedel gerekir.

Üçüncü taraf lisans ve müşteri GPU’su ayrı kalem olmalı. Enterprise Sonar, GitLab offline ve benzeri kapsamlar için teklif gerekir; giriş seviyesi web fiyatları bu kurulumun bütçesi değildir. CodeFix zaten lisanslıysa ek bir yama sağlayıcısını satın almak yerine mevcut özelliği ölçmek daha mantıklı olabilir.[^41][^8][^16]

### Tamamen varsayımsal örnek: tek kurum

| Kalem | Varsayım | Not |
| --- | --- | --- |
| SafePatch yıllık bedeli | 300.000 TL | Piyasa fiyatı veya doğrulanmış ödeme isteği değildir. |
| İlk kurulum | 80.000 TL | Tek Git/CI, standart destek profili; özel geliştirme hariç. |
| GPU/sunucu yatırımı | 200.000 TL | Teklif alınmamıştır; örnek sermaye gideri. 3 yılda dağıtılırsa 66.667 TL/yıl. |
| Yıllık işletim | 60.000 TL | Enerji, altyapı yönetimi ve offline güncelleme için örnek bütçe. |
| Ek üçüncü taraf lisansı | 0 TL + gerçek teklif | Sıfır yalnız mevcut hak/ücretsiz uygun kapsam senaryosudur. |
| İlk yıl nakit çıkışı | 640.000 TL + ek lisans | 300.000 + 80.000 + 200.000 + 60.000. |
| İlk yıl yıllıklaştırılmış maliyet | 506.667 TL + ek lisans | Donanımın 3 yıllık payıyla; nakit çıkışıyla karıştırılmaz. |

Tasarruf varsayımı: Doğru düzeltilip birleştirilen her işte net 45 dakika aktif mühendis emeği azalıyor; yüklü saat maliyeti 1.000 TL. Başarısız/geri dönen denemelerin ek incelemesi ayda 10 saat. Yıllık emek faydası = **N × 12 × 0,75 × 1.000 - 10 × 12 × 1.000**. N, aylık doğru kabul edilen iş sayısıdır; sadece üretilen yama sayısı değildir. Bekleme süresi ve olası ihlal zararı tasarrufa eklenmemiştir.

| Aylık doğru iş N | Net yıllık emek faydası | İlk yıl ekonomik sonuç |
| --- | --- | --- |
| 20 | 60.000 TL | -446.667 TL |
| 60 | 420.000 TL | -86.667 TL |
| 120 | 960.000 TL | +453.333 TL |

Bu varsayımlarla ilk yıl yıllıklaştırılmış başabaş yaklaşık **70 doğru iş/ay**; nakit çıkışını aynı yılda karşılamak için yaklaşık **85 iş/ay** gerekir. Donanım zaten varsa, ücret daha düşükse veya vakalar daha fazla zaman kazandırıyorsa sonuç değişir. Küçük düzeltme hacimli müşteri için ürün ekonomik olmayabilir. Donanım seçimi model adıyla değil bağlam uzunluğu, eşzamanlılık, VRAM/RAM, derleme yükü ve gerçek gecikme ölçümüyle yapılmalıdır.

**Üretici ekonomisi:** 300.000 TL yıllık bedelde, tamamen varsayımsal 60.000 TL/kişi-ay maliyet ve yılda iki kişi-ay müşteri desteği 120.000 TL tüketir; satış, genel gider ve Ar-Ge öncesi 180.000 TL kalır. Destek beş kişi-aya çıkarsa bu katkı sıfırlanır. Bu nedenle desteklenen kurulum matrisi, ücretli değişiklik talebi ve standart offline bakım paketi zorunludur. Gerçek fiyatlama pilot sonrası hesaplanmalıdır.

## 12. Karşılaştırmalı deney tasarımı

**Ana deney:** Aynı sabit model/checkpoint, quantization, sistem istemi, sıcaklık/seed politikası, donanım, tarama profili, başlangıç bağlamı, en çok üç deneme ve toplam süre/token bütçesiyle üç kol çalıştırın. Getirme ve analiz maliyetini de bütçeye dahil edin. Bir kolun daha fazla hesaplama yapması performans üstünlüğü diye gizlenmemelidir.

| Kol | Yalnız değişen unsur |
| --- | --- |
| A - Hafızasız | Önceki yama bağlamı verilmez. |
| B - Basit hafıza | Aynı havuzdan kural filtresi + metin/vektör benzerliğiyle en uygun örnekler; aynı bağlam bütçesi. |
| C - Koşullu hafıza | Aynı havuzdan geçerlilik/uyumsuzluk denetimi ve örnek seçimi; gerekirse örnek getirmeden çalışma. |

**İki farklı deney birbirinden ayrılmalı:** Önce A/B/C aynı standart kabul kapısında ölçülerek hafızanın etkisi bulunur. Sonra aynı aday yama havuzu standart kapı ve F2 kapısında değerlendirilerek test yönteminin etkisi ayrılır. En son birleşik C+F2 akışı denenir; birleşik iyileşmenin hangi bileşenden geldiği bu ara sonuçlarla açıklanır. İzin ve uygulanabilirlik uygunsa RAVEN tarzı çoklu getirici/seçici bir güçlü ek baseline olmalıdır.

**Veri ayrımı:** İlk mühendislik deneyi için 20 geliştirme + en az 40 ayrı değerlendirme vakası hedefi bir başlangıçtır, istatistiksel güç garantisi değildir. Depo/CVE/patch ailesine göre ayrım yapın; çatallar, aynı düzeltmenin biçim varyantları ve yakın kopyaları birlikte tutun. Değerlendirme yamaları, commit mesajları ve gizli testler hafızaya, istem ayarına veya seçici kalibrasyonuna girmesin. Ana deney boyunca havuz sabit kalsın. Ardından ayrı zamansal deneyde yalnız daha önce sonuçlanıp onaylanmış işler kullanılabilir.

Vul4J gibi açık vakalar modelin ön eğitiminde bulunmuş olabilir; bunu sıfırladığınızı iddia etmeyin. Müşteriye ait daha yeni, izinli ve ayrı tutulan vakalarla ikinci değerlendirme yapın. Derlenemeyen veya kapsam dışı vakaları sessizce çıkarmayın: toplam havuz, uygun bulunanlar, derlenebilirler ve gerçek değerlendirme sayısı ayrı raporlanmalı.[^26]

| Ölçüt | Payda ve yorum |
| --- | --- |
| Doğru kabul edilen düzeltme | Gizli test + uzman değerlendirmesiyle doğru bulunan kabul / tüm uygun başvurular. Çekimserlik faydayı azaltır. |
| Hatalı kabul | Son değerlendirmede hatalı bulunan kabul / bütün kabuller. Ayrıca hata kabul / tüm işler verilir. Hiç kabul yoksa oran “tanımsız”. |
| Davranış kaybı | Meşru senaryoyu bozan aday ve kabul sayısı; güvenlik amacıyla gerekli davranış değişikliği ayrıca tanımlanır. |
| Emek, süre ve maliyet | Kör inceleme medyanı ve p90; bütün ret/yeniden çalışma dahil insan dakikası; GPU/CPU-saat, kuyruk ve iş başı toplam maliyet. |

Her vakayı örneğin üç tohumla tekrar etmek değişkenliği gösterir; bunlar üç bağımsız yeni vaka sayılmaz. Güven aralıkları proje/vaka kümeleri üzerinden hesaplanmalı; inceleyici sırası dengelenmeli ve adayın hangi koldan geldiği gizlenmelidir. Kırk bağımsız kabulde sıfır hata görülse bile yaklaşık %95 üst sınır 3/40 = %7,5’tir; “sıfır risk” sonucu çıkarılamaz. Başarı için hem faydalı kapsama hem hata oranına birlikte bakılmalıdır.

## 13. Doksan günlük doğrulama ve Ar-Ge planı

**Kaynak varsayımı:** İki tam zamanlı geliştirici, yarı zamanlı Java/AppSec uzmanı, mevcut yerel model donanımı ve ilk ay içinde erişilebilir iki tasarım ortağı. Bunlar mevcut ekibin doğrulanmış kapasitesi değildir. Tek kişi veya müşteri erişimi gecikmesi halinde kapsam küçülür ya da takvim uzar. Doksan günün çıktısı satışa hazır genel platform değil, teknik ve ticari yatırım kararını destekleyen dar pilot kanıtıdır.

| Dönem | İş ve sorumlu rol | Çıktı / karar kapısı |
| --- | --- | --- |
| Gün 1-15 | Kurucu: 6 ilk görüşme ve satın alma zinciri. Java/AppSec: Sonar kural/edition deneyi, tekrar eden iş seçimi. | En az bir erişilebilir Java depo adayı; gerçek tarama ve derleme kanıtı. Uygun kural yoksa scanner kararı değişir. |
| Gün 16-30 | Java geliştirici: veri ayrımı ve A/B baseline. Platform: sabit sürümlü ortam, süre/token kaydı. | Toplam 10 görüşme hedefi; lisans/altyapı kapsamı; 20 geliştirme vakası ve kilitlenmiş değerlendirme listesi. |
| Gün 31-45 | Java/AppSec: F1’in API/sürüm koşulları; platform: onaylı hafıza, köken ve iptal. | Basit ve koşullu getiricinin aynı havuzda çalışması; uyumsuz örnek testleri. |
| Gün 46-60 | Java/AppSec: F2’nin korunan güvenlik ve davranış kontrolleri. Platform: gerçek izolasyon. | Ayrı aday havuzunda kabul kapısı deneyi; ağ kesme/yeniden başlatma kanıtı. |
| Gün 61-75 | Ekip + müşteri: gölge modda bir depo, kör inceleme ve maliyet ölçümü. | En az 40 ayrı değerlendirme vakası hedefi; tüm retler ve eksik derlemeler raporlu. Eşikler sonuca göre geriye dönük oynanmaz. |
| Gün 76-90 | Kurucu: somut pilot teklifi. Ekip: hata analizi ve tekrar kurulum. | Bir ücretli pilot kararı veya gerekçeli ret; F1/F2’nin ek değerine göre devam/daraltma kararı. |

### 4-18 aylık araştırma iş paketleri

**İP1 - Veri ve kapsam, ay 1-3:** Lisansı uygun yeniden üretilebilir Java vakaları, proje bazında veri ayrımı, temel ölçüm ve pilot protokolü. Başarı çıktısı güvenilir karşılaştırma altyapısıdır; “çok veri topladık” değildir.

**İP2 - Koşullu hafıza, ay 3-8:** API/veri akışı koşulu çıkarma, eksik bilgi ve uyumsuzlukta seçim yöntemi. Basit ve güçlü getiriciye karşı deney; sürüm değişimi ve yeni proje aktarımı. **İP3 - Kabul yöntemi, ay 4-10:** Güvenlik sözleşmeleri, negatif kontroller ve test yeterliliği; doğru kabul ile hatalı kabulün ortak değerlendirmesi.

**İP4 - Kurumsal ürün, ay 7-13:** Kimlik, onay, iptal, kayıt dışa aktarımı, offline güncelleme ve bir desteklenen dağıtım profili. **İP5 - Pilot ve bağımsız doğrulama, ay 10-18:** İki farklı müşteri bağlamı, ikinci modelle genellenebilirlik deneyi, gerçek inceleme maliyeti ve yenileme niyeti. Snyk/Trivy/Grype yalnız doğrulanmış alıcı ihtiyacıyla eklenir.

Başlıca riskler ve yanıtlar: düşük tekrar hacminde F1’i küçültüp F2’ye odaklanmak; eski depolar derlenmiyorsa destek matrisini daraltmak; test üretimi pahalıysa uzman onaylı sözleşme kitaplığı kullanmak; lisans engelinde uygun sağlayıcı/adaptör seçmek; müşteri erişimi yoksa teknik başarıyı satış kanıtı olarak sunmamak.

## 14. Müşteri görüşmesi ve ücretli pilot

**Görüşme yaklaşımı:** İlk görüşmede ürün demosundan önce son gerçek olay incelenmeli. On görüşme bir pazar anketi değil, problem ve satın alma sürecini keşfetme hedefidir. Geliştirici, AppSec/platform karar vericisi ve bütçe sahibinin görüşleri ayrılmalı; yalnız “güzel fikir” cevabı ticari doğrulama sayılmamalıdır.

| Soru | İstenen somut kanıt |
| --- | --- |
| 1. Son kapattığınız yüksek öncelikli Java bulgusunun akışını gösterebilir misiniz? | Tespit, atama, aktif çalışma, inceleme, onay, dağıtım zamanları. |
| 2. Son 20 bulgunun kaçı gerçekti ve hangileri tekrar açıldı? | Yanlış pozitif ve hatalı düzeltme gerekçeleri. |
| 3. Ayda kaç bulgu Java kaynak kodu değişikliği gerektiriyor? | Bağımlılık/imaj güncellemesinden ayrı uygun iş hacmi. |
| 4. Aynı düzeltme stratejisi nerelerde tekrar ediyor? | İzinli örnek diffler; kurumlar arası aktarım gerektirmeyen tekrar. |
| 5. Hangi depolar bugün çevrimdışı derlenip test edilebiliyor? | JDK/build aracı matrisi, test süresi, bağımlılık aynası. |
| 6. Kod, prompt, log ve hata çıktısının nereye gitmesine izin var? | Yazılı veri sınıfı ve ağ politikası; “banka olduğu için” varsayımı yok. |
| 7. Mevcut Sonar/GitLab/AI lisansınızın hangi özellikleri açık? | Gerçek edition/sürüm, yetki ve kullanılmayan özellikler. |
| 8. Bir yamayı reddetmenize neden olan en yaygın üç şey nedir? | İşlev kaybı, test eksiği, kapsam dışı diff, gerekçe/kanıt yetersizliği. |
| 9. Sizin için ölçülebilir bir pilot başarısı ne olur? | Dakika, kabul oranı, bakım yükü ve kabul edilmeyen hata türleri. |
| 10. Satın alma bütçesi kimde, hangi kalemden ve hangi tarihte? | Teknik sponsor ile bütçe sahibinin adı/rolü ve karar süreci. |
| 11. Yerel kurulum ve güncellemeyi kim işletir; özel geliştirme beklentisi nedir? | Sorumluluk matrisi, destek penceresi ve entegrasyon sınırı. |
| 12. Belirlenen koşullarda ücretli pilotu onaylamanızı ne engeller? | Gerçek itiraz; ücretsiz denemeyle ücretli talebin ayrılması. |

**Pilot kapsamı:** Bir kurum, bir veya iki Java/Maven deposu, iki zafiyet ailesi, 4-6 hafta ve önceden belirlenmiş iş sayısı. İlk bölüm yalnız gölge modda geçmiş/ayrı vakalar; sonraki bölüm taslak PR ve insan incelemesi. Üretim erişimi verilmez. Veri kurumda kalır; dışarı çıkarılacak metrikler ayrıca kapsamlandırılır. Kurumun mevcut yöntemi ile A/B/C kıyaslaması yapılır.

**Ücretli pilota giriş:** İsimlendirilmiş teknik sponsor ve bütçe sahibi, uygun depo/iş hacmi, lisans ve veri erişim yetkisi, temel derleme, yazılı kapsam/fiyat ve ölçüm protokolü gerekir. Başlangıç ücretini nihai ürünün performansı ispatlanmış gibi gerekçelendirmeyin; pilotun ölçüm ve kurulum hizmeti olduğu açık olmalı.

**Pilot sonrası devam hedefleri - hipotez:** Uygun işlerin en az %25’inde bağımsız değerlendirmede doğru, insanın birleştirebildiği yama; karşılaştırılabilir işlerde medyan aktif inceleme süresinde %30 azalma; kurumun kritik gördüğü hatalı kabulde otomasyonu durdurup kök neden incelemesi. Bütün retlerin emeği dahil toplam fayda pozitif ve standart kurulum tekrar edilebilir olmalı. Küçük örneklem güvenlik garantisi vermez; yıllık alımın son eşiği müşterinin gerçek iş hacmi ve maliyet hesabıyla belirlenir.

## 15. TÜBİTAK BiGG değerlendirmesi

**Doğrulanmış ölçütler:** 1812 Aşama 2; teknoloji düzeyi/yenilik, uygunluk/yapılabilirlik ve ticarileşme potansiyelini değerlendirir. 2026-2 çağrı metninin 5.3 bölümünde üç boyutun her biri 10, toplamı 30 puandır. Uygulayıcı kuruluşun hızlandırma sonu en az 6/10 ve toplam 20 koşulu ayrı bir aşamadır; panel sonucu veya yatırım garantisi gibi kullanılamaz.[^37][^39]

| Ölçüt | Bugünkü kanıt | Koşullu geliştirilmiş durum | Puanı artıracak kanıt |
| --- | --- | --- | --- |
| Teknoloji / yenilik | 5,5 / 10 | 8 / 10 | F1/F2’nin güçlü karşılaştırmalara göre özgül teknik katkısı; aynı model/bütçede tekrarlanabilir sonuç. |
| Uygunluk / yapılabilirlik | 6,5 / 10 | 7,5 / 10 | Gerçek Sonar veya seçilen scanner, müşteri deposu, korunmuş testler, ağ kesme/yeniden kurulum ve yeterli ekip. |
| Ticarileşme | 5,5 / 10 | 7,5 / 10 | Bütçe sahibiyle doğrulanmış sorun, ücretli pilot, aktif zaman tasarrufu ve sürdürülebilir kurulum/destek maliyeti. |
| Toplam / ortalama | 17,5 / 30; 5,8 / 10 | 23 / 30; 7,7 / 10 | Analitik değerlendirme; resmî panel puanı veya kabul olasılığı değildir. |

**Mevcut puanın gerekçesi:** Dar gerçek model ve korunan test kanıtı yapılabilirliği destekliyor. Buna karşılık ana hafıza yöntemi, canlı Sonar, kurumsal izolasyon ve müşteri örneği henüz tamamlanmış değil. Yerel model + RAG + tekrar döngüsünün güçlü öncülleri olduğu için yenilik puanı sınırlı. Müşteri erişimi, ekip özgeçmişi, bütçe ve ücretli talep kanıtı olmadan ticari puan yükseltilemez.[^1]

**Koşullu puan bir tahmin taahhüdü değildir:** Yalnız yeni özellikleri iş planına yazmak projeyi 7,7’ye çıkarmaz. F1/F2’nin anlamlı teknik farkı gösterilmezse bu artış gerçekleşmez. BiGG bir Ar-Ge ve iş geliştirme sürecini destekleyebilir; başvuru öncesinde tüm kurumsal ürünün bitmiş olması gerektiği sonucu da çıkarılmamalıdır.

**Önerilen teknik katkı metni:** “Proje, Java güvenlik yamalarının bağlama bağlı uygulanabilirlik koşullarını çıkaran ve bu koşulları güvenlik/davranış testlerinin ayırt etme gücüyle birleştiren bir karar yöntemi araştırır. Amaç, sabit yerel model ve sınırlı hesaplama bütçesinde yanlış yama aktarımını ve hatalı kabulü azaltırken doğru kabul edilen düzeltme sayısını artırmaktır.”

İş planında bunun altına iki araştırma sorusu, veri/karşılaştırma tasarımı, başarısızlık ölçütleri, 18 aylık iş paketleri ve müşteri keşfi eklenmeli. AGY112; pazar, rekabet, fiyat, finans, ekip ve risklerin somutlaştırılmasını gerektirir. “Savunma ve bankalar güvenlik istediği için satın alır” ifadesi bu bölümlerin yerine geçmez.[^40]

**Takvim ve finansman:** 2026-2 başvurusu 31 Ağustos-30 Eylül 2026 aralığındadır ve Aşama 1’i tamamlayıp Aşama 2’ye hak kazanma koşulu vardır. Çağrı %3 hisse karşılığı 1.350.000 TL yatırım açıklar; bu hibe değildir. Devam yatırımı talep edilebilir, otomatik hak değildir. Bu rapordaki 90 günlük plan mevcut çağrının son tarihini aşar; uygunluk ve başvuru hazırlığı ayrıca ele alınmalıdır.[^38]

## 16. Yatırım kararını değiştirecek eksik kanıtlar

| Eksik kanıt | Olumlu sonuçta karar | Olumsuz sonuçta karar |
| --- | --- | --- |
| Gerçek ve tekrarlayan uygun Java iş hacmi | F1 hafızasına yatırım; müşteriye özgü fayda hesabı. | Hafıza geliştirmesini küçült; F2 veya farklı alt segmente odaklan. |
| F1’in basit/güçlü getirici karşısında ek etkisi | Geçerlilik çıkarma yöntemini Ar-Ge omurgası yap. | RAG entegrasyonunu standart özellik say; özgünlük iddiasını daralt. |
| F2’nin hatalı kabul ve faydalı kapsam dengesi | Yama kabul yöntemini ürün çekirdeği yap. | Test üretme/inceleme maliyeti düzelmiyorsa otomatik onarım yatırımını azalt. |
| Mevcut CodeFix/GitLab/kurum içi çözümle karşılaştırma | Ek lisans/entegrasyonun geri dönüşü gösterilebiliyorsa sat. | Aynı işi aynı kalitede daha ucuza yapan mevcut çözüm varsa genel orkestratör satışını bırak. |
| Lisans ve offline kurulumun uygulanabilirliği | Desteklenen sürüm/kurulum profilini sözleşmeye bağla. | Engelli bileşeni değiştir veya ilgili müşteri kullanımından vazgeç. |
| Ücretli pilot ve destek birim ekonomisi | Tekrarlanabilir satış ve sınırlı özel geliştirme varsa ölçekle. | Talep yalnız özel danışmanlıksa bunu hizmet işi olarak fiyatla; ürün geliri gibi modelleme. |
| Bağımsız müşteri vakasında doğruluk | Yeni projeye aktarım ve daha büyük deney için yatırım yap. | Sentetik demoyu koru; kurumsal başarı iddiasında bulunma. |

**İlk yatırım kararı:** Birden çok tarayıcıyı eklemek ve büyük platform ekranı yapmak yerine, ilk 90 günde iki hipotezi ve bir alıcıyı doğrulamaya bütçe ayırın. İlk hipotez koşullu hafızanın basit getirmeden daha yararlı olmasıdır. İkincisi, yama doğrulamanın insan inceleme yükünü azaltırken faydalı kabul oranını korumasıdır. Alıcı doğrulaması ise gerçek depo, uygun iş hacmi ve ücretli pilot kararından oluşur.

**Alternatif yön:** Yama üretme kalitesi mevcut ürünlerin gerisinde kalır fakat doğrulama/kanıt güçlü değer üretirse SafePatch; Sonar, GitLab veya insanın hazırladığı yamaları kabul değerlendirmesine alan bir doğrulama ürünü olarak daraltılabilir. Bu da rekabetsiz alan değildir; aynı müşteri maliyeti ve baseline disipliniyle değerlendirilmelidir.

**Kanıt sınırları:** Kamuya açık belgeler ürün özelliklerini destekler; gerçek kurulumların güvenliğini veya satılabilirliğini tek başına kanıtlamaz. Türkiye’de bu tam ürün için doğrulanmış satın alma bütçesi, yeterli açık ihale şartnamesi veya müşteri ödeme isteği bulunmadı. CodeThreat katalog kaydı yerel rekabet göstergesidir, eksiksiz Türkiye pazar haritası değildir. Fiyatlar ve kurumsal sözleşme kapsamları teklif gerektirir; varsayımsal maliyetler piyasa tahmini olarak kullanılmamalıdır.

Bu nedenle bugün verilebilecek karar **koşullu ve dar kapsamlı devam** kararıdır. Satılabilirlik için makul bir problem alanı var; genel “air-gap AI düzeltme platformu” konumlandırmasının güçlü özgünlüğü yok. Yatırımın gerekçesi, kurumun mevcut araçları üzerinde ölçülen daha iyi yama kabulü, daha az uzman emeği ve yönetilebilir işletim maliyeti olmalıdır.

## Kaynaklar

Bütün çevrimiçi kaynaklara erişim: 12 Eylül 2026.

[^1]: SafePatch. STATUS.md ve docs/DEGERLENDIRME.md. 11 Eylül 2026. Yerel proje kayıtları; C:/DevSecOps_Tubitak. Sonuçlar kayıtlı prototip kanıtıdır; bu rapor için yeniden çalıştırılmış bağımsız performans deneyi değildir.

[^2]: JPMorganChase. [Driving enterprise software delivery at scale at JPMorganChase](https://www.jpmorganchase.com/about/technology/blog/driving-enterprise-software-delivery). 11 Temmuz 2023. Kurumun kendi mühendislik anlatımı; SafePatch satın alma niyeti değildir.

[^3]: Avrupa Komisyonu / EUR-Lex. [Commission Delegated Regulation (EU) 2024/1774](https://eur-lex.europa.eu/eli/reg_del/2024/1774). 13 Mart 2024; 25 Haziran 2024 metni. Özellikle madde 10, 16 ve 17; DORA kapsamındaki kuruluşlar için.

[^4]: NIST. [SP 800-218: Secure Software Development Framework (SSDF), Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final). Şubat 2022. Nihai v1.1 çerçevesi; mevzuat veya ürün sertifikası değildir.

[^5]: Moderne. [Tackling technical debt at big bank scale](https://moderne.ai/case-study/tackling-technical-debt-at-big-bank-scale). Tarih belirtilmemiş. Üreticinin anonim banka vaka çalışması; bağımsız sonuç doğrulaması yok.

[^6]: SonarSource. [Enable AI CodeFix - SonarQube Server](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix). Güncel, sürümsüz belge. Enterprise / Data Center; self-hosted gateway ve outbound erişimsiz çalışma bölümleri.

[^7]: SonarSource. [SonarQube AI Remediation Agent & Closed Loop Verification](https://www.sonarsource.com/products/sonarqube/remediation-agent/). Güncel ürün sayfası. SonarQube Cloud Enterprise kapsamındaki ürün beyanı; bağımsız pilot değil.

[^8]: GitLab. [Self-hosted models](https://docs.gitlab.com/administration/gitlab_duo_self_hosted/). Güncel belge; özellik bazında 17.9-18.9 geçmişi. Vulnerability Resolution: self-hosted tabloda 18.1.2+, beta. Agent Platform: 18.8+, GA.

[^9]: GitLab. [Resolve vulnerabilities with GitLab Duo](https://docs.gitlab.com/user/application_security/remediate/duo/). Güncel belge. Ultimate ve ilgili Duo yetkisi; desteklenen CWE ve MR/CI iş akışı.

[^10]: Semgrep. [The tech behind Semgrep Assistant](https://semgrep.dev/blog/2024/the-tech-behind-semgrep-assistant/). 21 Ağustos 2024. Önceki düzeltme difflerinin getirilmesi, akış izi ve yeniden tarama tasarımı.

[^11]: Semgrep. [Semgrep Workflows overview](https://semgrep.dev/docs/workflows/overview). 18 Mart 2026 güncellemesi. Beta; yönetilen iş akışları ve özel iş akışı seçenekleri.

[^12]: CodeThreat. [CodeThreat GenAI On-Prem Integration](https://www.codethreat.com/blogs/codethreat-genai-onprem-integration). Ocak 2024. Üretici beyanı: kurum içi GenAI entegrasyonu ve öneriler.

[^13]: Türkiye Siber Güvenlik Kümelenmesi. [CodeThreat ürün kaydı](https://siberkume.org.tr/katalog/urunler/detay/c0fadce0-a466-4bbc-8fdf-0be54e28c30e-codethreat). Tarih belirtilmemiş. Katalogda Cyberwise altında listelenir; güncel tüzel sahiplik veya satış kanıtı olarak yorumlanmaz.

[^14]: Mend. [Remediate your code (SAST) findings](https://docs.mend.io/platform/latest/remediate-your-code-sast-findings). Güncel belge. Gen 2 SAST; Mend tarafından yönetilen model ve müşteri kod parçacıkları.

[^15]: Snyk. [Snyk Code Local Engine](https://github.com/snyk/user-docs/blob/main/scan-fix-and-prevent/scan-with-snyk/snyk-code/snyk-code-local-engine.md). Güncel resmî dokümantasyon deposu. Yeni kurulum almayan eski ürün; sonuçların SaaS platformuna aktarılması.

[^16]: Snyk. [Plans and pricing](https://snyk.io/plans/). Güncel fiyat sayfası. Geliştirici ve ürün bazlı kapsam; Enterprise teklif gerektirir.

[^17]: OpenRewrite. [Getting started with running recipes](https://docs.openrewrite.org/running-recipes/getting-started). Güncel belge. Maven/Gradle tarifleri ve kod dönüşümü; her tarifin ayrı lisansı incelenmelidir.

[^18]: Moderne. [Licensing overview](https://docs.moderne.io/licensing/overview/). Güncel belge. DX, Connector ve belirli tariflerin özel lisansı; OpenRewrite ile aynı ürün değildir.

[^19]: Moderne. [Moderne CLI license](https://docs.moderne.io/user-documentation/moderne-cli/getting-started/moderne-cli-license/). 6 Mayıs 2026 güncellemesi. Yerel anahtar doğrulaması; tüm platformun air-gap yeterliliği anlamına gelmez.

[^20]: Weishi Wang, Yue Wang, Shafiq Joty, Steven C.H. Hoi. [RAP-Gen: Retrieval-Augmented Patch Generation with CodeT5 for Automatic Program Repair](https://arxiv.org/abs/2309.06057). 12 Eylül 2023; FSE 2023. Hakemli FSE çalışması; geçmiş yama getirme + model ince ayarı, genel program onarımı.

[^21]: Varun Gadey, Zijie Liu, Alexandra Dmitrienko. [RAVEN: Agentic RAG for Automated Vulnerability Repair](https://arxiv.org/html/2606.22647v1). 21 Haziran 2026, v1. Ön baskı, under review. Bölüm III-B4 ve IV: referans düzeltmeye dayalı son değerlendirme.

[^22]: Matthew Jin ve diğerleri. [InferFix: End-to-End Program Repair with LLMs](https://arxiv.org/html/2303.07263v1). 13 Mart 2023, v1. FSE 2023 çalışması. Bölüm 8: yazarların Microsoft iç CI entegrasyonu anlatımı.

[^23]: Sicong Cao ve diğerleri. [Knowledge-Enhanced Agentic Vulnerability Repair](https://arxiv.org/abs/2607.00820). 1 Temmuz 2026, v1. KeaRepair ön baskısı; erişilen kayıtta hakemli kabul bilgisi doğrulanmadı.

[^24]: Ali Ghanbari, Andrian Marcus. [Patch Correctness Assessment in Automated Program Repair Based on the Impact of Patches on Production and Test Code](https://ali-ghanbari.github.io/publications/issta22-shibboleth.pdf). ISSTA 2022. Shibboleth; hakemli çalışma. Yama doğruluğu değerlendirmesi ve DiffTGen karşılaştırması.

[^25]: Varun Gadey, Ziad Marey, Alexandra Dmitrienko. [CodePoisonRAG: Knowledge Poisoning Attacks on Retrieval-Augmented Code Generation](https://arxiv.org/abs/2609.02774). 2 Eylül 2026, v1. Ön baskı, under review; belirli saldırgan ve veri kümesi varsayımları altında.

[^26]: TUHH SoftSec / Vul4J yazarları. [Vul4J: A Dataset of Reproducible Java Vulnerabilities](https://github.com/tuhh-softsec/vul4j). MSR 2022; depo yeniden üretim kaydı 20 Mayıs 2026. Güncel depoda PoV içeren ve yalnız statik uyarı içeren örnekler ayrıdır.

[^27]: SonarSource. [SonarQube Community Build](https://www.sonarsource.com/open-source-editions/sonarqube-community-edition/). Güncel ürün sayfası. Ücretsiz açık kaynak yapı; Java desteği her ücretli güvenlik kuralının dahil olduğu anlamına gelmez.

[^28]: SonarSource. [sonarqube/LICENSE.txt](https://github.com/SonarSource/sonarqube/blob/master/LICENSE.txt). Erişilen master dalı. LGPL v3 metni; gerçek dağıtım bileşenlerinin lisansları ayrıca incelenir.

[^29]: SonarSource. [Primary Customer Agreement](https://www.sonarsource.com/legal/primary-agreement/). 27 Ağustos 2026 güncellemesi. İç kullanım, devredilemez ve alt lisans verilemez haklar; mevcut sözleşmelerde geçiş koşulları vardır.

[^30]: SonarSource. [AI Annex](https://www.sonarsource.com/legal/ai/). 27 Ağustos 2026 güncellemesi. Öneriler, müşteri kodu ve Sonar Proprietary Logic ayrımı; ek ürün şartlarıyla birlikte okunmalıdır.

[^31]: Snyk. [Terms of Service](https://snyk.io/policies/terms-of-service/). Erişilen güncel metin. Bölüm 2: yeniden satış, service bureau, rekabet ve kıyaslama kullanım sınırlamaları.

[^32]: Qwen / Alibaba Cloud. [Qwen2.5-Coder-7B-Instruct LICENSE](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct/blob/main/LICENSE). Model deposundaki lisans. Apache 2.0; yalnız bu model seçimi için doğrulandı.

[^33]: DeepSeek. [DeepSeek-Coder-V2 LICENSE-MODEL](https://github.com/deepseek-ai/DeepSeek-Coder-V2/blob/main/LICENSE-MODEL). Model deposundaki lisans. Attachment A askerî kullanımı kısıtlar; tüm DeepSeek modellerine genellenemez.

[^34]: Aqua Security. [Trivy LICENSE](https://github.com/aquasecurity/trivy/blob/main/LICENSE). Erişilen main dalı. Apache 2.0; veri kaynaklarının ve dağıtılan diğer bileşenlerin şartları ayrıca değerlendirilir.

[^35]: Aqua Security. [Trivy: Connectivity and network considerations / air-gap](https://trivy.dev/docs/latest/advanced/air-gap/). Güncel belge. Yerel veritabanı ve çevrimdışı tarama yapılandırması.

[^36]: Anchore. [Grype LICENSE](https://github.com/anchore/grype/blob/main/LICENSE). Erişilen main dalı. Apache 2.0; zafiyet veritabanı işletimi ek sorumluluktur.

[^37]: TÜBİTAK. [1812 - Yatırım Tabanlı Girişimcilik Destek Programı](https://tubitak.gov.tr/tr/destekler/sanayi/ulusal-destek-programlari/1812-yatirim-tabanli-girisimcilik-destek-programi-bigg-yatirim). Güncel program sayfası. Aşama 2 ölçütleri ve uygulayıcı kuruluş değerlendirmesi ayrı süreçlerdir.

[^38]: TÜBİTAK. [BiGG Yatırım Programı 2026-2 Çağrısı Açıldı](https://tubitak.gov.tr/tr/destekler/destek/sanayi/ulusal-destek-programlari/cagri-bigg-yatirim-programi-2026-2-cagrisi-acildi). 2026-2 çağrısı. 31 Ağustos-30 Eylül 2026; Aşama 1 koşulu ve hisse karşılığı yatırım.

[^39]: TÜBİTAK. [1812-2026-2 Çağrı Duyurusu v2](https://tubitak.gov.tr/sites/default/files/2026-09/1812-2026-2_Cagri_Duyurusu_v2.pdf). Eylül 2026. 11 sayfa; değerlendirme ve çağrı koşullarının asıl metni.

[^40]: TÜBİTAK. [AGY112 İş Planı, v1.2](https://tubitak.gov.tr/sites/default/files/2024-03/1812_agy_112_pdf_form_v1.2.pdf). Mart 2024; güncel program sayfasından bağlantılı. Teknik katkı, pazar, rekabet, finans ve risklerin iş planına dönüştürülmesi.

[^41]: SonarSource. [SonarQube plans and pricing](https://www.sonarsource.com/plans-and-pricing/sonarqube/). Güncel fiyat sayfası. Sürüm, analiz edilen kod hacmi ve instance kapsamına göre; kurumsal kurulum için teklif gerekir.

[^42]: GitLab. [Deploy GitLab Duo Agent Platform Self-Hosted in an offline environment](https://docs.gitlab.com/administration/gitlab_duo_self_hosted/offline_deployment/). Güncel belge. Offline lisans, model ve servis hazırlığı; kurulumun bağımsız ağ testi değildir.

[^43]: SonarSource. [Indirect Reseller Agreement Terms](https://www.sonarsource.com/legal/indirect-reseller-agreement-terms/). Erişilen güncel metin. Yetkili yeniden satış ve son kullanıcı sözleşmesi gereklilikleri.
