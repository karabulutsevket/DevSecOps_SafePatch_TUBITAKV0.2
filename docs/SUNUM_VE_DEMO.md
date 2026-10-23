# Sunum ve canlı demo anlatımı

Sunum: `presentation/SafePatch_V01_Sunum.pptx`. Yaklaşık 12–15 dakikalık anlatım için hazırlanmıştır. Sayılar `evidence/` dosyalarından gelir; her slayttaki notlar ölçümün sınırını açıklar.

## Ana cümle

“SafePatch, sabit yerel bir modelin ürettiği Java güvenlik düzeltmelerini bağımsız testlerle kontrol eden ve insanın onayladığı düzeltmeleri uygunluk koşullarıyla yeniden kullanan bir kurum içi otomasyon prototipidir.”

## 5 dakikalık canlı gösterim

1. Servisleri başlatın; demo ortamında başka benchmark çalışmadığından emin olun. Arayüzü açın, geliştirici anahtarıyla oturum açın.
2. `sql-01`, `Semgrep` seçip iş başlatın. Başlangıçtaki güvenlik testinin başarısız, normal davranışın başarılı olduğunu gösterin.
3. Yerel modelin diff'ini, yeniden taramayı, JUnit sonuçlarını ve artifact hash'ini gösterin. Durum **insan incelemesine hazır** olmalıdır. Bu gerçek insan onayı değildir.
4. İnceleyen kişi reviewer anahtarıyla girip diff'i gerçekten inceledikten sonra onaylasın. Sonra **Onaylı düzeltmeyi hafızaya al** düğmesine bassın. Onayları bir sunucu betiğinin sessizce vermediğini anlatın.
5. Aynı `sql-01` işini tekrar başlatın. Hafıza eşleşmesi, `approved-memory-replay`, sıfır model token'ı ve yeniden çalışan testleri gösterin. Geliştirici/veri onayı olmadan staging'e geçemediğini gösterin.
6. İstenirse deployer anahtarıyla **Onaylı artifact'i staging'e dağıt** kullanın. Bu sadece yerel sentetik staging'dir. Hash'i onay öncesi artifact ile karşılaştırın.
7. İnceleyen, hafıza kaydını gerekçe girerek geri çeksin. Kaydın yeni işlerde kullanılmadığını ve bağlı bekleyen onayın iptal edildiğini gösterin.

## Başarısızlığın da değeri var

Path örneğinde modelin yalnız `startsWith` eklemesi tarayıcıyı temizleyebilir ama `../secret.txt` tanığını geçmeyebilir. Bu durumu “AI düzeltti” diye sunmayın; kabul mekanizmasının yanlış öneriyi durdurması olarak gösterin. Command örneği ek dayanıklılık kontrolüdür; ilk ticari kapsamın SQL/path ile sınırlanması hâlâ uygundur.

## Jüri / müşteri soruları

**Kendi kendine öğreniyor mu?** Model ağırlıkları değişmiyor. İnsan onaylı, sürümlü yama örnekleri aramaya ekleniyor. Bu sürümde vektör RAG yerine muhafazakâr sözleşme/hash eşleştirmesi var.

**SonarQube'un rakibi mi?** Tarayıcıyı değiştirmek zorunda olmayan bir onarım/doğrulama katmanı hedefliyoruz. V0.1'de ücretsiz tarama Semgrep ile yapılıyor; Sonar adaptörü var fakat canlı Sonar testi yok.

**Sıfır veri sızıntısı mı?** Böyle bir garanti vermiyoruz. Model yerel; bu native demo tam sistem airgap doğrulaması değildir. Kurumsal sürüm için ayrı sandbox, offline tedarik ve bütün rollerden egress testleri gerekir.

**Ne kadar hızlandırıyor?** Ölçüm raporundaki tam süreleri söyleyin. Hafıza aramasının milisaniye sürmesi tüm onarımın milisaniyede bittiği anlamına gelmez. Küçük sentetik çalışmayı müşteri tasarrufuna genellemeyin.

**Satılır mı?** Teknik bir başlangıç ve açık bir değer hipotezi var. Satış için gerçek Java projelerinde pilot, aktif mühendis süresi ölçümü, AppSec kabulü ve satın alma isteği kanıtlanmalıdır. Bunlar yapılmış değildir.
