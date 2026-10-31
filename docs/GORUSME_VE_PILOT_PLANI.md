# Müşteri görüşmesi ve pilot ölçüm planı (Hafta 11)

**Durum: taslak, proje liderinin onayına sunuldu (31 Ekim 2026).** Eşikler ve başarı ölçütleri, görüşmeler ve pilot başlamadan önce sabitlenir; sonuç görüldükten sonra değiştirilmez. Ana deneyde uyguladığımız kural burada da geçerli.

**Dayandığı belgeler**
- [ARASTIRMA_ONCALISMASI.md](ARASTIRMA_ONCALISMASI.md), bölüm 1 ve 14: soru seti, pilot kapsamı, devam hedefleri.
- [ARGE_VE_TICARILESME.md](ARGE_VE_TICARILESME.md), "Pilot tasarımı".
- ROADMAP Hafta 11 ("Pilot protokolü") ve bölüm 10 (görüşme hedefleri).

## Neden şimdi

- **Ölçülen:** Ürünün doğrulama ve kanıt katmanı ölçüldü: hatalı yamayı durduran kabul kapısı, sandbox, egress testi, denetim kaydı.
- **Desteklenmeyen:** Hafızanın onarım oranını artırdığı hipotezi değerlendirme setinde desteklenmedi ([OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md)).
- **Hiç ölçülmeyen:** talep. Depoda henüz tek bir müşteri görüşmesi kaydı yok. ROADMAP Hafta 10'a kadar 12 görüşme ve 2 pilot adayı hedefliyordu.

Bu plan üç soruyu ölçer:

| # | Soru | Neden önemli |
|---|---|---|
| S1 | **Talep:** Kapalı ağda çalışan, doğrulanmış düzeltme için kim, ne kadar ve hangi bütçeden öder? | Ürünün var olma koşulu |
| S2 | **Hacim:** Bir kurumda ayda kaç bulgu Java kaynak kodu değişikliği gerektiriyor? | Varsayımsal fiyatla müşterinin başabaşı yaklaşık ayda 70 doğru onarılmış iş ([ARASTIRMA_ONCALISMASI.md](ARASTIRMA_ONCALISMASI.md), bölüm 11) |
| S3 | **Tekrar:** Aynı düzeltme stratejisi bir kurumun kodunda ne sıklıkla tekrarlanıyor? | Hafızanın ticari değeri buna bağlı. Değerlendirme setinde bunu ölçemedik: OWASP Benchmark'ın servletleri birbirinden farklı, birebir tekrar hiç olmadı |

## 1. Görüşmeler

**Kimle**
- Her kurumda en az iki rol konuşulur:
  - kullanıcı: Java geliştiricisi ya da kod inceleyicisi;
  - değerlendiren: AppSec ya da platform/DevOps lideri.
- Mümkünse bütçe sahibiyle de konuşulur: mühendislik yöneticisi, CISO ya da BT yöneticisi. Rollerin görüşleri ayrı kaydedilir.
- Segment sırası, araştırmadaki erişilebilirlik hipotezine göre:
  1. finans kuruluşuna yazılım sağlayan Java ekibi;
  2. orta ölçekli finans ya da fintek AppSec ekibi;
  3. büyük banka ya da savunma ana yüklenicisi.

**Hedef sayılar (ROADMAP bölüm 10):**
- toplam 12 görüşme;
- 2 pilot adayı;
- Faz 4'ün geçiş koşulu: en az 2 pilot adayıyla yazılı kapsam görüşmesi.

**Yöntem**
- Görüşme yaklaşık 45 dakika sürer ve demoyla başlamaz. Önce kurumun son gerçek bulgusunun akışı konuşulur; demo, görüşmenin sonunda ve istenirse gösterilir.
- Soru seti araştırmadaki 12 sorudur ([ARASTIRMA_ONCALISMASI.md](ARASTIRMA_ONCALISMASI.md), bölüm 14). Her sorunun cevabı şablondaki bir alana, mümkünse bir sayıya yazılır ([musteri/GORUSME_SABLONU.md](musteri/GORUSME_SABLONU.md)).

**Talep sayılmayanlar**
- "Güzel fikir" ya da genel ilgi.
- Ücretsiz deneme isteği.
- Tek kişinin kişisel görüşü.

**Görüşme sonucu üç sınıftan birine yazılır:**

| Sınıf | Tanım |
|---|---|
| Güçlü sinyal | Adı bilinen bir teknik sponsor ve bütçe sahibi var; kurum, yazılı bir pilot kapsam görüşmesine evet diyor |
| Zayıf sinyal | Sorun kabul ediliyor, ama sponsor ya da bütçe belli değil |
| Sinyal yok | Sorun yok, mevcut araçla çözülmüş ya da Java kaynak düzeltmesi hacmi çok küçük |

**Kayıt ve gizlilik**
- **Depo herkese açık.** Git'e yalnız anonim özet girer:
  - kurum kodu (K01, K02…), segment ve görüşülen rol;
  - kişi adı ve kurum adı girmez.
- Ham notlar ve iletişim bilgileri depo dışında, ekibin erişebildiği bir yerde tutulur.
- Kurum adı yalnız yazılı izinle kullanılır. Kişisel veriler KVKK kapsamında; görüşmeye başlarken not alınacağı söylenir.

## 2. Önceden tanımlı karar kuralları (öneri)

Eşikler önerimdir; proje lideri görüşmeler başlamadan sabitler. Her kuralın tutmadığında ne yapılacağı şimdiden yazılı.

| Soru | Kanıt | Önerilen eşik | Eşik tutmazsa |
|---|---|---|---|
| S1 Talep | Görüşme sınıfları ve pilot kapsam yazışmaları | En az 2 kurumda güçlü sinyal | Segment ya da teklif değişir. Araştırmanın alternatifi: dışarıdan üretilen yamaların doğrulanması ve inceleme kanıtı hizmeti |
| S2 Hacim | Soru 3: aylık Java kaynak düzeltmesi gerektiren bulgu sayısı | Pilot adayı kurumda ayda en az 70 uygun iş | Fiyat ve paket yeniden hesaplanır. Küçük hacimli kurum için ürün ekonomik olmayabilir; bunu kuruma açıkça söyleriz |
| S3 Tekrar | Bölüm 3'teki ölçüm; yapılamazsa soru 4 | Son 12 ayın güvenlik düzeltmelerinin en az %20'si, daha önceki bir düzeltmeyle aynı zafiyet ailesini ve yapısal imza biçimini paylaşıyor | %10'un altında: hafıza ürün dilinde yalnız "onaylı düzeltmenin birebir tekrarı ve uzman yaması" olarak kalır, aktarım üzerine Ar-Ge Aşama 2'de durdurulur. %10–20 arası: karar pilottaki ölçüme kalır |
| Pilot ön koşulu | Pilot deposunun SafePatch proje tanımıyla sandbox'ta derlenmesi | Derleme ve testler çevrimdışı koşuyor | Pilot başlamaz ya da desteklenen JDK/build matrisi daraltılır |

**%10 ve %20 eşikleri bir ilk tahmindir; ölçülmüş bir değerden gelmiyor.** Dayanak şu: değerlendirme setinde hafızanın sonucu değiştirebileceği vaka oranı küçüktü (30 açığın 7'si ile 12'si arası). Tekrar az olan bir kurumda hafızanın katkısı bundan da küçük kalır.

## 3. Tekrar sıklığını kod kurumdan çıkmadan ölçmek

Hafızanın kurum için değerini belirleyen ölçü S3'tür. SafePatch'in hafızası kayıtları zafiyet ailesi ve koddan çıkarılan yapısal imzayla eşleştiriyor (`safepatch/weakness.py`, `safepatch/signature.py`). Aynı yöntem kurumun geçmişine uygulanabilir.

1. **Girdi:** Kurumun son 12 ayda kapattığı güvenlik bulgularının dışa aktarımı (tarayıcı raporu) ve bunları kapatan düzeltme commit'leri. İkisi de kurumdan çıkmaz.
2. **Kurum içinde hesaplanır:** Her düzeltmenin öncesindeki kodda, bulgunun ailesi ve yapısal imzası çıkarılır. Aynı (aile, imza biçimi) çiftine düşen düzeltmeler gruplanır.
3. **Dışarı çıkan yalnız sayılardır:**
   - toplam düzeltme;
   - grup sayısı;
   - daha önceki bir düzeltmeyle aynı gruba düşen düzeltmelerin oranı;
   - aile başına dağılım.

   Kod, dosya adı ve imzanın kendisi çıkmaz. Rapor kurumun onayıyla dışarı verilir.
4. **Henüz yapılmayan:** Bunun için bir ölçüm betiği gerekiyor; şimdilik yok. Pilot öncesi yazılır ve kendi deposunda bir sentetik geçmişle denenir.

Ölçüm yapılamıyorsa görüşmedeki 4. soru kullanılır: son 20 güvenlik düzeltmesinin kaçı aynı stratejiyle yapıldı? Bu cevap bir tahmin olarak işaretlenir.

## 4. Pilot protokolü

**Kapsam**
- Bir kurum.
- Bir ya da iki Java/Maven deposu.
- SafePatch'in desteklediği ailelerden ikisi.
- 4–6 hafta.
- İş listesi baştan belirlenir.

**Veri**
- Kod, model istemleri ve çıktıları, hafıza ve kayıtlar kurumda kalır.
- Üretim erişimi istenmez; kişisel veri ve kimlik bilgisi istenmez.
- Dışarı yalnız kurumun satır satır onayladığı sayısal rapor çıkar.

**Önce sabitlenenler:** ölçütler, eşikler, iş listesi ve karşılaştırma yöntemi. Hepsi pilot başlamadan yazılı bir protokolde kurumla birlikte sabitlenir; ana deneyin protokolü gibi.

| Hafta | Aşama | Ne yapılır |
|---|---|---|
| 0 | Kapsam | Protokol, izinler, iş listesi. Kurumun geçmiş onaylı düzeltmelerinin hafızaya alınması için ayrı izin |
| 1–2 | Kurulum ve taban | Çevrimdışı paketle kurulum; kurulum süresi ölçülür. Temiz makine ölçümü de böylece yapılmış olur ([KURULUM_CEVRIMDISI.md](KURULUM_CEVRIMDISI.md)). Proje tanımı ve derlenebilirlik. Paralelde, mevcut süreçte bulgu başına aktif mühendis ve inceleme süresi ölçülür; bekleme süresi ayrı tutulur |
| 2–3 | Gölge mod | Kapanmış geçmiş bulgular üzerinde SafePatch iki kolla koşar: hafıza kapalı ve hafıza açık. Hafızaya kurumun geçmişte onayladığı düzeltmeler (izinle) alınır. Adaylar kurumun gerçek düzeltmesiyle ve testlerle karşılaştırılır. Üretim akışına dokunulmaz. **Hafızanın gerçek bir kod tabanındaki ilk ölçümü budur** |
| 4–6 | Canlı karşılaştırma | Yeni ve benzer bulgular, mevcut süreç ile SafePatch destekli süreç arasında dengeli atanır. Aynı kişi aynı yamayı iki kolda görmez. AppSec uzmanı yamaları hangi koldan geldiğini bilmeden değerlendirir. Onaylar gerçek insan onayıdır |
| Kapanış ve 30 gün sonra | Rapor | Devam kararı. Pilottan 30 gün sonra tekrar açılan bulgular ve bakım maliyeti |

**Ölçütler**

| Kod | Ölçüt | Tanım |
|---|---|---|
| M1 | Uygun iş hacmi | Ayda Java kaynak değişikliği gerektiren bulgu sayısı; bağımlılık ve imaj güncellemeleri ayrı |
| M2 | Derlenebilirlik | Pilot depolarının proje tanımıyla sandbox'ta derlenip testlerinin koştuğu oran |
| M3 | Tekrar sıklığı | Bölüm 3 |
| M4 | Doğru ve birleştirilebilir yama | Uygun işlerden, SafePatch adayının insan incelemesinde kabul edilip birleştirildiği oran |
| M5 | Aktif süre | Bulgu başına aktif mühendis ve inceleme süresi, mevcut süreç ile SafePatch destekli süreçte; bekleme süresi ayrı |
| M6 | Hatalı kabul | SafePatch'in kabul ettiği ama inceleyenin, gizli testlerin ya da 30 günlük izlemenin geri çevirdiği yamalar |
| M7 | İnsana devir | SafePatch'in "insan gerekli" dediği işlerin oranı ve nedenleri |
| M8 | Hafıza | Gölge modda hafıza kapalı ve açık kollar arasındaki M4 farkı; birebir tekrar ve örnek sayıları |
| M9 | Kurulum ve işletim | Kurulum süresi, ayda işletim saati |
| M10 | Satın alma | Ücretli devam ya da niyet mektubu; bütçe kalemi ve karar tarihi |

**Örnek başarı hedefleri** (hipotez; pilot öncesi kurumla tek bir set sabitlenir)
- M4: uygun işlerin en az %25'inde doğru ve birleştirilebilir yama.
- M5: aktif süre hedefi iki belgemizde farklı yazılmış; pilot öncesi biri seçilmeli:
  - [ARGE_VE_TICARILESME.md](ARGE_VE_TICARILESME.md): aktif mühendis süresinde en az %25 azalma;
  - [ARASTIRMA_ONCALISMASI.md](ARASTIRMA_ONCALISMASI.md): medyan aktif inceleme süresinde %30 azalma.
- M6: hatalı güvenlik kabulü mevcut sürece göre artmaz.

**Durdurma kuralı:** Kurumun kritik saydığı bir hatalı kabul görülürse otomatik akış durur, kök neden incelenir. Pilot ancak kurumun onayıyla sürer.

**Ücret:** Pilot, bir ölçüm ve kurulum hizmeti olarak ücretlendirilir; ürünün performansı kanıtlanmış gibi gerekçelendirilmez. Fiyat teklifi ayrı bir belgedir (ROADMAP Hafta 11, "Pilot teklifi").

## 5. Sorumlular

ROADMAP'teki atamalara göre:
- **Görüşmeler ve pilot protokolü:** Şevket ve Reşat; finans görüşmeleri Reşat.
- **Tekrar ölçüm betiği (bölüm 3):** model ve deneyler sorumlusu Kadir için öneri.
- **Gölge mod ve canlı aşamanın sandbox, kurulum ve egress tarafı:** Şevket ve Yiğithan.

## Proje liderinin kararı gereken noktalar

1. **Eşikler (bölüm 2):** S1 en az 2 güçlü sinyal; S2 ayda 70 iş; S3 %10 ve %20.
2. **M5 hedefi:** %25 aktif mühendis süresi mi, %30 medyan inceleme süresi mi?
3. **Görüşme notları:** Git'e yalnız anonim özet girsin, ham notlar depo dışında tutulsun mu?
4. **Gölge mod izni:** kurumun geçmiş onaylı düzeltmelerinin hafızaya alınması için izin metni.
5. **Tekrar ölçüm betiği:** pilot öncesi yazılsın mı, kim yazsın?
