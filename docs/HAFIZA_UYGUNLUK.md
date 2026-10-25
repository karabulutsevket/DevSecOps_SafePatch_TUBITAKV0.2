# Hafıza uygunluk kararı

Bu belge, bir hafıza kaydının yeni bir bulguya **ne zaman** ve **nasıl** uygulanabileceğinin nasıl kararlaştırıldığını anlatır (ROADMAP.md Hafta 4). Onaylı kayıtlar ve [başarısızlık kayıtları](BASARISIZLIK_HAFIZASI.md) aynı kararı kullanır. Kod: `safepatch/weakness.py`, `safepatch/signature.py`, `safepatch/memory.py` (`context_for`, `applicability`, `adaptability`, `use_of`).

## Karar (25 Ekim, Hafta 4)

Her kayıt ve her yeni iş bir **bağlam** taşır. Bir kaydın kullanımı için iki ayrı karar verilir. Her biri `compatible`, `incompatible` ya da `unknown` olur; bir alan bir tarafta yoksa sonuç `unknown`.

| Karar | Zorunlu alanlar | Neye izin verir |
|---|---|---|
| **Birebir** (`applicability`) | Proje, CWE ailesi, JDK, dosya yolu, build dosyası özeti, test sözleşmesi özeti | Kaynak kod da aynıysa kaydın yaması **model çağrılmadan** tekrar uygulanır |
| **Uyarlamalı** (`adaptability`) | Proje, CWE ailesi, JDK ve [yapısal imzanın](#yapısal-imza-25-ekim-hafta-4) biçimi: hedef çağrı, kurulum, kütüphane, kütüphane sürümü | Kayıt **modele örnek** olarak verilir; dosya, build ve test özetleri aranmaz |

Korumalı modda (`guarded`, yeni işlerin varsayılanı ve deneylerde C kolu) bir kaydın kullanımı şöyle belirlenir:

| Kullanım | Koşul |
|---|---|
| `replay` | Birebir karar `compatible` ve kaynak kod özeti aynı |
| `example` | Uyarlamalı karar `compatible` |
| `example_unknown` | Uyarlamalı karar `unknown` (ör. kayıtta imza yok, JDK bilinmiyor). Yol haritası kararı: bilinmeyen kayıt **en fazla modele örnek** olur, asla tekrar edilmez. |
| Elenir | Uyarlamalı karar `incompatible` (başka proje, aile, JDK ya da imza biçimi) |

- **Seçim sırası:** önce `replay`, sonra `example`, sonra `example_unknown`; her grupta en yeni kayıt. Hiçbir durumda hafızadan gelen aday doğrulamayı atlamaz.
- **Hash'lerin rolü:** kaynak, build ve test özetleri yalnız birebir tekrar kararına girer.
- **Kaynak türü:** değerin nereden geldiği (`source`) imza karşılaştırmasına girmez; düzeltme kalıbını değiştirmez.
- **Kanıt:** her aday için iki karar ve kullanım, işin kanıtında `memory_lookup.considered` alanına, elenenler `rejected` alanına yazılır. Hafta 5'teki "neden seçildi / elendi" paneli bunu gösterecek.
- **Ön koşulsuz kol** (`naive`, deneylerde B kolu): aynı ailedeki en yeni kaydı ön koşul aramadan örnek olarak verir, tekrar etmez.
- **Başarısızlık kayıtları:** aynı kaynak (`same_source`), aynı sözleşme (`same_context`) ve aynı imza biçimi başka dosyada (`same_shape`) ilişkileriyle bulunur. `unknown` bağlamlar ders sayılmaz.

**Etkisi:** Hafta 4'ten önce dosya yolu, build ve test özetlerinin hepsi aynı olmadan kayıt örnek olarak bile kullanılamıyordu. Aynı projede başka bir dosyadaki aynı kalıp hafızadan yararlanamıyordu. Bu değişiklik H1 deneyinin C kolunu da değiştirir. V0.1 benchmark kanıtı eski kararla üretilmiştir ve olduğu gibi kalır.

## CWE ailesi (25 Ekim, Hafta 4)

Hafta 4'ten önce bağlam, tarayıcının kural kimliğini (`rule_id`) ve sentetik vakanın laboratuvar etiketini (`kind`) zorunlu alan olarak kullanıyordu. Bu iki sonuç doğuruyordu:
- Semgrep bulgusundan onaylanan bir düzeltme, aynı zayıflığın Sonar ya da FindSecBugs bulgusunda hiç eşleşmiyordu.
- Laboratuvar etiketi olmayan gerçek projelerde kayıtlar hep `unknown` kalıyordu.

Artık her bulgu bir **CWE ailesine** indirgeniyor (`weakness.family`):

1. Bulgunun kendi CWE'si varsa o kullanılır. Semgrep metadata'sı ve yerleşik demo tarayıcısı CWE taşır; `CWE-89`, `cwe-089` ve `["CWE-89: ..."]` biçimleri tanınır.
2. Yoksa kural tablosuna bakılır:
   - kendi Semgrep kurallarımızın metadata'sı (`rules/java.yml`);
   - runner'ın kullandığı Sonar anahtarları;
   - FindSecBugs desen adları.
3. Alt CWE'ler aileye bağlanır: CWE-564 → CWE-89, CWE-23 ve CWE-36 → CWE-22, CWE-338 → CWE-330.
4. CWE'si bulunamayan bulgunun ailesi `None` olur ve hafıza `unknown` der. Yanlış eşleşme yerine çekimserlik.

`rule_id` bağlamda izlenebilirlik için kalır, eşleşmeye katılmaz.

**Kural tablosunun sınırı:** Sonar ve FindSecBugs girdileri şu an yalnız mevcut sınıfları (CWE-89, 22, 78) ve sıradaki zayıf rastgele sayı sınıfını (CWE-330) kapsar. Her giriş, ilgili adaptör gerçek araçla ilk kez koştuğunda doğrulanacak. Yeni bir sınıf paketi kendi kural eşlemesini ekler. Kendi Semgrep kurallarımızın her birinin CWE metadata'sı taşıması testle zorunlu.

**Rehber:** yeniden deneme rehberi de laboratuvar etiketi yerine aileden seçilir (`feedback.GUIDANCE_KEY`). Ailesi bilinen ama kendi metni olmayan zayıflıklar genel metni alır. H2, Hafta 3 ve path ölçümlerindeki 153 işin hepsinde aileden seçilen anahtar eski etiketle aynı; sentetik vakalarda model istemleri değişmedi.

**Eski kayıtlar:** Hafta 4'ten önce yazılmış bağlamlarda `cwe_family` alanı yoktur. Ailesi kural kimliğinden hesaplanır. Kural tabloda yoksa kayıt `unknown` kalır. Kayıtların kendisi değiştirilmez; kalıcı geçiş betiği Hafta 4'ün ayrı maddesi.

## Yapısal imza (25 Ekim, Hafta 4)

Kaynak kod farklı olduğunda (uyarlamalı kullanım), kaydın uygulanabilirliğini kod özetleri değil, **koddan okunan yapı** belirlemeli. `safepatch/signature.py` bunu tree-sitter-java ile çıkarır. Yalnız sözdizimine bakar: adlar dosyanın importlarından nitelendirilir, tip denetimi yapılmaz.

| Alan | Anlamı | Örnek |
|---|---|---|
| `sink` | Zayıflığın hedef çağrısı, nitelikli adıyla | `java.sql.Statement.executeQuery`, `org.springframework.jdbc.core.JdbcTemplate.queryForList`, `java.lang.ProcessBuilder.<init>` |
| `construction` | Hedefe giden değerin nasıl kurulduğu | `concatenation`, `format`, `string_builder`, `resolve`, `direct`, `literal`, `none`, `other` |
| `source` | Değerin kökeni; birden çok kaynak varsa dışarıdan en kolay kontrol edilen | `http_request` > `method_parameter` > `environment` > `system_property` > `unknown` |
| `library`, `library_version` | Hedefi sağlayan kütüphane; sürüm yalnız üçüncü taraf kütüphaneler için `pom.xml`'den (`${özellik}` çözülür, sürümsüz bağımlılık `managed`) | `jdbc`, `spring-jdbc` + `6.1.14`, `java-process` |

Hedef seçimi: bulgu satırını içeren metottaki hedef çağrılar aday olur. Tarayıcılar farklı satır bildirir (Semgrep hedef çağrıyı, demo tarayıcı argümanın kurulduğu satırı). Adaylar arasında argümanı dışarıdan beslenen önce gelir, sonra satıra yakın olan. Değer geriye doğru en çok 4 yerel atama izlenir; `StringBuilder`'a sonradan eklenen (`append`) değerler de sayılır. Ailenin hedef tablosunda çağrı bulunamazsa imza `None` olur.

Dokuz sentetik vakanın hepsinde imza, tarayıcının bildirdiği satırdan bağımsız olarak doğru çıkıyor. Spring `JdbcTemplate`, `prepareStatement` içinde birleştirme, `StringBuilder`, `Runtime.exec`, `Files.newInputStream(Paths.get(...))`, `FileInputStream` ve `Random` kalıpları testle sabit (`tests/test_signature.py`).

İmza, her işin ve kaydın bağlamına `signature` alanıyla yazılır ve uyarlamalı kararın temelidir (yukarıdaki Karar bölümü).

**Bilinen sınırlar:** dosyalar arası veri akışı izlenmez (değer başka bir sınıftan geliyorsa kaynak `unknown`); alan (field) ve kalıtım üzerinden gelen türler yalnız bildirimden okunur; hedef tablosu şu an CWE-89, 22, 78 ve 330 içindir, yeni sınıf paketleri kendi hedeflerini ekler.

## Sıradaki adımlar (Hafta 4)

- **Geçiş betiği:** eski kayıtlara aileyi yeni sürüm olarak yazan betik.
- **Bilinen sınır:** runner'ın Sonar ön denetimi hâlâ laboratuvar etiketine göre kural seçiyor; yalnız sentetik vakalarda kullanılıyor.
