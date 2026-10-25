# Hafıza uygunluk kararı

Bu belge, bir hafıza kaydının yeni bir bulguya **ne zaman** uygulanabileceğinin nasıl kararlaştırıldığını anlatır (ROADMAP.md Hafta 4). Onaylı kayıtlar ve [başarısızlık kayıtları](BASARISIZLIK_HAFIZASI.md) aynı kararı kullanır. Kod: `safepatch/weakness.py`, `safepatch/memory.py` (`context_for`, `applicability`).

## Karar

Her kayıt ve her yeni iş bir **bağlam** taşır. Uygunluk üç değerden biridir:

| Karar | Ne zaman | Ne olur |
|---|---|---|
| `compatible` | Zorunlu alanların hepsi iki tarafta da var ve eşit | Kayıt kullanılabilir; aynı kaynak kodda birebir tekrar edilir, aday yine tam doğrulamadan geçer |
| `incompatible` | Zorunlu alanlardan biri farklı | Kayıt elenir, gerekçesi işin kanıtında |
| `unknown` | Zorunlu alanlardan biri bir tarafta yok | Kayıt otomatik kullanılmaz (çekimser) |

Zorunlu alanlar: proje, **CWE ailesi**, JDK, dosya yolu, build dosyası özeti, test sözleşmesi özeti. Kaynak kod özeti yalnız birebir tekrar için kullanılır.

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

## Sıradaki adımlar (Hafta 4)

- **Yapısal imza:** koddan çıkarılan hedef çağrı, kirli değerin kuruluşu, kaynak türü ve kütüphane. Uyarlamalı kullanımda (kaynak kod farklı) karar buna dayanacak.
- **Hash'lerin rolü:** kaynak, build ve test özetleri yalnız birebir tekrarda zorunlu olacak.
- **Geçiş betiği:** eski kayıtlara aileyi yeni sürüm olarak yazan betik.
- **Bilinen sınır:** runner'ın Sonar ön denetimi hâlâ laboratuvar etiketine göre kural seçiyor; yalnız sentetik vakalarda kullanılıyor.
