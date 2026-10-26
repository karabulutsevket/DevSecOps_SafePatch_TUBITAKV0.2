# L3 değerlendirme seti (Hafta 6, 26 Ekim 2026)

**Katalog:** [l3/catalog.yml](../l3/catalog.yml). **Denetim:** `scripts/l3_catalog.py`. **Hazırlık:** `scripts/prepare_vul4j.py` (VUL4J-79), `scripts/prepare_l3.py` (diğer Vul4J vakaları). **Vaka kontrolü:** `scripts/vul4j_check.py`, `scripts/l3_check.py`. **Gizli testler:** `scripts/l3_hidden.py`.

## Kurallar

Katalog yalnız üst bilgi tutar: kaynak, proje, CWE, taraf, lisans, upstream commit'leri, hazırlık betiği, tanık, gizli testler, durum. Dış projelerin kodu bu depoya girmez; depolar ve proje tanımları `.runtime/l3` altında üretilir. `scripts/l3_catalog.py` şunları denetler ve bozulursa sıfırdan farklı kodla çıkar:

- **Dış vaka yalnız değerlendirme tarafında.** Vul4J ve OWASP Benchmark vakaları geliştirme tarafına giremez.
- **Bir proje yalnız bir tarafta.** Bu yüzden sahibi olduğumuz bütün sentetik vakalar geliştirme tarafında: `-02` ve `-03` varyantları `-01` ile aynı şablonu paylaşıyor. Önceki ölçümlerde bunlar "değerlendirme" diye raporlanmıştı; L3'te öyle sayılmaz.
- **Hazır bir değerlendirme vakasının gizli testi var.** Klasörü ve test seçicileri tanımlı olmalı.
- **Dışlanan vaka gerekçesini yazar.** Ayrıca kimlikler tekil olmalı ve her gizli test klasörü bir vakaya ait olmalı.

## Gizli değerlendirme testleri

Amaç, **yanlış kabulü** ölçmek: doğrulamadan geçen ama açığı gerçekte kapatmayan ya da davranışı bozan bir düzeltme.
- Gizli testler vakanın deposunda değil, `l3/hidden/<vaka>` altında durur; doğrulayıcı onları hiç görmez ve çalıştırmaz.
- Bir aday kabul edildikten sonra `l3_hidden.py` testleri adayın temiz bir kopyasına koyar ve sandbox'ta çalıştırır.
- Yalnız `lab` ve `evaluation` profilinde çalışır.
- Deney işleri için: `scripts/l3_hidden.py --jobs <jobs.db ya da iş JSON klasörü> --label <ad>`; kabul edilen her iş için bir satır ve yanlış kabul sayısı yazar.
- Testler sabit bir istisna beklemez; yalnız diske ne yazıldığına bakar. Böylece farklı ama doğru düzeltmeler de geçer.
- Testlerin bir kısmı davranış testidir (ör. adında ".." geçen ama hedef klasörde kalan dosyalar). Fazla katı bir düzeltme de böylece yakalanır.
- Bir ilke: gizli testler, upstream insan düzeltmesinin de karşıladığı davranışı tarif eder. Örneğin VUL4J-43'ün upstream düzeltmesi, kanonik olmayan bir hedef klasörde yanlış alarm verebilir; bunu sınayan bir test bilerek eklenmedi.

## Vakalar

| Vaka | Proje | Açık | Davranış testleri | Durum |
|---|---|---|---|---|
| VUL4J-79 | zt-zip | CWE-22 | 116 | hazır ([kontrol](../evidence/v02-l3-gizli/vul4j-79-check.json)) |
| VUL4J-43 | rdf4j, `util` modülü | CWE-22 | 108 | hazır ([kontrol](../evidence/v02-l3-vakalar/vul4j-43-check.json)) |
| VUL4J-41 | plexus-archiver | CWE-22 | 140 | hazır ([kontrol](../evidence/v02-l3-vakalar/vul4j-41-check.json)) |
| VUL4J-18 | jspwiki, `jspwiki-main` | CWE-22 | — | planlandı: JUnit 5, diğer modüllere bağımlı |
| VUL4J-42 | plexus-utils | CWE-78 | — | **dışlandı**: düzeltme üç kaynak dosyayı ve mevcut testlerin beklentilerini değiştiriyor; bir iş yalnız bulgunun dosyasını değiştirebilir |

Her vaka dört durumla kontrol edildi; her birinde gizli testler de çalıştı:
- açık sürüm;
- upstream insan düzeltmesi;
- yalnız yorum ekleyen kontrol;
- kısmi düzeltme: makul ama eksik bir düzeltme.

| Vaka | Kısmi düzeltme | Doğrulama | Gizli testler |
|---|---|---|---|
| VUL4J-79 | Upstream'in 4 korumasından yalnız tanığın sınadığı 2'si | **doğrulandı** | 2/4 başarısız: yakalandı |
| VUL4J-43 | Yalnız dosya dalında kontrol; klasör girdisi dışarıda oluşturuluyor | **doğrulandı** | 1/3 başarısız: yakalandı |
| VUL4J-41 | Yalnız `../` ile başlayan adları reddeden kontrol | **doğrulandı** | 2/3 başarısız (iç içe ve mutlak ad): yakalandı |

Bütün vakalarda kontroller beklendiği gibi sonuçlandı:
- Açık sürüm geçerli taban; tanığı başarısız.
- İnsan düzeltmesi doğrulandı ve gizli testlerin hepsini geçti.
- Kontrol yaması reddedildi.

## Vul4J'nin hazır testleriyle ilgili bulgular

1. **Saldırı testleri insan düzeltmesinin mesajını sınıyor.**
   - VUL4J-41 ve VUL4J-43'ün saldırı testleri, istisnanın upstream düzeltmesindeki mesajla başlamasını şart koşuyor; VUL4J-43'te istisnanın türü de sabit.
   - Mesajı farklı yazan ya da kötü girdiyi atlayan doğru bir düzeltme bu yüzden reddedilirdi.
   - Bu vakalarda tanığı SafePatch yazdı (`l3/witness/<vaka>`, MIT); tanık yalnız etkiye bakıyor. Vul4J'nin arşiv dosyaları korunuyor.
2. **VUL4J-43'ün saldırı girdisi Linux'ta dışarı çıkamıyor.**
   - `hello/../../world.txt` düzeltilmemiş kodda da yazılamıyor, çünkü `hello` klasörü yok ve dosya açılamıyor.
   - Vul4J'nin testi yalnız istisna mesajı farklı olduğu için başarısız oluyor.
   - SafePatch tanığı `../world.txt` kullanıyor; bu, düzeltilmemiş kodda gerçekten dışarı yazıyor.
3. **Ortama bağlı testler.**
   - plexus-archiver'ın sembolik bağlantı testleri ve izin testi, Windows'taki çalışma kopyasında geçemiyor. Git sembolik bağlantı oluşturma yetkisi olmadan onları düz dosya olarak çıkarıyor; `/mnt/c` izinleri tutmuyor.
   - Bu testler gerekçesiyle proje tanımından çıkarıldı (zt-zip'teki çalıştırma izni testi gibi).
   - Atlanan testler de çıkarıldı: `JarToolModularJarArchiverTest` JDK 9+ istiyor (sandbox JDK 8), `ConcurrentJarCreatorTest` upstream'de `@Ignore`. Runner atlanan testi olan paketi geçmiş saymaz; bu kural gevşetilmedi.
4. **Ayırt etmeyen gizli test.** VUL4J-41'in ilk gizli testlerinden biri tar arşivinde `../../evil.txt` deniyordu; bu girdi düzeltilmemiş kodda da dışarı yazmadı, yani hiçbir şey ölçmüyordu. Yerine mutlak yollu bir girdi kondu. Kural: bir gizli test açık sürümde başarısız olmalı ya da davranış testi olmalı.

## Bu sırada düzeltilen altyapı sorunları

- **Çok modüllü projeler.** Proje tanımı bir Maven modülü seçebiliyor: `build.module` (`-pl`); modül repodaki başka modüllere bağlıysa `also_make` (`-am`). Testler ve raporlar o modülden okunur. Modül adı harf ya da rakamla başlamak zorunda, böylece `-am` gibi bir değer Maven'a seçenek olarak gidemez.
- **Testlerde de geçerli ayarlar.** Paketleme adımında atlanan eklentiler (ör. animal-sniffer) test adımında da atlanıyor. Bu yapılmayınca çevrimdışı test adımı başarısız oluyordu.
- **Davranış seçicisi.** Yalnız dışlama (`!X`) içeren bir seçici, Surefire'ın test klasöründeki bütün sınıfları, fixture olarak gelen derlenmiş sınıflar dahil, yüklemesine yol açtı. Yeni vakalarda Surefire'ın varsayılan test adları ve dışlama birlikte yazılıyor.
- **Bağımlılık indirme.** Surefire'ın JUnit sağlayıcısı, projenin kendi Surefire ve JUnit sürümlerine sabitlenmiş deneme projesiyle çözülüyor. Hâlâ hiçbir proje testi ağ açıkken çalışmıyor.

İndirilenler (izinli):

| Kaynak | Boyut |
|---|---|
| plexus-archiver | 0,7 MB |
| plexus-utils | 0,3 MB |
| rdf4j | 1,2 MB |
| jspwiki | 6 MB |
| OWASP Benchmark | 10 MB |
| Maven bağımlılıkları (VUL4J-41 ve VUL4J-43) | 18 + 33 MB |

Hepsinden yalnız düzeltme commit'i ve ebeveyni çekildi; Benchmark'tan yalnız son commit.

## Sayılar ve sonraki adım

`l3_catalog.py` çıktısı: geliştirme tarafında 13 hazır vaka (hedef 20), değerlendirme tarafında hazır vakalar yukarıdaki tabloda (hedef 40).

**OWASP Benchmark** tek bir projedir (2 740 vaka), tamamı değerlendirme tarafına gider.

| Kategori | Gerçek açık | Güvenli (yanlış pozitif) |
|---|---|---|
| SQL injection | 272 | 232 |
| Path traversal | 133 | 135 |
| Komut enjeksiyonu | 126 | 125 |

Sonraki sınıf paketleri için de vaka var: zayıf rastgele 218/275, cookie 36/31, XPath 15/20, LDAP 27/32.

Benchmark'ta saldırı testi yok. Her kategori için bir tanık şablonu gerekiyor: servlet sahte bir istekle doğru girdi kaynağından çağrılır ve etkiye bakılır (dışarıdaki dosyanın okunması, çalışan komutun bıraktığı iz, sorgunun döndürdüğü fazladan satır). Güvenli vakalarda tanık açık sürümde de geçer. Bu yüzden taban geçersiz sayılır ve iş modele gitmeden insana döner; bu, bu vakalarda istenen davranıştır.
