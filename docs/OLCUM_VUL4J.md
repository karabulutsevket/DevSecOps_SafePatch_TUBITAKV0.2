# İlk gerçek açık kaynak proje: VUL4J-79 (25 Ekim 2026, Hafta 5)

**Ham kayıt:** [evidence/v02-vul4j/vul4j-79-check.json](../evidence/v02-vul4j/vul4j-79-check.json). Betikler: `scripts/prepare_vul4j.py`, `scripts/vul4j_check.py`. Kurulum: [KURULUM_V02.md](KURULUM_V02.md#değerlendirme-vakası-vul4j-79-l3-hafta-5).

Bu bir **onarım ölçümü değildir**. Burada sınanan şeyler şunlardır:
- Gerçek bir açık kaynak projenin SafePatch'in proje tanımıyla Docker sandbox'ında derlenebilmesi ve test edilebilmesi.
- Güvenlik tanığının açık sürümü düzeltilmiş sürümden ayırabilmesi.

Yamayı model değil, projenin kendi geliştiricisi yazmıştır.

## Vaka

| Alan | Değer |
|---|---|
| Vaka | VUL4J-79, CVE-2018-1002201, CWE-22 ("Zip Slip": arşivdeki `../` yolu hedef klasörün dışına yazar) |
| Proje | zeroturnaround/zt-zip, Apache-2.0, Maven, Java 6 hedefli (JDK 8 imajında derlenir) |
| Açık sürüm | `d1c4077` (düzeltmenin ebeveyni) |
| Düzeltme | `759b72f`, `ZipUtil.java`'da 4 yere 36 satır |
| Türetilmiş commit | `57c32d5`: açık sürüm + düzeltmedeki saldırı testi ve iki arşiv; sabit kimlik ve tarihle her seferinde aynı özet |
| Dosya | `ZipUtil.java`, 97 694 karakter, 3 310 satır |
| Güvenlik tanığı | `DirectoryTraversalMaliciousTest` (2 test: `unpack` ve `BackslashUnpacker`) |
| Davranış testleri | Projenin kendi testlerinden tanık ve aşağıdaki bir test dışındaki 116'sı |
| Bulgular | Cevap anahtarından 4 konum (satır 1152, 1220, 1225, 1260): "bilinen bulgu" kipi |

Vul4J (GPL-3.0) yalnız vaka listesi olarak kullanıldı; kodu alınmadı. Vaka yalnız L3'tedir: türetilmiş depo ve proje tanımı `.runtime/l3` altındadır, Git'e, `samples/`'a ve ürüne girmez.

## Sonuç

Üç koşu, aynı sandbox'ta: `maven:3.9.16-eclipse-temurin-8`, özetle sabit, ağ yok.

| Koşu | Derleme | Davranış | Güvenlik tanığı | Bulgu | Sonuç |
|---|---|---|---|---|---|
| Açık sürüm (taban) | geçti | 116/116 geçti | 2/2 başarısız (beklenen) | 4 | **taban geçerli** |
| Upstream insan düzeltmesi | geçti | 116/116 geçti | 2/2 geçti | 0 | **doğrulandı**, jar üretildi |
| Kontrol: yalnız yorum ekleyen yama | geçti | 116/116 geçti | 2/2 başarısız | 0 | **reddedildi** |

Notlar:
- İnsan düzeltmesi bir aday yamayla aynı yoldan geçti: yama politikası (36 değişen satır), aday commit, derleme, davranış ve tanık.
- Kontrol yaması tanığın sonucu belirlediğini gösterir. Bilinen bulgu kipinde yamadan sonra yeniden tarama yapılmaz, bu yüzden bulgu listesi her yamada boştur; kabulü tanık verir.
- Jar özeti koşudan koşuya değişir, çünkü Maven arşive zaman damgası yazar. Özet yalnız o koşuyu tanımlar.

## Uçtan uca: orkestratör üzerinden uzman yolu

**Ham kayıt:** [evidence/v02-vul4j/e2e/](../evidence/v02-vul4j/e2e/protocol.json). Betik: `scripts/vul4j_e2e.py`. Kayıt temiz bir commit'ten (`e83544e`) alındı.

Akış, orkestratörün gerçek uygulamasıyla (uç noktalar, yetki, iş deposu, motor) koştu; doğrulama worker2 ve runner servisleri üzerinden sandbox'ta yapıldı. İki kimlik betiğin sürdüğü **test kimlikleridir**: `SIMULATED-expert` (iş açar, inceler) ve `SIMULATED-reviewer` (inceler). Kararlar **simüledir**, insan kararı değildir. Uzman yaması olarak upstream insan düzeltmesi gönderildi.

| Adım | Sonuç |
|---|---|
| 1. İş (bilinen bulgu kipi) | Taban sandbox'ta geçerli, 4 bulgu tek dosyada tek iş |
| 2. Model | **Çağrılmadı.** Dosya modelin girdi sınırını aşıyor; iş `needs_human` / `source_exceeds_model_context` ile uzmana düştü (0 model denemesi, token ayrılmadı) |
| 3. Uzman yaması | Ön izleme 36 satır; politika ve doğrulamadan geçti, `awaiting_review` |
| 4. Dört göz | Yazarın kendi onayı reddedildi; ikinci kimlik onayladı |
| 5. Hafıza | Yazarın hafızaya alması reddedildi (`author_cannot_promote_own_patch`); ikinci kimlik aldı |
| 6. İkinci iş, aynı vaka | Kayıt **birebir tekrar** edildi (`approved-memory-replay`, model yok), sandbox'ta yeniden doğrulandı |
| 7. İkinci işin onayı | Tekrar edilen yama yazarını korur: yazarın onayı yine reddedildi; ikinci kimlik onayladı |

Hafıza kaydının kanıt vektörü:
- 1 doğrulanmış yeniden kullanım ve 1 inceleyici onayı.
- Tarama sonucu "yok". Bilinen bulgu kipinde yamadan sonra yeniden tarama yapılmaz; arayüz bunu "yeniden taranmadı, tanık belirler" diye gösterir.

Yapısal imza: hedef çağrı `java.io.File.<init>`, kaynak metot parametresi.

Dağıtım (staging) bu akışa dahil edilmedi. zt-zip bir kütüphanedir; staging'in çalıştırdığı bir uygulama değildir.

## Model, bölge kipinde (25 Ekim, Hafta 5)

**Ham kayıt:** [evidence/v02-vul4j/model/](../evidence/v02-vul4j/model/summary.json). Betik: `scripts/vul4j_model.py`. Kayıt temiz bir commit'ten (`9c89d47`) alındı. Tasarım: [GERCEK_DEPO_TASARIMI.md §9](GERCEK_DEPO_TASARIMI.md#9-bölge-tabanlı-düzenleme-25-ekim-2026-hafta-5).

`ZipUtil.java` bütünüyle modele sığmadığı için model, dört bulguyu içeren **üç metodu** (3 128 karakter) ve dosyanın import satırlarını gördü. Ayarlar:
- `guided+context` stratejisi, hafıza kapalı, 3 deneme, seed 42, 43 ve 44.
- Deney işleri: onaya ve hafızaya girmez.
- Sistem talimatı ve CWE-22 notu bu vakaya göre **ayarlanmadı**.

| Ölçü | Sonuç |
|---|---|
| Doğrulanan iş | **0 / 3** |
| Bölge kipi mekaniği | 9 denemenin 9'unda çalıştı: model 3 bölgeyi döndürdü, SafePatch dosyaya yerleştirdi, sandbox'ta derlendi |
| İstem / cevap | Ölçülen istem 2 472–2 623 token (sınır 5 632), cevap 903–1 142 token (sınır 2 048), model süresi 19–24 sn |
| Başarısızlık | 6 denemenin 6'sı `compilation_failed`: "cannot find symbol". Kalan 3 deneme önceki yamanın tekrarı (`duplicate_patch`), doğrulamaya girmedi |

Gözlemler:
1. **Model import eklemedi.** `Path`, `Paths` ve `Files` kullandı ama cevabın `imports` alanını 9 denemede de boş bıraktı. Bu tipler dosyada import edilmemiş.
2. **Modele giden derleme hatası eksik sembolün adını içermiyor.**
   - javac adı "cannot find symbol" satırının altındaki `symbol:` satırında verir.
   - Projenin eski derleyici eklentisi (maven-compiler-plugin 2.3.2) bu satırı Maven çıktısına hiç yazmıyor (elle yeniden derlenerek görüldü).
   - SafePatch da yalnız ilk satırı alıyor. Model neyin eksik olduğunu bilemedi.
3. **CWE-22 notu bu durumda yanlış yöne itiyor.** Not "gerçek yolu `toRealPath()` ile çöz" diyor. Bir model cevabı bunu uyguladı, ama arşiv açarken hedef dosya henüz yok ve bu çağrı hata verir.
4. **Belirlenimlilik.** Sıcaklık 0'daki ilk deneme üç seed'de de aynı yamayı verdi. İkinci deneme (sıcaklık 0,4) üçünde de ilkini tekrarladı.

Bu sonuçlar sistem talimatı, CWE-22 notu ya da derleme geri bildirimi değiştirilmeden alındı. VUL4J-79 bir **değerlendirme** vakası olduğu için bu sorunlar bu vakaya bakarak ayarlanırsa ölçüm kirlenir. Düzeltmeler önce geliştirme vakalarında (ör. sahibi olduğumuz büyük dosyalı sentetik vakalar) geliştirilip ölçülmeli; VUL4J-79 sonra bir kez yeniden koşulmalı.

## Vakayı çalıştırırken bulunan ve düzeltilen sorunlar

1. **Yasak ifade kontrolü bütün dosyaya bakıyordu.** `ZipUtil.java` dosyasında projenin kendi koyduğu üç `// NOSONAR` var. Bu yüzden bu dosyaya gelen her yama, insan düzeltmesi dahil, reddediliyordu.
   - Yeni kural: yama yasak bir ifadeyi eklenen bir satıra koyamaz ve bir ifadenin dosyadaki sayısını artıramaz. İkinci koşul satırlara bölünmüş ifadeyi de yakalar.
   - Dokunulmamış koddaki mevcut ifadeler artık engel değil.
   - Sentetik vakalarda davranış aynı. Ekleme, taşıma ve bölme durumları için testler var (`tests/test_policy.py`).
2. **Bir yama en çok 24 000 karakter taşıyabiliyordu.** Sınır 1 000 000 karaktere çıktı. Modelin girdi sınırı (worker1, 24 000 karakter) değişmedi; aşağıya bakın.
3. **JDK 8 gerekiyordu.** Projenin derleyici eklentisi (2.3.2, Java 6 hedefi) JDK 17'de çalışmıyor. Sandbox imajını artık proje tanımındaki `java` sürümü seçiyor; JDK 17 ve JDK 8 imajları özetle sabit.
4. **Tanık, insan düzeltmesini de reddetti.**
   - Neden: saldırı arşivi `/tmp/evil.txt` dosyasına yazıyor. Kapsayıcıda Java'nın geçici klasörü `/tmp` olduğu için, düzeltilmiş kod bu yolu "hedef klasörün içinde" sayıyordu.
   - Düzeltme: sandbox'ta test JVM'i artık ayrı bir geçici klasör kullanıyor (`/jvmtmp`, `/tmp` gibi `noexec`).
   - Bu değişiklik bütün projeler için geçerli. Sentetik üç aile sandbox'ta yeniden doğrulandı.
   - Gözlem: tanık ortama bağımlıdır. Linux'ta geçici klasör `/tmp` ise bu vaka düzeltmeyi ayırt edemez.
5. **Bir davranış testi sandbox kısıtıyla çelişiyor.** `FilePermissionsTest#testPreserveExecuteFlag` çalıştırılabilir dosya izni bekliyor; sandbox'ın geçici klasörleri ise `noexec`.
   - Sandbox gevşetilmedi. Bu tek test (117 testin biri) proje tanımında `!` seçicisiyle dışlandı; gerekçesi `prepare_vul4j.py` içinde yazılı.
6. **Surefire'ın JUnit 4 sağlayıcısı önceden indirilmemişti.** Surefire sağlayıcıyı yalnız bir test seçildiğinde çözüyor.
   - Bağımlılıklar ağı açık, öteki kısıtları aynı bir kapsayıcıda indiriliyor.
   - Bu sırada zt-zip testi çalışmıyor. Sağlayıcıyı kendi tek testli deneme projemiz çözüyor.
   - İndirilen toplam yaklaşık 28 MB.

## Sınırlar

- **Tanık 4 konumun 2'sini sınıyor** (`unpack` ve `BackslashUnpacker`). Bu iki yolu koruyan ama `unwrap` ve üst düzey `BackslashUnpacker` dalını korumayan bir yama da kabul edilir. Bu Vul4J'nin saldırı testinin sınırıdır; raporlarda belirtilmelidir.
- **Bulgu konumları düzeltmeden alındı.** Bilinen bulgu kipi, tarayıcının bulmadığı açıkları onarım ölçümüne sokmak içindir. Tespit başarısı ayrıca ölçülecek (Hafta 7).
- **Tek vaka.** Genelleme yapılmaz. Davranış testleri projenin kendi testleridir; gizli değerlendirme testi yoktur.
- **Model bu dosyayı bütünüyle göremez.** `ZipUtil.java` 97 694 karakter; model bağlamı 8K token. Bölge kipiyle yalnız bulguları içeren metotları görüyor (yukarıda).
- **Henüz doğrulanan bir model yaması yok.** Geliştirme vakalarındaki düzeltmelerden sonra yeniden koşuldu, yine 0/3. Import sorunu kalktı; kalan hatalar modelin `File` ile `Path` API'lerini karıştırmasından ([OLCUM_BOLGE_GELISTIRME.md](OLCUM_BOLGE_GELISTIRME.md#vul4j-79-bir-kez-yeniden-26-ekim)).
- **Arayüz tarayıcıda denenmedi.** Yeni seçenek ("Bilinen bulgu · değerlendirme vakası", cevap anahtarı olan vakada kendiliğinden seçilir) ve yeni açıklama metinleri tarayıcıda görülmedi. Uçtan uca akış API üzerinden koştu.
