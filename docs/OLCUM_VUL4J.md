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
- **Model bu dosyayı göremiyor.** `ZipUtil.java` 97 694 karakter. worker1 en çok 24 000 karakterlik kaynak alıyor, model bağlamı 8K token. Model bütün dosyayı yeniden yazdığı için çıktı da sığmaz. Bu vakada model tarafı (bölge tabanlı düzenleme ya da yalnız uzman yolu) ayrıca kararlaştırılacak.
- **Uçtan uca iş henüz yok.** Bu kayıt runner düzeyindedir: orkestratör üzerinden iş, inceleme, hafıza ve dağıtım bu vakada çalıştırılmadı. Orkestratörün iş isteği `known` tarayıcısını henüz kabul etmiyor.
