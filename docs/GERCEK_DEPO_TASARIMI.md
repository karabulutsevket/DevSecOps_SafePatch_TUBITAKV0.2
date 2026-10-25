# Gerçek depo desteği — envanter ve proje tanımı tasarımı

**Durum:** Onaylandı, 25 Ekim 2026 (kararlar Bölüm 6'da) · **Tarih:** 25 Ekim 2026

Bu belge iki şey içerir: (1) V0.2 kodunun bugün yalnız 9 sentetik vakayı işleyebilmesine neden olan sabitlerin envanteri, (2) bunların yerine gelecek **proje tanımı** şeması ve tasarım kararları. Kod tarafında şema `safepatch/project.py` içinde tanımlıdır; Hafta 3'te iş akışına bağlandı (Bölüm 7).

---

## 1. Envanter: sentetik vakalara bağlı varsayımlar

| # | Yer | Varsayım | Gerçek depoda ne olur? | Çözüm (hafta) |
|---|---|---|---|---|
| 1 | `common.py:118`, `orchestrator.py:143` | Vaka kimliği şemada sabit: `^(sql\|path\|command)-0[123]$` | Başka proje kaydedilemez | Genel proje kimliği deseni + kayıt kontrolü (3) |
| 2 | `common.py:17` `SOURCE` (ürün kodunda 30 kullanım) | Modelin değiştirebileceği tek dosya `src/main/java/demo/DemoService.java` | Bulgu başka dosyadaysa düzeltilemez | Tanımdaki `editable` kuralları + bulgunun dosyası (3–4) |
| 3 | `repository.py` `baseline()` | Depodaki **bütün** dosyalar belleğe UTF-8 metin olarak okunur ve tek tek SHA-256 ile karşılaştırılır | İkili dosyalarda (resim, jar) çöker; büyük depoda yavaş | Git commit'i bütünlüğü zaten sabitler; yalnız gereken dosyalar okunur, çalışma alanı `git` ile çıkarılır (3) |
| 4 | `repository.py` `materialize()` | Çalışma alanı bellekteki metin sözlüğünden yazılır | İkili dosyalar ve dosya izinleri kaybolur | Çalışma alanı doğrudan depodan, sabit commit'ten çıkarılır (3) |
| 5 | `repository.py` `review_commit()` | Taban commit sabit yazar/tarih/dosya listesiyle **sıfırdan yeniden üretilir**; dosya yolu sabit | Geçmişi olan depoda aynı commit üretilemez | İnceleme deposu gerçek taban commit'ten klonlanır, aday onun çocuğu olur (3) |
| 6 | `runner.py:36,116,117` | Test raporu `TEST-demo.{BehaviorTest,SecurityTest}.xml` | Projenin kendi testleri okunmaz | Bütün Surefire raporları okunur; testler tanımdaki seçicilerle rollere ayrılır (4) |
| 7 | `runner.py:48,126` | Güvenlik işaretleri ve "beklenen işaret" vaka türüne göre sabit | Projenin tanığı farklı adlandırılır | Tanımdaki tanık seçicisi; işaret isteğe bağlı (4) |
| 8 | `runner.py:131` | Çıktı `target/demo.jar` | Proje çıktısı farklı | Tanımda isteğe bağlı `artifact`; yalnız staging için gerekir (3) |
| 9 | `runner.py:61–79`, `scanner.py:26,33,35` | Semgrep yalnız `SOURCE` dosyasını tarar; her bulgunun dosyası `SOURCE` diye **üzerine yazılır**; parmak izi `kural + SOURCE` | Bulgunun gerçek dosyası kaybolur | Tanımdaki tarama yolları; bulgu gerçek göreli yolunu taşır (3–4) |
| 10 | `scanner.py:17` `builtin_scan`, `runner.py:84` Sonar kural eşlemesi | Vaka türüne (`kind`) göre sabit kural | `kind` gerçek projede yok | Bulgunun CWE'si (Hafta 4 eşleme tablosu) |
| 11 | `engine.py:93`, `orchestrator.py:80` | İş yalnız **ilk taramanın ilk bulgusunu** ele alır | Diğer bulgular kaybolur | Bulgu başına iş (4) |
| 12 | `engine.py` (`case["kind"]`), `feedback.py`, `memory.py:24` | Rehber ve hafıza vaka türüne bağlı | `kind` yok | CWE ailesi → rehber anahtarı; hafıza CWE + yapısal imza (4) |
| 13 | `policy.py` | `edit.path != SOURCE` ise ret | — | Tanımdaki `editable` + sabit koruma listesi (3) |
| 14 | `worker1.py` `SYSTEM`, `CONTEXT_PATH` | Sistem talimatı sentetik vakalara özgü ("owned synthetic file", `demo.EchoMain`); bağlam yolu `src/main/java/` | Gerçek projede yanıltıcı | Genel talimat + projeye özgü bilgi bağlam verisinde (4) |
| 15 | `deployer.py` | Spring Boot jar'ı `java -jar` ile staging'de çalıştırılır | Her proje çalıştırılabilir uygulama değil | Staging yalnız sentetik demo profilinde; gerçek projede kapalı |
| 16 | `seed.py` manifest | `allowed: [SOURCE]` alanı var ama **hiçbir yerde kullanılmıyor** | — | Tanımdaki `editable` ile değişir |

Testler (`tests/`) ve deney betikleri de `SOURCE` ve vaka kimliklerini kullanıyor; geçişte sentetik vakalar yeni tanımlarla çalıştırılarak aynı davranış korunur (Hafta 3 kabul ölçütü).

---

## 2. Tasarım ilkeleri

1. **Proje tanımı güvenilir yapılandırmadır, depo içeriği değildir.** Tanım, SafePatch yöneticisinin kaydettiği bir dosyadır. Müşteri deposundaki bir dosya **hiçbir zaman** düzenlenebilir alanı genişletemez, test komutunu değiştiremez ya da politika belirleyemez. Depo içeriği, model çıktısı gibi güvenilmeyen veridir.
2. **Komutlar serbest metin değildir.** Derleme ve test, seçeneklerle tanımlanır (ör. Maven hedefleri, test seçicileri); kabuk komutu yazılamaz. Çevrimdışı (`-o`) ve yerel önbellek bayrakları SafePatch tarafından eklenir, tanımla kapatılamaz.
3. **Bütünlüğü Git sağlar.** Tanım 40 karakterlik commit özetini sabitler; çalışma alanı o commit'ten çıkarılır. Dosya başına özet listesi yalnız sentetik vakalarda ek kontrol olarak kalır.
4. **Değiştirilebilir alan dar başlar.** Varsayılan değiştirilebilir dosya yoktur; tanım açıkça izin verir. İlk sürümde model yalnız **bulgunun bulunduğu dosyayı** değiştirebilir ve o dosya `editable` kurallarına uymalıdır.
5. **Sabit koruma listesi tanımdan güçlüdür.** Testler, derleme dosyaları ve CI yapılandırması tanım ne derse desin korunur.
6. **Kanıt yoksa iddia yok.** Projede güvenlik tanığı yoksa sistem "güvenlik doğrulandı" diyemez (bkz. açık karar 3).

---

## 3. Proje tanımı şeması (`safepatch-project/1`)

```yaml
schema: safepatch-project/1
id: sql-01                          # ^[a-z0-9][a-z0-9._-]{0,62}$
scope: owned-java-demo              # yetki kapsamı (kullanıcıların proje listesi)
repository:
  path: .runtime/repos-v3/sql-01    # yerel Git deposu (çıplak ya da çalışma kopyası)
  commit: 0123...abcd               # 40 karakter, sabit taban commit
java: "17"
build:
  tool: maven                       # V0.2'de yalnız maven
  package_goals: ["-DskipTests", "package"]
  artifact: target/demo.jar         # isteğe bağlı; yalnız staging için
tests:
  behavior:                         # meşru davranışı koruyan testler
    selectors: ["demo.BehaviorTest"]
  security:                         # güvenlik tanığı (yoksa açık karar 3)
    selectors: ["demo.SecurityTest"]
    markers: ["SQL_INJECTION_REGRESSION"]
editable: ["src/main/java/**/*.java"]
scan:
  paths: ["src/main/java"]
limits:
  build_seconds: 240
  test_seconds: 240
labels:                             # yalnız laboratuvar/deney için; ürün kararlarında kullanılmaz
  kind: sql
  split: development
```

**Test seçicileri** Maven `-Dtest=` sözdiziminin güvenli bir alt kümesidir: `paket.Sınıf`, `paket.Sınıf#metot`, `paket.*Test` gibi; boşluk, tırnak ve kabuk karakterleri reddedilir. Rapor okuma, seçicinin eşleştiği sınıfların Surefire raporlarını toplar.

**Sabit koruma listesi** (tanım değiştiremez): `pom.xml` ve alt modüllerdeki `pom.xml`, `*.gradle`, `*.gradle.kts`, `gradlew*`, `mvnw*`, `.mvn/**`, `src/test/**`, `**/src/test/**`, `.github/**`, `.gitlab-ci.yml`, `Jenkinsfile`, `.git/**`, `.semgrep*`, `sonar-project.properties`.

### Gerçek bir proje için örnek (Hafta 5 hedefi; değerler örnek)

```yaml
schema: safepatch-project/1
id: vul4j-ornek
scope: lab-evaluation
repository: {path: /veri/depolar/proje-x, commit: <zafiyetli commit>}
java: "8"
build: {tool: maven, package_goals: ["-DskipTests", "package"]}
tests:
  behavior: {selectors: ["org.ornek.**.*Test"]}
  security: {selectors: ["org.ornek.parser.XmlParserTest#testXxe"]}   # zafiyeti gösteren test
editable: ["src/main/java/**/*.java"]
scan: {paths: ["src/main/java"]}
labels: {split: evaluation, source: vul4j}
```

Vul4J her vaka için zafiyeti gösteren testleri listeler; bu bilginin şemaya nasıl aktarılacağı Hafta 5'te veri setinin kendisinden doğrulanacak.

---

## 4. Uygulama planı

| Hafta | Adım | Kabul ölçütü |
|---|---|---|
| 2 | Şema (`safepatch/project.py`), doğrulama kuralları, 9 sentetik vakanın tanımları, testler | Ekip onayı; tanımlar şemadan geçiyor |
| 3 | Kayıt ve çalışma alanı: `git` ile çıkarma, ikili dosya desteği, gerçek taban commit'in çocuğu olarak aday commit; politika `editable` + koruma listesiyle | 9 sentetik vaka yeni yoldan aynı sonucu veriyor; mevcut testler ve kısa H2 tekrarı **(25 Ekim: tamamlandı; 194 birim + 10 gerçek Maven/JUnit entegrasyon testi)** |
| 4 | Bulgu başına iş; bulgu gerçek dosya yolunu taşır; Surefire raporlarının seçicilerle okunması; tanık yoksa davranış (açık karar 3) | Tek depoda birden çok bulgu ayrı işler olarak ilerliyor |
| 5 | İlk gerçek açık kaynak proje (Vul4J) uçtan uca | Derleme, test, bulgu, yama, doğrulama kayıtları |
| 5–6 | Docker sandbox | Gerçek proje sandbox içinde |

---

## 5. Ekip kararı bekleyen konular

1. **Tanım biçimi:** YAML (insan tarafından düzenlenir; `yaml.safe_load`) — önerilen. Alternatif JSON.
2. **Tanımların yeri:** Sunucuda SafePatch veri klasöründe (`DATA_ROOT/projects/*.yml`), yalnız yönetici yazabilir — önerilen. Sentetik vaka tanımları `seed.py` tarafından üretilir. **Müşteri deposunun içinde tanım okunmaz.**
3. **Güvenlik tanığı olmayan proje:** Aday derleme, davranış testleri ve yeniden taramadan geçse bile "incelemeye hazır" olmaz; `needs_human` + `security_witness_missing` gerekçesiyle, kanıtları ve diff'i ekli olarak insana gider — önerilen. Alternatif: "kanıt eksik" etiketiyle incelemeye hazır.
4. **Davranış testleri uzun sürerse:** İlk sürümde tanımdaki seçicilerle sınırlanır; çok modüllü projede yalnız etkilenen modülü derlemek (`-pl ... -am`) sonraki adım.
5. **Bir işte birden çok dosya:** İlk sürümde yalnız bulgunun dosyası. Birden çok dosya gerektiren düzeltmeler insana devredilir.

---

## 6. Kararlar (25 Ekim 2026)

| # | Konu | Karar | Nasıl verildi |
|---|---|---|---|
| 1 | Tanım biçimi | YAML, `yaml.safe_load` | Önerilen varsayılan; itiraz gelirse değişir |
| 2 | Tanımların yeri | Sunucuda `DATA_ROOT/projects/*.yml`, yalnız yönetici yazar; müşteri deposunun içinde tanım okunmaz | Proje sahibi seçti |
| 3 | Güvenlik tanığı olmayan proje | Aday "incelemeye hazır" olmaz; `needs_human` + `security_witness_missing`, diff ve kanıtlar ekli | Proje sahibi seçti |
| 4 | Uzun davranış testleri | İlk sürümde tanımdaki seçicilerle sınırlı; çok modüllü derleme sonraki adım | Önerilen varsayılan; itiraz gelirse değişir |
| 5 | Bir işte dosya sayısı | Yalnız bulgunun dosyası (ve o dosya `editable` kurallarına uymalı); çok dosyalı düzeltme insana | Proje sahibi seçti |

---

## 7. Hafta 3 uygulaması (25 Ekim 2026)

| Envanter # | Ne yapıldı |
|---|---|
| 1 | Vaka kimliği şemada genel proje kimliği deseni; kayıt kontrolü proje tanımlarından |
| 2, 13 | Değiştirilebilir dosya artık sabit değil: yalnız bulgunun dosyası ve o dosya tanımın `editable` kurallarına uymalı (`repository.allowed_files`); politika izinli dosyayı açıkça ister |
| 3 | `baseline()` dosyaları sabit commit'ten ihtiyaç duyuldukça okur; ikili dosya yalnız metin olarak okunmaya çalışılırsa reddedilir, ham baytı ayrıca okunabilir |
| 4 | Çalışma alanı `git clone` + sabit commit; ikili dosyalar ve kipler korunur, uzak depo bağlantısı silinir |
| 5 | Aday commit gerçek taban commit'in çocuğu; runner ve bağımsız doğrulayıcı aynı yamadan aynı commit'i üretir |
| 6, 7 | Testler tanımdaki seçicilerle çalışır; bütün Surefire raporları okunur; işaretler tanımdan gelir |
| 8 | Çıktı yolu tanımdan; tanımda yoksa aday kabul edilmez (gerçek projeler için Hafta 5) |
| 9 | Tarama yolları tanımdan; bulgu gerçek göreli yolunu taşır, çalışma alanı dışı yol reddedilir |
| — | Korunan dosyaların değişmediği `git status` ile denetlenir (bütün dosyaları belleğe almadan) |
| — | Güvenlik tanığı olmayan projede aday asla kabul edilmez; iş `security_witness_missing` ile insana gider (karar 3) |

Kalan envanter maddeleri: 11 (bulgu başına iş, Hafta 4), 14 (genel sistem talimatı, Hafta 4), 15 (staging yalnız sentetik demoda). 12 ve 10 Hafta 4'te yapıldı: hafıza ve rehber CWE ailesine bağlandı ([HAFIZA_UYGUNLUK.md](HAFIZA_UYGUNLUK.md)); 10'un kalan parçası olan Sonar ön denetimi yalnız sentetik vakalarda laboratuvar etiketini kullanıyor.

**Doğrulama:** 194 birim testi; gerçek Maven/JUnit ile 10 entegrasyon testi (9 sentetik vaka: başlangıçta zafiyet, referans düzeltme kabul, işlevi bozan yama ret, test dosyasına dokunan yama çalıştırılmadan ret; 1 staging/geri alma). Gerçek projeye benzeyen geçici bir depoyla (birden çok paket, ikili dosya, commit geçmişi) okuma, klon, aday commit ve izin testleri.

**Model tekrarı (commit `592d03d`):** H2 deneyinin seed 42 dilimi yeni iş akışıyla yeniden koşuldu: 9 vaka × `v01` ve `guided+context` = 18 iş ([kanıt](../evidence/v02-w3-dogrulama/retry/)). Amaç yeni bir ölçüm değil, davranışın değişmediğini göstermek.

| | H2 (`3d0f54f`, seed 42) | Hafta 3 (`592d03d`) |
|---|---|---|
| `v01` kabul | 3/9 (yalnız SQL) | 3/9 (yalnız SQL) |
| `guided+context` kabul | 7/9 | 8/9 |

- Sistem talimatı ve rehber özetleri H2 protokolüyle aynı. İlk deneme istemi 18 işin 18'inde H2 ile bayt bayt aynı: yeniden yazım modelin girdisini değiştirmedi.
- 18 işin 17'si aynı sonucu verdi. Tek fark `command-03` / `guided+context`: H2'de üç denemede reddedildi, bu koşuda üçüncü denemede kabul edildi. Bu iş, ilk deneme istemi aynı olduğu hâlde model farklı yama ürettiği için ayrıştı. 8/9 bu yüzden bir iyileşme olarak raporlanmaz.
- Aynı istem, aynı seed ve sıcaklık 0 ile iki ilk denemede (`command-03` / `guided+context`, `path-03` / `v01`) model H2'dekinden farklı yama üretti. Yerel model çalışma zamanı bayt düzeyinde tekrarlanabilir değil; tek koşuluk vaka sonuçları gürültülüdür.
- İki `v01` işinin ret gerekçesi `no_progress` yerine `duplicate_patch`: model ikinci denemede ilk yamayı aynen tekrarladı. İkisi de H2'deki gibi reddedildi.
- Kabul edilen 11 işin hepsinde inceleme deposunun HEAD'i adayın commit'i, onun ebeveyni de gerçek taban commit.

Sonuç: Hafta 3 kabul ölçütü ("sabitler kaldırılır, davranış aynı kalır") karşılandı.
