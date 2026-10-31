# Kurumun tarayıcı bulgularını içeri alma (SARIF 2.1.0)

**Durum (31 Ekim 2026).** Okuyucu ve testleri hazır: `safepatch/sarif.py`, `tests/test_sarif.py`. API, arayüz ve iş açma yok. Önce aşağıdaki kabul sorusunda proje liderinin kararı gerekiyor ("Karar").

**Neden.** Pilotun zorunlularından biri bu: kurum kendi tarayıcısını kullanıyor (CodeQL, Semgrep, Checkmarx, Fortify, SonarQube). Bugün bir iş yalnız SafePatch'in kendi tarayıcılarından başlıyor, laboratuvarda da cevap anahtarından. Kendi Semgrep kurallarımız L3'te 30 gerçek açığın hiçbirini bulmadı ([OLCUM_TESPIT.md](OLCUM_TESPIT.md)). Pilotta bulguların asıl kaynağı kurumun tarayıcısı olacak.

## Okuyucu

**Girdi.** Dışa aktarılan dosyanın baytları, projenin sabit commit'i, o commit'te izlenen dosyalar ve proje tanımındaki tarama yolları.

**Çıktı.** SARIF dosyasındaki her koşu (`run`) için bir rapor. Raporda şunlar var:
- `findings`: desteklenen ailelerdeki bulgular (CWE-89, 22, 78);
- `other_findings`: ayrı tutulanlar ve nedenleri;
- `skipped`: içeri alınmayan sonuçların sayıları;
- üretici aracın adı ve sürümü, dosyanın SHA-256'sı, dosyanın commit beyan edip etmediği.

**Bütün dosyayı reddeden durumlar.**

| Durum | Kod |
|---|---|
| 32 MiB'den büyük | `sarif_too_large` |
| UTF-8 JSON değil; yinelenen anahtar, NaN ya da Infinity var | `sarif_invalid_json` |
| `version` "2.1.0" değil ya da `$schema` başka bir sürümü gösteriyor | `sarif_version_unsupported` |
| Hiç koşu yok ya da bir koşunun `results` dizisi yok (araç bitirmemiş) | `sarif_run_without_results` |
| `executionSuccessful` true değil | `sarif_incomplete_scan` |
| 20'den çok koşu, 10 000'den çok sonuç ya da 500'den çok desteklenen bulgu | `sarif_too_many_runs`, `sarif_too_many_results`, `sarif_too_many_findings` |
| Beyan edilen commit (`revisionId`) sabit commit değil | `sarif_commit_mismatch` |
| Depo dışını gösterebilen konum: `..`, sürücü harfi, ters bölü, NUL, yüzde kodlu `..`, beyan edilmiş bir kökün altında olmayan mutlak yol | `sarif_path_outside_repository` |
| Şemaya uymayan alan: tanımsız `level` ya da `kind`, mesajsız sonuç, çelişen ya da yazdırılamayan kural kimliği, geçersiz satır | `sarif_malformed` |
| Kural kimliği, mesaj, dosya ya da araç adı SafePatch doğrulayıcı notunu taklit ediyor | `suspected_prompt_injection` |

**500 sınırı.** Bir işin doğrulama isteği diğer dosyalardaki en çok 500 bulgunun parmak izini taşıyabiliyor (`VerifyRequest.tolerated`).

**Sayılan ama içeri alınmayanlar (`skipped`).**
- `not_failure`: `kind` değeri `fail` değil (`pass`, `review`, `open`…).
- `absent`: aracın kendi karşılaştırmasında artık yok (`baselineState: absent`).
- `suppressed`: kabul edilmiş bastırma (kaynakta ya da aracın kendi incelemesinde). İncelemedeki (`underReview`) ya da reddedilmiş bastırma bulguyu gizlemez.
- `unmapped`: konumu yok ya da dosya sabit commit'te izlenmiyor.
- `outside_scan_paths`: dosya, proje tanımının tarama yollarının dışında.
- `duplicate`: aynı kural, aynı dosya, aynı satır.

**Yollar.**
- Göreli yol depo kökünden okunur; `uriBaseId` zinciri izlenir.
- Beyan edilmemiş ya da URI'si olmayan taban depo köküdür. Semgrep `%SRCROOT%` adını beyan etmeden kullanıyor.
- Mutlak yol (`file:///…`) yalnız koşunun beyan ettiği mutlak bir tabanın altındaysa kabul edilir. En dıştaki mutlak taban, taranan kök, yani depo kökü sayılır.
- Yol tahmin edilmez; son ek eşleştirmesi yapılmaz. SpotBugs'ın kaynak köküne göre yazdığı yollar bu yüzden `unmapped` olur.
- Varsayım: kurum depoyu kökünden taradı. Bir modül klasöründen taradıysa `unmapped` sayısı büyür. Çözüm, dışa aktarım ayarını düzeltmek ya da yöneticinin vereceği bir kök öneki eklemek; ikincisi bugün yok.

**CWE ailesi.**
- CWE kaynakları: kuralın CWE taksonomisine ilişkisi (SpotBugs); kural etiketleri (CodeQL `external/cwe/cwe-089`, Semgrep `CWE-89`); sonucun kendi `taxa` alanı ve etiketleri.
- Hiçbiri yoksa kural kimliği `weakness.family` ile aranır (ör. Sonar `javasecurity:S3649`).
- Alt CWE aileye bağlanır, ör. CWE-564 → CWE-89 (`weakness.FAMILY`).
- Tam olarak bir desteklenen aile adlandıran sonuç bulgudur. CodeQL'in `java/path-injection` kuralı CWE-22, 23, 36 ve 73 etiketli; tek desteklenen aile CWE-22.
- Diğerleri ayrı tutulur: desteklenmeyen aile (`unsupported_family`), iki desteklenen aile (`ambiguous_family`), hiç CWE yok (`no_cwe`). Bunlar raporlanır, iş açmaz, yeniden taramayı engellemez (FindSecBugs'taki `other_findings` gibi).

**Parmak izi.** `sarif`, üretici araç, kural ve dosyanın SHA-256 özeti.
- Satır numarası girmez. Yamadan sonra satırlar kayar; aynı kural aynı dosyada hâlâ raporlanıyorsa bulgu gitmemiş sayılmalı. Semgrep bulgularının parmak izi de bugün kural ve dosyadır.
- Aracın kendi `fingerprints` ve `partialFingerprints` alanları kullanılmaz. Bunlar güvenilmeyen veridir; Semgrep OSS bu alana "requires login" yazıyor (kayıtlı fikstür).

**Güvenilmeyen metin (CLAUDE.md kural 1).**
- Mesaj tek satıra indirilir. Satır sonu, kontrol ve yön değiştirme karakterleri boşluk olur. 300 karakterde kesilir; Semgrep ve FindSecBugs mesajlarıyla aynı sınır.
- Kural kimliği ve araç adı yalnız yazdırılabilir karakter içerebilir.
- Doğrulayıcı notunu taklit eden metin bütün dosyayı reddettirir. İş açılırsa motor bulguyu model çağrısından önce bugünkü gibi yeniden denetler (`imitates_note(canonical(finding))`).
- Kural açıklaması, yardım metni ve kod parçacığı (`snippet`) içeri alınmaz.

**Neyle denendi.**
- Gerçek dışa aktarımlar: Semgrep 1.136.0'ın SARIF çıktısı (kendi kurallarımız, sentetik laboratuvar, 3 vaka; `tests/fixtures/sarif/`). SpotBugs 4.9.8 + FindSecBugs SARIF'i (Hafta 7 fikstürü). SpotBugs Türkçe yerel ayarlı makinede `level` değerini "warnıng" (noktasız ı) yazıyor; okuyucu bunu düzeltip okuyor.
- CodeQL biçiminde elle yazılmış örnek. Araç çıktısı değil.
- Checkmarx, Fortify ve SonarQube dışa aktarımı denenmedi; elimizde örnek dosya yok. SonarQube'un SARIF dışa aktarıp aktarmadığı sürüme bağlı; doğrulanmadı.
- Pilottan önce kurumun gerçek dosyasıyla denenmeli. CWE başka bir alandaysa eşlemesi o zaman eklenir (Hafta 4 tablosundaki ilke).

## Karar: yamadan sonra "bulgu gitti" kanıtı

**Bugünkü kural (ürün profili).** Kabul için derleme, davranış testleri, güvenlik tanığı ve SafePatch'in kendi tarayıcısıyla temiz yeniden tarama gerekir. Lab ve evaluation profilindeki bilinen bulgu kipinde yeniden tarama yapılmaz, tanık karar verir.

**Sorun.** Yamadan sonra kurumun tarayıcısı SafePatch içinde çoğu zaman yeniden çalıştırılamaz: kapalı ağ, lisans. "Bulgu gitti" kanıtı şu üç kaynaktan birinden gelmeli:

| | Kaynak | Artısı | Eksisi |
|---|---|---|---|
| **(a)** | SafePatch'in kendi tarayıcısı da bulguyu görüyorsa (aynı dosya, aynı aile) bugünkü kural aynen uygulanır. Görmüyorsa iş açılmaz ya da insana gider. | Kabul kuralı ve doğrulayıcı değişmez. | Kapsam dar. Kendi Semgrep kurallarımız L3'te 0/30 buldu. FindSecBugs 30/30 buldu ama 15 güvenli vakanın 15'inde de alarm verdi ([OLCUM_TESPIT.md](OLCUM_TESPIT.md)). FindSecBugs doğru bir komut düzeltmesinden sonra da bulgu raporluyor ([FINDSECBUGS.md](FINDSECBUGS.md)): doğru yama reddedilir. Kurumun aracının ne dediğini göstermez. |
| **(b)** | Yalnız güvenlik tanığı, laboratuvardaki bilinen bulgu kipindeki gibi. Tanık tabanda başarısız, yamadan sonra geçer. Yeniden tarama "yapılmadı" diye kaydedilir ve arayüzde öyle gösterilir. | Tanığı olan her projede, her içeri alınan bulguda çalışır. Ölçümlerde ayırt eden kapı tanık oldu: V0.1'de tarayıcıya bakan kapı 6 hatalı yamanın 6'sını kabul etti, tam kapı hiçbirini ([OLCUM_SONUCLARI.md](OLCUM_SONUCLARI.md)). | **Ürün profilinde kabul kuralını gevşetir.** Tanık bulgunun bütün konumlarını sınamayabilir: VUL4J-79'da 4 konumdan 2'sini sınıyor. İlk L3 koşusunda tanıkla kabul edilen 9 adaydan biri (vul4j-43) yanlış kabuldü; gizli testler yakaladı ([OLCUM_L3_MODEL.md](OLCUM_L3_MODEL.md)). Denetçiye "tarayıcınız artık raporlamıyor" denemez. |
| **(c)** | Kurum aday commit'i kendi CI'ında tarar, SARIF yeniden içeri alınır. Parmak izi yoksa bulgu gitmiştir. O zamana kadar iş yeni bir "tarama bekliyor" durumunda kalır. | Kanıt kurumun kendi aracından gelir; denetim için en güçlüsü. | Döngü uzar. MR/PR entegrasyonu (pilot zorunlusu 3) olmadan dosya elle taşınır. Yeni bir iş durumu ve uç nokta gerekir. Taramanın aday commit'e ait olduğu gösterilmeli; `revisionId` zorunlu olur. Kurumun aracı da yanılabilir (FindSecBugs'taki kalıcı bulgu gibi). |

**Önerim (karar liderin).** İnceleme için (b), (a) mümkünse ek kanıt olarak; (c) geldiğinde kanıta eklenir ama onayı beklemez.
- Koşullar: yalnız güvenlik tanığı olan projelerde; tanığı olmayan iş bugünkü gibi `security_witness_missing` ile insana gider.
- Onay ekranında ve kanıt özetinde hangi kanıtın kullanıldığı yazar: "tanık", "SafePatch taraması", "kurum taraması".
- (b) bir gevşetmedir. Bu yüzden lider açıkça seçmeden uygulanmaz.
- Sakıncası: (c) gelmeden onaylanan bir yama, kurumun tarayıcısında hâlâ bulgu verebilir. Bu durum kanıtta görünür ama onayı geri almaz.

**Kararla değişecek kod (henüz yapılmadı).**
- Runner'da yeni tarayıcı kipi (ör. `sarif`; (a) için `sarif+semgrep`, `sarif+findsecbugs`) ve `VerifyRequest.scanner` deseni.
- `memory.evidence_vector` bugün `known-finding` dışındaki her aracı yeniden tarama sayıyor. (b) seçilirse `sarif` de "yeniden taranmadı" sayılmalı; yoksa hafıza kaydı olmayan bir taramayı kanıt diye taşır.
- Yeni uç nokta: dosya ve önizleme. Örnek: `POST /v1/finding-imports` ve `/preview`, `submit` rolü, `findings.imported` denetim kaydı (dosyanın SHA-256'sı, üretici, sayılar). Bulgular dosya başına işe bölünür (Hafta 4 kuralı).
- Arayüzde "Bulgu içeri al" formu ve Türkçe metinler.
