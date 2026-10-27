# L3 üzerinde ilk model ölçümü (26 Ekim 2026, Hafta 6)

**Ham kayıtlar:** [evidence/v02-l3-model/l3-model/](../evidence/v02-l3-model/l3-model/): `protocol.json`, `summary.json`, vaka başına `jobs/<vaka>.json`. **Betik:** `scripts/l3_measure.py`. **Set:** [L3_SETI.md](L3_SETI.md).

Modelin cevapları üçüncü taraf kodunu içerdiği için Git'e girmez (`.runtime/l3-measure/l3-model-1/`); kayıtlar yalnız özetlerini tutar.

Ölçüm Benchmark'ın `5b970a2` değerlendirme commit'inde koştu; bu commit, SafePatch'in `55a549e` commit'indeki betiklerle aynen yeniden üretilir. Sonraki ölçümler, görünür SQL testi düzeltilmiş `8bd5841` commit'inde koşar ([aşağıda](#görünür-sql-davranış-testinin-düzeltilmesi-26-ekim)).

## Kurulum

| Alan | Değer |
|---|---|
| Vakalar | L3 kataloğunda hazır olan 45 değerlendirme vakasının hepsi. 30'u gerçek açık: 27 OWASP Benchmark, 3 Vul4J. 15'i güvenli kod, hepsi Benchmark |
| İş | Vaka başına bir iş: yerel model (`qwen2.5-coder:7b-instruct-q4_K_M`), `guided+context`, hafıza kapalı, en çok 3 deneme, seed 42 |
| İş türü | Deneme işi: onaylanmaz, hafızaya girmez |
| Bulgu | Cevap anahtarından ("bilinen bulgu") |
| Kabul | Derleme, davranış testleri, güvenlik tanığı ve politika birlikte karar verir |
| Doğrulama ortamı | Docker sandbox'ı, WSL diskindeki çalışma kopyası |
| Yanlış kabul ölçümü | Kabul edilen her aday, doğrulayıcının hiç görmediği gizli testlerle bir daha sınanır |
| Süre | Toplam 85 dakika. İş başına ortalama 113 sn (en çok 225 sn), güvenli vakalar ~26 sn. Model çağrısı ortalama 12,7 sn |

## Sonuç

| Vakalar | İş | Doğrulayıcının kabul ettiği | Gizli testleri geçen | Gizli testlerin yakaladığı | Deneme hakkı biten | Politikanın reddettiği |
|---|---|---|---|---|---|---|
| Gerçek açık, path (Benchmark) | 10 | 1 | 1 | 0 | 8 | 1 |
| Gerçek açık, path (Vul4J) | 3 | 1 | 0 | 1 | 2 | 0 |
| Gerçek açık, SQL | 10 | 5 | 2 | 3 | 5 | 0 |
| Gerçek açık, komut | 7 | 2 | 2 | 0 | 4 | 1 |
| **Gerçek açık, toplam** | **30** | **9** | **5** | **4** | **19** | **2** |
| Güvenli kod | 15 | 0 | — | — | — | — |

- **Güvenli kod:** 15 vakanın 15'i modele gitmeden insana döndü. Bu vakalarda tanık açık sürümde zaten geçtiği için taban geçersiz sayılıyor. Model hiç çağrılmadı.
- **Kabul edilen 9 aday hangi denemede geldi:** 4'ü ilk denemede, 2'si ikincide, 3'ü üçüncüde.

## Gizli testlerin yakaladığı 4 aday: inceleme

Gizli testler kabul edilen 9 adaydan 4'ünü başarısız buldu. Dördünün de kodu okundu. İnceleyen Claude; insan incelemesi bekliyor.

| Vaka | Aday ne yapıyor | Gizli testte başarısız olan | Sonuç |
|---|---|---|---|
| vul4j-43 | Çıkış yolunu `toRealPath()` ile çözüyor; kök kontrolü yok | İçinde nokta geçen zararsız bir adla çıkarma (hata) | **Gerçek yanlış kabul.** Henüz var olmayan bir dosyada `toRealPath()` hata atar. Saldırı engellenmiş görünüyor, çünkü artık hiçbir yeni dosya çıkarılamıyor. Görünür 108 davranış testinin hepsi geçti; demek ki hiçbiri bu yoldan yeni bir dosya çıkarmıyor. |
| Benchmark 00678, 01087, 02181 | Parametreli sorgu: `PASSWORD=?`, girdi bağlı parametre olarak geçiyor | Başka bir zararsız girdiye verilen yanıt eskisiyle aynı mı | **Gizli testin hatası.** Sonuç boş dönünce servlet sorgu metnini yanıta yazıyor; parametreli sorguda bu metin `?` içeriyor. Gizli testin zararsız girdisi (`User01`) hiçbir satırla eşleşmediği için tam bu yola düşüyor. Test, bu servlet'lerdeki her doğru parametreleştirmeyi reddeder. Gizli saldırı testi üç adayda da geçti. |

**Sayımlar:**

| | İlk gizli testler | Kod incelemesi | Düzeltilmiş gizli testler |
|---|---|---|---|
| Yanlış kabul | 4 / 9 | 1 / 9 | **1 / 9** |
| Doğru onarım | 5 / 30 | 8 / 30 | **8 / 30** |

İlk gizli test kaydı değiştirilmedi; üç sayım birlikte raporlanır.

### Düzeltilmiş gizli testlerle yeniden ölçüm (26 Ekim)

**Kayıtlar:** [hidden/l3-model-1-gizli-sql.json](../evidence/v02-l3-model/hidden/l3-model-1-gizli-sql.json) (9 aday), [evidence/v02-l3-gizli-sql/](../evidence/v02-l3-gizli-sql/) (kontrol ve negatif kontrol).

Gizli SQL testi düzeltildi. Kabul edilen 9 aday, kayıtlı cevaplarıyla yeniden sınandı; model yeniden çağrılmadı.

- **Ne değişti.** Gizli testin ikinci zararsız girdisi karşılaştırılırken, servlet'in yanıta yazdığı sorgu metni (`... query: <sorgu>`) ayıklanıyor. Satırlar, iletiler ve reddetmeler karşılaştırmada kalıyor. Kod: `l3/benchmark/hidden` (`HiddenSupport`).
- **Doğrulayıcının testleri değişmedi.** `HiddenSupport` yalnız gizli testlerle gidiyor. Değerlendirme deposunun sabitlenmiş commit'i aynı çıktı (`5b970a2`); vaka tanımları ve katalog değişmedi.
- **Yeni kayıt.** Benchmark yeniden kaydedildi. Değişen tek değerler, `User01` yanıtında sorguyu yazan 6 SQL vakasının gizli test özetleri. Diğer bütün kayıtlı değerler aynı; yeni özetler de çalıştırmadan çalıştırmaya değişmiyor.
- **Kontrol.** 42/42 beklendiği gibi: gizli testler açık sürümde, eskiden olduğu yerlerde başarısız oluyor ve geçiyor.
- **Negatif kontrol.** 00678'in doğru adayına, küçük harf dışındaki her girdiyi reddeden bir koşul eklendi. Görünür girdi (`bar`) bundan geçiyor; düzeltilmiş gizli test bu adayı yine yakaladı.
- **Sonuç.** 9 adaydan 8'i düzeltilmiş gizli testleri geçti. Tek yanlış kabul vul4j-43; değişmeyen gizli testi yine yakaladı.

Düzeltme sonuçlar görüldükten sonra yapıldı. Yalnız sorgu yankısını ayıklıyor; doğrulayıcının testleri ve kabul kararları aynı kaldı.

Gizli testleri geçen 5 aday da okundu:
- **01964, 02091 (SQL):** Parametreli sorgu. 02091 ayrıca girdiyi olduğu gibi döndüren bir yardımcı çağrıyı kaldırıyor; davranış değişmiyor.
- **02414 (komut):** Kabuk yerine `echo`'ya ayrı bir argüman veriyor.
- **01839 (path):** Gerçek yollarla kök kontrolü yapıyor.
- **00306 (komut):** Girdiyi betiğe giden ortam değişkeninden tamamen çıkarıyor. Kaba bir düzeltme, ama veri akışını kesiyor ve yanıt değişmiyor.

## Reddedilen denemeler

Model yalnız gerçek açıklarda çağrıldı: 78 deneme.

| Denemenin sonucu | Path | SQL | Komut | Toplam |
|---|---|---|---|---|
| Derlenmedi | 15 | 7 | 2 | 24 |
| Boş yama (kod değişmedi) | 0 | 4 | 9 | 13 |
| Önceki yamanın aynısı | 7 | 3 | 1 | 11 |
| Açığı kapattı, davranışı bozdu | 4 | 0 | 5 | 9 |
| Açık kaldı | 5 | 2 | 0 | 7 |
| Açık kaldı, davranış da bozuldu | 3 | 0 | 0 | 3 |
| Politika reddi | 1 | 0 | 1 | 2 |
| Doğrulandı | 2 | 5 | 2 | 9 |
| **Toplam** | **37** | **21** | **20** | **78** |

- **Açığı kapatıp davranışı bozan 9 deneme.** Hepsi okundu; davranış testi dokuzunda da haklı. Adaylar şunları yapıyor:
  - tek bir sabit dışındaki her girdiyi reddediyor;
  - yalnız harf ve rakama izin veriyor;
  - programı yer tutucuyla değiştiriyor (`fixed_executable`, `/path/to/fixed/executable`);
  - Linux'ta `cmd.exe` çağırıyor;
  - kökü yanlış yerden alıyor.
- **Politika reddi (2 iş).** Politika reddi işi hemen bitirir; kalan denemeler kullanılmaz.
  - **01066:** Aday yeni bir `Runtime.getRuntime().exec` satırı ekliyor. Ret tasarım gereği.
  - **01643:** Aday, zaten var olan `java.net.URISyntaxException` geçen bir `catch` satırını değiştiriyor. Değişen satırda yasak bir ifade geçtiği için iş reddedildi. Burada politika amaçlanandan katı davranıyor. Gevşetilip gevşetilmeyeceği politika sahibinin kararı; bu çalışmada politika değiştirilmedi.

## Gözlemler

Bunların hepsi geliştirme tarafında ele alınmalı. Değerlendirme seti ayar yapmak için kullanılmaz.

1. **vul4j-43'te görünür davranış testleri zayıf.** Testler yeni dosya çıkarmayı sınamıyor. CWE-22 notu "kontrol etmeden önce gerçek yolları `toRealPath()` ile çöz" diyor; model bunu henüz var olmayan çıkış yoluna uyguladı ve kök kontrolünü hiç yazmadı.
2. **Küçük dosyalarda bölge kipi.** 78 denemenin 62'si bölge kipinde, ilk denemelerin bile yarısı (30'da 16). Tüm dosya bütçesi her baytı bir token sayıyor; 70 satırlık bir servlet, yeniden denemenin bağlamıyla birlikte bu bütçeye sığmıyor. Boş yamalar iki kipte de çıktı (bölge 9, tüm dosya 4).
3. **Komut vakaları.** Model ya kodu değiştirmeden dönüyor (20 denemenin 9'u) ya da programı bir yer tutucuyla değiştiriyor. Benchmark'ın komut vakaları girdiyi bir betiğe ortam değişkeni olarak veriyor. CWE-78 notunun "sabit bir programa tek argüman" tarifi bu kalıba uymuyor olabilir; bu bir varsayım, sınanmadı.
4. **En büyük kayıp derleme.** 78 denemenin 24'ü derlenmedi. Örnekler: var olmayan yardımcılar (`getSqlPreparedStatement`), `Path`/`File` tip karışıklığı.

## Görünür SQL davranış testinin düzeltilmesi (26 Ekim)

**Kayıtlar:** [evidence/v02-l3-gorunur-sql/](../evidence/v02-l3-gorunur-sql/) (kontrol, referans düzeltmeler, eski commit'te referans düzeltmeler), [evidence/v02-l3-model-sql/](../evidence/v02-l3-model-sql/l3-model/jobs/) (yeniden koşu). **Betik:** `scripts/benchmark_sql_reference.py`.

Gizli testteki sorgu yankısı sorunu doğrulayıcının görünür davranış testinde de vardı. O da düzeltildi; etkilenen vakalar model ile yeniden koşuldu.

- **Sorun.** Örneklenen 3 servlet (00196 ve 01097 gerçek açık, 01315 güvenli kod), davranış testinin girdisine (`bar`) verdiği yanıta sorgu metnini yazıyor. Bu vakalarda görünür test her doğru parametreleştirmeyi reddediyordu; doğrulayıcı doğru bir adayı geri çevirirdi.
- **Düzeltme.** `WitnessSupport.sqlAnswer` da yanıtı karşılaştırmadan önce sorgu metnini ayıklıyor. Değerlendirme commit'i artık `8bd5841`; `5b970a2`'den yalnız `WitnessSupport` ve bu üç vakanın davranış testinde ayrılıyor. Yeniden kayıtta yalnız bu üç vakanın görünür özetleri değişti.
- **Kontrol.** 42/42 beklendiği gibi.
- **Referans düzeltmeler.** 00196 ve 01097 için düz birer parametreli sorgu yazıldı. Betik bu düzeltmeleri tek satırlık değişikliklerle kurar; Benchmark kodu depoya girmez.
  - `8bd5841`'de ikisi de doğrulamadan (davranış, tanık) ve gizli testlerden geçiyor.
  - `5b970a2`'de ikisini de davranış testi reddediyor; tanık ikisinde de geçiyor.
- **Model ile yeniden koşu.** 00196, 01097 ve 01315 yeniden koşuldu; seed 42, aynı ayarlar. Sonuç değişmedi:
  - 00196 ve 01097'de üç deneme de derlenmedi ya da önceki yamanın aynısıydı. Model var olmayan yardımcılar çağırıyor (`getSqlPreparedStatement`, `getConnection`) ya da `execute`'u yanlış imzayla kullanıyor. Hiçbir aday davranış testine ulaşamadı.
  - 01315 modele gitmeden insana döndü.
  - 01097'nin iki denemesi aynı seed'le ilk koşudan farklı bir yama üretti.

Bu yüzden bu belgedeki sayılar değişmedi: görünür testteki hata bu ölçümün sonucunu etkilemedi.

## İkinci koşu: düzeltilmiş kodla (27 Ekim)

**Kayıtlar:** [evidence/v02-l3-model-2/l3-model/](../evidence/v02-l3-model-2/l3-model/). **Kod:** `hafta6-kok-neden` (`3cc5d50`).

Aynı 45 vaka ve aynı ayarlarla koşuldu: seed 42, `guided+context`, hafıza kapalı, 3 deneme. İlk koşudan farklar:
- **Bütçe.** İstem iki bayt bir token sayılıyor; tüm dosya kipi yalnız cevap da sığıyorsa seçiliyor ([KOK_NEDEN_UC_SORUN.md](KOK_NEDEN_UC_SORUN.md)). Bağlam artık modele gidiyor.
- **Değerlendirme commit'i.** `8bd5841`: görünür SQL testi düzeltilmiş.
- **Gizli SQL testi** düzeltilmiş.
- **Bağlam seçimi** hızlandı; aynı dosyaları seçiyor.
- **Politika aynı.**

| | İlk koşu | İkinci koşu |
|---|---|---|
| Güvenli kod modele gitmeden insana döndü | 15 / 15 | 15 / 15 |
| Doğrulayıcının kabul ettiği | 9 / 30 | 7 / 30 |
| Yanlış kabul (düzeltilmiş gizli testlerle) | 1 / 9 (vul4j-43) | **0 / 7** |
| Doğru onarım | 8 / 30 (%14–44) | 7 / 30 (%12–41) |
| Denemelerin kipi (tüm dosya / bölge) | 16 / 62 | 67 / 7 |
| En az bir bağlam dosyası giden deneme | 50 / 78 (hepsi bölge kipinde) | 55 / 74 |
| Politika reddi (iş biter) | 2 | 3 |
| Kodu değiştirmeyen cevap | 13 | 13 (hepsi gösterilen kodun tekrarı, hepsinde tanık başarısız) |
| Toplam süre | 85 dk | 68 dk |

İkinci koşuda doğru onarım SQL'de 5/10, path'te 2/13, komutta 0/7.

**Sonucu değişen 4 vaka:**

| Vaka | İlk koşu | İkinci koşu | Ne oldu |
|---|---|---|---|
| owasp-benchmark-02032 (path) | Deneme hakkı bitti (bölge kipi) | Doğru onarım (tüm dosya, ilk denemede) | — |
| owasp-benchmark-02414 (komut) | Doğru onarım (3. denemede) | Deneme hakkı bitti | İlk deneme derlenmedi; sonra iki boş cevap |
| owasp-benchmark-00306 (komut) | Doğru onarım (2. denemede) | Politika reddi, iş ilk denemede bitti | Aşağıda |
| vul4j-43 (path) | Yanlış kabul | Deneme hakkı bitti | Yanlış kabul edilen aday bu kez çıkmadı |

**Politika reddi (00306).** Model komut çalıştıran kodun tamamını yorum satırına aldı ve yerine girdiyi kaçırmadan yazan bir ileti koydu. Bu bir düzeltme değil; davranış testi de büyük olasılıkla reddederdi. Ama yorum satırı `Runtime.getRuntime` içerdiği için politika reddetti ve ret işi bitirdi. İlk koşuda aynı vaka ikinci denemede doğru onarılmıştı.

**İki koşuda toplam beş politika reddi** var:
- 01066 iki kez: gerçek bir yeni `exec` satırı.
- 01643 iki kez ve 00306 bir kez: değişen satırda zaten var olan ifade.

Beşi de işi ilk ret anında bitirdi. Önerilen kural (`hafta6-politika-onerisi`) 01066'yı yine reddeder, diğer üçünü doğrulamaya geçirir. Bu kural (öneri A) 27 Ekim'de uygulandı.

**Okuma:**
- **Fark gürültü içinde.** 8 → 7 doğru onarım, tek seed'li ölçümün ±1–2 vakalık gürültüsü içinde. Vakaların ikisi bir yöne, ikisi öteki yöne değişti; bütçe düzeltmesinin ya da bağlamın etkisi bu koşuyla ayırt edilemiyor. Paket şekilli geliştirme vakalarındaki sonuç da aynıydı.
- **Kesin olan:** kip dağılımı tersine döndü ve süre 85 dakikadan 68 dakikaya indi. Bağlam seçiminin hızlanması iş başına yaklaşık 97 saniye kazandırdı; tüm dosya cevapları ise daha uzun.
- **Yanlış kabul yok.** Bu koşuda kabul edilen 7 adayın hepsi gizli testleri geçti.

## Sınırlar

- **Tek seed (42).** ROADMAP en az 3 seed istiyor.
- **Küçük örneklem.** 30 gerçek açıkla %95 Wilson aralıkları geniş:
  - doğrulayıcı kabulü 9/30: %17–48;
  - doğru onarım, incelemeden sonra 8/30: %14–44, ham sayımla 5/30: %7–34;
  - yanlış kabul, incelemeden sonra 1/9: %2–44.
- **Tek proje ağırlığı.** 30 gerçek açığın 27'si tek bir projeden (Benchmark) geliyor; Benchmark servlet'leri kısa ve kalıplı.
- **İnceleme tek kişinin.** Yukarıdaki kod incelemesi Claude'un; insan incelemesi yapılmadı. Düzeltilmiş gizli testler incelemeyle aynı sonucu verdi.
- **Test sonradan düzeltildi.** Gizli SQL testi, sonuçlar görüldükten sonra düzeltildi. Değişiklik yalnız sorgu yankısını ayıklıyor ve bir negatif kontrolle sınandı.

## Tekrar

Ollama, worker1, worker2 ve runner şu değişkenlerle başlatılır: `PROJECTS_DIR=.runtime/l3/projects`, `SAFEPATCH_PROFILE=evaluation`, `RUNNER_SANDBOX=docker`, `SANDBOX_MAVEN_CACHE=/home/mirror/.safepatch/m2` ([KURULUM_V02.md](KURULUM_V02.md)). Ardından:

```powershell
$env:EVIDENCE_DIR = 'evidence/v02-l3-model'
.venv/Scripts/python.exe scripts/l3_measure.py --run l3-model-1
```

Yarıda kalan bir koşu aynı `EVIDENCE_DIR` ve `--run` ile yeniden başlatılır: biten vakalar atlanır, yeni başlangıç `resume-*.json` olarak kaydedilir.
