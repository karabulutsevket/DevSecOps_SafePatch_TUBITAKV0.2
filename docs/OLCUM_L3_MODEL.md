# L3 üzerinde ilk model ölçümü (26 Ekim 2026, Hafta 6)

**Ham kayıtlar:** [evidence/v02-l3-model/l3-model/](../evidence/v02-l3-model/l3-model/): `protocol.json`, `summary.json`, vaka başına `jobs/<vaka>.json`. **Betik:** `scripts/l3_measure.py`. **Set:** [L3_SETI.md](L3_SETI.md).

Modelin cevapları üçüncü taraf kodunu içerdiği için Git'e girmez (`.runtime/l3-measure/l3-model-1/`); kayıtlar yalnız özetlerini tutar.

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

1. **Görünür SQL davranış testinde de aynı açık var.** Gizli test düzeltildi (yukarıda), görünür test değişmedi. İki örneklenmiş servlet (01097 gerçek açık, 01315 güvenli kod), sorgu metnini her yanıta yazan `outputUpdateComplete` ile cevap veriyor. Bu servlet'lerde görünür test (`bar`) her doğru parametreleştirmeyi reddeder: doğrulayıcı doğru bir adayı geri çevirir. Bu ölçümü etkilemedi; 01097'nin üç denemesi testlere ulaşamadı (derleme hatası ve tekrarlanan yama). Düzeltmek değerlendirme deposunu, dolayısıyla sabitlenmiş commit'i değiştirir; ayrı bir karar.
2. **vul4j-43'te görünür davranış testleri zayıf.** Testler yeni dosya çıkarmayı sınamıyor. CWE-22 notu "kontrol etmeden önce gerçek yolları `toRealPath()` ile çöz" diyor; model bunu henüz var olmayan çıkış yoluna uyguladı ve kök kontrolünü hiç yazmadı.
3. **Küçük dosyalarda bölge kipi.** 78 denemenin 62'si bölge kipinde, ilk denemelerin bile yarısı (30'da 16). Tüm dosya bütçesi her baytı bir token sayıyor; 70 satırlık bir servlet, yeniden denemenin bağlamıyla birlikte bu bütçeye sığmıyor. Boş yamalar iki kipte de çıktı (bölge 9, tüm dosya 4).
4. **Komut vakaları.** Model ya kodu değiştirmeden dönüyor (20 denemenin 9'u) ya da programı bir yer tutucuyla değiştiriyor. Benchmark'ın komut vakaları girdiyi bir betiğe ortam değişkeni olarak veriyor. CWE-78 notunun "sabit bir programa tek argüman" tarifi bu kalıba uymuyor olabilir; bu bir varsayım, sınanmadı.
5. **En büyük kayıp derleme.** 78 denemenin 24'ü derlenmedi. Örnekler: var olmayan yardımcılar (`getSqlPreparedStatement`), `Path`/`File` tip karışıklığı.

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
