# Bölge kipi: geliştirme vakaları (25 Ekim 2026, Hafta 5)

**Ham kayıt:** [evidence/v02-bolge-gelistirme/region-dev/](../evidence/v02-bolge-gelistirme/region-dev/) (`before`, `after`, `after2`). Betik: `scripts/region_dev.py`. Vakalar: `samples/region/`. Tasarım: [GERCEK_DEPO_TASARIMI.md §9](GERCEK_DEPO_TASARIMI.md#9-bölge-tabanlı-düzenleme-25-ekim-2026-hafta-5).

## Neden

Gerçek model bölge kipinde VUL4J-79'da 0/3 verdi ([OLCUM_VUL4J.md](OLCUM_VUL4J.md)). VUL4J-79 bir değerlendirme vakası olduğu için düzeltmeler ona bakarak ayarlanmadı; önce sahibi olduğumuz geliştirme vakalarında geliştirilip ölçüldü.

## Vakalar

Dört sentetik sınıf, her biri 5,6–6,4 KB. Bu boyut modelin bütün dosya bütçesini (yaklaşık 3,6 KB) aşar, bu yüzden model her zaman bölgeleri görür. Açık metot sıradan yardımcı metotların arasında; import'lar tek tek yazılı, yani düzeltme için yeni bir tip gerekirse import da gerekir. Bulgular cevap anahtarından gelir (VUL4J-79 gibi).

| Vaka | Açık | Testler |
|---|---|---|
| `region-path-read` | Dosya okuma (`new File(root, input)`) | Sentetik path testleri (bağlantı tanığı dahil) |
| `region-path-write` | Dosya yazma ve ekleme, iki metot | Yeni: `../`, iç içe `../`, ekleme; davranışta iç içe klasör ve bağlantılı kök |
| `region-sql` | Birleştirilen SQL | Sentetik SQL testleri |
| `region-command` | Kabuk komutu | Sentetik komut testleri |

Her vakada başlangıç taraması geçerli ve elle yazılmış bir referans düzeltme doğrulamadan geçiyor. Yazma vakasında hedef dosyaya `toRealPath()` uygulayan bir düzeltme davranış testlerinde düşüyor: henüz var olmayan dosyada bu çağrı hata verir.

Koşullar: `guided+context`, hafıza kapalı, 3 deneme, seed 42, 43 ve 44, yerel runner, deney işleri.

## Sonuç

| Tur | Kod | Değişiklik | path-read | path-write | sql | command | Toplam |
|---|---|---|---|---|---|---|---|
| `before` | `feb66fe` | Bölge kipi v1 (VUL4J-79'daki hâli) | 0/3 | 0/3 | 0/3 | 2/3 | **2/12** |
| `after` | `aaec48f` | Sembol adlı derleme hataları, bölge talimatında import cümlesi, uzun CWE-22 notu, boş cevaba yeniden deneme | 0/3 | 0/3 | 0/3 | 1/3 | **1/12** |
| `after2` | `22bae35` | Otomatik JDK import'u, CWE-22 notu eski hâline | 1/3 | 0/3 | **3/3** | 1/3 | **5/12** |

Notlar:
- Her turda 12 iş var. Tek koşu; iş sayısı az, bu yüzden turlar arasındaki fark büyük ölçüde SQL'den geliyor.
- Sıcaklık 0'daki ilk deneme seed'den bağımsız olarak aynı.

## Gözlemler

1. **Model import satırı yazmıyor.**
   - Cevap şemasındaki `imports` alanı 36 işin 36'sında boş kaldı.
   - Talimata eklenen cümle de, derleme hatasının eksik tipi adıyla söylemesi de bunu değiştirmedi.
   - SafePatch'in sabit bir tablodan JDK import'u eklemesi SQL'i 0/3'ten 3/3'e çıkardı (ilk denemede).
   - `after2`'de 8 denemede import eklendi. Eklenen import'lar denemenin kaydında (`imports_completed`).
2. **Derleme hatasına sembol adı eklemek tek başına yetmedi.**
   - Örneğin "cannot find symbol: PreparedStatement" gören model sonraki iki denemede aynı yamayı tekrarladı.
   - Path vakalarında "cannot find symbol: toRealPath" görülüyor: model `toRealPath()`'i `File` üzerinde çağırıyor, `Path` üzerinde değil. Bu bir import sorunu değil, modelin hatası.
3. **Uzun CWE-22 notu ters etki yaptı.** Notu "oluşturulacak dosya" durumunu da anlatacak şekilde uzatınca model iki path vakasında da bölgeleri değiştirmeden döndürdü. Not ölçülmüş eski hâline döndü. Yazma durumu yalnız yeniden deneme tarifinde (`feedback.RECIPES["path"]`) kaldı.
4. **Boş cevap artık işi bitirmiyor.**
   - Eskiden model bölgeyi hiç değiştirmediğinde iş politika hatasıyla reddediliyordu (Faz 1 ölçümünde 3 iş de böyle bitmişti).
   - Şimdi bu başarısız bir deneme sayılıyor ve model geri bildirimle yeniden deniyor. `after2`'de path-read bir işte, command bir işte bu sayede sonraki denemede doğrulandı.
5. **`region-path-write` hiç çözülmedi.** Model ilk iki denemede kodu değiştirmeden döndürüyor; üçüncüde ya derleme hatası ya da yeni dosyada `toRealPath()` (davranış testlerinde 4 hata) çıkıyor.

## Bütün dosya kipine etkisi: sentetik yeniden ölçüm (26 Ekim)

**Ham kayıt:** [evidence/v02-bolge-sentetik/retry/](../evidence/v02-bolge-sentetik/retry/summary.json), commit `731943e`.

Bu turdaki değişikliklerin bir kısmı bütün dosya kipini de etkiler:
- derleme hatalarının biçimi;
- path tanısı ve tarifi;
- boş cevabın yeniden denenmesi.

Bu yüzden 9 sentetik vakanın genel talimat ölçümü ([OLCUM_GENEL_TALIMAT.md](OLCUM_GENEL_TALIMAT.md)) aynı koşullarla tekrarlandı: 2 strateji × 3 seed = 54 iş. Sistem talimatı ve zafiyet notları referansla bayt bayt aynı; yalnız yeniden deneme metinleri ve kod farklı.

| Strateji | SQL | Path | Command | Toplam | Referans |
|---|---|---|---|---|---|
| `v01` | 9/9 | 0/9 | 0/9 | **9/27** | 9/27 |
| `guided+context` | 9/9 | 9/9 | 0/9 | **18/27** | 18/27 |

Notlar:
- **Sonuç değişmedi.** Vaka, strateji ve seed eşleştirmesinde 54 işin hiçbirinde sonuç farklı değil.
- **Durma nedenleri kaydı.** Başarısız `v01` işlerinde durma nedeni değişti: önceki patch'in tekrarı (`duplicate_patch`) 11→14, ilerleme yok (`no_progress`) 1→4, deneme bütçesi 6→0.
  - Olası açıklama: derleme hataları eskiden runner'ın her denemede farklı olan çalışma klasörü yolunu içeriyordu. Artık aynı hata aynı istemi veriyor, bu yüzden model aynı yamayı daha erken tekrarlıyor.
  - Kabul sayısını etkilemedi.

## VUL4J-79, bir kez yeniden (26 Ekim)

**Ham kayıt:** [evidence/v02-vul4j-model2/model/](../evidence/v02-vul4j-model2/model/summary.json), commit `731943e`. Koşullar ilk ölçümle aynı ([OLCUM_VUL4J.md](OLCUM_VUL4J.md#model-bölge-kipinde-25-ekim-hafta-5)).

| Ölçü | İlk ölçüm (`9c89d47`) | Yeniden (`731943e`) |
|---|---|---|
| Doğrulanan iş | 0 / 3 | **0 / 3** |
| Doğrulamaya giren denemelerin sonucu | 6/6 derleme hatası, "cannot find symbol" | 6/6 derleme hatası, tip hatası |
| SafePatch'in eklediği import | — | 9 denemenin 9'unda `Files`, `Path`, `Paths`, `StandardCopyOption` |

Eksik import sorunu kalktı. Kalan hatalar modelin kendi hatası:
- `Paths.get(...)` metoduna `File` veriyor (ancak `String` ya da `URI` alır);
- `File` beklenen yerde `String` kullanıyor.

Geliştirme vakalarında da benzer bir kalıp var ("cannot find symbol: toRealPath": `File` üzerinde `Path` metodu). Bu, 7B modelin `File` ile `Path` API'lerini karıştırdığını gösteriyor. VUL4J-79'a bakarak başka ayar yapılmadı.
