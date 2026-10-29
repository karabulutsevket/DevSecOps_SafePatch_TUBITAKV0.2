# Denetim kaydı: hash zinciri (Hafta 10)

**Kod:** `safepatch/audit.py`. **Testler:** `tests/test_audit.py`; L2 içe alma kaydı `tests/test_l2.py` içinde.

**Neden.** Bu sürümden önce kararların izi üç ayrı yerde tutuluyordu: işlerin `events` listesi, hafıza kayıtlarının `events` alanı ve dağıtıcının defteri. Üçü de sonradan değiştirilebilir ve değişiklik iz bırakmaz.

**Yeni kayıt.** Güven açısından önemli her karar, veritabanında tek bir tabloya (`audit`) sırayla eklenir. Kayıtlar yalnız eklenir; uygulama kayıt güncellemez ya da silmez.

**Hash zinciri.**
- Her kayıt, kendinden önceki kaydın SHA-256 özetini taşır (`prev`; ilk kayıtta 64 sıfır).
- Bir kaydı değiştirmek, silmek ya da yerini değiştirmek zinciri o noktadan itibaren kırar.
- `verify` komutu zinciri baştan yürür ve ilk kırığı numarasıyla bildirir.

Zincir, kayıtların değiştirilemeyeceğini göstermez; değiştirildiklerinde bunun fark edileceğini gösterir.

## Ne kaydedilir

Kaydı yazan taraf, kararın kimden geldiğini isteğin içeriğinden değil, sunucu tarafındaki kimlikten alır. Kayda kodun kendisi girmez, yalnız özetleri girer: yama, aday commit, artifact ve kanıt paketi.

| Olay (`action`) | Kim (`actor`) | Konu (`subject`) | Kayda girenler (`data`) |
|---|---|---|---|
| `job.created` | işi açan kullanıcı | iş | vaka, taban commit, tarayıcı, hafıza kipi, strateji, politika sürümü |
| `job.awaiting_review`, `job.needs_human`, `job.rejected`, `job.infrastructure_error` | `safepatch` (doğrulayıcının kararı) | iş | gerekçe; incelemeye hazırsa kanıt, commit, artifact ve yama özetleri, kaynak (model ya da uzman), yazar |
| `expert_patch.submitted`, `expert_patch.refused` | uzman | iş | yama özeti, gerekçe ya da ret nedeni |
| `job.approved`, `job.rejected` | inceleyen | iş | onaylanan commit, artifact, kanıt özeti, politika sürümü, yorum |
| `job.cancelled` | kullanıcı | iş | — |
| `job.deployed`, `job.deploy_failed` | dağıtan | iş | artifact özeti; başarılıysa dağıtım sonucunun özeti |
| `staging.rolled_back` | dağıtan | `staging` | geri dönülen artifact özeti |
| `memory.promoted` | inceleyen | hafıza kaydı | iş, gerekçe, kanıt özeti |
| `memory.state_changed` | inceleyen | hafıza kaydı | yeni durum (karantina, iptal, yeniden onay), gerekçe, etkilenen işler |
| `l2.imported` | `operator:<makinedeki hesap>` (komut satırı, çevrimdışı) | paket manifest özeti | yayıncı, sürüm, imzalayan, deney paketi mi, kayıt sayısı |

**Kayda girmeyenler**
- Reddedilen istekler: yetkisiz, kapsamı değişmiş ya da süresi dolmuş onay denemeleri. Bunlar bir karar değil.
- İptal edilmiş bir işin sonradan gelen sonucu da girmez. Motor bu sonucu işe de yazmaz.

## Kaydın biçimi

Her satırda dört alan var:
- `seq`: sıra numarası, birincil anahtar;
- `subject`: aramayı hızlandıran sütun;
- `entry`: kaydın kendisi;
- `hash`: kaydın özeti.

`entry`, özeti alınan metnin aynısıdır: `seq`, `at`, `actor`, `action`, `subject`, `data` ve `prev` alanları, anahtarları sıralı, boşluksuz JSON olarak. `hash`, bu metnin SHA-256 özetidir. Metin olduğu gibi saklandığı için, veritabanı sayıları ya da JSON'u yeniden biçimlendirse bile doğrulama etkilenmez.

**İki yazıcı aynı anda yazarsa.** Orkestratör ve çevrimdışı L2 komutu aynı veritabanına aynı anda yazabilir.
- Sıra numarası birincil anahtar olduğu için iki kayıt aynı numarayı alamaz; zincir çatallanamaz.
- Numarayı kaçıran yazıcı, öbürünün kaydının üzerine zincirlenerek yeniden dener.
- Test: iki ayrı bağlantıdan 15'er kayıt yazılıyor; sonuçta 30 kayıtlık sağlam bir zincir çıkıyor.

## Doğrulama ve kontrol noktası

```powershell
.venv/Scripts/python.exe -m safepatch.audit verify
.venv/Scripts/python.exe -m safepatch.audit head
.venv/Scripts/python.exe -m safepatch.audit verify --checkpoint 128:<hash>
```

**`verify`**
- Zincir sağlamsa kayıt sayısını ve zincirin başını (son kaydın numarası ve özeti) yazar; çıkış kodu 0.
- Kırıksa ilk kırık kaydın numarasını ve nedenini yazar; çıkış kodu 1. Nedenler:
  - `hash_mismatch`: kaydın metni değişmiş;
  - `chain_broken`: kayıt değişmiş, özeti de yeniden hesaplanmış; bir sonraki kayıt artık ona uymuyor;
  - `sequence_gap`: kayıt silinmiş ya da numarası değişmiş;
  - `subject_mismatch`: arama sütunu kayıtla uyuşmuyor; bir kaydı aramadan saklama girişimi;
  - `entry_unreadable`: kayıt JSON değil.

**`head`:** zincirin başını yazar.

**Kontrol noktası.** Veritabanına tam erişimi olan biri, bir kayıttan sonrasını özetleriyle birlikte baştan yazabilir. O zaman zincir kendi içinde tutarlı görünür. Bunu yalnız dışarıda saklanan bir kontrol noktası gösterir.
- Operatör `head` çıktısını düzenli aralıklarla veritabanından ayrı bir yere kopyalar: SIEM, imzalı bir not ya da başka bir makine.
- `verify --checkpoint SEQ:HASH` iki durumu yakalar:
  - o kayıt hâlâ var ama değişmiş: `checkpoint_mismatch`;
  - zincir o noktadan önce kesilmiş: `checkpoint_missing`.

## Sınırlar

- **Kontrol noktası otomatik dışarı aktarılmıyor.** Bütün zincirin yeniden yazılmasına karşı koruma, operatörün başı dışarıda saklamasına bağlı.
- **Kayıt, kararın etkisinden hemen sonra yazılıyor ve ayrı bir veritabanı işlemiyle.**
  - İkisinin arasında süreç çökerse karar kayıtsız kalabilir.
  - Tersi olmaz: kayıt varsa karar da uygulanmıştır.
- **İmza yok.** Zincir, değişikliği gösterir; kaydı kimin yazdığını kriptografik olarak kanıtlamaz. `actor`, sunucunun doğruladığı kimliktir. Komut satırında ise makinedeki hesaptır.
- **Eski izler olduğu gibi duruyor.** İşlerin `events` listesi, hafıza kayıtlarının olayları ve dağıtıcının defteri değişmedi; arayüz bunları göstermeye devam ediyor. Denetim için geçerli kayıt, zincirdir.
- **Bu sürümden önceki kararlar zincirde yok.**
- **Kayıtlar henüz arayüzde ya da API'de gösterilmiyor.** Okuma ve doğrulama yalnız komut satırından. Denetçi rolü ve görünümü sonraki adım ([HEDEF_MIMARI_V2.md](HEDEF_MIMARI_V2.md)).
- **Saklama süresi ve arşivleme politikası tanımlı değil.** Tablo büyümeye devam eder.
