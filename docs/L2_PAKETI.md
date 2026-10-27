# L2 ortak bilgi paketi (27 Ekim 2026, Hafta 7)

**Kod:** `safepatch/l2.py` (paket okuma, imza denetimi, L2 deposu), `safepatch/memory.py` (arama ve terfi), `scripts/l2_build.py` (yayıncı tarafı), `scripts/l2_exit.py` (Faz 2 gösterimi). **Testler:** `tests/test_l2.py`. **Ölçüm:** [OLCUM_L2.md](OLCUM_L2.md).

L2, SafePatch'te üretilen ve müşteriye **imzalı paketle** giren ortak bilgidir (ROADMAP.md, Bölüm 2). Müşteri verisinden toplanmaz. Bugünkü kaynağı yalnız SafePatch'in kendi laboratuvarı: sahibi olduğumuz geliştirme vakalarında doğrulanmış ve onaylanmış düzeltmeler.

## Paket biçimi

Tek bir zip dosyası. İçinde yalnız şunlar bulunabilir; başka bir dosya varsa paket reddedilir:

| Dosya | İçerik |
|---|---|
| `manifest.json` | şema `safepatch-l2/1`, yayıncı, **sürüm** (tam sayı), oluşturulma zamanı, deney paketi mi, kayıt listesi (kimlik + **SHA-256**), geri çekilen kayıtlar |
| `manifest.json.sig` | manifestin **imzası**: OpenSSH, Ed25519, ad alanı `safepatch-l2` |
| `records/<sha256>.json` | her kayıt; dosya adı kaydın kendi özetidir |

İmza manifesti kapsar, manifest her kaydın özetini taşır. Böylece bir kayıttaki tek bir bayt değişikliği de yakalanır.

**İmza aracı.** `ssh-keygen -Y sign` ve `ssh-keygen -Y verify`. Yeni bir Python bağımlılığı gerekmiyor:
- Windows 10/11 OpenSSH'yi yerleşik getiriyor (bu makinede 9.5);
- Linux'ta `openssh-client` paketi var;
- Docker imajında orkestratör aşamasına `openssh-client` eklendi (imaj bu oturumda derlenmedi).

Aynı yöntem Git commit imzalamada da kullanılıyor.

HMAC (`common.seal`) seçilmedi: paylaşılan bir anahtar ister. O anahtar müşteride olunca müşteri de paket üretebilir.

## İçeri alma (çevrimdışı)

```powershell
$env:DATABASE_URL = 'sqlite:///C:/.../jobs.db'     # kurulumun veritabanı
.venv/Scripts/python.exe -m safepatch.l2 verify paket.zip --trusted allowed_signers   # yalnız denetler
.venv/Scripts/python.exe -m safepatch.l2 import paket.zip --trusted allowed_signers   # denetler ve içeri alır
.venv/Scripts/python.exe -m safepatch.l2 list
```

**Güven dosyası.** `allowed_signers`, kurulumun güvendiği yayıncı anahtarlarını listeleyen OpenSSH dosyasıdır. Satır biçimi:

```
safepatch-l2 namespaces="safepatch-l2" ssh-ed25519 AAAA...
```

Kurulumla birlikte gelir. Yolu `--trusted` ile ya da `L2_ALLOWED_SIGNERS` ile verilir. Dosya yoksa içeri alma reddedilir.

İçeri alma ya tamamen olur ya hiç olmaz. Şu durumlarda **paketin tamamı reddedilir**:

| Durum | Hata |
|---|---|
| İmza yok, bozuk, güvenilmeyen anahtardan ya da başka bir ad alanı için | `signature_invalid` |
| Güven dosyası verilmemiş | `l2_trust_not_configured` |
| Bir kaydın özeti manifestle uyuşmuyor | `record_sha256_mismatch` |
| Fazla, eksik ya da tekrarlanan dosya | `package_members` |
| Kurulu sürümden eski sürüm | `package_downgrade` |
| Aynı sürüm numarasıyla farklı içerik | `package_version_conflict` |
| Simüle onaylı deney paketi, ürün profilinde | `experiment_package_outside_lab_profile` |
| Bir kaydın alanları kurala uymuyor | aşağıdaki tablo |

Aynı paketi ikinci kez içeri almak hiçbir şey değiştirmez (`already_installed`).

Paket hiçbir zaman diske açılmaz. Her dosya bellekte, boyut sınırıyla okunur:

| Sınır | Değer |
|---|---|
| Paket | 20 MB |
| Kayıt | 256 KB |
| Kayıt sayısı | 2000 |

## Kayıt kuralları

İmza, paketi kimin yaptığını kanıtlar; içeriğin güvenli olduğunu kanıtlamaz. Kayıtlar veri olarak kalır (CLAUDE.md, kural 1) ve her alan ayrıca denetlenir. Aynı denetim paket üretilirken de çalışır: kurala uymayan bir kayıt imzalanmaz.

| Kural | Hata |
|---|---|
| Alanlar tam olarak şemadakiler; bilinmeyen alan yok | `record_fields` |
| CWE ailesi desteklenenlerden (CWE-89, 22, 78), JDK sürümü bir sayı | `record_weakness` |
| Yapısal imza var: hedef çağrı, kuruluş, kütüphane | `record_signature` |
| Fark tek bir `.java` dosyasında, birleşik fark biçiminde | `diff_not_one_java_file`, `diff_not_unified` |
| Farkta eklenen satırda bastırma ya da test/build işareti yok; yasak kabiliyet eklenmiyor (`policy.py`'nin kuralı) | `diff_forbidden_capability` |
| Fark doğrulayıcı notunu taklit etmiyor | `diff_imitates_verifier_note` |
| Kendi doğrulaması geçmiş: derleme, davranış testi, güvenlik tanığı | `record_not_verified` |
| Onaylayan, yazandan farklı | `record_reviewer` |
| Kaynak lisansı izinli. Bugün yalnız MIT, yani kendi laboratuvar kodumuz | `record_origin` |

## Güven seviyesi

L2 kayıtları L1'den **ayrı bir tabloda** durur (`shared_memory`). Kayıtların güven etiketi `external_not_verified_here`; arayüzde "dış kaynak, bu kurumda doğrulanmadı" olarak görünür.

- **Yalnız L1 uymazsa.** `guarded` kipte önce kurumun kendi kayıtları aranır. Uygun bir L1 kaydı yoksa L2'ye bakılır. `off` ve `naive` (B kolu) kipleri L2'ye hiç bakmaz.
- **Yalnız örnek.** L2 kaydı hiçbir zaman birebir tekrar edilmez. Modele örnek fark olarak gider ve aday her zamanki gibi doğrulanır: derleme, davranış testi, tanık, yeniden tarama.
- **Proje bağımsız eşleşme.** L2 kaydı başka bir projeden gelir; bu yüzden proje, dosya ve özetler eşleşmede kullanılmaz. Gerekenler:
  - aynı CWE ailesi;
  - aynı JDK;
  - **bilinen ve aynı** yapısal imza biçimi: hedef çağrı, kuruluş, kütüphane ve sürümü.

  Biçim bilinmiyorsa kayıt kullanılmaz. L1'de bu durum "uygunluğu bilinmeyen örnek" sayılır.
- **Terfi.** L2 kaydından yararlanan bir düzeltme kurumda doğrulanır, sonra bir insan onaylar ve hafızaya alır (`Memory.promote`, kural 3: otomatik terfi yok). Bundan sonra düzeltme L1 kaydı olur:
  - L1 kaydı nereden geldiğini `l2_origin` alanında taşır: kayıt, özet, yayıncı, sürüm;
  - L2 kaydının `validated_here` listesine bu L1 kaydı eklenir.

  Aynı projedeki sonraki işler artık L1 kaydını kullanır.
- **Yeni sürüm.** Paket her sürümde kayıtların tam listesini taşır.
  - Yeni sürümde olmayan bir kayıt `retired` olur: yeni işlere önerilmez, onunla yapılmış işlere dokunulmaz.
  - Yayıncının açıkça geri çektiği kayıt (`withdrawn`) L1'deki geri çekme gibi davranır: ondan üretilmiş, onay ya da dağıtım bekleyen adaylar durur.
  - Kurumda biriken kullanım izi ve doğrulamalar sürümler arasında korunur.

## Yayıncı tarafı

```powershell
.venv/Scripts/python.exe scripts/l2_build.py --database sqlite:///LAB.db --version 1 --key YAYINCI_ANAHTARI --out safepatch-l2-v1.zip [--experiment]
```

`l2_build.py` kayıtları laboratuvar veritabanının onaylı L1 kayıtlarından alır. Her kaydın vakası kaynak işinden okunur ve L3 kataloğunda (`l3/catalog.yml`) aranır. Yalnız şu vakalar pakete girer:
- `split: development`;
- `source: safepatch-synthetic`;
- lisansı izinli.

Bu kurallar değerlendirme setini (OWASP Benchmark, Vul4J) ve dış kodu pakete sokmaz (CLAUDE.md, kural 8). Katalogda bulunmayan bir vaka paketi durdurur.

Onayı simüle olan bir kayıt (`SIMULATED-…`) yalnız `--experiment` ile üretilen bir pakete girer. Böyle bir paket ürün profilinde içeri alınamaz.

## Karar bekleyenler

1. **Üretim imza anahtarı.** Bugüne kadar yalnız deney anahtarları üretildi (parolasız, `.runtime` altında). Gerçek yayıncı anahtarı için karar gerekiyor:
   - anahtarı kimin tutacağı;
   - nerede tutulacağı (çevrimdışı makine, parola ya da donanım anahtarı);
   - anahtar değişiminin müşterilere nasıl duyurulacağı.

   Bu bir güvenlik kararı; proje liderinin.
2. **Laboratuvar dışı kaynaklar.** CVE düzeltme commit'leri (ROADMAP Hafta 7, *Kadir*) henüz yok. Her kaynak için ayrı lisans incelemesi gerekiyor. Kod tarafında izinli lisans listesi bugün yalnız MIT; listeyi genişletmek bir lisans kararıdır.
3. **Varsayılan davranış.** L2 paketi kurulu bir kurulumda `guarded` kip L2'ye de bakar; paket kurulu değilse hiçbir şey değişmez. Deneyin C kolu (yalnız L1) L2 paketi olmayan bir veritabanıyla koşulur.

## Sınırlar

- Yalnız düzeltme kayıtları var. ROADMAP'teki "bu bağlamda çalışmaz" türü başarısızlık kalıpları henüz pakete girmiyor.
- Eşleşme yapısal imzanın biçimine bağlı. Biçimi aynı olup gerçekte uymayan bir örnek modele gidebilir. Kabul kararı yine doğrulayıcınındır; örnek kabulü etkilemez.
- Docker imajındaki `openssh-client` eklemesi derlenip denenmedi.
