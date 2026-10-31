# Dışarıdan gelen yamanın doğrulanması

Bir güvenlik düzeltmesini SafePatch'in modeli yazmak zorunda değildir. Düzeltme bir geliştiriciden, GitHub Copilot Autofix'ten ya da Sonar AI CodeFix'ten gelebilir. Bu düzeltme `git diff` çıktısı olarak SafePatch'e gönderilir ve model yamasıyla aynı kapıdan geçer: politika, derleme, davranış testleri, güvenlik tanığı ve yeniden tarama. Model çağrılmaz, hafıza kullanılmaz. Onayı başka bir inceleyici verir.

**Neden:** SafePatch'in en güçlü ölçülmüş varlığı doğrulama kapısıdır. V0.1 kabul deneyinde yalnız tarayıcıya bakan kapı 6 hatalı yamanın 6'sını kabul etti, tam kapı hiçbirini ([OLCUM_SONUCLARI.md](OLCUM_SONUCLARI.md)). Bu özellik kapının değerini yerel modelin onarım oranından ayırır. Rakip araçların ürettiği yamalar da SafePatch'in girdisi olabilir. Araştırma ön çalışması da bunu önermişti: değer, yama kaynağından bağımsız doğrulama ve kanıt olmalı ([ARASTIRMA_ONCALISMASI.md](ARASTIRMA_ONCALISMASI.md)).

Bu iş 12 haftalık planda yoktu; 31 Ekim'deki ürün hazırlığı değerlendirmesinden çıktı ve proje liderinin değerlendirmesini bekliyor.

Kod:
- `safepatch/submission.py`: diff'in okunması ve uygulanması;
- `safepatch/engine.py`: `Engine._run_submitted`;
- `safepatch/orchestrator.py`: uç noktalar.

Testler: `tests/test_submitted_patch.py`; gerçek Maven ve JUnit ile `tests/test_java_integration.py`. Canlı deneme betiği: `scripts/submitted_patch_demo.py`.

## İstek

```
POST /v1/verifications
Authorization: Bearer <kullanıcı anahtarı>        # rol: submit

{
  "case_id": "<kayıtlı proje>",
  "idempotency_key": "<8-100 karakter: harf, rakam, _ ve ->",
  "scanner": "semgrep",                          # iş başlatmadaki seçeneklerin aynısı
  "tool": "copilot-autofix",                     # yamanın kaynağı (beyan)
  "diff": "<git diff çıktısı>",
  "rationale": "<en az 20 karakter: düzeltme neden doğru>"
}
```

**Yanıt.** `201` döner ve iş `queued` durumunda başlar (`mode: submitted-patch`).
- Aynı anahtar aynı içerikle yeniden gönderilirse aynı iş döner.
- Aynı anahtar başka bir içerikle gönderilirse `409 idempotency_payload_conflict` döner.

**Gönderen.** İstekten alınmaz, kimlik doğrulamasındaki kullanıcıdır. Gövdede fazladan bir alan (`author` gibi) `422` döner.

**`tool`.** Gönderenin beyanıdır; SafePatch yamanın o araçtan geldiğini doğrulamaz.
- Biçim: küçük harf, rakam ve `. _ + -`; en çok 40 karakter. Açıklama değil, etikettir: `developer`, `copilot-autofix`, `sonar-codefix`, `other`.
- Kanıt özetine, denetim kaydına ve hafıza kaydına yazılır.

**Önizleme.** `POST /v1/verifications/preview` isteği `case_id`, `diff` ve isteğe bağlı `rationale` alır. Gönderimdeki denetimlerin aynısını çalıştırır ve şunu döndürür: dosya, doğrulanacak diff, yama özeti, değişen satır sayısı. Hiçbir şey saklamaz, denetim kaydına yazmaz.

## Diff nasıl uygulanır

**Taban.** Taban, proje tanımındaki sabit commit'tir; diff bu commit'e göre üretilmelidir.
- Bağlam ve silinen satırlar birebir tutmalıdır.
- Bir bölüm (hunk) dosyanın başka yerindeyse, satırları dosyada **yalnız tek bir yerde** geçiyorsa oraya uygulanır. Bu, `git apply` gibi önceki değişikliklerin kaydırdığı bölümleri bulur. Bulanık eşleştirme yapılmaz.
- Önceki bölüm ne kadar kaydıysa sonraki bölüm önce o kaymayla aranır.

**Kabul edilen biçimler.**
- Araçlar: `git diff`, `git show`, `git format-patch` ve `diff -u` çıktısı.
- İlk dosya başlığından önceki metin yok sayılır: commit mesajı ve e-posta başlıkları. `format-patch` imzası da yok sayılır.
- Yol önekleri: `a/` ve `b/`, `i/` ve `w/` gibi tek harfli önekler ya da öneksiz (`--no-prefix`) yollar.
- GNU diff'in tarih damgası ve `\ No newline at end of file` satırı okunur.

**Reddedilenler.**
- CR (Windows satır sonu) ya da NUL içeren metin.
- Yeni, silinen, yeniden adlandırılan, ikili ya da izni değişen dosya.
- Birden çok dosya.
- Bağlamsız ekleme.
- Tırnak içindeki yol.
- 100'den çok bölüm ya da 200 000 karakterden uzun metin.

**Güven sınırı.** Diff veridir. Satırları yalnız eşleştirilir ve kopyalanır.
- **Doğrulanan diff.** Doğrulanan ve inceleyiciye gösterilen diff, SafePatch'in taban dosya ile sonuç arasında kendisinin hesapladığı farktır.
- **Gönderilen metin.** Ayrıca saklanır ("Gönderilen yama (gönderildiği gibi)").
- **Motorun yeniden türetmesi.** Motor, doğrulamadan önce yamayı saklanan diff'ten yeniden türetir. Kayıtlı bir dönüşüm sonucuna güvenmez.

## Gönderimde denetlenenler

| Kural | Uymazsa |
|---|---|
| Yalnız `submit` rolü, yalnız erişebildiği proje | `403` / `404` |
| `known` tarayıcısı yalnız lab ve evaluation profilinde | `409 known_findings_only_in_lab_profile` |
| Diff okunabiliyor ve var olan tek bir dosyanın satırlarını değiştiriyor | `409 diff_malformed`, `diff_invalid_encoding`, `diff_unsupported_change`, `patch_must_change_one_file`, `diff_too_large` |
| Diff tabana birebir uyuyor | `409 diff_does_not_apply`, `diff_ambiguous`, `diff_needs_context`, `diff_unknown_file` |
| Uzman yamasıyla aynı politika: yalnız proje tanımının izin verdiği kaynak dosya; test, build ve CI dosyalarına dokunmaz; yasak yetenek ve bastırma yorumu yok; satır bütçesi | `409 protected_or_unauthorized_path`, `forbidden_capability_or_suppression`, `empty_patch`, `line_budget`, `source_requires_final_newline`, … |
| Gerekçe, diff ve sonuç dosyası SafePatch doğrulayıcı notunu taklit etmez | `409 suspected_prompt_injection` |

Reddedilen gönderim hiçbir şey saklamaz. Denetim kaydına üç şey yazılır: kimin gönderdiği, gönderilen diff'in özeti ve ret nedeni (`patch_submission.refused`, konu: proje).

## Doğrulama

Motor modeli ve hafızayı hiç çağırmaz:

1. Yamayı saklanan diff'ten yeniden türetir ve politikayı yeniden uygular.
2. Başlangıç taramasını normal işle aynı biçimde yapar: tarama, davranış testleri, güvenlik tanığı.
3. Yamanın değiştirdiği dosyada başlangıç bulgusu yoksa durur: yamanın neyi düzelttiği gösterilemez.
4. Yamayı worker2 → runner zincirinden geçirir: derleme, davranış testleri, güvenlik tanığı, yeniden tarama, aday commit. Başka dosyalardaki başlangıç bulguları kalabilir. Yamanın dosyasındaki bulguların hepsi gitmeli ve yeni bulgu olmamalıdır.

| Sonuç | İş durumu |
|---|---|
| Başlangıç taraması beklenen bulguyu ve başarısız tanığı üretmedi | `needs_human`, `baseline_missing_expected_failing_security_assertion_or_finding` |
| Yamanın dosyasında başlangıç bulgusu yok | `rejected`, `no_finding_in_patched_file` |
| Geçti | `awaiting_review`; adayda `origin: submitted-patch`, `author: <gönderen>`, `tool` |
| Projede güvenlik tanığı yok | `needs_human`, `security_witness_missing` |
| Ortam hatası (derleyici tanısı olmayan derleme, JUnit raporu olmayan test koşusu) | `infrastructure_error`, `verification_infrastructure:<neden>`. Aynı diff yeni bir istekle yeniden gönderilebilir |
| Başarısız | `needs_human`, `submitted_patch_failed_verification`. Başarısızlık sınıfı denemeye yazılır. Yama kaynaklı başarısızlık [başarısızlık hafızasına](BASARISIZLIK_HAFIZASI.md) girer (`origin: submitted-patch`). Bir uzman aynı işe düzeltilmiş yamayı [uzman yaması](UZMAN_YAMASI.md) olarak gönderebilir (üç deneme) |
| Saklanan diff sonradan değişmiş ve politikaya uymuyor | `rejected` |

## Dört göz ve köken

- **Gönderen yazar sayılır.** Yamayı bir araç üretmiş olsa da onu getiren kişi sorumluluğunu üstlenir. Bu yüzden kendi gönderdiği yamayı onaylayamaz ve hafızaya alamaz. Kural, hem `submit` hem `review` rolü olan kullanıcı için de geçerlidir.
- **Kanıta bağlanan alanlar.** Köken (`submitted-patch`), yazar ve `tool` kanıt özetine (`acceptance_manifest`) bağlıdır. Adayda biri değişirse onay `authorship_changed` ile durur.
- **Staging.** İşin modu `submitted-patch` olur. Staging bu modu, gerçek doğrulamadan geçmiş bir iş olarak kabul eder; `mock-test` sonuçları yine reddedilir.
- **Hafıza kaydı.** Hafızaya alınan kayıt şu alanları taşır: `provenance: human-approved-submitted-patch`, `tool`, `author: <gönderen>`, `model: null`. Kayıt sonraki bir işte birebir tekrar edilirse aday yine yazarını taşır.
- **Denetim kaydı.** Şu olaylar kaydedilir:
  - `job.created`: mod, `tool`, gönderilen diff'in ve yamanın özeti;
  - motorun kararı (`tool` dahil);
  - onay ve hafızaya alma.

## Arayüz

İş listesinin üstünde, `submit` rolü olan kullanıcı için **Yama doğrula** düğmesi vardır.
- **Form alanları.** Form, proje ve tarayıcıyı üstteki seçimlerden alır. Ayrıca şunları ister: yamanın kaynağı, `git diff` metni, gerekçe.
- **Önizle.** Doğrulanacak diff'i güvenilir koddan alıp gösterir. Politika ihlali, gönderimden önce Türkçe açıklamasıyla görünür.
- **Doğrulamaya gönder.** İşi açar ve detayını gösterir.

İş ekranı:
- Listede gönderilen yamaların başında **Yama ·** yazar.
- Detayda kaynak, gönderen ve gerekçe görünür.
- **Gönderilen yama (gönderildiği gibi)** bölümü, gönderilen metni olduğu gibi gösterir.
- Doğrulamadan geçemeyen bir işte uzman yaması bölümü açılır.

## Canlı deneme (31 Ekim 2026)

Betik: `scripts/submitted_patch_demo.py`. Ham kayıt: [`evidence/v02-yama-dogrulama/demo/`](../evidence/v02-yama-dogrulama/demo/) (`summary.json`, iş başına bir dosya, gönderilen diff'ler, denetim kaydı).

**Kurulum.**
- Profil ürün profiliydi. worker2 ve runner servis olarak çalıştı; runner Docker sandbox'ındaydı (ağsız, salt okunur, yetkisiz).
- Tarayıcı Semgrep 1.136.0'dı.
- Orkestratör uygulaması betiğin içinde çalıştı: uç noktalar, yetki, iş deposu, motor.
- Her yama, sabit commit'in temiz bir kopyasında üretilmiş gerçek `git diff` çıktısıydı.

**Kimlikler.** İki kimlik betiğin sürdüğü **test kimlikleridir**: `SIMULATED-developer` (gönderir ve inceler) ve `SIMULATED-reviewer` (inceler). Kararlar simüledir, insan kararı değildir.

**Yamalar.** Yamaları elle yazdık ve `tool: handwritten-control` etiketiyle gönderdik; hiçbiri bir aracın çıktısı değildir. Bu deneme kapının her yama türüne ne yaptığını gösterir, araçların yama kalitesini ölçmez.

| Yama | Ne yapıyor | sql-01 | path-01 | command-01 |
|---|---|---|---|---|
| `reference` | Bilinen doğru onarım (`tests/mock_patches.py`) | `awaiting_review`, sonra onay | `awaiting_review`, sonra onay | `awaiting_review`, sonra onay |
| `scanner_quiet` | Kodu, kuralımızın artık eşleşmediği biçimde yeniden yazar; zafiyet kalır. Sorgu `String.format` ile kurulur; yol normalize edilmeden `startsWith` ile denetlenir; komut `ProcessBuilder(List.of(...))` ile yine kabuğa gider | `needs_human`: tanık düştü | `needs_human`: tanık düştü | `needs_human`: tanık düştü |
| `disabled` | Metodu `return "";` satırına indirir: ne sink kalır ne işlev | `needs_human`: davranış testleri düştü | `needs_human`: davranış ve tanık düştü | `needs_human`: davranış ve tanık düştü |
| `test_change` | Kodu değil güvenlik testini kapatır (`@Disabled`) | `409 protected_or_unauthorized_path`, iş açılmadı | aynı | aynı |

**Hatalı yamalar.**
- Doğrulanan 9 yamanın 9'unda da derleme geçti ve yeniden tarama temizdi.
- Yalnız taramaya bakan bir kapı hatalı 6 yamanın 6'sını kabul ederdi; SafePatch'in kapısı hiçbirini kabul etmedi. V0.1 kabul deneyiyle (6/6'ya karşı 0/6) aynı yönde, bu kez dışarıdan gönderilen yama yolunda.
- `scanner_quiet` yamalarını güvenlik tanığı yakaladı (3/3; davranış testleri geçti). `disabled` yamalarını davranış testleri yakaladı (3/3).
- Test değişiklikleri gönderimde, hiçbir şey derlenmeden reddedildi ve denetim kaydına `patch_submission.refused` olarak girdi.

**Dört göz.** 3 referans yamada gönderen, kendi yamasını ne onaylayabildi (`409`) ne hafızaya alabildi (`409 author_cannot_promote_own_patch`). İkinci kimlik onayladı ve hafızaya aldı. Hafıza kayıtları şu alanları taşıyor: `provenance: human-approved-submitted-patch`, `tool: handwritten-control`, `author: SIMULATED-developer`, `model: null`.

**Süre.** İş başına 39,5–47,7 sn, ortalama 43,8 sn. Bu süre başlangıç taramasını ve doğrulamayı kapsar; ikisi de Docker sandbox'ta tam derleme, test ve Semgrep taramasıdır.

**Denetim zinciri.** 27 kayıt, doğrulama `ok`:

| Olay | Sayı |
|---|---|
| `job.created` | 9 |
| `patch_submission.refused` | 3 |
| `job.awaiting_review` | 3 |
| `job.needs_human` | 6 |
| `job.approved` | 3 |
| `memory.promoted` | 3 |

**Koşu kaydı.** Kod commit'i `cd5df67`, `git_dirty: false`.

İlk koşu aynı gün aynı 12 sonucu verdi, ama kaydında iki kusur vardı:
- Özet, referans işlerin durumunu onaydan sonra okuduğu için 12 yamanın 9'unu eşleşti saydı.
- Koşu sırasında belgeler düzenlendiği için `git_dirty: true` yazıldı.

Betik düzeltildi ve deneme temiz ağaçla yeniden koşuldu. Yukarıdaki tablo ikinci koşudandır; ilk koşunun çıktısı Git'e alınmadı.

**Kapsam.** Üç sentetik aile ve elle yazılmış yamalar kullanıldı. Gerçek bir müşteri deposu ya da gerçek bir araç yaması denenmedi.

## Sınırlar

- **Taban.** Taban yalnız proje tanımındaki sabit commit'tir; bir dalın kendi tabanına göre doğrulama yoktur. Bu, Git platformunda birleştirme isteği (MR/PR) entegrasyonuyla birlikte ele alınmalıdır ([BACKLOG.md](BACKLOG.md)).
- **Bulgu şartı.** Bir yama tek bir dosyayı değiştirir ve o dosyada başlangıç taramasının bulduğu bir bulgu olmalıdır. SafePatch'in tarayıcısının görmediği bir zafiyetin düzeltmesi bu yolla doğrulanamaz. Kurumun kendi tarayıcısının bulgularını içeri alma (SARIF) henüz yoktur.
- **Kapsam.** Ürünün geri kalanıyla aynıdır: Java ve Maven; desteklenen sınıflar CWE-89, 22 ve 78; güvenlik tanığı olan projeler.
- **`tool` beyandır.** Raporlarda araçlara göre kırılım, beyana dayanır.
- **Gerçek araç yamaları denenmedi.** Copilot Autofix ya da Sonar AI CodeFix'in gerçek yamaları henüz bu kapıdan geçirilmedi. Araçların yama kalitesi hakkında bir sayı yoktur.
