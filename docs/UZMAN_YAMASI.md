# Uzman yaması

Model bir bulguyu çözemediğinde iş `needs_human` durumuna düşer. Bu belge, bir uzmanın o işe kendi yamasını nasıl gönderdiğini ve yamanın hangi sınırlardan geçtiğini anlatır (ROADMAP.md Hafta 3).

Kod: `safepatch/orchestrator.py` (uç nokta), `safepatch/engine.py` (`check_expert_patch`, `expert_scope`, `Engine._run_expert`). Testler: `tests/test_expert_patch.py`, gerçek Maven/JUnit ile `tests/test_java_integration.py`.

## İstek

```
POST /v1/jobs/{job_id}/expert-patch
Authorization: Bearer <kullanıcı anahtarı>        # rol: submit

{
  "edits": [{"path": "<bulgunun dosyası>",
             "old_sha256": "<taban dosyanın SHA-256 özeti>",
             "content": "<dosyanın yeni hâli>"}],
  "rationale": "<en az 20 karakter: düzeltme neden doğru>"
}
```

Yanıt `202`: iş `queued` durumuna geçer, doğrulama arka planda çalışır. İşin süre bütçesi gönderim anından yeniden başlar. Yazar istekten alınmaz, kimlik doğrulamasındaki kullanıcıdır; gövdede fazladan bir alan (`author` gibi) `422` döner.

## Gönderimde denetlenenler

| Kural | Uymazsa |
|---|---|
| Yalnız `submit` rolü, yalnız erişebildiği iş | `403` / `404` |
| İş `needs_human` durumunda | `409 job_not_waiting_for_a_human` |
| Deney (değerlendirme) işi değil | `409 evaluation_job_cannot_take_expert_patch` |
| Başlangıç taraması geçerli bir bulgu üretmiş | `409 baseline_not_valid` |
| İş başına en fazla 3 uzman denemesi | `409 expert_attempt_budget_exhausted` |
| Model yamasıyla aynı politika: yalnız bulgunun dosyası ve proje tanımının izin verdiği dosya; test, build, CI dosyalarına dokunmaz; taban özeti tutar; yasak yetenek ve bastırma yorumu yok; dosya ve satır bütçesi | `409 protected_or_unauthorized_path`, `stale_base_hash`, `forbidden_capability_or_suppression`, … |
| Yama ve gerekçe SafePatch doğrulayıcı notunu taklit etmez (onaylanan yama hafıza yoluyla sonraki model istemlerine girebilir) | `409 suspected_prompt_injection` |
| İşin kullandığı hafıza kaydı hâlâ onaylı | `409 memory_no_longer_approved` |

Reddedilen istek işi değiştirmez; işin olay kaydına kimin, hangi gerekçeyle reddedildiği yazılır (`expert_patch_refused`).

## Doğrulama

Motor politika denetimini yeniden yapar, sonra yamayı **modeli hiç çağırmadan** model yamasıyla aynı worker2 → runner zincirinden geçirir: derleme, davranış testleri, güvenlik tanığı, yeniden tarama, aday commit. Uzman denemeleri model denemelerinden sonra numaralanır (en çok 4–6).

| Doğrulama sonucu | İş durumu |
|---|---|
| Geçti | `awaiting_review`; adayda `origin: human-authored` ve `author` |
| Projede güvenlik tanığı yok | `needs_human`, `security_witness_missing` |
| Ortam hatası (derleyici tanısı olmayan derleme, JUnit raporu olmayan test koşusu) | `needs_human`, `verification_infrastructure:<neden>`; ortam düzelince uzman yeniden gönderebilir (üç deneme hakkından biri sayılır) |
| Başarısız | `needs_human`, `expert_patch_failed_verification`; başarısızlık sınıfı denemeye yazılır, uzman yeniden gönderebilir. Yama kaynaklı başarısızlık, yazarıyla birlikte [başarısızlık hafızasına](BASARISIZLIK_HAFIZASI.md) girer |
| Kayıtlı yama gönderimden sonra değişmiş ve politikaya uymuyor | `rejected` |

## Dört göz kuralı

- Köken ve yazar kanıt özetine (`acceptance_manifest`) bağlıdır. Adaydaki yazar sonradan değişirse onay `authorship_changed` ile durur.
- Yazar kendi yamasını onaylayamaz (`409`) ve hafızaya alamaz (`author_cannot_promote_own_patch`). Hem `submit` hem `review` rolü olan kullanıcı için de geçerlidir.
- Hafızaya alınan uzman yamasının kaydı `provenance: human-authored`, `author: <kullanıcı>`, `model: null` taşır.

## Henüz yok

- Arayüzde gönderme ve diff ekranı (Hafta 3).
- İnceleyicinin reddettiği (`rejected`) işe uzman yaması; şimdilik yalnız `needs_human` işler.
