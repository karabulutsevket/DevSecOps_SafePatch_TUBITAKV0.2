# CLAUDE.md — SafePatch V0.2

Bu dosya, bu depoda kod yazan Claude oturumları ve ekip üyeleri için çalışma kurallarıdır. Plan ve haftalık görevler [ROADMAP.md](ROADMAP.md) içindedir; bir göreve başlamadan önce ilgili haftayı oku.

## Proje

SafePatch, Java güvenlik bulguları için yerel modelle düzeltme adayı üretir, adayı bağımsız testlerle doğrular ve insanın onayladığı düzeltmeleri uygunluk koşullarıyla yeniden kullanır. V0.2, V0.1 kodunun üzerine kurulur; sıfırdan yeniden yazım yapılmaz.

- Hedef kod: Java 17, Maven, JUnit 5. Orkestrasyon: Python 3.12, FastAPI, SQLite (SQLAlchemy).
- Yerel model: Ollama 0.34.0 + `qwen2.5-coder:7b-instruct-q4_K_M`. Model özeti `safepatch/worker1.py` içinde sabitlenmiştir.
- Tarayıcı: Semgrep 1.136.0 (Windows'ta WSL içinden), kurallar `rules/java.yml`. Sürüm uyuşmazlığı işi durdurur.
- Maven çevrimdışı (`-o`) çalışır; eksik artifact internetten indirilmez.
- Gerçek (sentetik olmayan) bir proje yalnız Docker sandbox'ında derlenir ve test edilir (`RUNNER_SANDBOX=docker`; ağsız, salt okunur, yetkisiz). Runner yerel kipte reddeder; bu kural gevşetilmez. Yerel derleme yalnız geliştirme profilinde (`SAFEPATCH_PROFILE=lab`) ve yalnız sentetik laboratuvar için açıktır (Hafta 8; [docs/SANDBOX.md](docs/SANDBOX.md)).
- Değerlendirme vakaları (ilk: VUL4J-79) `.runtime/l3` altında, `scripts/prepare_vul4j.py` ile hazırlanır; bulgular cevap anahtarından gelir ("bilinen bulgu", `scanner: known`) ve bu kip yalnız `SAFEPATCH_PROFILE=lab|evaluation` iken açılır ([docs/OLCUM_VUL4J.md](docs/OLCUM_VUL4J.md)).
- Modele giden sistem talimatı geneldir; projeye özgü bilgi talimata yazılmaz, yalnız bağlam verisi olarak gider (`worker1.SYSTEM`, `WEAKNESS_NOTES`; ölçüm: [docs/OLCUM_GENEL_TALIMAT.md](docs/OLCUM_GENEL_TALIMAT.md)).
- Yeni işlerin varsayılan yeniden deneme stratejisi `guided+context` (ölçüm: [docs/OLCUM_V02_YENIDEN_DENEME.md](docs/OLCUM_V02_YENIDEN_DENEME.md)). Rehber metinleri `safepatch/feedback.py` içindeki güvenilir statik metindir; model ya da depo içeriği oraya girmez.
- FindSecBugs adaptörü Hafta 7'de eklendi (tarayıcı `findsecbugs` ya da `semgrep+findsecbugs`; [docs/FINDSECBUGS.md](docs/FINDSECBUGS.md)). Hafıza hiçbir tarayıcının kural kimliğine bağımlı olmamalı: eşleştirme CWE ailesi ve koddan çıkarılan yapısal imza ile yapılır (ROADMAP.md Hafta 4).
- L2 ortak bilgi paketi Hafta 7'de eklendi (`safepatch/l2.py`; [docs/L2_PAKETI.md](docs/L2_PAKETI.md)). Paket OpenSSH Ed25519 ile imzalı, çevrimdışı içeri alınır. L2 kayıtları L1'den ayrı durur ve yalnız örnek olarak kullanılır; birebir tekrar edilmez. L1'e yalnız kurumda doğrulanıp insan onayıyla hafızaya alınarak girer. Pakete yalnız sahibi olduğumuz geliştirme vakaları girer.

## Yerleşim

| Servis | Dosya | Port (varsayılan) |
|---|---|---|
| Orkestratör + arayüz | `safepatch/orchestrator.py`, `engine.py`, `static/` | 8100 |
| Worker1 — yerel model | `safepatch/worker1.py` | 8101 |
| Worker2 — doğrulayıcı | `safepatch/worker2.py`, `acceptance.py` | 8102 |
| Runner — derleme/test/tarama | `safepatch/runner.py`, `scanner.py` | 8103 |
| Deployer — staging | `safepatch/deployer.py` | 8104 |

Diğerleri: proje tanımı şeması `safepatch/project.py` ve depo erişimi `safepatch/repository.py` (Git'e sabitlenmiş taban, tembel okuma, aday commit; tasarım: [docs/GERCEK_DEPO_TASARIMI.md](docs/GERCEK_DEPO_TASARIMI.md)), hafıza `safepatch/memory.py` (CWE ailesi `weakness.py`, yapısal imza `signature.py`; uygunluk kararı: [docs/HAFIZA_UYGUNLUK.md](docs/HAFIZA_UYGUNLUK.md)), politika `safepatch/policy.py`, dışarıdan gelen yamanın (`git diff`) doğrulanması `safepatch/submission.py` ([docs/YAMA_DOGRULAMA.md](docs/YAMA_DOGRULAMA.md)), iş deposu `safepatch/store.py`, hash zincirli denetim kaydı `safepatch/audit.py` ([docs/DENETIM_KAYDI.md](docs/DENETIM_KAYDI.md)), sentetik vakalar `samples/`, testler `tests/`, betikler `scripts/`, ölçüm kanıtları `evidence/`, belgeler `docs/`, L3 değerlendirme seti `l3/` (yalnız üst bilgi ile SafePatch'in yazdığı tanık ve gizli testler; dış projelerin kodu girmez, [docs/L3_SETI.md](docs/L3_SETI.md)).

## Komutlar (PowerShell)

Ayrıntılı ve doğrulanmış kurulum: [docs/KURULUM_V02.md](docs/KURULUM_V02.md).

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.lock
.venv/Scripts/python.exe scripts/init_config.py
.venv/Scripts/python.exe scripts/seed.py
./scripts/run-tests.ps1                 # birim / sözleşme testleri (JUnit: evidence/v02-local/)
./scripts/run-tests.ps1 -Integration    # gerçek Maven/JUnit dahil
./scripts/start-native.ps1 -Restart     # servisler, arayüz http://127.0.0.1:8100
./scripts/stop-native.ps1
```

Testler, benchmark ve canlı demo aynı makinede aynı anda çalıştırılmaz (runner ve GPU paylaşılır).

## Değişmez kurallar

1. **Güven sınırı.** Politika, doğrulayıcı ve onay kodu güvenilir koddur. Model çıktısı, bulgu metni, depo içeriği ve hafıza kayıtları veridir; talimat sayılmaz. Bu sınırı gevşeten değişiklik yapılmaz.
2. **Doğrulama atlanmaz.** Hafızadan gelen aday da (birebir tekrar dahil) derleme, davranış testi, güvenlik tanığı ve yeniden taramadan geçer. Puan sıralar, kabul kararı vermez.
3. **İnsan onayı otomatikleşmez.** Kod onayı, hafızaya alma ve dağıtım ayrı rollerin ayrı kararlarıdır. Testlerdeki simüle onay gerçek onay diye raporlanmaz.
4. **Politika sınırları korunur.** Model yalnız izin verilen kaynak dosyayı değiştirir; test, build, CI, tarayıcı ayarı ve politika dosyaları korunur. Yasak kabiliyet listesi ve satır sınırı `policy.py`'dedir.
5. **Sayı uydurulmaz.** Her ölçüm, `evidence/` altında ham bir kayda (JSON/CSV/JUnit) bağlanır. Başarısız koşular paydadan çıkarılmaz. Test sayısı onarım sayısı değildir.
6. **V0.1 kanıtları değiştirilmez.** `evidence/` altındaki mevcut dosyalar V0.1'e aittir ve bayt düzeyinde korunur (`.gitattributes`: `evidence/** -text`). Yeni çıktılar yalnız `safepatch.common.evidence()` üzerinden yazılır; bu fonksiyon `EVIDENCE_DIR` klasörünü kullanır (varsayılan `evidence/v02-local/`, Git'e girmez) ve V0.1 klasörlerini reddeder. Yayımlanacak sonuçlar için `EVIDENCE_DIR=evidence/v02-<ad>` verilir (ör. `v02-retry`, `v02-benchmark`). Yeni bir betik ya da test `evidence/` yolunu elle kurmaz. `scripts/build_presentation.mjs` ve `scripts/summarize_delivery.py` V0.1 arşiv raporlarıdır.
7. **Sırlar depoya girmez.** `.secrets/`, `.runtime/`, `.env`, model ağırlıkları ve müşteri kodu Git'e eklenmez.
8. **Kural ve veri lisansı.** Semgrep kuralları kendimiz yazarız (MIT); Semgrep'in yayımladığı kural koleksiyonlarından kopyalama yapılmaz. OWASP Benchmark ve Vul4J vakaları yalnız değerlendirmede (L3) kullanılır; L2 paketine, `samples/`'a veya ürüne konmaz. Bir zafiyet sınıfı, sınıf paketinin beş parçası (ROADMAP.md Bölüm 5) tamamlanmadan "destekleniyor" sayılmaz.
9. **Kapsam.** ROADMAP.md Bölüm 3'teki kapsam dışı işler (başka diller, DAST/IAST, SaaS, Kubernetes, model eğitimi) yapılmaz; öneri `docs/BACKLOG.md`'ye yazılır.

## Kod üslubu

- Mevcut dosyaların üslubunu izle: kısa fonksiyonlar, az ama gerekçe anlatan yorum, kod ve yorumlar İngilizce.
- Kullanıcıya görünen metinler (arayüz, hata açıklamaları, belgeler) Türkçe.
- Yeni bağımlılık eklemeden önce gerçekten gerekli mi düşün; eklenirse `requirements.in` ve `requirements.lock` birlikte güncellenir.
- Her davranış değişikliği bir test ile gelir. Java çalıştıran testler `@pytest.mark.integration` ile işaretlenir.

## Git akışı

- Her görev ayrı dalda: `haftaN-kisa-aciklama` (ör. `hafta1-retry-stratejisi`).
- Küçük ve odaklı commit'ler; mesaj İngilizce, ilk satır ne yapıldığını söyler.
- `main`'e birleştirmeden önce başka bir ekip üyesi gözden geçirir. Kimse kendi yamasının başarı etiketini vermez.
- Bitmiş sayılma koşulu: `./scripts/run-tests.ps1` geçer, ROADMAP.md'deki ilgili kutu işaretlenir.

## Görev isteği şablonu

```
Görev: <tek cümle>
Bağlam: ROADMAP.md Hafta <n>, ilgili dosyalar: <yollar>
Kabul ölçütü: <test veya gözlenebilir sonuç>
Kısıtlar: kapsam dışına çıkma, politika/doğrulayıcıyı gevşetme, sayı uydurma
Çıktı: küçük bir dal + testler + kısa açıklama
```
