# Karşılaştırmalı tespit ölçümü: Semgrep ve FindSecBugs (27 Ekim 2026, Hafta 7)

**Ham kayıtlar:** [evidence/v02-detection/detection/](../evidence/v02-detection/detection/): vaka başına `cases/<vaka>.json` ve `summary.json`. **Betik:** `scripts/detection_measure.py`. **Set:** [L3_SETI.md](L3_SETI.md). **Adaptör:** [FINDSECBUGS.md](FINDSECBUGS.md).

## Kurulum

- **Vakalar.** L3 değerlendirme setinin hazır 45 vakası: 30 gerçek açık (27 OWASP Benchmark, 3 Vul4J) ve 15 güvenli kod (Benchmark'ın "yanlış pozitif" vakaları).
- **Tarama.** Her vaka başlangıç sürümünde bir kez, iki tarayıcıyla birlikte tarandı (`semgrep+findsecbugs`). Tarama, bir işin ilk doğrulamasıyla aynı akışta: derleme, testler, tarama. Gerçek projeler Docker sandbox'ında.
- **Araçlar:**
  - Semgrep 1.136.0, **SafePatch'in kendi üç kuralıyla** (`rules/java.yml`, laboratuvar için yazıldı). Semgrep'in yayımladığı kural koleksiyonları lisans kuralı gereği kullanılmıyor (CLAUDE.md, kural 8).
  - SpotBugs 4.9.8 ve FindSecBugs 1.14.0.
- **"Buldu" ne demek.** Bir tarayıcı bir vakayı, cevap anahtarındaki dosyada **aynı CWE ailesinden** bir bulgu raporladıysa "buldu" sayılıyor. Bulgu cevap anahtarındaki satırın tam üstündeyse ayrıca "satırında buldu".
  - Gerçek açıkta bu bir tespit.
  - Güvenli kodda bu bir yanlış alarm.
- **Hatalar.** Taraması başarısız olan vaka paydada kalırdı; bu ölçümde hiç tarama hatası olmadı.
- **Süre.** Toplam 60 dakika.

## Sonuç

| | Semgrep (kendi 3 kuralımız) | FindSecBugs | İkisinden biri |
|---|---|---|---|
| Gerçek açıkta tespit | **0 / 30** (%0–11) | **30 / 30** (%89–100) | 30 / 30 |
| Bunların cevap anahtarı satırında olanı | 0 | 22 / 30 | — |
| Güvenli kodda yanlış alarm | **0 / 15** (%0–20) | **15 / 15** (%80–100) | 15 / 15 |

Parantez içleri %95 Wilson güven aralığı.

**Sınıf bazında:**

| Aile | Gerçek açık: Semgrep | Gerçek açık: FindSecBugs | Güvenli kod: Semgrep | Güvenli kod: FindSecBugs |
|---|---|---|---|---|
| CWE-22 (path) | 0 / 13 | 13 / 13 (satırında 7) | 0 / 5 | 5 / 5 |
| CWE-89 (SQL) | 0 / 10 | 10 / 10 (satırında 8) | 0 / 5 | 5 / 5 |
| CWE-78 (komut) | 0 / 7 | 7 / 7 (satırında 7) | 0 / 5 | 5 / 5 |

**Ayrıntılar:**
- **FindSecBugs'ın kuralları.** Gerçek açıklarda bulguyu veren kurallar: `PATH_TRAVERSAL_IN` (19), `COMMAND_INJECTION` (7), `SQL_INJECTION_SPRING_JDBC` (6), `SQL_INJECTION_JDBC` (4), `SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE` (2).
- **Güvenli kodda da aynı kurallar.** Güvenli kodda aynı kurallar aynı biçimde raporluyor. Benchmark'ın güvenli vakaları, verinin gerçekte sabit bir değerle değiştirildiği ya da hiç kullanılmadığı tuzaklar. FindSecBugs'ın veri akışı analizi yol duyarlı olmadığı için bunları ayırt etmiyor.
- **Satır farkları.** Satırı tutmayan 8 bulgunun 7'si cevap anahtarından 1–5 satır uzakta; birden fazla satıra yayılan ifadeler. VUL4J-41'deki 18 satır.
- **Ailesi dışındaki bulgular.** FindSecBugs 45 vakada desteklenen ailelerin dışında 114 bulgu daha raporladı (log injection, güven sınırı vb.). Bunlar `other_findings`; iş açmıyor.
- **Semgrep.** Kendi üç kuralımız 45 projenin hiçbirinde, hiçbir dosyada bulgu vermedi. Kurallar laboratuvarın kod kalıpları için yazıldı (ör. `new ProcessBuilder(shell, flag, x)`), gerçek kodun biçimlerini kapsamıyor.

## Okuma

- **FindSecBugs bu örneklemde ayırt etmiyor.** Bütün gerçek açıkları buluyor ama bütün güvenli vakaları da işaretliyor: 30/30 tespit, 15/15 yanlış alarm. Tek başına bir bulgunun açık olduğuna kanıt değil.
- **Kendi Semgrep kurallarımızın gerçek kodda kapsamı yok.** Semgrep'le gerçek projelerde bulgu üretmek için kuralların genişletilmesi gerekiyor. Bu, sınıf paketlerinin "kural" parçasının işi.
- **Tarayıcıdan bağımsızlık.** Hafıza, eşleştirmeyi CWE ailesi ve yapısal imzayla yapıyor. FindSecBugs bulguları da bu ailelere bağlanıyor (CWE SARIF'ten geliyor), dolayısıyla hafıza tarafında tarayıcı değişikliği bir sorun değil.

## Güvenli kodda yanlış alarmlar iş açar mı

**Kayıt:** [guvenli-taban/scanner-probe-findsecbugs.json](../evidence/v02-detection/guvenli-taban/scanner-probe-findsecbugs.json).

15 güvenli vaka, tarayıcı yalnız FindSecBugs iken bir işin ilk doğrulamasıyla yeniden koşuldu.
- **Bulgu var.** 15'inin hepsinde FindSecBugs desteklenen ailede 1–2 bulgu raporladı.
- **İş açılmıyor.** 15'inin hepsinde taban geçersiz. Güvenlik tanığı güvenli kodda geçtiği için "açık var" kanıtı yok; iş modele gitmeden insana döner.

Yani FindSecBugs'ın yanlış alarmlarını tanık kapısı süzüyor. Model çağrılmıyor, hatalı bir aday üretilmiyor. Bu, yalnız tanığı olan sınıflar için geçerli. Tanığı olmayan bir bulgu (`finding_without_security_witness`) bu kapıdan geçemez; böyle bir bulgu iş açarsa yanlış alarm olabileceği kayda yazılır ([KOK_NEDEN_UC_SORUN.md](KOK_NEDEN_UC_SORUN.md)).

## Sınırlar

- **Örneklem küçük ve tek projeye dayanıyor.** 45 vakanın 42'si OWASP Benchmark'tan; Benchmark'ın servlet'leri kısa ve kalıplı. Güven aralıkları geniş.
- **"Buldu" dosya ve aile düzeyinde.** Cevap anahtarındaki satırla birebir eşleşme ayrıca raporlandı.
- **Semgrep sonucu yalnız kendi kurallarımız için geçerli.** Semgrep'in kendisinin değil, bizim üç kuralımızın kapsamını ölçüyor.
