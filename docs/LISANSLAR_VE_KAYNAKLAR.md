# Lisans, maliyet ve kaynak notları

12 Eylül 2026 tarihinde incelenen belgeler. Bu tablo satın alma/yeniden dağıtım sözleşmesi değildir; paketleme kararında seçilen sürümün lisans metni ayrıca saklanmalıdır.

| Parça | V0.1 kararı | Ticari ürüne etkisi |
|---|---|---|
| SafePatch kaynakları ve kendi kuralları | MIT | Kaynakta LICENSE korunur |
| Qwen2.5-Coder-7B-Instruct | Model kartı Apache-2.0; ağırlık özeti sabitlenir | İsim ailesi yerine seçilen model/sürüm lisansı doğrulanır; ağırlıklar bu depoda dağıtılmaz |
| Semgrep CE motoru | LGPL-2.1; ayrı süreç olarak çağrılır | Dağıtım yükümlülükleri ayrıca ele alınır |
| Semgrep'in yayımladığı kural koleksiyonları | Bu depoda kullanılmıyor; kendi üç MIT kuralı var | Motor lisansıyla karıştırılmaz; Semgrep Rules License ayrı kısıtlar içerir |
| SpotBugs 4.9.8 | LGPL-2.1; ayrı süreç olarak çağrılır, depoda yok (`.runtime/tools`) | Dağıtım yükümlülükleri ayrıca ele alınır |
| FindSecBugs eklentisi 1.14.0 | LGPL-3.0; SpotBugs eklentisi olarak yüklenir, depoda yok | Dağıtım yükümlülükleri ayrıca ele alınır |
| maven-dependency-plugin 3.8.1 | Apache-2.0; çevrimdışı Maven önbelleğinde, projenin sınıf yolu için | Dağıtılmaz |
| SonarQube Community Build | Zorunlu değil | Ticari sürümlerdeki bütün güvenlik kuralları yoktur |
| SonarQube ticari / CodeFix | V0.1 için alınmadı | Müşteri lisansı veya açık OEM/yeniden satış anlaşması gerekir; bizim tek lisansımızın bütün müşterileri kapsadığı varsayılmaz |
| Snyk ve diğer ticari servisler | Kullanılmadı | Offline destek, veri akışı, kullanım ve yeniden dağıtım hakları sağlayıcıyla doğrulanır |
| Maven/Java/Python/bağımlılıklar | Geliştirme ortamı ve demo bağımlılıkları | Güncel zafiyet taraması, lisans envanteri ve offline güncelleme süreci ürünün bakım işidir |

Sonar belgeleri, güncel Enterprise/Data Center AI CodeFix'in kurum içi LLM gateway ile dış internet erişimi olmadan çalışabilecek şekilde tasarlandığını belirtiyor. Yerel API çağrısı internet demek değildir. Eski 2025.5 belgesi farklı davranış tarif ettiği için sürüm belirtilmeden kesin genelleme yapılmamalıdır. SafePatch'in ticari farkı yalnızca “yerelde LLM” olamaz.

Sonar, Community Build'in taint analizini desteklemediğini ve güvenlik kapsamının sınırlı olduğunu ayrıca açıklıyor. Bu nedenle bu demoda SQL/path/command bulguları kendi Semgrep kurallarından gelir; Sonar kapsam eksikliği bir başarılı tarama gibi gizlenmez.

## L2 paketi ve veri setleri (27 Ekim 2026)

L2 paketine yalnız lisansı izinli kaynaktan gelen düzeltme girer ([L2_PAKETI.md](L2_PAKETI.md)). Kod tarafındaki izin listesi `safepatch/l2.py` içindeki `LICENSES`; paket üretilirken de içeri alınırken de denetlenir.

| Kaynak | Lisans | L2'ye girer mi |
|---|---|---|
| SafePatch'in sentetik geliştirme vakaları (`samples/`, `l3/catalog.yml` içinde `source: safepatch-synthetic`, `split: development`) | MIT (bu depo) | Evet. Bugün izinli tek kaynak |
| OWASP Benchmark (Java) | GPL-2.0 (`l3/catalog.yml`) | **Hayır.** Yalnız L3 değerlendirmede kullanılır (CLAUDE.md, kural 8); paket üreticisi değerlendirme vakalarını reddeder |
| Vul4J vaka listesi ve vakaların projeleri | Liste GPL-3.0; projeler kendi lisanslarıyla (ör. Apache-2.0) | **Hayır.** Yalnız L3 değerlendirmede kullanılır |
| Açık kaynak projelerin CVE düzeltme commit'leri (SAP project-kb, GitHub Advisory/OSV bağlantıları) | Her proje kendi lisansıyla | Henüz değil. Kaynak başına lisans incelemesi ve `LICENSES` listesine ekleme kararı gerekir; L3 değerlendirme projeleriyle çakışanlar dışarıda kalır |

Pakete düzeltmenin farkı (değişen satırlar ve çevresi) girer, projenin kodu girmez. Yine de farkın kaynağı lisansı taşır. Bu yüzden lisans kaydı her kaydın `origin.license` alanında durur.

## Birincil kaynaklar

1. [Sonar AI CodeFix güncel yapılandırma](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix.md): yerel gateway ve paket koşulları.
2. [Sonar Community Build kural kapsamı](https://docs.sonarsource.com/sonarqube-community-build/quality-standards-administration/managing-rules/rules): ticari sürümlere özgü kurallar.
3. [Sonar'ın Java SQL injection analizi açıklaması](https://www.sonarsource.com/blog/how-sonarqube-traces-a-sql-injection-your-ai-coding-agent-produced/): Community Build taint sınırı ve `javasecurity:S3649`.
4. [Qwen model kartı](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct): seçilen model ve Apache-2.0 lisansı.
5. [Semgrep CE](https://semgrep.dev/products/community-edition/): motor lisansı.
6. [Semgrep kural lisansı](https://semgrep.dev/legal/rules-license/): motor dışında ayrı kural lisansı.
8. [SpotBugs](https://github.com/spotbugs/spotbugs): motor ve LGPL-2.1 lisansı; dağıtım paketi Maven Central `com.github.spotbugs:spotbugs:4.9.8` (zip).
9. [Find Security Bugs](https://find-sec-bugs.github.io/): eklenti, hata desenleri ve LGPL-3.0 lisansı; Maven Central `com.h3xstream.findsecbugs:findsecbugs-plugin:1.14.0`.
7. [Sonar plan ve fiyatlandırma](https://www.sonarsource.com/plans-and-pricing/sonarqube/): paket/sözleşme değerlendirmesi; V0.1 için ücretli satın alma yapılmadı.

Rakiplerle lisanslı başa baş benchmark, müşteri satın alma görüşmesi veya gerçek kurumda pilot yapılmış gibi bir iddia yoktur. Bu depodaki ölçümler SafePatch'in kendi yerel koşularıdır.
