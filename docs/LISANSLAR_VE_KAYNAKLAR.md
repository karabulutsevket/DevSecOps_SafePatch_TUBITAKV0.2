# Lisans, maliyet ve kaynak notları

12 Eylül 2026 tarihinde incelenen belgeler. Bu tablo satın alma/yeniden dağıtım sözleşmesi değildir; paketleme kararında seçilen sürümün lisans metni ayrıca saklanmalıdır.

| Parça | V0.1 kararı | Ticari ürüne etkisi |
|---|---|---|
| SafePatch kaynakları ve kendi kuralları | MIT | Kaynakta LICENSE korunur |
| Qwen2.5-Coder-7B-Instruct | Model kartı Apache-2.0; ağırlık özeti sabitlenir | İsim ailesi yerine seçilen model/sürüm lisansı doğrulanır; ağırlıklar bu depoda dağıtılmaz |
| Semgrep CE motoru | LGPL-2.1; ayrı süreç olarak çağrılır | Dağıtım yükümlülükleri ayrıca ele alınır |
| Semgrep'in yayımladığı kural koleksiyonları | Bu depoda kullanılmıyor; kendi üç MIT kuralı var | Motor lisansıyla karıştırılmaz; Semgrep Rules License ayrı kısıtlar içerir |
| SonarQube Community Build | Zorunlu değil | Ticari sürümlerdeki bütün güvenlik kuralları yoktur |
| SonarQube ticari / CodeFix | V0.1 için alınmadı | Müşteri lisansı veya açık OEM/yeniden satış anlaşması gerekir; bizim tek lisansımızın bütün müşterileri kapsadığı varsayılmaz |
| Snyk ve diğer ticari servisler | Kullanılmadı | Offline destek, veri akışı, kullanım ve yeniden dağıtım hakları sağlayıcıyla doğrulanır |
| Maven/Java/Python/bağımlılıklar | Geliştirme ortamı ve demo bağımlılıkları | Güncel zafiyet taraması, lisans envanteri ve offline güncelleme süreci ürünün bakım işidir |

Sonar belgeleri, güncel Enterprise/Data Center AI CodeFix'in kurum içi LLM gateway ile dış internet erişimi olmadan çalışabilecek şekilde tasarlandığını belirtiyor. Yerel API çağrısı internet demek değildir. Eski 2025.5 belgesi farklı davranış tarif ettiği için sürüm belirtilmeden kesin genelleme yapılmamalıdır. SafePatch'in ticari farkı yalnızca “yerelde LLM” olamaz.

Sonar, Community Build'in taint analizini desteklemediğini ve güvenlik kapsamının sınırlı olduğunu ayrıca açıklıyor. Bu nedenle bu demoda SQL/path/command bulguları kendi Semgrep kurallarından gelir; Sonar kapsam eksikliği bir başarılı tarama gibi gizlenmez.

## Birincil kaynaklar

1. [Sonar AI CodeFix güncel yapılandırma](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix.md): yerel gateway ve paket koşulları.
2. [Sonar Community Build kural kapsamı](https://docs.sonarsource.com/sonarqube-community-build/quality-standards-administration/managing-rules/rules): ticari sürümlere özgü kurallar.
3. [Sonar'ın Java SQL injection analizi açıklaması](https://www.sonarsource.com/blog/how-sonarqube-traces-a-sql-injection-your-ai-coding-agent-produced/): Community Build taint sınırı ve `javasecurity:S3649`.
4. [Qwen model kartı](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct): seçilen model ve Apache-2.0 lisansı.
5. [Semgrep CE](https://semgrep.dev/products/community-edition/): motor lisansı.
6. [Semgrep kural lisansı](https://semgrep.dev/legal/rules-license/): motor dışında ayrı kural lisansı.
7. [Sonar plan ve fiyatlandırma](https://www.sonarsource.com/plans-and-pricing/sonarqube/): paket/sözleşme değerlendirmesi; V0.1 için ücretli satın alma yapılmadı.

Rakiplerle lisanslı başa baş benchmark, müşteri satın alma görüşmesi veya gerçek kurumda pilot yapılmış gibi bir iddia yoktur. Bu depodaki ölçümler SafePatch'in kendi yerel koşularıdır.
