# SonarQube adaptörünün canlı testi (30 Ekim 2026, Hafta 10)

**Soru (ROADMAP Hafta 10):** Adaptör, SonarQube Community Build'e karşı gerçekten çalışıyor mu? Gerekli kural bu sürümde yoksa işi güvenli şekilde durduruyor mu?

**Kanıt:** [`evidence/v02-sonar/canli/`](../evidence/v02-sonar/canli/). Her adımın kendi kaydı var; bir adım düzeltmeden sonra yeniden koşulduysa ikinci kayıt ayrı bir adla duruyor, ilki silinmedi.

**Betik:** `scripts/sonar_live_check.py`. Dört adımı var:
- `setup`: yerel test sunucusunun yönetici parolası, analiz anahtarı ve test kimlikleri;
- `check`: sunucu, kurallar ve adaptörün ön denetimi;
- `job`: servisler üzerinden bir iş;
- `scan`: adaptörün toplama yolu.

## Sonuç

- **Güvenli durma: evet.** Community Build'de adaptörün istediği taint kuralları yok. Bir `sonarqube+semgrep` işi modele hiç gitmeden, yaklaşık 20 saniyede `infrastructure_error` ile duruyor. İşin kaydındaki gerekçe artık adını söylüyor: `dependency_failure:RuntimeError:sonar_required_vulnerability_rule_unsupported` (`job-after-fix.json`).
- **Adaptör canlı testten önce hiçbir sunucuyla çalışamazdı.** Test dört hata buldu; dördü de düzeltildi ve her biri bir testle geldi (aşağıda).
- **Toplama yolu canlı sunucuda baştan sona çalışıyor.** Rapor, hesaplama görevi, analiz kimliği, kalite kapısı, bulgular ve hotspot'lar okunuyor (`scan-final.json`).
  - Community Build, sentetik `sql-01` vakasındaki açığı `java:S2077` kuralıyla buluyor: VULNERABILITY, `src/main/java/demo/DemoService.java` satır 17.
  - Bu yol üründe bugün kullanılmıyor, çünkü ön denetim işi daha önce durduruyor.

## Kurulum

| Alan | Değer |
|---|---|
| Sunucu | SonarQube Community Build **26.10.0.133078**, resmî Docker imajı. amd64 özeti `sha256:bf10a99d…7b36`, sıkıştırılmış 1,09 GB |
| Neden bu sürüm | Community Build'in uzun destekli sürümü yok; yalnız son sürüm destekleniyor (endoflife.date). Adaptörün sabitlendiği 25.9.0.112764'ün zip dosyası resmî indirme sunucusunda artık yok |
| Çalışma biçimi | WSL'deki Docker'da, yalnız `127.0.0.1:9000` adresinde. `SONAR_TELEMETRY_ENABLE=false`, `SONAR_UPDATECENTER_ACTIVATE=false`. Gömülü veritabanı, yalnız deneme için |
| Kimlik bilgileri | Yerel test sunucusunda varsayılan yönetici parolası rastgele bir parolayla değiştirildi ve bir kullanıcı anahtarı üretildi. İkisi `.secrets` içinde, ekrana yazılmadı (onay: proje lideri, 30 Ekim) |
| İndirmeler (onaylı) | İmaj (1,09 GB, Docker Hub). `sonar-maven-plugin` 5.1.0.4751 ve bağımlılıkları Maven Central'dan, çevrimdışı önbelleğe 12,8 MB. 8 MB'ı BouncyCastle; tahmin "birkaç MB" idi |
| Servisler | Lab profili, yerel runner (Sonar taraması Docker sandbox'ında reddedilir: tarayıcının sunucuya ağ erişimi gerekir), test kimlikleri, ayrı veritabanı |

## Canlı denetim (`check.json`)

| Kural (adaptörün eşlemesi) | Sunucunun cevabı | Ön denetim (düzeltmeden sonra) |
|---|---|---|
| `javasecurity:S3649` (SQL, CWE-89) | 404 | `sonar_required_vulnerability_rule_unsupported` |
| `javasecurity:S2083` (yol, CWE-22) | 404 | aynı |
| `javasecurity:S2076` (komut, CWE-78) | 404 | aynı |

- **Bu sürümde Java için kural depoları:** `java` ve dış raporlar için `external_*` depoları. `javasecurity` yok.
- **CWE etiketine göre Community Build'in sunduğu kurallar:**
  - CWE-89 için yalnız `java:S2077` ("SQL queries should not be dynamically formatted"). Bu kural artık VULNERABILITY türünde; eskiden hotspot'tu.
  - CWE-22 ve CWE-78 için hiç kural yok.

## Canlı testin bulduğu hatalar

1. **Adaptörün her sorgusu reddediliyordu.** Ortak `request()` fonksiyonu, güvenlik denetimi (`local_url`) gereği sorgu dizesi (`?key=...`) taşıyan her adresi reddediyor. Adaptör ise sorgu dizesini adrese ekliyordu.
   - Sonuç: sunucu durumundan sonraki ilk çağrıda `ValueError`. Runner bunu adlandırılmış bir hataya çevirmiyordu.
   - Birim testleri sahte bir çağrı kullandığı için görmemişti.
   - **Düzeltme:** `request()` sorguyu ayrı `params` olarak alıyor. `local_url` gevşetilmedi; adreste sorgu dizesi hâlâ reddediliyor.
2. **HTTP hataları adsızdı.** Olmayan kural 404 dönüyor, adaptör de ham bir HTTP hatası fırlatıyordu.
   - **Düzeltme:** HTTP hataları `sonar_http_<kod>` adını alıyor. Kural sorgusundaki 404 ise `sonar_required_vulnerability_rule_unsupported` oluyor.
3. **26.x'te hotspot araması `projectKey` parametresini reddediyor (400).** **Düzeltme:** parametrenin adı `project`.
4. **Bulgunun dosya alanı Sonar bileşen anahtarıydı.** Değer `<proje>:src/...` biçimindeydi; öbür tarayıcılar ise depoya göreli yol veriyor.
   - **Düzeltme:** proje öneki atılıyor, alan depoya göreli yol oluyor.

**Gerekçe işe kadar ulaşmıyordu.** Runner adlandırılmış hatayı 503 ile verse de worker2 bunu genel bir HTTP hatasına çeviriyordu. İşin kaydında yalnız `dependency_failure:HTTPStatusError` görünüyordu (`job.json`).
- **Düzeltme:** bir servisin sabit hata kodu artık işe kadar taşınıyor (`common.failure_code`).
- Yalnız `Tür:kod` biçimindeki kodlar geçiyor; kod kısmı yalnız küçük harf, rakam ve alt çizgi olabilir. Yol, adres ya da serbest metin işe girmez; bunu bir test denetliyor.

## Toplama yolu (`scan*.json`)

| Kayıt | Ne denendi | Sonuç |
|---|---|---|
| `scan.json` | Runner'ın komutu: Java 17, `skipJreProvisioning=true` | Tarayıcı açılmadı: "Java 17 is not supported. Please upgrade to Java 21". Eklenti bu çalışmada önbelleğe indi |
| `scan-server-jre.json` | Java 21 JRE'si Sonar sunucusundan (imajın içinde, `/opt/sonarqube/jres`; internetten değil) | Tarama başarılı; adaptör hotspot çağrısında `sonar_http_400` ile durdu (hata 3) |
| `scan-server-jre-fixed.json` | Hata 3 düzeltildi | Toplama başarılı; dosya alanı proje önekli (hata 4) |
| `scan-final.json` | Hata 4 düzeltildi | Kalite kapısı OK, 1 bulgu: `java:S2077`, `src/main/java/demo/DemoService.java:17`. Hotspot yok |

## Proje liderinin kararı gereken noktalar

1. **26.x tarayıcısı Java 21 istiyor.** Runner Maven'ı Java 17 ile çalıştırıyor ve JRE indirmesini kapalı tutuyor. Bu ayarla 26.x sunucusuna karşı tarama yapılamaz. Seçenekler:
   - runner makinesine Java 21 kurmak;
   - tarayıcının Java'yı müşterinin kendi Sonar sunucusundan almasına izin vermek. Bu internete çıkmaz; JRE sunucunun içinden gelir. Ama runner'ın bugünkü "indirme yok" ilkesini değiştirir.
2. **Community Build için kural eşlemesi.** Adaptör yalnız taint kurallarını kabul ediyor, bu yüzden Community Build'de her iş duruyor. SQL ailesi için `java:S2077` bu sürümde VULNERABILITY türünde ve `sql-01`'i buldu.
   - Eşlemeye eklenirse SQL ailesi Community Build'de de çalışır. Ama S2077 veri akışı izlemiyor, yalnız sorgunun nasıl kurulduğuna bakıyor; bu bir ürün kararı.
   - Yol ve komut aileleri için Community Build'de kural yok.
3. **Sürüm sabitlemesi.** Adaptör artık 26.10.0.133078'e sabit. Community Build her ay yeni sürüm çıkarıyor ve eskisini desteklemiyor. Sürüm uyuşmazlığı işi durdurduğu için, her yeni sürümde sabitlemenin canlı denetimle güncellenmesi gerekiyor.

## Sınırlar

- **Yalnız Community Build denendi.** Developer Edition ve üstündeki taint kurallarıyla tam ürün yolu, yani ön denetimin geçtiği ve bulguların işe girdiği yol, canlı denenmedi.
- **Tek vaka:** sentetik `sql-01`.
- **Compose dosyası denenmedi.** `compose.sonar.yml` aynı imaja ve ayarlara güncellendi, ama kendisi çalıştırılmadı; test `docker run` ile yapıldı.
- **Geniş yetkili anahtar.** Analiz için yönetici kullanıcısının anahtarı kullanıldı. Üründe en az yetkili ayrı bir hesap ve analiz anahtarı önerilir.
- **SonarQube'ün kendi dış bağlantıları tam ölçülmedi.** Sunucu telemetri ve güncelleme merkezi kapalı çalıştı.
  - Kayıtlarda "Sharing of SonarQube statistics is disabled" yazıyor.
  - Konteynerin anlık bağlantı tablosunda dışarıya açık bağlantı yoktu.
  - Ama sunucu, egress testindeki gibi bütün çalışma süresi boyunca izlenmedi.
- **WSL kapanıyor.** WSL, kendisine bağlı bir `wsl.exe` oturumu kalmayınca 15–20 saniye sonra dağıtımı kapatıyor; bu da konteyneri durduruyor. Konteyner bu yüzden bağlı bir oturumda çalıştırıldı.
- **Konteyner adı `safepatch-` ile başlamamalı.** Sandbox testleri, iş bittikten sonra bu önekle bir konteyner kalmadığını denetliyor. Testte konteyner `safepatch-sonarqube` adıyla çalışırken dört sandbox testi bu yüzden kaldı; konteyner durdurulunca geçtiler. Aşağıdaki komut başka bir ad kullanıyor.

## Yeniden kurmak

```powershell
wsl -d Debian --exec docker pull sonarqube@sha256:bf10a99dd098e5f9005f194100b7301fb938650833ec3b07b92e81c327a03b36
wsl -d Debian --exec docker run --rm --name sonarqube-live -p 127.0.0.1:9000:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -e SONAR_TELEMETRY_ENABLE=false -e SONAR_UPDATECENTER_ACTIVATE=false sonarqube@sha256:bf10a99dd098e5f9005f194100b7301fb938650833ec3b07b92e81c327a03b36
.venv/Scripts/python.exe scripts/sonar_live_check.py setup
```

Servisleri `SONAR_TOKEN_FILE=.secrets/sonar_token` ve `SONAR_URL=http://127.0.0.1:9000` ile başlatın. Ardından `EVIDENCE_DIR=evidence/v02-<ad>` ile `check`, `job` ve `scan --server-jre` adımlarını çalıştırın.
