# Bekleyen fikirler (kapsam dışı)

ROADMAP.md'deki 12 haftalık kapsama girmeyen ama ileride değerlendirilecek işler. Buraya yazmak, yapılacağı anlamına gelmez; karar müşteri görüşmeleri ve ölçüm sonuçlarına göre verilir.

| Fikir | Neden şimdi değil | Ne zaman değerlendirilir |
|---|---|---|
| Bağımlılık taraması ve sürüm yükseltme (Trivy/Grype, Maven CVE'leri) | SAST düzeltme döngüsü henüz sağlamlaşmadı | Müşteri görüşmelerinde talep görülürse, 2027 |
| C/C++ desteği (savunma) | Bellek güvenliği hatalarını düzeltmek ve doğrulamak çok daha zor | Java ile ölçülmüş sonuç sonrası Ar-Ge iş paketi |
| DAST / IAST | Çalışan uygulama ve çalışma zamanı verisi gerektirir | Uzun vadeli Ar-Ge |
| SaaS sürümü | Hedef müşteri kapalı ağ istiyor; kod dışarı çıkma riski | Kurum içi ürün ve referans müşteriler sonrası |
| Daha büyük yerel model (14B+) | 8 GB GPU sınırı | Pilot donanımı netleşince |
| GitLab/GitHub birleştirme isteği (MR/PR) entegrasyonu | Onaylanan düzeltme şu an yalnız SafePatch arayüzünde; önce gerçek depo desteği gerekli | Müşteri görüşmelerinde hangi Git platformu kullanıldığı netleşince; pilot öncesi |
| Kurumsal kimlik doğrulama (Active Directory / LDAP / SSO) | Pilot öncesi dosya tabanlı anahtarlar yeterli | Pilot kurumun şartına göre |
| Çoklu süreç ve PostgreSQL | Tek süreç, bellek içi kuyruk ve SQLite pilot için yeterli; aynı anda tek doğrulama | Birden çok geliştiricili pilot |
| Müşteriden isteğe bağlı L2 geri bildirimi | Hava boşluklu ağdan veri çıkarma onayı belirsiz | Müşteri görüşmelerinde sorulacak |
| Daha büyük değerlendirme setiyle hafıza ölçümü (H1) | V0.2 ölçümü `ana-1` ve `ana-2` ile kapandı ([OLCUM_SONUCLARI_V02.md](OLCUM_SONUCLARI_V02.md)). 30 açık vakayla güç düşük: kaba bir tahminle C–A için yaklaşık %17 (varsayım: çiftlerin %7'si uyuşmuyor ve bunların %80'i C lehine; seed'ler bağımsız sayıldığı için iyimser). Yeni vakalar, tanık ve gizli testleri ve yaklaşık 40 saatlik GPU koşusu Hafta 10–12'ye sığmaz | Proje bittikten sonra (Aşama 2). Koşullar: yeni vakalar (kaba tahmin 90–120 açık vaka); mevcut 30 değerlendirme vakasına bakarak ayar yok; önceden sabitlenmiş yeni protokol; ürün sürümü ve model özeti kaydedilir; yeniden koşmanın etkisini ölçen bir kol. `ana-1` ve `ana-2` ile karşılaştırma yalnız gösterge olur |
