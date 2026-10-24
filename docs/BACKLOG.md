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
