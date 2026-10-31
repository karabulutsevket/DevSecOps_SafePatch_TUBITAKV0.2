# Görüşme notu şablonu

Plan ve sorular: [GORUSME_VE_PILOT_PLANI.md](../GORUSME_VE_PILOT_PLANI.md).

Her görüşmeyi bu klasörde ayrı bir dosyaya, `K01-1.md` biçiminde yazın: kurum kodu ve o kurumla kaçıncı görüşme olduğu.

**Depo herkese açık.**
- Kişi ve kurum adı, e-posta, telefon ya da kurumu tanıtacak bir ayrıntı yazmayın.
- Kurum kodunun hangi kuruma karşılık geldiği depo dışında tutulur.
- Kurum adı yalnız yazılı izinle kullanılır.

Bir sayıyı bilmiyorsanız tahmin etmeyin; "bilinmiyor" yazın. Tahmin edilen bir sayı "tahmin" diye işaretlenir.

---

## Görüşme

| Alan | Değer |
|---|---|
| Kurum kodu | K__ |
| Segment | 1: finansa yazılım sağlayan Java ekibi · 2: finans/fintek AppSec · 3: büyük banka / savunma |
| Görüşülen rol(ler) | geliştirici / inceleyen · AppSec · platform/DevOps · bütçe sahibi |
| Tarih, süre | |
| Görüşmeyi yapan | |
| Not alınacağı söylendi mi | evet / hayır |

## Cevaplar

Soruların tam hâli: [ARASTIRMA_ONCALISMASI.md](../ARASTIRMA_ONCALISMASI.md), bölüm 14.

| # | Konu | Kaydedilecek |
|---|---|---|
| 1 | Son kapatılan yüksek öncelikli Java bulgusu | Tespit → atama → aktif çalışma → inceleme → onay → dağıtım; her adımın süresi (gün ya da saat). Aktif çalışma ile bekleme ayrı |
| 2 | Son 20 bulgu | Kaçı gerçek, kaçı yanlış pozitif, kaçı tekrar açıldı ve neden |
| 3 | Aylık hacim (S2) | Ayda Java kaynak değişikliği gerektiren bulgu sayısı. Bağımlılık ve imaj güncellemeleri ayrı |
| 4 | Tekrar (S3) | Son 20 güvenlik düzeltmesinin kaçı aynı stratejiyle yapıldı. İzinli örnek var mı |
| 5 | Çevrimdışı derleme | Hangi depolar çevrimdışı derlenip test edilebiliyor; JDK ve build aracı sürümleri; test süresi |
| 6 | Veri ve ağ | Kod, istem, kayıt ve hata çıktısı nereye gidebilir; politika yazılı mı |
| 7 | Mevcut araçlar | Tarayıcı ve sürümü (ör. SonarQube edition), Git platformu, yapay zekâ araçları ve açık özellikleri |
| 8 | Ret nedenleri | Bir yamayı reddettiren en yaygın üç neden |
| 9 | Pilot başarısı | Kuruma göre ölçülebilir başarı: dakika, kabul oranı, kabul edilemeyecek hata türleri |
| 10 | Bütçe | Bütçe sahibinin rolü (ad değil), kalem, karar dönemi |
| 11 | İşletim | Yerel kurulumu ve güncellemeyi kim işletir; özel geliştirme beklentisi |
| 12 | Engel | Ücretli pilotu onaylamanın önündeki gerçek engel |

## Sonuç

| Alan | Değer |
|---|---|
| Sınıf | güçlü sinyal / zayıf sinyal / sinyal yok (tanımlar: plan, bölüm 1) |
| Gerekçe | Bir cümle |
| Sonraki adım ve tarihi | |
| İzinler | Kurum adı kullanılabilir mi; tekrar ölçümü (plan, bölüm 3) yapılabilir mi |
