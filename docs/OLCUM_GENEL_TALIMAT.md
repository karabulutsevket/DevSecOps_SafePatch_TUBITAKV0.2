# Genel sistem talimatı ölçümü (Hafta 4)

**Tarih:** 25 Ekim 2026 · **Ürün kodu:** commit `d4f1ec2` · **Ham kanıt:** [`evidence/v02-genel-talimat/retry/`](../evidence/v02-genel-talimat/retry/) · **Referanslar:** SQL ve command için [H2](OLCUM_V02_YENIDEN_DENEME.md) ([`evidence/v02-retry`](../evidence/v02-retry/retry/)), path için [güçlü tanıklı yeniden ölçüm](OLCUM_PATH_TANIGI.md) ([`evidence/v02-path-tanigi`](../evidence/v02-path-tanigi/retry/))

## Soru

Modele giden sistem talimatı sentetik vakalara göre yazılmıştı. Vakaya özgü ipuçları içeriyordu; command vakaları için çözümün kendisini veren `demo.EchoMain` yardımcı sınıfı satırı da vardı. Gerçek bir projede bu talimat yanıltıcı olurdu ([envanter maddesi 14](GERCEK_DEPO_TASARIMI.md)). Soru: talimat genelleştirilince sonuç değişiyor mu?

## Değişen

| | Önce | Sonra |
|---|---|---|
| Kimlik satırı | "one owned synthetic Java source file" | "one Java source file of the user's project" |
| Zayıflık bilgisi | Üç ailenin ipucu her istemde, vakaya özgü sözcüklerle ("normal accounts", "echo:") | Yalnız işin CWE ailesi için tek satırlık genel onarım notu (`WEAKNESS_NOTES`) |
| Projeye özgü bilgi | `demo.EchoMain` yardımcısının ne yaptığı ve nasıl çağrılacağı | Talimatta yok; yardımcı sınıf yalnız salt okunur bağlam verisinde (`guided+context`) |

Model, sıcaklık, deneme bütçesi, tanıklar ve rehber metinleri referanslarla aynı. 9 vaka × 2 strateji × 3 seed = 54 iş, 59 dakika.

## Sonuç

| Strateji | SQL | Path | Command | Toplam | Referans |
|---|---|---|---|---|---|
| `v01` | 9/9 | 0/9 | 0/9 | **9/27** | 9/27 |
| `guided+context` | 9/9 | 9/9 | 0/9 | **18/27** | 18/27 (SQL 9, path 8, command 1) |

- **`v01`:** vaka ve seed bazında referansla birebir aynı.
- **`guided+context`:** bir iş kazanıldı (`path-02`, seed 44), bir iş kaybedildi (`command-02`, seed 42). Daha önce ölçtüğümüz model belirlenimsizliği (aynı istemde 18 işte 2 farklı yama) bu düzeyde fark üretir.
- **Eşleştirilmiş karşılaştırma:** genel talimatla `v01` → `guided+context` 9–0, kesin McNemar p = 0,004. Kazancın tamamı path ailesinden. H2'deki command kazancı (1 iş) bu koşuda yok.
- **Command ailesi** `guided+context` ile 9 işin 9'unda derleme hatasıyla bitti. Model, H2'de de görülen aynı hatayı yapıyor: `ProcessBuilder.start()` sonucunu `ProcessBuilder` türünde bir değişkene atıyor. Yardımcı sınıf bağlamda olsa da 7B model onu doğru kullanamıyor.

**Karar:** genel talimat ürünün talimatı olarak kalır. Sentetik vakalarda kabul oranını düşürmedi; gerçek projelerde yanıltıcı ve vakaya özgü bilgi taşımıyor.

## Gözlem ve sonraki iş

Derleyici tanıları modele runner çalışma klasörünün mutlak yoluyla gidiyor (`/C:/.../.runtime/runner-work/<iş>-<deneme>-<rastgele>/src/main/java/...`). Bu yol modele bilgi taşımaz, token harcar ve her denemede değişir. Tanıların depo göreli yola indirilmesi küçük bir iş; command ailesindeki derleme hatalarında modelin geri bildirimi daha iyi okumasına yardım edebilir. Etkisi ayrıca ölçülmeli.

## Sınırlar

- Tek koşu, 3 seed; karşılaştırma aynı koşudaki eski talimatla değil, önceki koşularla. Path referansı güçlü tanıklı ölçümden, SQL/command referansı H2'den.
- Sentetik vakalar talimatın genelliğini sınamaz. Asıl sınama gerçek projelerde (Vul4J, Hafta 5).

## Yeniden üretim

```powershell
$env:EVIDENCE_DIR = 'evidence/v02-genel-talimat-yeni'
.venv/Scripts/python.exe scripts/retry_experiment.py --strategies v01,guided+context --seeds 42,43,44   # Ollama ve servisler çalışırken
```
