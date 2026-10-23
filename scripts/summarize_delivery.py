"""Generate the presentation/report numbers from actual evidence, not literals."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

root=Path(__file__).resolve().parents[1]
def read(path):return json.loads((root/path).read_text(encoding='utf-8'))
def junit(name):
    node=ET.parse(root/'evidence'/name).getroot()
    suites=list(node) if node.tag=='testsuites' else [node]
    values={k:sum(int(s.get(k,'0')) for s in suites) for k in ('tests','failures','errors','skipped')}
    return {**values,'passed':values['tests']-values['failures']-values['errors']-values['skipped']}
bench=read('evidence/benchmark/summary.json');runs=read('evidence/benchmark/runs.json')
acceptance=read('evidence/acceptance/summary.json');release=read('evidence/release-smoke.json')
summary={'unit':junit('unit-tests.xml'),'java':junit('java-integration.xml'),'staging':junit('staging-integration.xml'),
         'benchmark_runs':len(runs),'benchmark_accepted':sum(r['accepted'] for r in runs),
         'acceptance':acceptance,'release_smoke':{k:release[k] for k in ('passed','first_seconds','replay_seconds','after_revocation')},
         'dependency_audit':{k:read('evidence/dependency-audit.json')[k] for k in ('queried_packages','affected_packages')},
         'limitations':['synthetic families, no independent project holdout','simulated test reviewers','native same-user runner','no live SonarQube or Docker execution','no customer pilot or sales interviews']}
(root/'evidence/delivery-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
def num(x):return f'{x:.1f}'.replace('.',',')
md=['# SafePatch V0.1 — ölçüm sonuçları','', 'Sonuçlar bu makinede gerçekten çalıştırılan komutlardan üretilmiştir. Ham JSON/CSV ve JUnit dosyaları `evidence/` içindedir.','',
    '## Doğrulama testleri','', '| Paket | Geçen | Hata / başarısız | Kapsam |','|---|---:|---:|---|']
for k,label,scope in [('unit','Birim / sözleşme','Yetki, politika, hafıza, bütçe, tarayıcı sözleşmeleri'),('java','Java entegrasyonu','Gerçek Maven/JUnit; elle yazılmış referans ve negatif yamalar'),('staging','Staging / rollback','Gerçek JAR süreçleri; insan onayı simüle')]:
    v=summary[k];md.append(f'| {label} | {v["passed"]} | {v["failures"]+v["errors"]} | {scope} |')
md+=['','## Gerçek model karşılaştırması','',f'{len(runs)} değerlendirme koşusunda {sum(r["accepted"] for r in runs)} aday insan incelemesine hazır oldu. Bu sayı 18 farklı zafiyet anlamına gelmez: 3 sentetik aile, aynı kaynak tekrarı ve küçük kaynak varyantları kullanıldı. Hafıza hazırlığı ayrıca 3 gerçek model koşusudur; yalnız SQL örneği geçti ve 1 hafıza kaydı oluşturuldu.','',
     '| Kapsam | Yaklaşım | Kabul / koşu | Tüm koşuların ortancası (sn) |','|---|---|---:|---:|']
for g in bench['groups']:
    md.append(f'| {g["phase"]} | {g["arm"]} | {g["accepted"]}/{g["n"]} | {num(g["median_wall_seconds"])} |')
sql={r['arm']:r for r in runs if r['case_id']=='sql-01' and r['phase']=='recurrence'}
gain=(sql['off']['wall_seconds']-sql['guarded']['wall_seconds'])/sql['off']['wall_seconds']*100
md+=['',f'Aynı SQL kaynağında A hafızasız {num(sql["off"]["wall_seconds"])} sn, B örnekli {num(sql["naive"]["wall_seconds"])} sn, C yeniden uygulama {num(sql["guarded"]["wall_seconds"])} sn sürdü. Bu tek eşleştirilmiş örnekte C toplam süresi A’dan %{num(gain)} daha kısadır. C model çağrısı yapmadı; doğrulama yine çalıştı.','',
     'Varyantta hafıza örneği modele ek bağlam getirir; hız kazanımı otomatik değildir. Aynı kaynakta kaydedilmiş yamayı uygulamak ile yeni projeye genellemek farklı deneylerdir. Path ve command için hazırlıkta uygun hafıza oluşmadığı için bu kollarda hafıza boş kaldı. Bu nedenle üç aile için F1 üstünlüğü iddia edilemez.','',
     'Karşılaştırma tek seed ile yapıldı. Sıralama dengeli döndürüldü; model/GPU paylaşan başka benchmark çalıştırılmadı, ancak makine ayrılmış laboratuvar sunucusu değildir. Isınma, OS yükü, Semgrep süreç başlatma ve önbellek etkileri vardır. n=3/kol, bağımsız aile sayısı 3 olduğundan p95/popülasyon güven aralığı ve genel hız iddiası yayımlanmıyor. İnsan zamanı ölçülmedi.','',
     'İlk 18 koşu FastAPI 0.116.1 / Starlette 0.47.3 ortamında ölçüldü. Bağımlılık taraması sonrası teslim sürümü FastAPI 0.141.1 / Starlette 1.6.0 / pytest 9.1.1 ile tekrar test edildi. Aşağıdaki release smoke güncel ortamın gerçek onarım/hafıza akışıdır; eski ölçümler güncel ortam sonucu gibi etiketlenmez.','',
     '## Güncel teslim ortamı: gerçek uçtan uca kontrol','',
     f'Yeni runtime ile SQL onarımı {num(release["first_seconds"])} sn, yeniden uygulama {num(release["replay_seconds"])} sn. Model + HTTP worker servisleri + gerçek Java/Semgrep kullanıldı. Kontrol API’si in-process HTTP test istemcisiyle çağrıldı. İzole test DB’sinde reviewer rolü simüle edilerek onay, hafızaya alma ve geri çekme doğrulandı. Geri çekme sonrası durum: `{release["after_revocation"]}`. Gerçek insan onayı veya üretim dağıtımı değildir.','',
     '## Kabul yöntemi karşılaştırması','', '| Kapı | İyi aday kabulü | Kötü adayın yanlış kabulü |','|---|---:|---:|']
for name,g in acceptance['gates'].items():md.append(f'| {name} | {g["true_accepts"]}/{g["good_candidates"]} | {g["false_accepts"]}/{g["bad_candidates"]} |')
md+=['','Aynı 9 adayın gerçek derleme/test/tarama sonuçları üç kapı için değerlendirildi. Adaylar elle yazılan 3 referans onarım ve 6 kasıtlı işlev bozma örneğidir. Bu sonuç, genel dünyada sıfır yanlış kabul garantisi değildir. Gerçek modelin path önerisinde tarama temizken güvenlik tanığının başarısız olması da ham koşularda görülebilir.','',
     '## Bağımlılık ve ağ kanıtı','',
     f'İlk Python kilidinde 27 paketten 2 paket için OSV kaydı bulundu: Starlette ve pytest. Güncelleme sonrasında {summary["dependency_audit"]["queried_packages"]} paket için sorguda {summary["dependency_audit"]["affected_packages"]} eşleşme bulundu. Bu, sorgu tarihindeki Python kilidiyle sınırlıdır; Java/image/model taraması veya zafiyetsizlik garantisi değildir. Kaynak kod gönderilmedi; yalnız bu açık kaynak paket adları ve sürümleri internetli hazırlık aşamasında sorgulandı.','',
     'Linux `unshare -Urn` probunda boş route tablosu ve dış bağlantı denemesinde ENETUNREACH ölçüldü. Bu yalnız probun ağ ad alanını doğrular; Maven, model, bütün host veya airgap sertifikasyonu değildir. Native runner aynı kullanıcıyla çalışır.','',
     '## Yapılmayan ve ayrıca gereken ölçümler','',
     'Canlı SonarQube/CodeFix, Snyk, Trivy/Grype entegrasyonu, Docker kötü niyetli build testi, tüm sistem paket kaydı, yüksek yük/HA, bağımsız holdout corpus, farklı model/GPU kıyası, AppSec uzman doğrulaması, gerçek geliştirici süresi ve müşteri ödeme isteği ölçülmedi. Protokoller `ARGE_VE_TICARILESME.md` içinde.']
(root/'docs/OLCUM_SONUCLARI.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2))
