// Requires the bundled @oai/artifact-tool presentation runtime and retained template.
// Set ARTIFACT_MODULE, PRESENTATION_SKILL, TEMPLATE_PATH, RUNTIME_PYTHON,
// and RUNTIME_NODE_MODULES for the first-party final import check.
// Template is imported and its slides, positions, theme and image are reused.
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'..');
const {FileBlob,PresentationFile}=await import(pathToFileURL(process.env.ARTIFACT_MODULE).href);
const skill=process.env.PRESENTATION_SKILL;
const utils=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')).href);
const build=path.join(root,'.presentation-build');
await fs.mkdir(build,{recursive:true});
const p=await PresentationFile.importPptx(await FileBlob.load(process.env.TEMPLATE_PATH));
const source=[...p.slides.items];
const bench=JSON.parse(await fs.readFile(path.join(root,'evidence/benchmark/summary.json'),'utf8'));
const runs=JSON.parse(await fs.readFile(path.join(root,'evidence/benchmark/runs.json'),'utf8'));
const acceptance=JSON.parse(await fs.readFile(path.join(root,'evidence/acceptance/summary.json'),'utf8'));
const delivery=JSON.parse(await fs.readFile(path.join(root,'evidence/delivery-summary.json'),'utf8'));
const slides=[];
const font='Helvetica Neue';
async function copy(number){
 const s=source[number-1].duplicate();slides.push(s);
 const layout=JSON.parse(await(await s.export({format:'layout'})).text());
 const elements=layout.elements.filter(e=>e.kind==='shape'&&e.text);
 for(const e of elements.filter(e=>e.bbox[1]>650&&/^\d+$/.test(e.text)))p.resolve(e.aid).text=String(slides.length);
 for(const e of layout.elements.filter(e=>e.name?.startsWith('Footer Placeholder'))){
  const shape=p.resolve(e.aid);shape.text='SafePatch V0.1 · Sentetik demo · 12.09.2026';
  shape.text.style={typeface:font,fontSize:13.33,color:'#FFFFFF'};
 }
 return {s,elements};
}
function text(e,value,size){const shape=p.resolve(e.aid);shape.text=value;if(size)shape.text.style={typeface:font,fontSize:size,color:'#FFFFFF',autoFit:'none'};return shape;}
function title(o,value){return text(o.elements.find(e=>e.bbox[1]<100&&e.bbox[2]>600),value,38.67);}
function notes(s,value){s.speakerNotes.textFrame.setText(value);}
async function columns(heading,values,note){
 const o=await copy(6);title(o,heading);
 const bodies=o.elements.filter(e=>e.bbox[1]>200&&e.bbox[1]<650).sort((a,b)=>a.bbox[0]-b.bbox[0]);
 bodies.forEach((e,i)=>text(e,values[i],25));notes(o.s,note);return o;
}
async function cards(heading,intro,values,note){
 const o=await copy(12);title(o,heading);
 text(o.elements.find(e=>e.bbox[1]>100&&e.bbox[1]<248),intro,23);
 const bodies=o.elements.filter(e=>e.bbox[1]>250&&e.bbox[1]<630).sort((a,b)=>Math.round(a.bbox[1]/100)-Math.round(b.bbox[1]/100)||a.bbox[0]-b.bbox[0]);
 bodies.forEach((e,i)=>text(e,values[i],24));notes(o.s,note);return o;
}
async function timeline(heading,values,labels,note){
 const o=await copy(18);title(o,heading);
 const bodies=o.elements.filter(e=>e.bbox[1]>140&&e.bbox[1]<500).sort((a,b)=>a.bbox[0]-b.bbox[0]);
 bodies.forEach((e,i)=>text(e,values[i],25));
 o.elements.filter(e=>e.text==='Date').sort((a,b)=>a.bbox[0]-b.bbox[0]).forEach((e,i)=>text(e,labels[i],23));
 // The source timeline extends past the right edge; trim to its intended canvas.
 for(const sh of o.s.shapes.items)if(sh.position.left+sh.position.width>1280)sh.position={...sh.position,width:1238-sh.position.left};
 notes(o.s,note);return o;
}
async function table(heading,intro,values,note){
 const o=await copy(14);title(o,heading);
 const introBox=o.elements.find(e=>e.bbox[1]>100&&e.bbox[1]<236);if(introBox)text(introBox,intro,22);
 const t=o.s.tables.items[0];
 for(let r=0;r<9;r++)for(let c=0;c<5;c++){t.cells.set(r,c,values[r]?.[c]??'');t.getCell(r,c).text.style={typeface:font,fontSize:18.5,color:'#FFFFFF',bold:r===0};}
 notes(o.s,note);return o;
}
let o=await copy(1);
text(o.elements.find(e=>e.text.includes('Simple Dark Mode')),'SafePatch\nV0.1',74);
text(o.elements.find(e=>e.text.includes('Lorem ipsum')),'Yerel Java onarımı, doğrulama ve yama hafızası\nTeknik demo · Ar-Ge · Ticarileşme',23);
text(o.elements.find(e=>e.text==='Supertitle'),'BULGUDAN ONAYLI YAMAYA',20);
notes(o.s,'Çalışan sentetik demo. Üretime hazır savunma/banka ürünü iddiası değildir. Kaynak: README.md ve docs/CALISAN_MIMARI.md. Kapak fotoğrafı seçilen Simple Dark Mode şablonundan aynen korunmuştur.');
await columns('Çözdüğümüz problem',[
 'Onarım yükü\nBulgu, kod değişikliği, test ve inceleme farklı adımlarda yürütülüyor. Hedef: bu akışı ölçülebilir hâle getirmek.',
 'Yanlış yama riski\nTarayıcı bulgusu kaybolabilir; meşru davranış veya güvenlik hâlâ bozuk olabilir. Ayrı kabul testleri gerekiyor.',
 'Kurum hafızası\nİncelenmiş bir düzeltmeyi yalnız uygun koşullarda yeniden kullanmak; gerektiğinde geri çekebilmek.'
], 'Bunlar ürün ihtiyacı hipotezleridir. Gerçek kurum görüşmeleri yapılmadı. Pilot planı: docs/ARGE_VE_TICARILESME.md.');
await cards('Çalışan mimari: dört temel sorumluluk',
 'Kayıtlı Java deposu → tarama → hafıza / model → bağımsız doğrulama → insan onayı',[
 '01 · Orkestratör\nFastAPI, iş sırası, yetki ve bütçe. Kod/dağıtım kararları ayrı rollerde.',
 '02 · Yama hafızası\nSQLite, uygunluk koşulları, köken ve kullanım izi. Karantina / geri çekme.',
 '03 · Yerel model\nOllama + sabit Qwen 7B. Yama önerir; inceleme veya dağıtım onayı vermez.',
 '04 · Doğrulayıcı / runner\nMaven, korunan JUnit, Semgrep. Commit, JAR ve kanıt hash ile bağlanır.'
], 'Kod: safepatch/orchestrator.py, engine.py, memory.py, worker1.py, worker2.py, runner.py, acceptance.py. Native servisler ayrı süreçlerdir; aynı OS kullanıcısı güçlü bir güvenlik sınırı değildir.');
await timeline('Hafıza bir onay ve geri çekme döngüsüdür',[
 'İncele ve kaydet\nKod testleri geçer. İnsan diff’i onaylar. Ayrı bir kararla hafızaya alınır. Model ağırlıkları değişmez.',
 'Uygunluğu kontrol et\nProje, kural, Java, derleme ve test sözleşmesi eşleşir. Aynı kaynaksa yama tekrarlanır; testler yine çalışır.',
 'Gerektiğinde geri çek\nYeni kullanım engellenir. Bağlı bekleyen onaylar iptal edilir. Dağıtılmış işler için görünür uyarı oluşur.'
],['Onay','Yeniden kullanım','Geri çekme'],'V0.1: muhafazakâr hash/sözleşme eşleştirmesi; vektör RAG veya AST/dataflow uygunluğu değil. Testler: tests/test_memory.py. Benchmark hafıza onayı simüledir ve ayrı DB’dedir.');
await cards('Bir aday hangi koşullarda kabul edilir?',
 'Başlangıç kodunda normal davranış geçer, beklenen güvenlik tanığı başarısız olur. Ardından her aday baştan doğrulanır.',[
 'Derleme ve artifact\nTemiz dizinde Maven offline. Onaylanan JAR sonradan yeniden derlenmez.',
 'Meşru davranış\nİşlevi kapatan veya sabit yanıt veren “düzeltme” testte reddedilir.',
 'Güvenlik tanığı\nSQL/path/command saldırı örneği tekrar çalışır; korunan test değiştirilemez.',
 'Tarama ve bütünlük\nGerçek Semgrep; kaynak ve test hash kontrolü. Tarayıcı hatası temiz sonuç değildir.'
], 'Test geçişi yalnız bu testlerin kapsadığı davranış için kanıttır. Genel güvenlik veya semantik doğruluk ispatı değildir. docs/CALISAN_MIMARI.md.');
await table('V0.1 kapsamı', 'Çalışan yetenek ile gelecek hedefi ayrı tutuyoruz.',[
 ['Bileşen','Çalışıyor','Kanıt','Kapsam','Sonraki adım'],
 ['Yerel Qwen','Evet','Gerçek koşu','7B / 8 GB','Model kıyası'],
 ['Semgrep','Evet','Gerçek tarama','3 özel kural','Geniş kapsama'],
 ['Yama hafızası','Evet','Yaşam döngüsü','Hash / sözleşme','AST önkoşulu'],
 ['İnsan onayı','Evet','Rol / hash testi','Yerel kullanıcı','Kurumsal SSO'],
 ['Staging / rollback','Evet','Gerçek JAR','Sentetik yerel','Kurum CI'],
 ['SonarQube','Adaptör','Sözleşme testi','Canlı test yok','Lisanslı pilot'],
 ['Sandbox / airgap','Kısmi prob','Namespace','Tam sistem değil','İzole runner'],
 ['Snyk / Trivy / Grype','Hayır','Plan','Entegre değil','Ayrı adaptörler']
], 'Kaynak: bu depodaki kod ve evidence/. Docker/HA/SSO/kurumsal pilot için sonuç üretilmedi.');
o=await copy(19);title(o,'Modelin her önerisi kabul edilmiyor');
text(o.elements.find(e=>e.bbox[1]>100&&e.bbox[1]<300),'Hafıza hazırlığı: 3 farklı sentetik zafiyet ailesi. Yalnız testlerden geçen gerçek model yaması örnek havuzuna alındı.',23);
const statNumbers=o.elements.filter(e=>e.text.includes('%')).sort((a,b)=>a.bbox[0]-b.bbox[0]);
const statText=o.elements.filter(e=>e.bbox[1]>500&&e.bbox[1]<630).sort((a,b)=>a.bbox[0]-b.bbox[0]);
['1 / 3','2 / 3','1'].forEach((v,i)=>text(statNumbers[i],v,78));
['SQL tek denemede geçti.\nBaşarılı hafıza kaydı oluştu.','Path / command durduruldu.\nTarama temizliği yetmedi.','Tek onaylı örnek.\nDeğerlendirmede sabit.'].forEach((v,i)=>text(statText[i],v,23));
notes(o.s,'Kaynak: evidence/benchmark/construction.json. 1/3 yalnız üç hazırlık vakasına aittir. Bağımsız holdout başarı oranı değildir. İnsan onayı yalnız benchmark veritabanında simüle edildi.');
const fmt=v=>v.toFixed(1).replace('.',',');
await table('Üç yaklaşım, aynı model ve bütçe', 'İlk ölçüm ortamı. A: hafızasız · B: kural örneği · C: uygunluk + tekrar',[
 ['Kapsam','Kol','Kabul / n','Ortanca sn','Yorum'],
 ...bench.groups.map(g=>[g.phase==='recurrence'?'Aynı kaynak':'Küçük varyant',({off:'A',naive:'B',guarded:'C'})[g.arm],`${g.accepted} / ${g.n}`,fmt(g.median_wall_seconds),'Tüm sonuçlar']),
 ['18 koşu','3 aile','Tek seed','Ayrı DB','Hafıza sabit'],
 ['Genelleme','Yapılmadı','Holdout yok','Pilot yok','Ham CSV var']
], 'Kaynak: evidence/benchmark/summary.json ve runs.csv. Küçük varyantlar aynı aileye aittir; bağımsız proje/CVE holdout değildir. Ortanca tüm sonuçları içerir; başarıyla tamamlanan iş süresi ile başarısız iş süresi karıştırılarak üstünlük iddia edilmez. Bu ilk karşılaştırma bağımlılık güncellemesi öncesi ortamda yapıldı; güncel sürüm ayrıca release smoke ile doğrulanır.');
o=await copy(22);title(o,'Aynı SQL yamasını yeniden kullanmak');
const sql=runs.filter(r=>r.case_id==='sql-01'&&r.phase==='recurrence');
const sqlValues=['off','naive','guarded'].map(arm=>sql.find(r=>r.arm===arm).wall_seconds);
const gain=(sqlValues[0]-sqlValues[2])/sqlValues[0]*100;
// This is a new measured-data chart, not the template's sample workbook.
// Reuse the template chart footprint, fonts and palette while authoring fresh literal data.
o.s.charts.deleteById(o.s.charts.items[0].id);
const chart=o.s.charts.add('bar',{
 position:{left:66.61,top:138.84,width:528.06,height:502.32},
 categories:['A Hafızasız','B Örnek','C Tekrar'],
 series:[
  {name:'Toplam süre (sn)',values:sqlValues,fill:'#6DCBF4',valuesFormatCode:'0.0'},
  {name:'Model süresi (sn)',values:['off','naive','guarded'].map(arm=>sql.find(r=>r.arm===arm).model_seconds),fill:'#3D8DFF',valuesFormatCode:'0.0'}
 ],
 barOptions:{direction:'column',grouping:'clustered',gapWidth:100},
 hasLegend:true,legend:{position:'bottom',textStyle:{typeface:font,fontSize:18,fill:'#FFFFFF'}},
 xAxis:{textStyle:{typeface:font,fontSize:18,fill:'#FFFFFF'},majorGridlines:null},
 yAxis:{min:0,max:70,majorUnit:10,numberFormatCode:'0',textStyle:{typeface:font,fontSize:18,fill:'#FFFFFF'},majorGridlines:{fill:'#555555',width:1}},
 dataLabels:{showValue:true,position:'outEnd',textStyle:{typeface:font,fontSize:18,fill:'#FFFFFF'}},
 chartFill:'#000000',plotAreaFill:'#000000'
});
utils.applyPresentationChartFont(chart,{fontFamily:font});
const right=o.elements.filter(e=>e.bbox[0]>650);
text(right.find(e=>e.text.includes('Title here')),'Üçünde de kabul koşulları geçti.\nTekrar kolu LLM çağrısını atladı; derleme, test ve tarama yine çalıştı. Bu tek eşleştirilmiş örnektir.',24);
const ns=right.filter(e=>e.text.includes('%')).sort((a,b)=>a.bbox[0]-b.bbox[0]);text(ns[0],'%'+fmt(gain),56);text(ns[1],'0',56);
const small=right.filter(e=>e.bbox[1]>530).sort((a,b)=>a.bbox[0]-b.bbox[0]);text(small[0],'Bu koşuda daha kısa\ntoplam süre',23);text(small[1],'Tekrar kolunda\nmodel token’ı',23);
notes(o.s,'Kaynak: evidence/benchmark/runs.csv; sql-01 recurrence, n=1/kol. A 56.865, B 57.8, C 46.73 saniye. %17.8 bu örneğe aittir; müşteri tasarrufu değildir. Model süresi ve toplam süre ayrı gösterilir. İlk ölçüm ortamı güncelleme öncesidir.');
o=await copy(19);title(o,'Güncel runtime ile akış yeniden doğrulandı');
text(o.elements.find(e=>e.bbox[1]>100&&e.bbox[1]<300),'Bağımlılık güncellemesi sonrası gerçek SQL onarımı, yeniden kullanım ve geri çekme. İnsan rolleri yalnız ayrı test DB’sinde simüle edildi.',23);
const newNums=o.elements.filter(e=>e.text.includes('%')).sort((a,b)=>a.bbox[0]-b.bbox[0]);
const newLabels=o.elements.filter(e=>e.bbox[1]>500&&e.bbox[1]<630).sort((a,b)=>a.bbox[0]-b.bbox[0]);
const release=delivery.release_smoke;
[fmt(release.first_seconds),fmt(release.replay_seconds),'%'+fmt((release.first_seconds-release.replay_seconds)/release.first_seconds*100)].forEach((v,i)=>text(newNums[i],v,78));
['saniye · ilk onarım\nYerel model + tüm kontroller','saniye · aynı yama\nModel çağrısı yok; tekrar test','Bu tek örnekte süre farkı\nMüşteri tasarrufu değildir'].forEach((v,i)=>text(newLabels[i],v,23));
notes(o.s,'Kaynak: evidence/release-smoke.json. FastAPI 0.141.1 / Starlette 1.6.0. Gerçek LLM, HTTP worker’lar, Java/Semgrep; kontrol API’si in-process test istemcisinde. İlk onarım 67.244 sn, replay 50.931 sn. Geri çekme sonrası bekleyen iş needs_human oldu. n=1 eşleştirme; istatistiksel genelleme yapılmaz.');
await table('Tarayıcı temizliği kabul için yeterli değil', 'Aynı aday havuzu: 3 referans onarım + 6 bilerek bozulan işlev. Gerçek Java ve Semgrep.',[
 ['Kabul kapısı','İyi aday','Kabul','Kötü aday','Yanlış kabul'],
 ...Object.entries(acceptance.gates).map(([k,g])=>[k.replace('V0_scanner_only','Yalnız tarama').replace('V1_build_and_scanner','Derleme + tarama').replace('V2_full_acceptance','Tüm kontroller'),String(g.good_candidates),String(g.true_accepts),String(g.bad_candidates),String(g.false_accepts)]),
 ['Kontrol adayları','Elle yazıldı','LLM değil','Aynı havuz','Adil kapı kıyası'],
 ['Kötü aday','İşlev kapatma','Sabit yanıt','Davranış kaybı','Beklenen ret'],
 ['Güvenlik tanığı','Korunuyor','Değişmez','Model yazamaz','Bağımsız kabul'],
 ['Sınır','3 sentetik aile','Genel ispat yok','Kör uzman yok','Pilot gerekli'],
 ['Kanıt','evidence/','acceptance/','JSON sonuçlar','Tekrarlanabilir']
], 'Kaynak: evidence/acceptance/summary.json ve tekil sonuç dosyaları. V2 false accept=0 yalnız bu kasıtlı kontrol havuzunu ifade eder; gerçek dünya yanlış kabul oranı değildir.');
await cards('İşletim kontrolleri test edildi', 'Test sayısı, başarılı AI onarımı sayısı değildir. Her kanıt türü ayrı raporlanır.',[
 `Birim / sözleşme\n${delivery.unit.passed} test geçti. Rol, uygunluk, hash, bütçe, iptal ve geri çekme.`,
 'Java / staging\nGerçek derleme ve testler. Aynı JAR ile staging ve rollback; insan rolleri simüle.',
 'Bağımlılık kontrolü\nOSV bildirimleri üzerine güncelleme. Python kilidi tekrar tarandı.',
 'Ağ sınırı\nAyrı Linux namespace dış bağlantıyı engelledi. Bütün uygulama airgap testi değil.'
], 'Kaynak: evidence/unit-tests.xml, java-integration.xml, staging-integration.xml, dependency-audit*.json, network-namespace.json. Native çalışma profili güçlü sandbox değildir.');
await columns('Ürüne dönüşmeden önce kapanacak boşluklar',[
 'Gerçek proje kapsaması\nBugün kayıtlı sentetik depolar var. Müşteri repo adaptörü, daha geniş Java kuralları ve bağımsız holdout gerekiyor.',
 'İzolasyon ve işletim\nTam sistem egress, kötü niyetli build sandbox’ı, offline güncelleme, SSO ve asimetrik imza tamamlanmalı.',
 'Kalite ve genelleme\nKüçük modelin başarısızlıkları görünür. Daha büyük model ve uygunluk yöntemleri aynı bütçe altında karşılaştırılmalı.'
], 'docs/CALISAN_MIMARI.md ile HEDEF_MIMARI_V2.md arasındaki açıklar. Bu sürüm savunma/banka üretim ortamına hazır değildir.');
await columns('Ticari değer pilotta ölçülecek',[
 'Müşteri hipotezi\nKapalı ağda Java geliştiren ekiplerde onarım ve inceleme yükünü azaltmak. AppSec ve platform ekipleriyle doğrulanmalı.',
 'Satın alınabilir paket\nKurum içi kurulum, sınırlı repo/kural kapsamı ve yıllık destek denenebilir. Fiyat ve ödeme isteği ölçülmedi.',
 'Farklılaşma hedefi\nUygun yama kullanımı, yanlış kabulün azaltılması ve geri çekilebilir hafıza. Yalnız yerel LLM yeni değildir.'
], 'docs/ARGE_VE_TICARILESME.md. Sonar güncel AI CodeFix dokümanı yerel gateway desteğini belirtir: https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix.md . Rakiplerle lisanslı başa baş test veya müşteri görüşmesi yapılmadı.');
await timeline('Bir sonraki kanıt paketi',[
 'Ar-Ge\nAST/veri akışı önkoşulları. Proje/CVE ailesine göre ayrılmış değerlendirme. Aynı model ve bütçede ablation.',
 'Kurum pilotu\nYetkili gerçek Java projeleri. Bağımsız AppSec değerlendirmesi. Aktif mühendis süresi ve yeniden açılan bulgular.',
 'Ticari doğrulama\n8–12 keşif görüşmesi. İki ücretli pilot adayı. Lisans, kurulum, bakım maliyeti ve satın alma kararı.'
],['Teknik kanıt','Kullanım kanıtı','Satış kanıtı'],'Bunlar önerilen sonraki işlerdir, tamamlanmış çıktılar değildir. 20 geliştirme + 40 bağımsız değerlendirme vakası planlanır; mevcut varyantlar bu hedefi doldurmaz.');
o=await copy(26);
text(o.elements.find(e=>e.text==='Thank you'),'Canlı\ngösterim',66);
text(o.elements.find(e=>e.text==='Supertitle'),'SAFEPATCH V0.1',21);
text(o.elements.find(e=>e.text.includes('Lorem ipsum')),'Canlı demo: SQL düzeltme → inceleme → hafıza → tekrar test\nKod ve ham ölçümler: GitHub deposu\nSonraki karar: gerçek kurum pilotu',24);
notes(o.s,'Demo adımları: docs/SUNUM_VE_DEMO.md. Repo: https://github.com/karabulutsevket/DevSecOps_SafePatch_TUBITAKV0.1 . Gerçek kullanıcı onayı olmadan operasyon veritabanına onay eklemeyin.');
for(const s of source)s.delete();
for(let i=0;i<slides.length;i++)slides[i].moveTo(i);
await fs.writeFile(path.join(build,'presentation.json'),(await p.inspect({kind:'slide,textbox,shape,table,chart',maxChars:50000})).ndjson);
const candidate=path.join(build,'candidate.pptx');
await(await PresentationFile.exportPptx(p)).save(candidate);
const final=path.join(root,'presentation','SafePatch_V01_Sunum.pptx');
await fs.mkdir(path.dirname(final),{recursive:true});
const tableSlides=[6,8,11];
await utils.finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath:final,
 pythonExecutable:process.env.RUNTIME_PYTHON,
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-bullet-geometry','--validate-heading-fit',
  ...tableSlides.flatMap(number=>['--require-native-table-slide',String(number)])],
 requiredNativeTableOwnerSlides:tableSlides,requiredNativeChartOwnerSlides:[9],
 materializeLiteralChartWorkbooks:true,
 fontPolicy:{basis:'reference',families:[font],referencePath:process.env.TEMPLATE_PATH,referenceSha256:createHash('sha256').update(await fs.readFile(process.env.TEMPLATE_PATH)).digest('hex')},
 verifyArtifactToolImport:true,receiptPath:path.join(build,`${path.basename(final)}.validation.json`)});
const finalized=await PresentationFile.importPptx(await FileBlob.load(final));
for(let i=0;i<finalized.slides.items.length;i++){
 const s=finalized.slides.items[i];
 await fs.writeFile(path.join(build,`slide-${i+1}.png`),new Uint8Array(await(await s.export({format:'png',scale:1})).arrayBuffer()));
}
console.log(final);
