let key='', me=null, selected=null;
const $=id=>document.getElementById(id);
const labels={queued:'Sırada',scanning:'Başlangıç taraması',patching:'Yerel AI düzeltmesi',verifying:'Worker2 doğrulaması',awaiting_review:'İnsan incelemesine hazır',approved:'İnsan onayı verildi',deployed:'Staging çalışıyor',needs_human:'İnsan müdahalesi gerekli',infrastructure_error:'Altyapı hatası',rejected:'Reddedildi',cancelled:'İptal edildi',expired:'Onay süresi doldu',deploying:'Staging başlatılıyor'};
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'Authorization':'Bearer '+key,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error(await r.text());return r.json()}
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}
function act(text,fn,enabled=true){const b=el('button',text);b.disabled=!enabled;b.onclick=()=>guard(fn);return b}
async function guard(fn){try{$('message').textContent='';await fn()}catch(e){$('message').textContent=e.message}}
$('login').onclick=()=>guard(async()=>{key=$('token').value;me=await api('/v1/me');$('token').value='';$('identity').textContent=me.subject+' · '+me.roles.join(', ');$('workspace').hidden=false;$('create').disabled=!me.roles.includes('submit');const cases=await api('/v1/cases');$('case').replaceChildren(...Object.keys(cases).map(k=>{const o=el('option',k+' · '+cases[k].split);o.value=k;return o}));await refresh()});
$('refresh').onclick=()=>guard(refresh);
$('create').onclick=()=>guard(async()=>{const j=await api('/v1/jobs','POST',{case_id:$('case').value,scanner:$('scanner').value,idempotency_key:crypto.randomUUID()});selected=j.id;await refresh()});
async function refresh(){await refreshMemory();const jobs=await api('/v1/jobs');$('jobs').replaceChildren(...jobs.map(j=>{const b=el('button',j.case_id,j.id===selected?'active':'');b.append(el('small',labels[j.status]||j.status));b.onclick=()=>guard(async()=>{selected=j.id;await refresh()});return b}));if(selected){const j=jobs.find(j=>j.id===selected);if(j)render(j)}}
function render(j){const d=$('detail');d.replaceChildren(el('h2',j.case_id+' · '+(labels[j.status]||j.status)));d.append(el('span',j.mode,j.mode==='mock-test'?'badge mock':'badge'),el('span',j.scanner,'badge'));const m=el('div',undefined,'metrics');for(const [a,b] of [[j.attempt_count+' / '+j.max_attempts,'Düzeltme denemesi'],[j.duration_seconds?Math.round(j.duration_seconds)+' sn':'—','Tamamlanan süre'],[j.approval?j.approval.reviewer:'Bekleniyor','İnsan kararı']]){const c=el('div');c.append(el('b',a),el('small',b));m.append(c)}d.append(m,el('p','İş: '+j.id,'hash'),el('p','Başlangıç commit: '+j.base_commit,'hash'));if(j.reason)d.append(el('p',j.reason));if(j.candidate){d.append(el('p','Doğrulanmış commit: '+j.candidate.commit,'hash'),el('p','Artifact SHA-256: '+j.candidate.artifact_sha256,'hash'),el('h3','İncelenecek değişiklik'),el('pre',j.candidate.diff))}for(const [title,data] of [['Başlangıç taraması ve beklenen başarısız güvenlik testi',j.baseline],['Hafıza eşleştirmesi',j.memory_lookup],['Denemeler, testler ve yeniden tarama',j.attempts],['İkinci modelin yardımcı yorumu',j.advisory]]){if(!data)continue;const det=el('details');det.append(el('summary',title),el('pre',JSON.stringify(data,null,2)));d.append(det)}const actions=el('div',undefined,'actions');if(j.candidate){for(const [text,decision]of[['İnceledim, onayla','approve'],['Reddet','reject']])actions.append(act(text,async()=>{if(!confirm(j.id+' işinin '+j.candidate.artifact_sha256+' artifact’i için '+text+'?'))return;await api('/v1/jobs/'+j.id+'/approval','POST',{candidate_commit:j.candidate.commit,artifact_sha256:j.candidate.artifact_sha256,policy_version:j.candidate.policy_version,decision});await refresh()},me.roles.includes('review')&&j.status==='awaiting_review'));actions.append(act('Onaylı artifact’i staging’e dağıt',async()=>{await api('/v1/jobs/'+j.id+'/deploy','POST');await refresh()},me.roles.includes('deploy')&&j.status==='approved'))}if(j.candidate)actions.append(act('Onaylı düzeltmeyi hafızaya al',async()=>{await api('/v1/memory/promote','POST',{job_id:j.id,reason:'İncelenen düzeltme kurum hafızasına alındı'});await refresh()},me.roles.includes('review')&&['approved','deployed'].includes(j.status)));actions.append(act('JSON kanıtını indir',async()=>{const data=await api('/v1/jobs/'+j.id+'/evidence.json');const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download=j.id+'.json';a.click();URL.revokeObjectURL(url)}));d.append(actions)}
setInterval(()=>{if(me)guard(refresh)},5000);

async function refreshMemory(){
  $('memory-panel').hidden=false;$('measurements-panel').hidden=false;
  const records=await api('/v1/memory');
  $('memories').replaceChildren(...records.map(r=>{
    const row=el('div',undefined,'memory-row');
    row.append(el('b',r.context.rule_id+' · '+r.state),el('p',r.context.project+' · v'+r.version+' · '+r.uses.length+' kullanım'),el('p',r.id,'hash'));
    if(me.roles.includes('review')&&r.state!=='revoked'){
      const reason=el('input');reason.placeholder='Karantina / geri çekme gerekçesi';reason.maxLength=1000;
      row.append(reason);
      for(const [title,state] of [['Karantinaya al','quarantined'],['Geri çek','revoked']])row.append(act(title,async()=>{await api('/v1/memory/'+r.id+'/state','POST',{state,reason:reason.value});await refresh()}));
    }return row;
  }));
  if(!records.length)$('memories').append(el('p','Henüz onaylanıp hafızaya alınmış düzeltme yok.'));
  const data=await api('/v1/measurements');
  $('measurements').replaceChildren();
  for(const [name,value] of Object.entries(data)){
    const detail=el('details');detail.append(el('summary',name),el('pre',JSON.stringify(value,null,2)));$('measurements').append(detail);
  }
}
