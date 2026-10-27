// Local application UI test. Tokens are read locally and are never logged.
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=path.resolve(import.meta.dirname,'..');
// Same rule as safepatch.common.evidence: the V0.1 archive is read-only.
const out=path.resolve(root,process.env.EVIDENCE_DIR||'evidence/v02-local');
const rel=path.relative(path.join(root,'evidence'),out);
if(!rel.startsWith('..')&&!path.isAbsolute(rel)&&!rel.split(path.sep)[0].startsWith('v02-'))throw new Error('V0.1 evidence is read-only; set EVIDENCE_DIR to evidence/v02-<name>');
await fs.mkdir(out,{recursive:true});
const {chromium}=await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
const browser=await chromium.launch({headless:true,channel:'msedge'});
const page=await browser.newPage({viewport:{width:1440,height:1100}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
const url=process.env.SAFEPATCH_UI_URL||'http://127.0.0.1:8100';
await page.goto(url);
await page.locator('#token').fill((await fs.readFile(path.join(root,'.secrets/developer.token'),'utf8')).trim());
await page.getByRole('button',{name:'Oturumu aç',exact:true}).click();
await page.locator('#workspace').waitFor({state:'visible'});
await page.locator('#memory-panel').waitFor({state:'visible'});
await page.locator('#measurements-panel').waitFor({state:'visible'});
await page.waitForFunction(()=>document.querySelector('#identity')?.textContent.includes('local-developer'));
const result={passed:errors.length===0,js_errors:errors,case_count:await page.locator('#case option').count(),
 token_cleared:await page.locator('#token').inputValue()==='',
 storage:await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length})),
 memory_visible:await page.locator('#memory-panel').isVisible(),
 measurements_visible:await page.locator('#measurements-panel').isVisible(),
 scope:'Real local browser, authenticated UI; no repair or approval clicked'};
if(!result.token_cleared||result.storage.local||result.storage.session||result.case_count!==9)result.passed=false;
await page.screenshot({path:path.join(out,'ui-desktop.png'),fullPage:true});
await page.setViewportSize({width:390,height:844});
await page.screenshot({path:path.join(out,'ui-mobile.png'),fullPage:true});
await browser.close();
await fs.writeFile(path.join(out,'ui-check.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify(result));
if(!result.passed)process.exitCode=1;
