import { chromium } from "/home/khushi/AD/.activeDIQ-worktrees/T-0966/web/node_modules/playwright-core/index.mjs";
const OUT = "/home/khushi/AD/.activeDIQ-worktrees/T-0966/factory/demos/evidence/T-0966/qa";
const BASE = "http://127.0.0.1:4180";
const col = (id,label,type="text",extra={}) => ({id,label,type,sortable:true,filterable:true,defaultVisible:true,choices:[],filterOperators:type==="text"?["equals","contains","starts_with"]:type==="integer"?["equals","greater_than"]:type==="boolean"?["equals"]:["equals"],...extra});
const defs = [
 {id:"usr-03",version:1,name:"Logon activity",description:"Who logged on, and when",category:"users",dataset:"inventory.users",freshnessKind:"synced",alsoKnownAs:[{meName:"Recently Logged on Users",presetId:"recent"},{meName:"Inactive Users",presetId:"inactive"},{meName:"Third name",presetId:"recent"}],
  columns:[col("name","Name"),col("days_since","Days since","integer"),col("enabled","Enabled","boolean"),col("kind","Kind","enum",{choices:[{id:"a",label:"Alpha"},{id:"b",label:"Beta"}],filterOperators:["equals"]}),col("probable_service_account","Service account","boolean")],
  exportFormats:["csv"],minScheduleIntervalHours:1,perDc:false,subjectKind:"none",
  presets:[{id:"inactive",name:"Inactive 90 days",meName:"Inactive Users",periodDays:90,columns:["name","days_since"],filters:[{kind:"ReportFilterConditionView",column:"probable_service_account",operator:"equals",values:[{kind:"ReportValueBoolean",value:false}]}]},{id:"recent",name:"Recently logged on",meName:"Recently Logged on Users",periodDays:30,columns:["name"],filters:[]}]},
 {id:"grp-02",version:1,name:"Group members <b>bold</b>",description:"Members of a group",category:"groups",dataset:"inventory.groups",freshnessKind:"synced",alsoKnownAs:[],columns:[col("name","Name")],exportFormats:[],minScheduleIntervalHours:1,perDc:false,subjectKind:"group",presets:[{id:"p",name:"All",meName:null,periodDays:null,columns:["name"],filters:[]}]},
 {id:"cmp-01",version:1,name:"Ünïcödé 日本語 レポート very long name that goes on and on and on and on and on and on and on and on",description:"computers",category:"computers",dataset:"inventory.computers",freshnessKind:"synced",alsoKnownAs:[],columns:[col("name","Name")],exportFormats:[],minScheduleIntervalHours:1,perDc:true,subjectKind:"none",presets:[{id:"p",name:"All",meName:null,periodDays:null,columns:["name"],filters:[]}]},
];
const RUN="22222222-2222-4222-8222-222222222222";
const mkrun=(o={})=>({id:RUN,definitionId:"usr-03",definitionVersion:1,presetId:"recent",state:"succeeded",asOf:new Date(Date.now()-60000).toISOString(),createdAt:new Date().toISOString(),createdBy:{kind:"user",id:"u"},startedAt:new Date().toISOString(),finishedAt:new Date().toISOString(),expiresAt:null,digest:"x",freshness:{state:"synced",label:"Synced just now"},objectsChecked:5000,rowCount:1200,scopeApplied:"Domain lab.test",parameters:{columns:["name","days_since"],connectionIds:[],filters:[],includeReadOnlyDcs:false,ouExclude:[],ouInclude:[],subjects:[]},progress:{percent:100,stage:"done"},skippedConnections:[],hiddenGroups:[],...o});
const problem=(s,t)=>({status:s,contentType:"application/problem+json",body:JSON.stringify({type:"about:blank",title:t,status:s,traceId:"trace-qa"})});
const log=[]; const findings=[];
const note=(ok,msg)=>{ (ok?log:findings).push((ok?"OK   ":"FAIL ")+msg); console.log((ok?"OK   ":"FAIL ")+msg); };
const browser = await chromium.launch();
async function mk(S, {w=1280,h=800,dark=false}={}) {
  const ctx = await browser.newContext({viewport:{width:w,height:h},colorScheme:dark?"dark":"light"});
  await ctx.grantPermissions(["clipboard-read","clipboard-write"],{origin:BASE});
  const page = await ctx.newPage();
  page.on("pageerror",e=>note(false,"pageerror "+e.message));
  page.on("console",m=>{ if(m.type()==="error") console.log("   console.error:",m.text().slice(0,200)); });
  await page.route("**/api/v1/auth/csrf",r=>r.fulfill({json:{header:"X-CSRF-Token",value:"c"}}));
  await page.route(/\/api\/v1\/reports\//, async route=>{
    const req=route.request(), url=new URL(req.url()), path=url.pathname.replace("/api/v1/reports","");
    S.reqs.push(req.method()+" "+path+url.search+(req.postData()?" "+req.postData():""));
    if(S.forbidden) return route.fulfill(problem(403,"Forbidden"));
    if(S.defsFail && path==="/definitions") return route.fulfill(problem(500,"Server exploded"));
    if(path==="/definitions"){
      const q=(url.searchParams.get("q")||"").toLowerCase(), cat=url.searchParams.get("category")||"";
      let items=defs.filter(d=>(!q||(d.name+d.description+d.alsoKnownAs.map(a=>a.meName).join(" ")).toLowerCase().includes(q))&&(!cat||d.category===cat));
      if(S.noDefs) items=[];
      let next=null; const cur=Number(url.searchParams.get("cursor")||0);
      if(S.pageDefs){ const all=items; items=all.slice(cur,cur+1); next=cur+1<all.length?String(cur+1):null; }
      return route.fulfill({json:{items,page:{nextCursor:next}}});
    }
    const m=path.match(/^\/definitions\/(.+)$/); if(m){ const d=defs.find(d=>d.id===m[1]); return d?route.fulfill({json:d}):route.fulfill(problem(404,"Not found")); }
    if(path==="/runs"&&req.method()==="POST"){ if(S.gate) await S.gate; if(S.runFail) return route.fulfill(problem(500,"Run start failed")); S.polls=0; const b=JSON.parse(req.postData()); return route.fulfill({status:202,json:mkrun({...(S.runOver||{}),presetId:b.presetId??"recent",definitionId:b.definitionId, parameters:{...mkrun().parameters,columns:b.parameters?.columns??["name","days_since"],filters:b.parameters?.filters??(b.presetId==="inactive"?defs[0].presets[0].filters:[])}})}); }
    if(path.endsWith("/cancel")) return route.fulfill({json:mkrun({state:"cancelled",rowCount:null})});
    if(path.endsWith("/retry")) return route.fulfill({status:202,json:mkrun()});
    if(path.endsWith("/rows")){
      if(S.rowsFail) return route.fulfill(problem(500,"Rows failed"));
      const start=Number(url.searchParams.get("cursor")||0), total=S.total??1200, sb=url.searchParams.get("sortBy"), ord=url.searchParams.get("order");
      const n=Math.max(0,Math.min(500,total-start));
      return route.fulfill({json:{runId:RUN,rowCount:total,page:{nextCursor:start+n<total?String(start+n):null},columns:defs[0].columns.slice(0,2),rows:Array.from({length:n},(_,i)=>{const k=start+i; const idx=ord==="desc"?total-1-k:k; return {rowKey:"r"+k,cells:[{kind:"ReportCellText",value:(k===0?"<img src=x onerror=alert(1)> *)(cn=*":"User ")+(k===0?"":idx)},{kind:"ReportCellInteger",value:String(idx)}]};})}});
    }
    if(path.match(/^\/runs\/[^/]+$/)){ if(S.running && ++S.polls<3) return route.fulfill({json:mkrun({state:"running",rowCount:null,progress:{percent:40,stage:"reading_directory"}})}); return route.fulfill({json:mkrun(S.runOver||{})}); }
    return route.fulfill(problem(404,"nf"));
  });
  return page;
}
const S0=()=>({reqs:[]});
const old=0;
const src=(o={})=>({connectionId:"11111111-1111-4111-8111-111111111111",namingContextId:"33333333-3333-4333-8333-333333333333",connectionName:"Lab DC1",cause:"older_than_threshold",ageSeconds:10800,lastPassAt:new Date(Date.now()-3*3600e3).toISOString(),...o});
const txt=async p=>(await p.locator("main").innerText()).replace(/\n+/g," | ");
// A. Stale with 2 sources + hidden groups
{ const S={reqs:[],runOver:{freshness:{state:"stale",label:"Stale: last sync 3 h ago",thresholdSeconds:7200,stale:[src(),src({connectionId:"44444444-4444-4444-8444-444444444444",connectionName:"Paris RODC",cause:"resync_required",ageSeconds:90000,lastPassAt:new Date(Date.now()-25*3600e3).toISOString()})]},asOf:new Date(Date.now()-3*3600e3).toISOString(),hiddenGroups:[{id:"svc",label:"probable service accounts",count:13,locked:false}],coverage:{dcsAnswered:5,dcsInScope:6,complete:false},skippedConnections:[{connectionId:"c1",reason:"never_synced"}]}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=inactive"); await p.getByText("User 5",{exact:true}).waitFor();
  const t=await txt(p); console.log("A main:",t.slice(0,1500));
  await p.screenshot({path:OUT+"/rereqa-stale-hidden.png",fullPage:true});
  note(/Lab DC1/.test(t)&&/Paris RODC/.test(t),"A stale banner names both connections");
  note(/older|threshold|2 h|2h/i.test(t),"A cause 1 (older than threshold) visible");
  note(/resync|re-sync/i.test(t),"A cause 2 (resync required) visible");
  note(/13/.test(t)&&/service account/i.test(t),"A hidden count 13 visible");
  await p.getByRole("button",{name:"Show",exact:true}).click().catch(e=>note(false,"no Show button"));
  await p.waitForTimeout(800); console.log("   url after Show:",p.url(),"last POST:",S.reqs.filter(r=>r.startsWith("POST /runs")).slice(-1));
  await p.close(); }
// B. locked group, paused cause, none hidden
{ const S={reqs:[],runOver:{freshness:{state:"stale",label:"Stale: paused",thresholdSeconds:null,stale:[src({cause:"paused",connectionName:"<i>Hostile</i> ü日本"})]},hiddenGroups:[{id:"svc",label:"probable service accounts",count:4,locked:true}]}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  const t=await txt(p); console.log("B main:",t.slice(0,900));
  note(/paused/i.test(t),"B paused cause"); note(/<i>Hostile<\/i>/.test(t)&&await p.locator("main i").count()===0,"B hostile connection name as text");
  note(await p.getByRole("button",{name:/^Show/}).count()===0,"B locked group has no Show");
  await p.screenshot({path:OUT+"/rereqa-stale-locked.png",fullPage:true}); await p.close(); }
{ const S={reqs:[],runOver:{hiddenGroups:[]}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  const t=await txt(p); note(!/hidden/i.test(t),"C no hidden banner when none hidden"); await p.close(); }
// D. stale but empty stale[] -> label fallback
{ const S={reqs:[],runOver:{freshness:{state:"stale",label:"Stale: last sync 3 h ago",thresholdSeconds:null,stale:[]}}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  console.log("D:",(await txt(p)).slice(0,500)); await p.close(); }
// E. 403 controls
{ const S={reqs:[],forbidden:true}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.getByText("You don't have access to reports").waitFor();
  note(await p.getByLabel("Filter reports").count()===0&&await p.getByLabel("Category").count()===0,"E 403: no filter/category controls");
  console.log("   buttons:",await p.getByRole("button").allInnerTexts()); await p.screenshot({path:OUT+"/rereqa-403.png"}); await p.close(); }
// F. AC1 counter again
{ const S={reqs:[]}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).waitFor();
  let n=0; await p.keyboard.press("/"); n++; await p.getByRole("combobox",{name:"Search reports"}).fill("inactive users"); await p.waitForTimeout(700);
  await p.keyboard.press("Enter"); n++; await p.getByText("User 5",{exact:true}).waitFor();
  console.log("   F url",p.url(),"interactions(/ + type + Enter)=3; POSTs",S.reqs.filter(r=>r.startsWith("POST /runs"))); 
  note(p.url().includes("preset=inactive")&&S.reqs.filter(r=>r.startsWith("POST /runs")).length===1,"F AC1 ME name -> preset + 1 run"); await p.close(); }
// G. 100k + sort + axe-less checks
{ const S={reqs:[],total:100000,runOver:{rowCount:100000,objectsChecked:120000,freshness:{state:"stale",label:"Stale: x",thresholdSeconds:7200,stale:[src()]}}}; const p=await mk(S,{dark:true}); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  console.log("G pager:",await p.locator(".rp-pager").innerText()); await p.screenshot({path:OUT+"/rereqa-100k-dark.png",fullPage:true});
  await p.getByRole("columnheader",{name:/Name/}).getByRole("button").first().click().catch(()=>console.log("   sort btn n/a")); await p.waitForTimeout(600);
  console.log("   rows reqs:",S.reqs.filter(r=>r.includes("/rows")).slice(-2)); await p.close(); }
await browser.close();
console.log("FAILS:",findings);
