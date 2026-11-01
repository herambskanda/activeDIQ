import AxeBuilder from "/home/khushi/AD/.activeDIQ-worktrees/T-0966/web/node_modules/@axe-core/playwright/dist/index.mjs";
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
const mkrun=(o={})=>({id:RUN,definitionId:"usr-03",definitionVersion:1,presetId:"recent",state:"succeeded",asOf:new Date(Date.now()-60000).toISOString(),createdAt:new Date().toISOString(),createdBy:{kind:"user",id:"u"},startedAt:new Date().toISOString(),finishedAt:new Date().toISOString(),expiresAt:null,digest:"x",freshness:{state:"synced",label:"Synced just now",stale:[],thresholdSeconds:null},objectsChecked:5000,rowCount:1200,scopeApplied:"Domain lab.test",parameters:{columns:["name","days_since"],connectionIds:[],filters:[],includeReadOnlyDcs:false,ouExclude:[],ouInclude:[],subjects:[]},progress:{percent:100,stage:"done"},skippedConnections:[],hiddenGroups:[],...o});
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


const axe=async(p,name)=>{const {violations}=await new AxeBuilder({page:p}).withTags(["wcag2a","wcag2aa","wcag21aa","wcag22aa"]).analyze(); console.log("AXE",name,violations.map(v=>v.impact+":"+v.id+" x"+v.nodes.length));};
for (const dark of [false,true]) {
 const S={reqs:[],total:100000,runOver:{rowCount:100000,objectsChecked:150000,freshness:{state:"stale",label:"Stale: x",thresholdSeconds:7200,stale:[{connectionId:"11111111-1111-4111-8111-111111111111",namingContextId:"33333333-3333-4333-8333-333333333333",connectionName:"Lab DC1",cause:"older_than_threshold",ageSeconds:10800,lastPassAt:new Date().toISOString()}]},coverage:{dcsAnswered:5,dcsInScope:6,complete:false},skippedConnections:[{connectionId:"c1",reason:"never_synced"}]}};
 const p=await mk(S,{dark}); await p.goto(BASE+"/reports/usr-03?preset=inactive"); await p.getByText("User 5",{exact:true}).waitFor();
 console.log("dark",dark,"DOM rows:",await p.locator("tbody tr, [role=row]").count(), "pager:",await p.locator(".rp-pager").innerText());
 await p.screenshot({path:OUT+`/rpt-100k-${dark?"dark":"light"}.png`}); await axe(p,"100k stale dark="+dark);
 // scroll grid to bottom
 await p.evaluate(()=>{const g=document.querySelector("[role=grid],table")?.closest("div"); document.querySelectorAll("div").forEach(d=>{if(d.scrollHeight>d.clientHeight+50&&getComputedStyle(d).overflowY!=="visible")d.scrollTop=d.scrollHeight;});});
 await p.waitForTimeout(400); console.log("  after scroll DOM rows:",await p.locator("tbody tr, [role=row]").count());
 await p.screenshot({path:OUT+`/rpt-100k-scrolled-${dark?"dark":"light"}.png`}); console.log("  body text sample:",(await p.locator("tbody, [role=rowgroup]").last().innerText().catch(()=>"?")).replace(/\s+/g," ").slice(0,200));
 for(let i=0;i<3;i++){ await p.getByRole("button",{name:"Load more rows"}).click(); await p.waitForTimeout(500);} console.log("  pager after 3 loads:",await p.locator(".rp-pager").innerText());
 await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).waitFor(); await axe(p,"library dark="+dark);
 await p.close();
}
{ const S={reqs:[],runOver:{state:"running",rowCount:null,progress:{percent:40,stage:"reading_directory"}}}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByRole("button",{name:"Cancel run"}).waitFor(); await axe(p,"running"); await p.close(); }
{ const S={reqs:[],runOver:{rowCount:0,emptyReason:"unsupported_scope_kind"}}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("Reports can’t use").waitFor(); console.log((await p.locator("main").innerText()).replace(/\n+/g," | ").slice(-420)); await p.screenshot({path:OUT+"/rpt-unsupported-scope.png"}); await axe(p,"unsupported"); await p.close(); }
{ const S={reqs:[]}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor(); await p.getByRole("button",{name:/^Columns/}).click(); await axe(p,"columns open"); await p.keyboard.press("Escape"); await p.getByRole("button",{name:"Filter a column"}).click(); await axe(p,"filter open"); await p.close(); }
await browser.close();
