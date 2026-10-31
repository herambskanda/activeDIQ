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
const mkrun=(o={})=>({id:RUN,definitionId:"usr-03",definitionVersion:1,presetId:"recent",state:"succeeded",asOf:new Date(Date.now()-60000).toISOString(),createdAt:new Date().toISOString(),createdBy:{kind:"user",id:"u"},startedAt:new Date().toISOString(),finishedAt:new Date().toISOString(),expiresAt:null,digest:"x",freshness:{state:"synced",label:"Synced just now"},objectsChecked:5000,rowCount:1200,scopeApplied:"Domain lab.test",parameters:{columns:["name","days_since"],connectionIds:[],filters:[],includeReadOnlyDcs:false,ouExclude:[],ouInclude:[],subjects:[]},progress:{percent:100,stage:"done"},skippedConnections:[],...o});
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

// ---- 1 Library
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports");
  await p.getByRole("link",{name:"Logon activity"}).waitFor();
  await p.screenshot({path:OUT+"/lib-1280-light.png"});
  note(await p.getByRole("heading",{name:"Group members <b>bold</b>"}).count()===0 && await p.getByText("Group members <b>bold</b>").count()>0,"library renders hostile name '<b>' as text");
  note(await p.getByText("Also known as: Recently Logged on Users, Inactive Users +1 more").count()>0,"library 'Also known as' shows 2 + 'more'");
  // headings
  console.log("   headings:", await p.locator("h1,h2").allTextContents());
  // filter box
  await p.getByLabel("Filter reports").fill("inactive"); await p.waitForTimeout(700);
  note(p.url().includes("q=inactive") && await p.getByRole("link",{name:"Logon activity"}).count()===1 && await p.getByRole("link",{name:/Ünï/}).count()===0,"library filter 'inactive' (ME name) narrows via server q; URL has q");
  await p.getByLabel("Filter reports").fill("*)(cn=*"); await p.waitForTimeout(700);
  note(await p.getByText(/No report matches/).count()>0,"LDAP metachars in library filter -> no-match state, no crash");
  await p.screenshot({path:OUT+"/lib-nomatch-ldap.png"});
  await p.getByRole("button",{name:"Clear filter"}).click(); await p.waitForTimeout(500);
  note(!p.url().includes("q=") && await p.getByRole("link",{name:"Logon activity"}).count()===1,"Clear filter restores library");
  // category
  await p.getByLabel("Category").selectOption({label:"Groups"}); await p.waitForTimeout(500);
  note(p.url().includes("category=groups") && await p.getByRole("link",{name:/Group members/}).count()===1 && await p.getByRole("link",{name:"Logon activity"}).count()===0,"category select filters");
  await p.getByLabel("Filter reports").fill("zzz"); await p.waitForTimeout(700);
  note(await p.getByText("No report matches “zzz”").count()>0,"no-match title with category");
  // back button
  await p.goBack(); await p.waitForTimeout(500); 
  console.log("   after back url:",p.url(), "box=",await p.getByLabel("Filter reports").inputValue());
  // nav link click
  await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).click(); await p.waitForURL(/reports\/usr-03/);
  note(true,"library link opens report "+p.url());
  await p.close(); }
// pagination of library
{ const S={reqs:[],pageDefs:true}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.getByRole("button",{name:"Load more reports"}).click(); await p.waitForTimeout(500);
  note(await p.getByRole("link").filter({hasText:/Logon|Group/}).count()>=2,"Load more reports appends"); console.log("   ",S.reqs.filter(r=>r.includes("definitions?")||r.includes("definitions")).slice(0,4)); await p.close(); }
// empty library / error / 403 / loading
{ const S={reqs:[],noDefs:true}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.getByText("No reports are available").waitFor(); await p.screenshot({path:OUT+"/lib-empty.png"}); note(true,"empty library state"); await p.close(); }
{ const S={reqs:[],defsFail:true}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.getByRole("button",{name:"Retry"}).waitFor(); await p.screenshot({path:OUT+"/lib-error.png"}); console.log("   error text:",(await p.locator("main, body").first().innerText()).replace(/\n+/g," | ").slice(0,400));
  S.defsFail=false; await p.getByRole("button",{name:"Retry"}).click(); await p.getByRole("link",{name:"Logon activity"}).waitFor(); note(true,"library error -> Retry recovers"); await p.close(); }
{ const S={reqs:[],forbidden:true}; const p=await mk(S); await p.goto(BASE+"/reports"); await p.waitForTimeout(1000); await p.screenshot({path:OUT+"/lib-403.png"}); console.log("   403 text:",(await p.locator("body").innerText()).replace(/\n+/g," | ").slice(0,500));
  await p.keyboard.press("/"); await p.waitForTimeout(300); 
  const cb=p.getByRole("combobox",{name:"Search reports"}); if(await cb.count()){ await cb.fill("logon"); await p.waitForTimeout(800); console.log("   403 search popover:",(await p.getByRole("dialog").innerText().catch(()=>"?")).replace(/\n+/g," | ")); await p.screenshot({path:OUT+"/search-403.png"}); } else console.log("   no search box under 403");
  console.log("   Search button present under 403:", await p.getByRole("button",{name:/Search reports/}).count());
  await p.close(); }
// ---- 2 Search
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports");
  await p.getByRole("link",{name:"Logon activity"}).waitFor();
  await p.getByRole("button",{name:/Search reports/}).click(); // button path
  note(await p.evaluate(()=>document.activeElement?.getAttribute("role")==="combobox"),"Search button opens popover with focus in box");
  await p.keyboard.press("Escape"); note(await p.getByRole("combobox").count()===0,"Esc closes search");
  note(await p.evaluate(()=>document.activeElement?.textContent?.includes("Search reports")),"focus returns to trigger");
  await p.keyboard.press("/"); const cb=p.getByRole("combobox",{name:"Search reports"});
  await cb.fill("zzzz"); await p.waitForTimeout(700); await p.screenshot({path:OUT+"/search-nohit.png"});
  note(await p.getByText("Nothing matches “zzzz”").count()>0,"search no-hit message");
  await cb.fill("<script>alert(1)</script>"); await p.waitForTimeout(600); note(await p.getByText("Nothing matches").count()>0,"HTML in search is text");
  await cb.fill("*)(cn=*"); await p.waitForTimeout(600); console.log("   ldap search reqs:",S.reqs.slice(-1));
  await cb.fill("log"); await p.waitForTimeout(600); 
  console.log("   hits:",await p.getByRole("option").allTextContents());
  await p.keyboard.press("ArrowDown"); await p.keyboard.press("ArrowDown"); await p.keyboard.press("ArrowUp");
  console.log("   active:",await p.locator('[role=option][aria-selected=true]').allTextContents());
  await p.screenshot({path:OUT+"/search-hits-qa.png"});
  // click a hit with mouse
  await p.getByRole("option").nth(1).click(); await p.waitForTimeout(600); console.log("   mouse-clicked hit ->",p.url());
  // typing / inside search box doesn't re-open
  await p.keyboard.press("/"); await p.getByRole("combobox",{name:"Search reports"}).fill("a/b"); console.log("   slash typed into field:",await p.getByRole("combobox",{name:"Search reports"}).inputValue());
  await p.keyboard.press("Escape");
  // Enter on ME name with other presets
  await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).waitFor(); await p.keyboard.press("/"); await p.getByRole("combobox",{name:"Search reports"}).fill("inactive users"); await p.keyboard.press("Enter"); await p.waitForURL(/usr-03/); console.log("   enter ME 'inactive users' ->",p.url());
  await p.waitForTimeout(800); console.log("   run POSTs:",S.reqs.filter(r=>r.startsWith("POST /runs")));
  await p.close(); }
// slash key on report page & search while on report
// ---- 3 Report page
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent");
  await p.getByText("User 5",{exact:true}).waitFor(); await p.screenshot({path:OUT+"/rpt-1280.png",fullPage:true});
  console.log("   strip:",(await p.locator(".rp-strip").innerText()).replace(/\n+/g," | "));
  console.log("   caption/pager:",await p.locator(".rp-pager").innerText());
  note(await p.locator("img[src=x]").count()===0,"hostile <img> in cell not rendered as HTML");
  console.log("   first row:",await p.locator("tbody tr, [role=row]").nth(1).innerText().catch(()=>"?"));
  // presets
  await p.getByRole("radio",{name:"Inactive 90 days"}).click().catch(async()=>await p.getByText("Inactive 90 days").click()); await p.waitForTimeout(800);
  console.log("   after preset url:",p.url()); console.log("   POSTs:",S.reqs.filter(r=>r.startsWith("POST /runs")));
  console.log("   svc banner:",await p.getByText("Probable service accounts are hidden").count());
  await p.screenshot({path:OUT+"/rpt-inactive.png",fullPage:true});
  await p.getByRole("button",{name:"Show them"}).click(); await p.waitForTimeout(800);
  console.log("   after Show them url:",p.url()); console.log("   last POST:",S.reqs.filter(r=>r.startsWith("POST /runs")).slice(-1));
  await p.getByRole("button",{name:"Hide them"}).click(); await p.waitForTimeout(600);
  // period
  console.log("   period opts:",await p.getByLabel("Period").locator("option").allTextContents()); await p.getByLabel("Period").selectOption({label:"Last 7 days"}); await p.waitForTimeout(700);
  console.log("   period url:",p.url()," last POST:",S.reqs.filter(r=>r.startsWith("POST /runs")).slice(-1));
  // column chooser
  await p.getByRole("button",{name:/^Columns/}).click(); console.log("   chooser:",await p.getByRole("checkbox").allTextContents(), await p.getByRole("checkbox").count());
  await p.screenshot({path:OUT+"/rpt-columns.png"});
  await p.getByRole("checkbox",{name:"Enabled"}).check(); await p.waitForTimeout(700); console.log("   cols url:",p.url()); 
  // uncheck all but one
  for (const n of ["Name","Days since","Enabled"]) { const c=p.getByRole("checkbox",{name:n}); if(await c.isChecked() && await c.isEnabled()) await c.uncheck().catch(()=>{}); await p.waitForTimeout(300);}
  console.log("   remaining checked:",await p.getByRole("checkbox",{checked:true}).count(), "disabled:",await p.getByRole("checkbox",{checked:true}).first().isDisabled());
  await p.keyboard.press("Escape");
  // filters
  await p.getByRole("button",{name:"Filter a column"}).click(); await p.screenshot({path:OUT+"/rpt-filter-open.png"});
  await p.getByRole("button",{name:"Apply filter (new run)"}).click(); console.log("   empty apply error:",await p.getByRole("alert").allTextContents());
  await p.getByLabel("Column").selectOption({label:"Days since"});
  await p.getByLabel("Value").fill("abc"); await p.getByRole("button",{name:"Apply filter (new run)"}).click(); console.log("   int bad:",await p.getByText("Enter a whole number.").count());
  await p.getByLabel("Value").fill("30"); await p.getByRole("button",{name:"Apply filter (new run)"}).click(); await p.waitForTimeout(800);
  console.log("   filter url:",p.url()); console.log("   last POST:",S.reqs.filter(r=>r.startsWith("POST /runs")).slice(-1));
  console.log("   applied chips:",await p.getByRole("list",{name:"Filters applied"}).innerText());
  // text filter with hostile
  await p.getByRole("button",{name:"Filter a column"}).click(); await p.getByLabel("Column").selectOption({label:"Name"}); await p.getByLabel("Value").fill("*)(cn=*<script>"); await p.getByRole("button",{name:"Apply filter (new run)"}).click(); await p.waitForTimeout(800);
  console.log("   hostile filter url:",p.url()); console.log("   last POST:",S.reqs.filter(r=>r.startsWith("POST /runs")).slice(-1));
  await p.screenshot({path:OUT+"/rpt-filters-applied.png"});
  // remove chip
  await p.getByRole("list",{name:"Filters applied"}).getByRole("button").first().click(); await p.waitForTimeout(800); console.log("   after chip remove url:",p.url());
  // enum/boolean filter
  await p.getByRole("button",{name:"Filter a column"}).click(); await p.getByLabel("Column").selectOption({label:"Kind"}); console.log("   enum opts:",await p.getByLabel("Value").locator("option").allTextContents()); await p.keyboard.press("Escape");
  await p.close(); }
// sort
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  const hdr=p.getByRole("columnheader",{name:/Days since/});
  await hdr.click(); await p.waitForTimeout(600); console.log("   sort1 url:",p.url(), await hdr.getAttribute("aria-sort"));
  await hdr.click(); await p.waitForTimeout(600); console.log("   sort2 url:",p.url(), await hdr.getAttribute("aria-sort"));
  await hdr.click(); await p.waitForTimeout(600); console.log("   sort3 url:",p.url(), await hdr.getAttribute("aria-sort"));
  console.log("   rows reqs:",S.reqs.filter(r=>r.includes("/rows")).slice(-4)); console.log("   POST count:",S.reqs.filter(r=>r.startsWith("POST /runs")).length);
  // keyboard sort
  await hdr.focus().catch(()=>{}); await p.keyboard.press("Enter"); await p.waitForTimeout(500); console.log("   kbd sort url:",p.url());
  // load more rows
  await p.getByRole("button",{name:"Load more rows"}).click(); await p.waitForTimeout(600); console.log("   pager:",await p.locator(".rp-pager").innerText());
  await p.close(); }
// states: running -> cancel
{ const S={reqs:[],running:true,polls:0,runOver:{state:"running",rowCount:null,progress:{percent:40,stage:"reading_directory"}}}; 
  S.runOver={state:"queued",rowCount:null,progress:{percent:0,stage:"queued"}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByRole("button",{name:"Cancel run"}).waitFor(); await p.screenshot({path:OUT+"/rpt-running.png"});
  await p.getByRole("button",{name:"Cancel run"}).click(); await p.getByText("Run cancelled").waitFor(); await p.screenshot({path:OUT+"/rpt-cancelled.png"});
  S.runOver={}; S.running=false; await p.getByRole("button",{name:"Run again"}).click(); await p.getByText("User 5",{exact:true}).waitFor(); note(true,"Cancel run -> cancelled -> Run again -> rows");
  await p.close(); }
// run start fail, rows fail
{ const S={reqs:[],runFail:true}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByRole("button",{name:/Retry/}).waitFor(); await p.screenshot({path:OUT+"/rpt-runstart-fail.png"}); console.log("   runstart fail text:",(await p.locator("main").innerText()).replace(/\n+/g," | ").slice(0,300));
  S.runFail=false; await p.getByRole("button",{name:/Retry/}).click(); await p.getByText("User 5",{exact:true}).waitFor(); note(true,"run-start failure Retry recovers"); await p.close(); }
{ const S={reqs:[],rowsFail:true}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByRole("button",{name:/Retry/}).waitFor(); await p.screenshot({path:OUT+"/rpt-rows-fail.png"}); S.rowsFail=false; await p.getByRole("button",{name:/Retry/}).click(); await p.getByText("User 5",{exact:true}).waitFor(); note(true,"rows failure Retry recovers"); await p.close(); }
// definition 404 / subject report / perDc
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports/nope"); await p.waitForTimeout(1000); console.log("   404 text:",(await p.locator("main").innerText()).replace(/\n+/g," | ").slice(0,300)); await p.screenshot({path:OUT+"/rpt-404.png"});
  await p.goto(BASE+"/reports/grp-02"); await p.waitForTimeout(1000); console.log("   subject text:",(await p.locator("main").innerText()).replace(/\n+/g," | ").slice(0,400)); console.log("   POSTs for subject:",S.reqs.filter(r=>r.startsWith("POST /runs")).length); await p.screenshot({path:OUT+"/rpt-subject.png"});
  await p.goto(BASE+"/reports/cmp-01"); await p.waitForTimeout(1000); await p.screenshot({path:OUT+"/rpt-longname.png"}); await p.close(); }
// stale w/ coverage, skipped, copy request, empty
{ const S={reqs:[],runOver:{freshness:{state:"stale",label:"Stale: last sync 3 h ago"},asOf:new Date(Date.now()-3*3600e3).toISOString(),coverage:{dcsAnswered:5,dcsInScope:6,complete:false},skippedConnections:[{connectionId:"c1",reason:"never_synced"}]}};
  const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor(); await p.screenshot({path:OUT+"/rpt-stale-cov-skipped.png",fullPage:true}); console.log("   banners:",(await p.getByRole("region").allInnerTexts?.call?.(p.getByRole("region"))||[]).length); console.log("   main text:",(await p.locator("main").innerText()).replace(/\n+/g," | ").slice(0,900)); await p.close(); }
{ const S={reqs:[],runOver:{rowCount:0,emptyReason:"scope_grants_nothing"}}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("Your role covers no directory objects").waitFor();
  await p.getByRole("button",{name:/Copy a request/}).click(); await p.waitForTimeout(400); console.log("   copied status:",await p.getByRole("status").allInnerTexts()); console.log("   clipboard:",await p.evaluate(()=>navigator.clipboard.readText())); await p.screenshot({path:OUT+"/rpt-empty-scope.png"}); await p.close(); }
{ const S={reqs:[],runOver:{rowCount:0}}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=inactive&f=name:contains:zz"); await p.getByText("No rows match").waitFor(); await p.getByRole("button",{name:/Remove the filter/}).click(); await p.waitForTimeout(600); console.log("   after remove filter url:",p.url()); await p.screenshot({path:OUT+"/rpt-nomatch.png"}); await p.close(); }
// expired / failed text
{ const S={reqs:[],runOver:{state:"expired",rowCount:null}}; const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("This result has expired").waitFor(); console.log("   expired:",(await p.locator("main").innerText()).replace(/\n+/g," | ").slice(0,500)); await p.close(); }
// dark + narrow + keyboard tab order
{ const S=S0(); const p=await mk(S,{w:1280,h:800,dark:true}); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor(); await p.screenshot({path:OUT+"/rpt-dark.png"}); await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).waitFor(); await p.screenshot({path:OUT+"/lib-dark.png"}); await p.close(); }
{ const S=S0(); const p=await mk(S,{w:480,h:800}); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor(); await p.screenshot({path:OUT+"/rpt-narrow.png",fullPage:true});
  console.log("   narrow horizontal overflow:",await p.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth)); await p.goto(BASE+"/reports"); await p.getByRole("link",{name:"Logon activity"}).waitFor(); await p.screenshot({path:OUT+"/lib-narrow.png"}); console.log("   lib narrow overflow:",await p.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth)); await p.close(); }
{ const S=S0(); const p=await mk(S); await p.goto(BASE+"/reports/usr-03?preset=recent"); await p.getByText("User 5",{exact:true}).waitFor();
  const seq=[]; for(let i=0;i<22;i++){ await p.keyboard.press("Tab"); seq.push(await p.evaluate(()=>{const e=document.activeElement; const cs=getComputedStyle(e); return (e.getAttribute("aria-label")||e.textContent||e.tagName).trim().slice(0,30)+" ["+e.tagName+"] outline="+cs.outlineStyle+" "+cs.outlineWidth;})); }
  console.log("   tab order:\n     "+seq.join("\n     ")); await p.close(); }
await browser.close();
console.log("\nFINDINGS:",findings);
