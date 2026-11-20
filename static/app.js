"use strict";
const app=document.querySelector("#app"), modal=document.querySelector("#modal"),
  modalTitle=document.querySelector("#modalTitle"),modalBody=document.querySelector("#modalBody");
let state={page:location.pathname==="/manageCenter"?"admin":location.pathname==="/logs"?"logs":"files",path:"",q:"",pageNo:1,pageSize:20,sort:"name",order:"asc",selected:new Set(),uploadMessage:"",logFilter:{username:"",action:"",result:"",start:"",end:""},sideCollapsed:localStorage.getItem("httpserver.side")==="1"};
let user=null, pending=0, lastRetry=null;
const token=()=>sessionStorage.getItem("httpserver.token")||"";
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt=n=>n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":n<1073741824?(n/1048576).toFixed(1)+" MB":(n/1073741824).toFixed(1)+" GB";
const button=(text,action,data="",kind="secondary")=>`<button type="button" class="btn ${kind}" data-action="${action}" data-value="${esc(data)}">${esc(text)}</button>`;
function notice(message,error=false){const n=document.querySelector("#notice");n.className="notice";n.textContent=message;n.style.background=error?"#991b1b":"#172033";clearTimeout(n.timer);n.timer=setTimeout(()=>{n.className="";n.textContent=""},6000)}
function forget(){sessionStorage.removeItem("httpserver.token");user=null}
async function api(url,opt={},retry=true){
  pending++;document.body.setAttribute("aria-busy","true");
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),url.startsWith("/api/downloads/prepare")?135000:35000);
  try{
    const response=await fetch(url,{...opt,signal:controller.signal,headers:{...(opt.headers||{}),Authorization:"Bearer "+token()}});
    if(response.status===401){if(!url.endsWith("/login")){forget();login()}throw Error("账号或密码错误，或登录已过期")}
    if(response.headers.get("X-Password-Change-Required")==="1"){passwordPage(true);throw Error("请先修改密码")}
    if(!response.ok){const d=await response.json().catch(()=>({}));throw Error(d.detail||"请求失败 ("+response.status+")")}
    if(opt.blob)return response.blob();
    return response.json();
  }catch(error){
    if((error.name==="TypeError"||error.name==="AbortError")&&retry&&(!opt.method||opt.method==="GET")){
      await new Promise(r=>setTimeout(r,400));return api(url,opt,false);
    }
    if(error.name==="AbortError")throw Error("请求超时，请重试。服务可能正在处理大目录");
    if(error.name==="TypeError")throw Error("网络连接失败，请检查服务和网络后重试");
    throw error;
  }finally{clearTimeout(timer);if(--pending===0)document.body.setAttribute("aria-busy","false")}
}
function login(){
  app.innerHTML=`<div class="login"><form class="loginbox" id="loginForm"><h1>HttpServer</h1><p>局域网文件共享系统</p><label>用户名<input name="username" class="input" required maxlength="64" autocomplete="username"></label><label>密码<input name="password" class="input" type="password" required autocomplete="current-password"></label><button class="btn" type="submit">登录</button><p id="formError" class="error" role="alert"></p></form></div>`;
}
function passwordPage(required=false){
  app.innerHTML=`<div class="login logindark"><form class="loginbox" id="passwordForm"><button type="button" class="pwclose" data-action="closePassword" aria-label="关闭">✕ 关闭</button><h1>修改密码</h1><p>${required?"当前账号须先修改密码才能继续。":"修改后所有已登录设备均需重新登录。"}</p><label>当前密码<input name="current" class="input" type="password" required autocomplete="current-password"></label><label>新密码（至少12个字符）<input name="password" class="input" type="password" required minlength="12" autocomplete="new-password"></label><label>确认新密码<input name="confirm" class="input" type="password" required minlength="12" autocomplete="new-password"></label><button class="btn" type="submit">更新密码</button>${button("退出登录","logout")}<p id="formError" class="error" role="alert"></p></form></div>`;
}
const NAV_ICONS={
  files:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
  admin:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 8h9M19 8h1M4 16h1M11 16h9"/><circle cx="16" cy="8" r="2.6"/><circle cx="8" cy="16" r="2.6"/></svg>',
  logs:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"><path d="M6 3h9l4 4v14H6z"/><path d="M9 11h7M9 15h7"/></svg>'
};
const navItem=(page,label)=>`<button type="button" class="navitem${state.page===page?" active":""}" data-action="nav" data-value="${page}" data-tip="${label}">${NAV_ICONS[page]}<span>${label}</span></button>`;
function shell(){
  app.innerHTML=`<div class="shell${state.sideCollapsed?" side-collapsed":""}"><aside class="side"><button type="button" class="sideToggle" data-action="toggleSide" data-tip="${state.sideCollapsed?"展开边栏":"收缩边栏"}" aria-label="收缩或展开侧边栏">${state.sideCollapsed?"»":"«"}</button><div class="logo">Http<span>Server</span></div><div class="nav">${navItem("files","文件浏览")}${user.role==="admin"?navItem("admin","管理中心")+navItem("logs","日志"):""}</div></aside><div class="user-panel"><div class="welcome">欢迎，${esc(user.username)}</div>${button("修改密码","password")}${button("退出","logout")}</div><main class="main" id="main"></main></div>`;
}
async function render(){if(!user)return login();if(user.must_change_password)return passwordPage(true);if((state.page==="admin"||state.page==="logs")&&user.role!=="admin"){state.page="files";history.replaceState(null,"","/files");notice("浏览和下载权限不包含管理权限，已返回文件页。",true)}shell();await refresh()}
async function refresh(loadingText="正在加载…"){
  const main=document.querySelector("#main");if(!main)return;
  main.innerHTML=`<p role="status">${esc(loadingText)}</p>`;
  try{if(state.page==="admin")await admin();else if(state.page==="logs")await logsPage();else await files();lastRetry=null}
  catch(e){if(document.querySelector("#main"))main.innerHTML=`<div class="card" style="padding:20px"><p class="error" role="alert">${esc(e.message)}</p>${button("重试","refresh")}</div>`;lastRetry=refresh;notice(e.message,true)}
}
function crumbs(){
  let pieces=state.path.split("/"),out=button("共享根目录","folder","");
  if(pieces.length>=2){out+=" / "+button("共享目录","folder",pieces.slice(0,2).join("/"));for(let i=2;i<pieces.length;i++)out+=" / "+button(pieces[i],"folder",pieces.slice(0,i+1).join("/"))}
  return out;
}
async function files(){
  const [d,health]=await Promise.all([api("/api/files?path="+encodeURIComponent(state.path)+"&q="+encodeURIComponent(state.q)+"&page="+state.pageNo+"&page_size="+state.pageSize+"&sort="+state.sort+"&order="+state.order),user.role==="admin"?api("/api/health").catch(()=>null):Promise.resolve(null)]);
  if(!state.q)state.path=d.path;
  state.pageNo=Math.min(d.pages,Math.max(1,state.pageNo));
  document.querySelector("#main").innerHTML=`<div class="top"><h1>文件浏览</h1></div>${user.role==="admin"?healthBar(health):""}<form id="searchForm" class="bar"><input class="input search" name="q" aria-label="搜索文件名" value="${esc(state.q)}" maxlength="256" placeholder="文件名搜索，支持 * 和 ?"><button class="btn">搜索</button>${button("清除","clear")}${button("刷新","refresh")}</form><div class="bar"><label>排序 <select class="input" id="sortSelect"><option value="name" ${state.sort==="name"?"selected":""}>名称</option><option value="size" ${state.sort==="size"?"selected":""}>大小</option><option value="modified" ${state.sort==="modified"?"selected":""}>修改时间</option><option value="type" ${state.sort==="type"?"selected":""}>类型</option></select></label><label>顺序 <select class="input" id="orderSelect"><option value="asc" ${state.order==="asc"?"selected":""}>升序</option><option value="desc" ${state.order==="desc"?"selected":""}>降序</option></select></label>${button("上传文件","pickUpload")}${button("上传文件夹","pickFolder")}${button("新建文件夹","newFolder")}${button("回收站","recycle")}${state.selected.size?button("下载所选","downloadBatch")+button("移动","moveBatch")+button("删除所选","deleteBatch","","danger"):""}<input id="uploadFiles" type="file" multiple hidden><input id="uploadFolder" type="file" webkitdirectory multiple hidden></div><div id="uploadProgress" class="statusline" ${state.uploadMessage?"":"hidden"}>${esc(state.uploadMessage)}</div><div class="card" style="padding:16px"><div>${crumbs()}<p class="muted">共 ${d.total} 项</p></div><div class="scroll"><table class="table"><thead><tr><th><input id="selectAll" type="checkbox" aria-label="选择本页"></th><th>名称</th><th>路径</th><th>大小</th><th>修改时间</th><th>操作</th></tr></thead><tbody>${d.items.map(x=>`<tr><td><input type="checkbox" data-select="${esc(x.path)}" ${state.selected.has(x.path)?"checked":""}></td><td>${x.type==="folder"?button("📁 "+x.name,"folder",x.path):esc(x.name)}</td><td>${esc(x.path)}</td><td>${x.type==="folder"?"—":fmt(x.size)}</td><td>${x.modified?new Date(x.modified*1000).toLocaleString():"—"}</td><td class="actions">${x.can_view?button("预览","view",x.path):""}${button(x.type==="folder"?"打包下载":"下载","download",x.path)}${x.can_modify?button("改名","rename",x.path):""}${x.can_delete?button("删除","deleteItem",x.path,"danger"):""}${user.role==="admin"?button(x.hidden?"取消隐藏":"隐藏","hide",x.path):""}</td></tr>`).join("")||'<tr><td colspan="6" class="empty">没有符合条件的文件，或没有可访问的共享目录。</td></tr>'}</tbody></table></div><div class="paging"><span>第 ${d.page}/${d.pages} 页</span><div>${d.page>1?button("上一页","page",String(d.page-1)):""}${d.page<d.pages?button("下一页","page",String(d.page+1)):""}</div></div></div>`;
}
function showModal(title,html){modalTitle.textContent=title;modalBody.innerHTML=html;modal.classList.remove("hidden")}
let conflictResolve=null;
function closeModal(){modal.classList.add("hidden");if(conflictResolve){const r=conflictResolve;conflictResolve=null;r(null)}}
async function download(path){
  notice("正在准备下载。目录打包可能需要一些时间。");
  const {ticket}=await api("/api/downloads/prepare?path="+encodeURIComponent(path),{method:"POST"});
  // Native download avoids buffering a large file in browser memory.
  const a=document.createElement("a");a.href="/api/files/download?path="+encodeURIComponent(path)+"&ticket="+encodeURIComponent(ticket);a.download="";document.body.append(a);a.click();a.remove();
}
function uploadOne(file,targetPath,name,conflict,onProgress){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();xhr.open("POST","/api/files/upload?path="+encodeURIComponent(targetPath)+"&filename="+encodeURIComponent(name)+"&conflict="+conflict);
    xhr.setRequestHeader("Authorization","Bearer "+token());xhr.upload.onprogress=e=>{if(e.lengthComputable)onProgress(e.loaded,e.total)};
    xhr.onload=()=>{let body={};try{body=JSON.parse(xhr.responseText)}catch{};if(xhr.status>=200&&xhr.status<300)resolve(body);else reject(Error(body.detail||"上传失败 ("+xhr.status+")"))};
    xhr.onerror=()=>reject(Error("网络连接失败，上传未完成"));xhr.onabort=()=>reject(Error("上传已取消"));xhr.send(file);
  });
}
async function uploadFiles(fileList){
  const files=Array.from(fileList);if(!files.length)return;
  const choice=await new Promise(resolve=>{conflictResolve=resolve;
    showModal("上传同名文件处理",`<form id="conflictForm"><p>目标位置存在同名文件时：</p><div class="conflictopts"><label><input type="radio" name="conflict" value="rename" checked>自动改名（推荐，保留原文件）</label><label><input type="radio" name="conflict" value="overwrite">覆盖（替换原文件）</label><label><input type="radio" name="conflict" value="skip">跳过（不上传该文件）</label><label><input type="radio" name="conflict" value="error">报错（记入失败列表）</label></div><div class="formrow"><button class="btn" type="submit">开始上传</button><button class="btn secondary" type="button" data-action="cancelUpload">取消</button></div></form>`)});
  if(!choice)return;
  const box=document.querySelector("#uploadProgress");box.hidden=false;let complete=0,loaded=0;const total=files.reduce((n,f)=>n+f.size,0);let failures=[];
  for(const file of files){
    try{
      const parts=(file.webkitRelativePath||file.name).split("/");const name=parts.pop();let folder=state.path;
      for(const part of parts){const next=folder+"/"+part;try{await api("/api/files/folders",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:folder,name:part})})}catch(e){if(!/同名目录已存在|exist|409/i.test(e.message))throw e}folder=next}
      await uploadOne(file,folder,name,choice,(part)=>{box.textContent=`${file.name} · ${fmt(loaded+part)} / ${fmt(total)} · ${complete+1}/${files.length}`});loaded+=file.size;complete++;
    }catch(e){failures.push(file.name+": "+e.message);loaded+=file.size}
  }
  state.uploadMessage=failures.length?`完成 ${complete}/${files.length}，失败 ${failures.length}：${failures.join("；")}`:`上传完成：${complete} 个文件，共 ${fmt(total)}`;
  state.pageNo=1;await refresh();
}
async function recycleView(){
  const rows=await api("/api/recycle-bin");showModal("回收站",rows.map(x=>`<div class="rootrow"><span>${esc(x.name)} · ${esc(x.path)}<br><span class="muted">${new Date(x.deleted_at*1000).toLocaleString()} · 保留至 ${new Date(x.expires_at*1000).toLocaleDateString()}</span></span>${button("恢复","restore",x.id)}${button("彻底删除","purge",x.id,"danger")}</div>`).join("")||"<p>回收站为空。</p>");
}
async function viewFile(path){
  if(path.toLowerCase().endsWith(".pdf")){
    const tab=window.open("about:blank","_blank");if(tab)tab.opener=null;
    try{const {ticket}=await api("/api/download-tickets?purpose=view&path="+encodeURIComponent(path),{method:"POST"});if(tab)tab.location="/api/files/inline?path="+encodeURIComponent(path)+"&ticket="+encodeURIComponent(ticket);else throw Error("请允许弹窗后重试")}
    catch(e){if(tab)tab.close();throw e}
  }else{
    const d=await api("/api/files/view?path="+encodeURIComponent(path));
    showModal(d.name,(d.truncated?'<p class="statusline">文件较大，仅预览前 2 MB。可下载完整文件。</p>':"")+"<pre>"+esc(d.content)+"</pre>");
  }
}
async function logsPage(){
  const f=state.logFilter,params=new URLSearchParams({limit:"100"});
  if(f.username)params.set("username",f.username);
  if(f.action)params.set("action",f.action);
  if(f.result)params.set("result",f.result);
  if(f.start)params.set("start",String(new Date(f.start).getTime()/1000));
  if(f.end)params.set("end",String(new Date(f.end).getTime()/1000));
  const logs=await api("/api/admin/audit?"+params.toString());
  document.querySelector("#main").innerHTML=`<div class="top"><h1>日志</h1></div><div class="card" style="padding:16px"><form id="logFilterForm" class="bar logfilter"><label>开始时间<input class="input" type="datetime-local" name="start" value="${esc(f.start)}"></label><label>结束时间<input class="input" type="datetime-local" name="end" value="${esc(f.end)}"></label><label>用户名<input class="input" name="username" maxlength="64" placeholder="支持部分匹配" value="${esc(f.username)}"></label><label>操作<input class="input" name="action" maxlength="64" placeholder="如 login、download" value="${esc(f.action)}"></label><label>结果<select class="input" name="result"><option value="">全部</option><option value="ok" ${f.result==="ok"?"selected":""}>ok（成功）</option><option value="denied" ${f.result==="denied"?"selected":""}>denied（拒绝）</option></select></label><button class="btn">查询</button>${button("重置","logReset")}</form></div><div class="card" style="padding:16px;margin-top:16px"><h2>最近审计与错误</h2><p class="muted">查询到 ${logs.length} 条（最多显示 100 条）</p><div class="scroll"><table class="table"><thead><tr><th>时间</th><th>用户</th><th>操作</th><th>结果</th><th>路径/详情</th></tr></thead><tbody>${logs.map(l=>`<tr><td>${new Date(l.created_at*1000).toLocaleString()}</td><td>${esc(l.username)}</td><td>${esc(l.action)}</td><td>${esc(l.result)}</td><td>${esc(l.path)} ${esc(l.detail)}</td></tr>`).join("")||'<tr><td colspan="5" class="empty">没有符合条件的日志。</td></tr>'}</tbody></table></div></div>`;
}
const fmtUptime=s=>{const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?`${d} 天 ${h} 小时 ${m} 分`:h?`${h} 小时 ${m} 分`:m?`${m} 分 ${s%60} 秒`:`${s} 秒`};
function healthBar(health){
  if(!health)return '<div class="healthbar card"><span class="v bad">服务状态异常：健康检查未通过，请稍后刷新重试。</span></div>';
  const labels={browse:"浏览",search:"搜索",preview:"预览",zip:"打包",upload:"上传",download:"下载"};
  const tasks=health.active_tasks||{},total=Object.values(tasks).reduce((a,b)=>a+b,0);
  const chips=Object.entries(tasks).map(([k,n])=>`<span class="chip ${n>0?"on":""}"><i>${esc(labels[k]||k)}</i><b>${n}</b></span>`).join("");
  return `<div class="healthbar card"><div class="stats"><div class="stat"><span class="k">版本</span><span class="v">${esc(health.version)}</span></div><div class="stat"><span class="k">已运行</span><span class="v">${fmtUptime(health.uptime_seconds)}</span></div><div class="stat"><span class="k">数据库</span><span class="v ${health.database==="ok"?"ok":"bad"}">${esc(health.database)}</span></div><div class="stat"><span class="k">可用空间</span><span class="v">${fmt(health.disk_free_bytes)}</span></div></div><div class="tasks"><span class="k">活动任务</span><div class="chips">${chips}</div><span class="tasksum ${total?"on":""}">${total?`共 ${total} 个进行中`:"当前空闲"}</span></div></div>`;
}
async function admin(){
  const [users,roots,sessions]=await Promise.all([api("/api/admin/users"),api("/api/admin/share-roots"),api("/api/admin/sessions")]);
  document.querySelector("#main").innerHTML=`<h1>管理中心</h1>${button("导出诊断包","diagnostics")}<div class="card" style="padding:16px;margin-top:16px"><h2>用户与权限</h2>${button("新建用户","user","0")}<div class="scroll"><table class="table"><thead><tr><th>账号</th><th>角色</th><th>默认浏览</th><th>默认下载</th><th>默认改名</th><th>默认删除</th><th>操作</th></tr></thead><tbody>${users.map(u=>`<tr><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${u.can_browse?"允许":"禁止"}</td><td>${u.can_download?"允许":"禁止"}</td><td>${u.can_rename?"允许":"禁止"}</td><td>${u.can_delete?"允许":"禁止"}</td><td>${button("编辑 / 重置密码","user",String(u.id))}${u.role!=="admin"?button("删除账号","deleteUser",String(u.id),"danger"):""}</td></tr>`).join("")}</tbody></table></div></div><div class="card" style="padding:16px;margin-top:16px"><h2>共享目录</h2><form id="rootForm" class="bar"><input name="name" class="input" placeholder="显示名称"><input name="path" class="input search" required placeholder="服务主机上的绝对目录路径"><button class="btn">添加</button>${button("浏览文件夹","browseRoot")}</form><p class="muted">现可按目录配置浏览、下载、上传、修改和删除权限。</p>${roots.map(r=>`<div class="rootrow"><span>${esc(r.name)}<br><span class="muted">${esc(r.path)}</span></span>${button("编辑","root",String(r.id))}${button("目录权限","acl",String(r.id))}${button("移除共享","deleteRoot",String(r.id),"danger")}</div>`).join("")}</div><div class="card" style="padding:16px;margin-top:16px"><h2>在线会话</h2>${sessions.map(s=>`<p>${esc(s.username)} · ${esc(s.client_ip)} · ${new Date(s.created_at*1000).toLocaleString()} ${button("强制下线","revoke",s.id)}</p>`).join("")}</div>`;
}
async function userEditor(id){
  const users=await api("/api/admin/users"),u=users.find(x=>x.id===+id)||{id:0,username:"",role:"user",can_browse:1,can_download:1,can_rename:0,can_delete:0};
  showModal(u.id?"编辑用户":"新建用户",`<form id="userForm" data-id="${u.id}"><label>账号<input class="input" name="username" required maxlength="64" value="${esc(u.username)}"></label><p><label>${u.id?"重置密码（留空保持原密码）":"初始密码"}<input class="input" name="password" type="password" autocomplete="new-password" ${u.id?"":"required"} minlength="12"></label></p><label>角色<select class="input" name="role"><option value="user" ${u.role==="user"?"selected":""}>普通用户</option><option value="admin" ${u.role==="admin"?"selected":""}>管理员</option></select></label><p><label><input name="browse" type="checkbox" ${u.can_browse?"checked":""}>默认允许浏览</label> <label><input name="download" type="checkbox" ${u.can_download?"checked":""}>默认允许下载</label> <label><input name="rename" type="checkbox" ${u.can_rename?"checked":""}>允许改名</label> <label><input name="delete" type="checkbox" ${u.can_delete?"checked":""}>允许删除</label></p><p class="muted">修改后该用户所有会话立即注销。改名权限同时包含移动；删除为移入回收站（30 天可恢复）。勾选仅作为默认权限，目录权限可单独覆盖。</p><button class="btn">保存</button><p class="error" id="modalError" role="alert"></p></form>`);
}
async function aclEditor(rootId){
  const entries=await api("/api/admin/share-roots/"+rootId+"/permissions");
  showModal("共享目录权限",`<p>按用户覆盖默认权限；每次文件操作都会在服务端重新检查权限。</p>${entries.map(e=>`<form class="aclForm" data-root="${rootId}" data-user="${e.user_id}"><b>${esc(e.username)}</b><p>${["browse","download","upload","modify","delete"].map((k,i)=>`<label><input type="checkbox" name="${k}" ${e[k]?"checked":""}>${["浏览","下载","上传","修改","删除"][i]}</label> `).join("")}</p><button class="btn">保存权限</button></form>`).join("")||"<p>请先创建普通用户。</p>"}`);
}
async function rootEditor(id){
  const entries=await api("/api/admin/share-roots"),r=entries.find(x=>x.id===+id);
  showModal("编辑共享目录",`<form id="editRootForm" data-id="${id}"><input name="name" class="input" value="${esc(r.name)}" required><p><input name="path" class="input" value="${esc(r.path)}" required></p><button class="btn">保存</button><p id="modalError" class="error"></p></form>`);
}
async function diagnostics(){
  const blob=await api("/api/admin/diagnostics",{blob:true});const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="HttpServer-diagnostics.zip";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);notice("诊断包已导出");
}
document.addEventListener("submit",async event=>{
  event.preventDefault();const form=event.target,submit=form.querySelector('button[type="submit"],button:not([type])');if(submit)submit.disabled=true;
  const data=new FormData(form),json=body=>({method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  try{
    if(form.id==="loginForm"){
      const d=await api("/api/login",json({username:data.get("username"),password:data.get("password")}));
      sessionStorage.setItem("httpserver.token",d.token);user=d.user;await render();
    }else if(form.id==="passwordForm"){
      if(data.get("password")!==data.get("confirm"))throw Error("两次新密码不一致");
      await api("/api/account/password",json({current_password:data.get("current"),new_password:data.get("password")}));forget();login();notice("密码更新成功，请重新登录");
    }else if(form.id==="conflictForm"){const r=conflictResolve;conflictResolve=null;closeModal();if(r)r(String(data.get("conflict")))}
    else if(form.id==="searchForm"){state.q=String(data.get("q")).trim();state.pageNo=1;await refresh("搜索中，请稍后…")}
    else if(form.id==="logFilterForm"){state.logFilter={username:String(data.get("username")).trim(),action:String(data.get("action")).trim(),result:String(data.get("result")),start:String(data.get("start")),end:String(data.get("end"))};await refresh()}
    else if(form.id==="userForm"){
      const id=+form.dataset.id;await api("/api/admin/users"+(id?"/"+id:""),{...json({username:data.get("username"),password:data.get("password"),role:data.get("role"),can_browse:data.has("browse"),can_download:data.has("download"),can_rename:data.has("rename"),can_delete:data.has("delete")}),method:id?"PUT":"POST"});
      closeModal();notice("用户保存成功");await refresh();
    }else if(form.id==="rootForm"||form.id==="editRootForm"){
      const id=form.dataset.id;await api("/api/admin/share-roots"+(id?"/"+id:""),{...json({name:data.get("name"),path:data.get("path")}),method:id?"PUT":"POST"});closeModal();notice("共享目录已保存");await refresh();
    }else if(form.classList.contains("aclForm")){
      const body=Object.fromEntries(["browse","download","upload","modify","delete"].map(k=>[k,data.has(k)]));
      await api("/api/admin/share-roots/"+form.dataset.root+"/permissions/"+form.dataset.user,{...json(body),method:"PUT"});notice("权限已更新");
    }
  }catch(error){const display=form.querySelector("#formError,#modalError");if(display)display.textContent=error.message;notice(error.message,true)}
  finally{if(submit)submit.disabled=false}
});
document.addEventListener("click",async event=>{
  const b=event.target.closest("[data-action]");if(!b)return;const value=b.dataset.value;b.disabled=true;
  try{
    switch(b.dataset.action){
      case "nav":state.page=value;state.path="";state.q="";history.replaceState(null,"",value==="admin"?"/manageCenter":value==="logs"?"/logs":"/files");await render();break;
      case "logReset":state.logFilter={username:"",action:"",result:"",start:"",end:""};await refresh();break;
      case "toggleSide":{state.sideCollapsed=!state.sideCollapsed;localStorage.setItem("httpserver.side",state.sideCollapsed?"1":"0");document.querySelector(".shell").classList.toggle("side-collapsed",state.sideCollapsed);b.textContent=state.sideCollapsed?"»":"«";b.setAttribute("data-tip",state.sideCollapsed?"展开边栏":"收缩边栏");break;}
      case "closePassword":if(user&&!user.must_change_password){await render()}else{forget();login()}break;
      case "logout":await api("/api/logout",{method:"POST"});forget();login();notice("已安全退出");break;
      case "password":passwordPage();break;
      case "folder":state.path=value;state.q="";state.pageNo=1;await refresh();break;
      case "refresh":await refresh();break;
      case "clear":state.q="";state.pageNo=1;await refresh();break;
      case "page":state.pageNo=+value;await refresh();break;
      case "pickUpload":document.querySelector("#uploadFiles").click();break;
      case "pickFolder":document.querySelector("#uploadFolder").click();break;
      case "newFolder":{const name=prompt("文件夹名称");if(name){await api("/api/files/folders",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:state.path,name})});await refresh()}break;}
      case "rename":{const name=prompt("新的名称",value.split("/").pop());if(name){await api("/api/files/item",{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:value,name})});await refresh()}break;}
      case "deleteItem":if(confirm("删除该项目？项目会进入回收站。")){await api("/api/files/item",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:value})});state.selected.delete(value);await refresh()}break;
      case "deleteBatch":if(confirm(`将 ${state.selected.size} 个项目移入回收站？`)){const results=await api("/api/files/delete-batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths:[...state.selected]})});notice(`已删除 ${results.results.filter(x=>x.ok).length}/${results.results.length} 项`);state.selected.clear();await refresh()}break;
      case "moveBatch":{const destination=prompt("输入目标目录虚拟路径",state.path);if(destination){const result=await api("/api/files/move",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths:[...state.selected],destination})});notice(`已移动 ${result.results.filter(x=>x.ok).length}/${result.results.length} 项`);state.selected.clear();await refresh()}break;}
      case "downloadBatch":{const paths=[...state.selected];notice("正在准备所选项目 ZIP。",false);const prepared=await api("/api/downloads/prepare-batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths})});const a=document.createElement("a");a.href="/api/files/download-batch?paths="+encodeURIComponent(paths.join("\n"))+"&ticket="+encodeURIComponent(prepared.ticket);a.download="HttpServer-files.zip";document.body.append(a);a.click();a.remove();break;}
      case "cancelUpload":closeModal();break;
      case "purge":if(confirm("彻底删除该项目？删除后不可恢复。")){await api("/api/recycle-bin/"+value,{method:"DELETE"});notice("已彻底删除");await recycleView();await refresh()}break;
      case "recycle":await recycleView();break;
      case "restore":await api("/api/recycle-bin/"+value+"/restore",{method:"POST"});notice("项目已恢复");await recycleView();await refresh();break;
      case "view":await viewFile(value);break;
      case "download":await download(value);break;
      case "hide":await api("/api/files/hidden?path="+encodeURIComponent(value),{method:"POST"});notice("可见性已更新");await refresh();break;
      case "user":await userEditor(value);break;
      case "root":await rootEditor(value);break;
      case "acl":await aclEditor(value);break;
      case "deleteUser":if(confirm("确认删除该账号？其所有会话将失效。")){await api("/api/admin/users/"+value,{method:"DELETE"});notice("账号已删除");await refresh()}break;
      case "deleteRoot":if(confirm("确认移除此共享目录？原始文件不会删除。")){await api("/api/admin/share-roots/"+value,{method:"DELETE"});notice("共享已移除");await refresh()}break;
      case "revoke":await api("/api/admin/sessions/"+value,{method:"DELETE"});notice("会话已注销");await refresh();break;
      case "diagnostics":await diagnostics();break;
      case "browseRoot":{const d=await api("/api/admin/share-roots/browse",{method:"POST"});if(d.path)document.querySelector("#rootForm [name=path]").value=d.path;break;}
    }
  }catch(error){notice(error.message,true)}finally{b.disabled=false}
});
document.addEventListener("change",async event=>{
  if(event.target.id==="uploadFiles"||event.target.id==="uploadFolder"){await uploadFiles(event.target.files);event.target.value=""}
  if(event.target.matches("[data-select]")){const p=event.target.dataset.select;event.target.checked?state.selected.add(p):state.selected.delete(p);await refresh()}
  if(event.target.id==="selectAll"){document.querySelectorAll("[data-select]").forEach(c=>{c.checked=event.target.checked;event.target.checked?state.selected.add(c.dataset.select):state.selected.delete(c.dataset.select)});await refresh()}
  if(event.target.id==="sortSelect"){state.sort=event.target.value;state.pageNo=1;await refresh()}
  if(event.target.id==="orderSelect"){state.order=event.target.value;state.pageNo=1;await refresh()}
});
modal.addEventListener("click",event=>{if(event.target===modal)closeModal()});
document.addEventListener("keydown",event=>{if(event.key==="Escape")closeModal()});
window.addEventListener("offline",()=>notice("网络已断开，恢复后可重试。",true));
window.addEventListener("online",()=>{notice("网络已恢复");if(lastRetry)lastRetry()});
// Remove V1.2's persistent browser credential; V1.3 uses a per-tab session token.
localStorage.removeItem("token");localStorage.removeItem("user");
(async()=>{if(!token())return login();try{user=await api("/api/account");await render()}catch(e){forget();login();notice(e.message,true)}})();
