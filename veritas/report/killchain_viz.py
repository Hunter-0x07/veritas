"""Kill chain 可视化回放：把攻击图 + 战果 + 命令时间线渲成【自包含单文件 HTML】。

与 killchain.py（markdown 报告）同源数据、同一套真实底物（footholds/edges/credentials/loot/
findings/activity/http_flows），但产出可读、可【回放】、可分享的 HTML：
  - 攻击图：按访问级别（external→…→domain_admin）横向泳道布局，pivot 父子边连成 kill chain，
    节点按 verdict 配色（verified 绿 / refuted 红 / unproven 琥珀）。
  - 回放：按 activity 时间线逐步播放引擎真实动作（命令/探针/安全闸/Observer），立足点随
    created_at 时间点逐个"点亮"，访问级别进度条随之攀升——还原"攻击如何一步步发生"。
  - 详情：选中节点看 evidence/主动探针/PoC；侧栏列凭据(脱敏)/战利品/漏洞/MITM curl/安全闸事件。

设计：`build_payload` 为纯函数（接 dict/Record 皆可），确定性可单测；`export_html` 把 payload
注进内联模板写出单文件（无外部依赖、离线可开、可截图/录屏分享）。build-in-public 友好：凭据
secret 默认脱敏（只留 username/kind/verdict，kill-chain 叙事不需要明文）。
"""
from __future__ import annotations

import json
import pathlib
import shlex
import time

from ..core.state import ACCESS_RANK, meets_goal, rank

_ACCESS_ORDER = sorted(ACCESS_RANK, key=lambda k: ACCESS_RANK[k])
_SKIP_HDR = {"host", "content-length", "proxy-connection", "connection"}


def _d(rec) -> dict:
    return dict(rec) if rec is not None else {}


def _epoch_ms(v) -> int:
    if v is None:
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    ts = getattr(v, "timestamp", None)
    if callable(ts):
        try:
            return int(v.timestamp() * 1000)
        except Exception:  # noqa: BLE001
            return 0
    return 0


def _mask(secret: str) -> str:
    """脱敏凭据明文（分享友好）：只透露长度量级，不泄露值。"""
    s = secret or ""
    return "•" * min(len(s), 12) if s else ""


def _curl(f: dict) -> str:
    parts = [f"curl -i -X {f.get('method') or 'GET'} {shlex.quote(f.get('url') or '')}"]
    for k, v in (f.get("req_headers") or {}).items():
        if k.lower() in _SKIP_HDR:
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if f.get("req_body"):
        parts.append(f"--data {shlex.quote(f['req_body'])}")
    return " ".join(parts)


def _slim_probe(p) -> dict | None:
    if not isinstance(p, dict) or not p:
        return None
    return {"method": p.get("method"), "tier": p.get("tier"), "verdict": p.get("verdict"),
            "trust": p.get("trust"), "detail": (p.get("detail") or "")[:300],
            "command": (p.get("command") or "")[:300]}


def build_payload(task_id: str, target: str, goal: str, max_access: str, mode: str,
                  footholds, edges, credentials, loot, findings, activity, flows,
                  mask_secrets: bool = True) -> dict:
    """把真实底物整理成可视化 payload（纯函数）。接 asyncpg.Record 或 dict 均可。"""
    foots = [_d(f) for f in (footholds or [])]
    fids = {f["id"] for f in foots}
    nodes = []
    for f in foots:
        props = f.get("props") or {}
        judge = props.get("probe_judge") if isinstance(props.get("probe_judge"), dict) else None
        replay = props.get("replay") if isinstance(props.get("replay"), dict) else None
        nodes.append({
            "id": f["id"], "label": f.get("label") or "", "access_level": f.get("access_level") or "",
            "rank": rank(f.get("access_level") or ""), "location": f.get("location") or "",
            "verdict": f.get("verdict") or "unproven",
            "evidence": (props.get("evidence") or "")[:1500],
            "probe": _slim_probe(props.get("probe")),
            "judge": {"detail": (judge.get("detail") or "")[:300], "trust": judge.get("trust")} if judge else None,
            "replay": replay,
            "t": _epoch_ms(f.get("created_at")),
        })
    vedges = [{"src": e2["src"], "dst": e2["dst"], "rel": e2.get("rel") or ""}
              for e2 in (_d(e) for e in (edges or [])) if e2.get("src") in fids and e2.get("dst") in fids]

    timeline = []
    for idx, a0 in enumerate(activity or []):
        a = _d(a0)
        c = a.get("content") or {}
        ev = {"i": idx, "worker": a.get("worker_id") or "", "t": _epoch_ms(a.get("created_at"))}
        if "observer" in c:
            ev.update(type="observer", observer=c.get("observer"), detail=(c.get("detail") or "")[:400])
        elif "gate" in c:
            ev.update(type="gate", gate=c.get("gate"), category=c.get("category"),
                      noise=c.get("noise"), cmd=(c.get("exec") or "")[:400])
        elif "probe" in c:
            ev.update(type="probe", probe=c.get("probe"), verdict=c.get("verdict"), tier=c.get("tier"),
                      trust=c.get("trust"), cmd=(c.get("exec") or "")[:400], detail=c.get("subject") or "")
        elif c.get("kind"):
            ev.update(type="fleet", kind=c.get("kind"), ok=bool(c.get("ok")), summary=(c.get("summary") or "")[:300])
        elif "exec" in c:
            ev.update(type="exec", rc=c.get("rc"), cmd=(c.get("exec") or "")[:400], out=(c.get("out") or "")[:600])
        else:
            continue
        timeline.append(ev)

    creds_out = []
    for c0 in (credentials or []):
        c = _d(c0)
        creds_out.append({"kind": c.get("kind"), "username": c.get("username") or "",
                          "secret": _mask(c.get("secret")) if mask_secrets else (c.get("secret") or ""),
                          "source": c.get("source") or "", "verdict": c.get("verdict") or "unproven"})
    loot_out = [{"kind": x.get("kind"), "summary": (x.get("summary") or "")[:300]} for x in (_d(l) for l in (loot or []))]
    find_out = [{"type": x.get("type"), "severity": x.get("severity") or "", "reproduction": (x.get("reproduction") or "")[:400]}
                for x in (_d(f) for f in (findings or []))]
    flows_out = []
    for fl0 in (flows or []):
        fl = _d(fl0)
        flows_out.append({"method": fl.get("method"), "url": fl.get("url"), "host": fl.get("host"),
                          "status": fl.get("status"), "curl": _curl(fl),
                          "resp_tail": (fl.get("resp_body") or "")[:400]})

    workers = sorted({ev["worker"] for ev in timeline if ev["worker"]})
    vc = sum(1 for n in nodes if n["verdict"] == "verified")
    rc_ = sum(1 for n in nodes if n["verdict"] == "refuted")
    uc = sum(1 for n in nodes if n["verdict"] not in ("verified", "refuted"))
    stats = {
        "verified": vc, "refuted": rc_, "unproven": uc,
        "credentials": len(creds_out), "loot": len(loot_out), "findings": len(find_out), "flows": len(flows_out),
        "scope_denied": sum(1 for e in timeline if e["type"] == "gate" and e.get("gate") == "scope_denied"),
        "needs_approval": sum(1 for e in timeline if e["type"] == "gate" and e.get("gate") == "needs_approval"),
        "observer_flags": sum(1 for e in timeline if e["type"] == "observer"),
    }
    return {
        "meta": {"task_id": task_id, "target": target, "goal": goal, "max_access": max_access,
                 "reached": meets_goal(max_access, goal), "mode": mode,
                 "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "workers": workers,
                 "masked": bool(mask_secrets)},
        "access_levels": _ACCESS_ORDER,
        "nodes": nodes, "edges": vedges, "credentials": creds_out, "loot": loot_out,
        "findings": find_out, "flows": flows_out, "timeline": timeline, "stats": stats,
    }


def export_html(payload: dict, out_path: str, title: str = "Veritas Kill Chain") -> str:
    html = _TEMPLATE.replace("__VZ_TITLE__", title).replace(
        "__VZ_PAYLOAD__", json.dumps(payload, ensure_ascii=False))
    p = pathlib.Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return str(p)


# —— 自包含单文件查看器（内联 CSS/JS + SVG，无外部依赖；__VZ_PAYLOAD__ 注入数据）——
_TEMPLATE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__VZ_TITLE__</title>
<style>
:root{
  --bg:#f6f8fa; --panel:#fff; --ink:#1f2328; --muted:#656d76; --line:#d0d7de;
  --ext:#8b949e; --verified:#1a7f37; --refuted:#cf222e; --unproven:#9a6700;
  --accent:#0969da; --chip:#eaeef2; --lane:#eef1f4; --lane2:#e7ebef;
}
:root:not([data-theme=light]) @media (prefers-color-scheme: dark){}
@media (prefers-color-scheme: dark){:root:not([data-theme=light]){
  --bg:#0d1117; --panel:#161b22; --ink:#e6edf3; --muted:#8b949e; --line:#30363d;
  --ext:#6e7681; --verified:#3fb950; --refuted:#f85149; --unproven:#d29922;
  --accent:#4493f8; --chip:#21262d; --lane:#12161c; --lane2:#161b22;
}}
:root[data-theme=dark]{
  --bg:#0d1117; --panel:#161b22; --ink:#e6edf3; --muted:#8b949e; --line:#30363d;
  --ext:#6e7681; --verified:#3fb950; --refuted:#f85149; --unproven:#d29922;
  --accent:#4493f8; --chip:#21262d; --lane:#12161c; --lane2:#161b22;
}
*{box-sizing:border-box} html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:17px;margin:0 0 2px} .sub{color:var(--muted);font-size:12px;word-break:break-all}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0}
.chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:12px;white-space:nowrap}
.chip b{font-variant-numeric:tabular-nums}
.badge{font-weight:600;border-radius:6px;padding:2px 8px;font-size:12px}
.ok{background:rgba(63,185,80,.15);color:var(--verified)} .no{background:rgba(248,81,73,.15);color:var(--refuted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle;margin-right:4px}
.v-verified{background:var(--verified)} .v-refuted{background:var(--refuted)} .v-unproven{background:var(--unproven)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px 0}
.panel h2{font-size:13px;margin:0 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
#graphwrap{overflow-x:auto}
svg{display:block;min-width:100%}
.lanelabel{fill:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.node rect{rx:8;stroke-width:1.5;cursor:pointer;transition:opacity .25s}
.node text{pointer-events:none}
.node .nl{font-size:11.5px;font-weight:600} .node .nloc{font-size:10px;opacity:.75}
.edge{fill:none;stroke:var(--muted);stroke-width:1.5;opacity:.5;transition:opacity .25s}
.dim{opacity:.16}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:6px 12px;font-size:13px;cursor:pointer}
button.ghost{background:var(--chip);color:var(--ink);border:1px solid var(--line)}
input[type=range]{flex:1;min-width:160px;accent-color:var(--accent)}
.log{font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px;max-height:230px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.log .ln{padding:1px 0;border-bottom:1px solid transparent}
.log .cur{background:rgba(9,105,218,.1);border-radius:4px}
.tag{font-weight:700;margin-right:6px}
.t-exec{color:var(--accent)} .t-probe{color:var(--verified)} .t-gate{color:var(--refuted)} .t-observer{color:var(--unproven)} .t-fleet{color:var(--muted)}
.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}
.tab{background:var(--chip);border:1px solid var(--line);border-radius:7px;padding:4px 10px;font-size:12px;cursor:pointer}
.tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.item{border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:6px 0;background:var(--bg)}
.item .k{color:var(--muted);font-size:11px} code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.hide{display:none} .muted{color:var(--muted)} .right{margin-left:auto}
a.theme{color:var(--muted);font-size:12px;cursor:pointer;text-decoration:underline}
.evbox{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto}
</style></head>
<body><div class="wrap">
  <div class="row" style="justify-content:space-between">
    <div><h1>🎯 Veritas Kill Chain 回放</h1><div class="sub" id="sub"></div></div>
    <a class="theme" id="theme">◐ 主题</a>
  </div>
  <div class="row" id="chips"></div>

  <div class="panel">
    <h2>攻击图 · 访问级别推进（点节点看详情）</h2>
    <div id="graphwrap"><svg id="svg"></svg></div>
  </div>

  <div class="panel">
    <h2>回放 · 引擎真实动作时间线</h2>
    <div class="controls">
      <button id="play">▶ 播放</button>
      <button class="ghost" id="step">⏭ 单步</button>
      <button class="ghost" id="reset">⏮ 重置</button>
      <input type="range" id="scrub" min="0" value="0">
      <span class="muted mono" id="pos"></span>
      <label class="muted" style="font-size:12px">速度
        <select id="speed"><option value="700">慢</option><option value="320" selected>中</option><option value="120">快</option></select>
      </label>
    </div>
    <div class="log" id="log"></div>
  </div>

  <div class="panel">
    <div class="tabs" id="tabs"></div>
    <div id="tabbody"></div>
  </div>
  <div class="sub" style="text-align:center;margin:8px 0 24px">Veritas · 自动化渗透引擎 · 结论可信度：只确定性证据计入进展</div>
</div>
<script>
const VZ = __VZ_PAYLOAD__;
const $ = s => document.querySelector(s);
const esc = s => (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const vClass = v => v==='verified'?'v-verified':(v==='refuted'?'v-refuted':'v-unproven');
const vInk = v => v==='verified'?'var(--verified)':(v==='refuted'?'var(--refuted)':'var(--unproven)');

// —— 头部 ——
const m = VZ.meta, st = VZ.stats;
$('#sub').textContent = `目标 ${m.target}  ·  goal=${m.goal}  ·  task ${m.task_id}  ·  ${m.mode}  ·  ${m.generated_at}  ·  舰队 ${(m.workers||[]).join(', ')||'—'}`;
const chips = [
  `<span class="badge ${m.reached?'ok':'no'}">${m.reached?'✅ goal 达成':'❌ 未达成'} · 最终 ${esc(m.max_access)}</span>`,
  `<span class="chip"><span class="dot v-verified"></span>verified <b>${st.verified}</b></span>`,
  `<span class="chip"><span class="dot v-refuted"></span>refuted <b>${st.refuted}</b></span>`,
  `<span class="chip"><span class="dot v-unproven"></span>unproven <b>${st.unproven}</b></span>`,
  `<span class="chip">🔑 凭据 <b>${st.credentials}</b></span>`,
  `<span class="chip">📦 战利品 <b>${st.loot}</b></span>`,
  `<span class="chip">🐞 漏洞 <b>${st.findings}</b></span>`,
  `<span class="chip">🌐 HTTP 流 <b>${st.flows}</b></span>`,
];
if(st.scope_denied) chips.push(`<span class="chip">🚫 scope 拦截 <b>${st.scope_denied}</b></span>`);
if(st.needs_approval) chips.push(`<span class="chip">⛔ 待审批拦截 <b>${st.needs_approval}</b></span>`);
if(st.observer_flags) chips.push(`<span class="chip">⚠️ Observer <b>${st.observer_flags}</b></span>`);
$('#chips').innerHTML = chips.join('');

// —— 攻击图布局（访问级别泳道，x=rank，纵向堆叠）——
const LV = VZ.access_levels, COLW=146, ROWH=70, PADX=20, PADY=34, NW=128, NH=46;
const laneOf = {}; LV.forEach((l,i)=>laneOf[l]=i);
const byLane = {}; VZ.nodes.forEach(n=>{(byLane[n.rank]=byLane[n.rank]||[]).push(n)});
Object.values(byLane).forEach(a=>a.sort((x,y)=>(x.t-y.t)||(x.id-y.id)));
const pos = {};
VZ.nodes.forEach(n=>{ const col=byLane[n.rank]; const row=col.indexOf(n);
  pos[n.id]={x:PADX+n.rank*COLW+(COLW-NW)/2, y:PADY+row*ROWH}; });
const maxRows = Math.max(1,...Object.values(byLane).map(a=>a.length));
const W = PADX*2+LV.length*COLW, H = PADY+maxRows*ROWH+10;
const svg = $('#svg'); svg.setAttribute('viewBox',`0 0 ${W} ${H}`); svg.setAttribute('height',H);
let g = '';
LV.forEach((l,i)=>{ const x=PADX+i*COLW;
  g += `<rect x="${x}" y="0" width="${COLW}" height="${H}" fill="${i%2?'var(--lane2)':'var(--lane)'}"/>`;
  g += `<text class="lanelabel" x="${x+COLW/2}" y="20" text-anchor="middle">${esc(l)}</text>`; });
VZ.edges.forEach(e=>{ const a=pos[e.src],b=pos[e.dst]; if(!a||!b) return;
  const x1=a.x+NW,y1=a.y+NH/2,x2=b.x,y2=b.y+NH/2,mx=(x1+x2)/2;
  g += `<path class="edge" data-s="${e.src}" data-d="${e.dst}" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`; });
VZ.nodes.forEach(n=>{ const p=pos[n.id]; const ink=vInk(n.verdict);
  g += `<g class="node" data-id="${n.id}" transform="translate(${p.x},${p.y})">
    <rect width="${NW}" height="${NH}" fill="var(--panel)" stroke="${ink}"/>
    <rect width="4" height="${NH}" fill="${ink}" rx="0"/>
    <text class="nl" x="10" y="19" fill="var(--ink)">${esc(n.access_level)}</text>
    <text class="nloc" x="10" y="34" fill="var(--muted)">${esc((n.label||'').slice(0,20))}</text></g>`; });
svg.innerHTML = g;

// —— 回放引擎 ——
const TL = VZ.timeline, scrub=$('#scrub'), logEl=$('#log');
scrub.max = Math.max(0, TL.length-1);
let cur = TL.length?TL.length-1:0, playing=false, timer=null;
function nodeRevealT(idx){ return TL.length?TL[idx].t:0; }
function hasTimes(){ return VZ.nodes.some(n=>n.t>0) && TL.some(e=>e.t>0); }
const TIMED = hasTimes();
function render(){
  const tcur = TIMED ? nodeRevealT(cur) : Infinity;
  const shown = new Set();
  VZ.nodes.forEach(n=>{ const on = !TIMED || n.t<=tcur || cur>=TL.length-1; if(on) shown.add(n.id);
    const el = svg.querySelector(`.node[data-id="${n.id}"]`); if(el) el.classList.toggle('dim',!on); });
  svg.querySelectorAll('.edge').forEach(p=>{ const on = shown.has(+p.dataset.s)&&shown.has(+p.dataset.d);
    p.classList.toggle('dim',!on); });
  // 日志（到 cur 为止）
  let h='';
  for(let i=0;i<=cur && i<TL.length;i++){ const e=TL[i];
    let body='';
    if(e.type==='exec') body=`$ ${esc(e.cmd)}  (rc=${e.rc})`;
    else if(e.type==='probe') body=`${esc(e.probe)}/${esc(e.tier||'')} → ${esc(e.verdict)} [${esc(e.trust||'')}] ${esc(e.detail||'')}`;
    else if(e.type==='gate') body=`${esc(e.gate)} ${e.category?('('+esc(e.category)+'/'+esc(e.noise)+')'):''}: ${esc(e.cmd)}`;
    else if(e.type==='observer') body=`${esc(e.observer)} — ${esc(e.detail)}`;
    else if(e.type==='fleet') body=`${esc(e.kind)} ${e.ok?'✓':'✗'} ${esc(e.summary||'')}`;
    h += `<div class="ln ${i===cur?'cur':''}"><span class="tag t-${e.type}">[${esc(e.worker||'·')}] ${e.type}</span>${body}</div>`;
  }
  logEl.innerHTML = h || '<span class="muted">（无动作记录）</span>';
  const c = logEl.querySelector('.cur'); if(c) c.scrollIntoView({block:'nearest'});
  scrub.value = cur; $('#pos').textContent = TL.length?`${cur+1}/${TL.length}`:'0/0';
}
function stop(){ playing=false; $('#play').textContent='▶ 播放'; if(timer){clearInterval(timer);timer=null;} }
function play(){ if(!TL.length) return; if(cur>=TL.length-1) cur=0;
  playing=true; $('#play').textContent='⏸ 暂停';
  timer=setInterval(()=>{ if(cur>=TL.length-1){stop();render();return;} cur++; render(); }, +$('#speed').value); }
$('#play').onclick=()=>playing?stop():play();
$('#step').onclick=()=>{ stop(); if(cur<TL.length-1){cur++;render();} };
$('#reset').onclick=()=>{ stop(); cur=0; render(); };
scrub.oninput=()=>{ stop(); cur=+scrub.value; render(); };
$('#speed').onchange=()=>{ if(playing){stop();play();} };

// —— 节点详情 ——
function nodeDetail(n){
  let h=`<div class="item"><div><span class="dot ${vClass(n.verdict)}"></span><b>${esc(n.access_level)}</b> · ${esc(n.label)} <span class="badge" style="background:transparent;color:${vInk(n.verdict)}">${esc(n.verdict)}</span></div>`;
  if(n.location) h+=`<div class="k">位置</div><code>${esc(n.location)}</code>`;
  if(n.probe){ const p=n.probe; h+=`<div class="k">主动探针（Stage 2）</div><div><code>${esc(p.method)}/${esc(p.tier||'')}</code> → <b style="color:${p.verdict==='proven'?'var(--verified)':(p.verdict==='refuted'?'var(--refuted)':'var(--unproven)')}">${esc(p.verdict)}</b> <span class="muted">[${esc(p.trust||'')}]</span> ${esc(p.detail||'')}</div>`;
    if(p.command) h+=`<div class="k">探针命令（可复现）</div><code>${esc(p.command)}</code>`; }
  if(n.judge) h+=`<div class="k">LLM-judge（低信任辅助·不驱动 verdict）</div><div class="muted">${esc(n.judge.detail)}</div>`;
  if(n.replay) h+=`<div class="k">可重放 PoC 配方</div><code>${esc(JSON.stringify(n.replay))}</code>`;
  if(n.evidence) h+=`<div class="k">证据 / PoC</div><div class="evbox">${esc(n.evidence)}</div>`;
  h+=`</div>`; selPanel(h);
}
svg.addEventListener('click',e=>{ const g=e.target.closest('.node'); if(!g) return;
  const n=VZ.nodes.find(x=>x.id==g.dataset.id); if(n){ setTab('节点'); nodeDetail(n); } });

// —— 侧栏 tabs ——
const TABS=['节点','凭据','战利品','漏洞','HTTP 流','安全闸'];
let curTab='节点';
function setTab(t){ curTab=t; $('#tabs').innerHTML=TABS.map(x=>`<span class="tab ${x===t?'active':''}" data-t="${x}">${x}</span>`).join('');
  if(t!=='节点') renderTab(t); }
function selPanel(h){ $('#tabbody').innerHTML=h; }
$('#tabs').addEventListener('click',e=>{ const t=e.target.dataset.t; if(t) setTab(t); if(t!=='节点') renderTab(t); else selPanel('<div class="muted">点上面攻击图里的节点查看详情。</div>'); });
function renderTab(t){
  let h='';
  if(t==='凭据'){ h = VZ.credentials.length?VZ.credentials.map(c=>`<div class="item"><span class="dot ${vClass(c.verdict)}"></span><b>${esc(c.username||'(无名)')}</b> <span class="muted">[${esc(c.kind)}]</span> <code>${esc(c.secret)}</code> <span class="k">← ${esc(c.source)} · ${esc(c.verdict)}</span></div>`).join(''):'<div class="muted">（无）</div>';
    if(m.masked) h+='<div class="k" style="margin-top:6px">secret 已脱敏（分享友好）</div>'; }
  else if(t==='战利品'){ h = VZ.loot.length?VZ.loot.map(x=>`<div class="item"><span class="muted">[${esc(x.kind)}]</span> ${esc(x.summary)}</div>`).join(''):'<div class="muted">（无）</div>'; }
  else if(t==='漏洞'){ h = VZ.findings.length?VZ.findings.map(x=>`<div class="item"><b>${esc(x.type)}</b> <span class="muted">[${esc(x.severity||'?')}]</span><div class="mono">${esc(x.reproduction)}</div></div>`).join(''):'<div class="muted">（无）</div>'; }
  else if(t==='HTTP 流'){ h = VZ.flows.length?VZ.flows.slice(0,60).map(f=>`<div class="item"><div><b>${esc(f.method)}</b> ${esc(f.url)} <span class="muted">→ ${esc(f.status)}</span></div><div class="k">可复现</div><code>${esc(f.curl)}</code></div>`).join(''):'<div class="muted">（本次无 MITM 留痕）</div>'; }
  else if(t==='安全闸'){ const ev=VZ.timeline.filter(e=>e.type==='gate'||e.type==='observer');
    h = ev.length?ev.map(e=> e.type==='gate'
      ? `<div class="item"><b style="color:var(--refuted)">${esc(e.gate)}</b> ${e.category?('<span class="muted">('+esc(e.category)+'/'+esc(e.noise)+')</span>'):''}<div><code>${esc(e.cmd)}</code></div></div>`
      : `<div class="item"><b style="color:var(--unproven)">⚠️ ${esc(e.observer)}</b><div class="muted">${esc(e.detail)}</div></div>`).join(''):'<div class="muted">（无 scope 拦截 / 审批拦截 / Observer 告警）</div>'; }
  selPanel(h);
}

// —— 主题 ——
$('#theme').onclick=()=>{ const r=document.documentElement; const cur=r.getAttribute('data-theme');
  r.setAttribute('data-theme', cur==='dark'?'light':'dark'); };

setTab('节点'); selPanel('<div class="muted">点上面攻击图里的节点查看详情。</div>'); render();
</script></body></html>
"""
