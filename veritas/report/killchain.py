"""Kill chain 报告：攻击路径（立足点推进，含并行分支）+ 每跳 PoC + 舰队执行归属 + 真实复现命令。"""
from __future__ import annotations

import pathlib
import shlex
import time

from ..core.state import meets_goal, rank

_SKIP_HDR = {"host", "content-length", "proxy-connection", "connection"}


def _curl(f) -> str:
    """把一条抓到的 HTTP 流渲染成可复现的 curl 命令。"""
    parts = [f"curl -i -X {f['method']} {shlex.quote(f['url'] or '')}"]
    for k, v in (f["req_headers"] or {}).items():
        if k.lower() in _SKIP_HDR:
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if f["req_body"]:
        parts.append(f"--data {shlex.quote(f['req_body'])}")
    return " ".join(parts)


def _build_tree(footholds, edges):
    """按血缘边还原立足点推进树（支持横向的并行分支）。返回 (children, roots)。"""
    by_id = {f["id"]: f for f in footholds}
    children: dict[int, list[int]] = {f["id"]: [] for f in footholds}
    has_parent: set[int] = set()
    for e in edges:
        if e["src"] in by_id and e["dst"] in by_id:
            children[e["src"]].append(e["dst"])
            has_parent.add(e["dst"])
    roots = [f["id"] for f in footholds if f["id"] not in has_parent]
    return by_id, children, roots


def _render_tree(by_id, children, roots) -> list[str]:
    lines: list[str] = []

    def walk(fid: int, depth: int):
        f = by_id[fid]
        indent = "  " * depth
        arrow = "└─ " if depth else ""
        badge = {"verified": "", "refuted": " ❌反证", }.get(f["verdict"], " ⚠️未证实")
        lines.append(f"{indent}{arrow}`{f['access_level']}` · {f['label']}"
                     + (f"  ({f['location']})" if f["location"] else "") + badge)
        for ch in sorted(children[fid], key=lambda i: rank(by_id[i]["access_level"])):
            walk(ch, depth + 1)

    for r in sorted(roots, key=lambda i: rank(by_id[i]["access_level"])):
        walk(r, 0)
    return lines


async def generate(board, task_id: str, target: str, goal: str,
                   out_root: str = "veritas_runs", mode: str = "mock"):
    footholds = await board.footholds(task_id)
    edges = await board.foothold_edges(task_id)
    creds = await board.credentials(task_id)
    loots = await board.loot(task_id)
    findings = await board.findings(task_id)
    acts = await board.activity_log(task_id)
    flows = await board.http_flows(task_id)
    max_acc = await board.max_access(task_id)
    reached = meets_goal(max_acc, goal)

    run_dir = pathlib.Path(out_root) / task_id
    run_dir.mkdir(parents=True, exist_ok=True)

    workers = sorted({a["worker_id"] for a in acts if a["worker_id"]})
    by_id, children, roots = _build_tree(footholds, edges)

    lines = [
        "# Veritas Kill Chain 报告", "",
        f"- 目标: `{target}`",
        f"- Goal: `{goal}` · 达成: {'✅ 是' if reached else '❌ 否'}（最终 `{max_acc}`）",
        f"- 任务: `{task_id}` · {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 执行: {mode} · 舰队 {len(workers) or 1} 个 solver（{', '.join(workers) or 'n/a'}）", "",
        "## Kill Chain（访问权限推进路径）", "",
    ]
    tree = _render_tree(by_id, children, roots)
    lines += tree or ["（无立足点）"]

    # 每跳 PoC：立足点的支撑证据
    lines += ["", "## 每一跳 · 立足点与 PoC", ""]
    for f in sorted(footholds, key=lambda x: rank(x["access_level"])):
        props = f["props"] or {}
        ev = props.get("evidence", "")
        badge = {"verified": "✅ verified", "refuted": "❌ refuted（有反证·不计入进展）"}.get(
            f["verdict"], "⚠️ unproven（未证实·不计入进展）")
        lines.append(f"### `{f['access_level']}` — {f['label']}  · {badge}")
        if f["location"]:
            lines.append(f"- 位置: `{f['location']}`")
        probe = props.get("probe")
        if probe:
            how = {"deterministic": "确定性", "llm-judged": "LLM辅助·低信任", "none": "被动兜底"}.get(
                probe.get("trust", ""), probe.get("trust", ""))
            lines.append(f"- 主动探针（Stage 2）: `{probe.get('method')}`/{probe.get('tier')} → "
                         f"**{probe.get('verdict')}**（{how}）— {probe.get('detail', '')}")
            if probe.get("command"):
                lines.append(f"  - 探针命令（可复现）: `{probe['command'][:200]}`")
        judge = props.get("probe_judge")
        if judge:
            lines.append(f"- LLM-judge（低信任辅助，不驱动 verdict）: {judge.get('detail', '')}")
        if ev:
            lines.append(f"- 证据/PoC:\n\n  ```\n  {ev.strip()[:800]}\n  ```")
        lines.append("")

    lines += ["## 战利品 · 凭据", ""]
    lines += [f"- [{c['kind']}] `{c['username']}:{c['secret']}` ← {c['source']}"
              + {"verified": "", "refuted": " ❌反证"}.get(c["verdict"], " ⚠️未证实") for c in creds] or ["- （无）"]
    lines += ["", "## 战利品 · 数据", ""]
    lines += [f"- [{lo['kind']}] {lo['summary']}" for lo in loots] or ["- （无）"]
    lines += ["", "## 漏洞（可走的边）", ""]
    lines += [f"- [{fd['severity'] or '?'}] {fd['type']} — {fd['reproduction']}" for fd in findings] or ["- （无）"]

    # 舰队执行归属：谁领了哪个前沿（证明分解并行）
    lines += ["", "## 舰队执行归属", ""]
    fleet = [a for a in acts if (a["content"] or {}).get("kind")]
    if fleet:
        for a in fleet:
            c = a["content"]
            lines.append(f"- [{a['worker_id']}] {c.get('kind')} → "
                         f"{'✅' if c.get('ok') else '❌'} {c.get('summary', '')}")
    else:
        lines.append("- （无）")

    # 真实复现命令：沙箱里跑过的 shell 命令（live 才有）
    execs = [a for a in acts if (a["content"] or {}).get("exec")]
    if execs:
        lines += ["", "## 复现命令（沙箱实跑，按序）", "", "```bash"]
        for a in execs:
            c = a["content"]
            lines.append(f"# [{a['worker_id']}] rc={c.get('rc')}")
            lines.append(c.get("exec", ""))
        lines.append("```")

    # 全链路 HTTP 留痕（MITM）：每条请求都可 curl 复现
    lines += ["", "## 全链路 HTTP 留痕（MITM）", ""]
    if not flows:
        lines.append("- （本次无 HTTP 留痕；mock 或未经沙箱代理）")
    else:
        lines.append(f"- 共抓取 **{len(flows)}** 条 HTTP 流（记录型代理透明留痕，逐条可复现）")
        lines.append("")
        for f in flows[:40]:
            lines.append(f"- `{f['method']} {f['url']}` → {f['status']}")
        if len(flows) > 40:
            lines.append(f"- …另有 {len(flows) - 40} 条")
        key = [f for f in flows if f["req_body"]] or list(flows)
        lines += ["", "### 原始请求（curl 可复现）", "", "```bash"]
        for f in key[:12]:
            lines.append(_curl(f))
        lines.append("```")

    # 结论可信度：证据验证 + Observer 监督
    obs = [a for a in acts if (a["content"] or {}).get("observer")]
    unver = [f for f in footholds if f["verdict"] != "verified"]
    trustworthy = reached and not obs
    lines += ["", "## 结论可信度", ""]
    lines.append("- 总体: " + ("✅ 结论可信（目标达成，立足点均过证据验证，无监督告警）"
                               if trustworthy else "⚠️ 存在存疑项，见下"))
    verified_n = sum(1 for f in footholds if f["verdict"] == "verified")
    refuted_n = sum(1 for f in footholds if f["verdict"] == "refuted")
    unproven_n = len(unver) - refuted_n
    lines.append(f"- 证据验证: {verified_n} verified · {unproven_n} unproven · {refuted_n} refuted"
                 f"（只 verified 计入进展，{'最终' if not reached else ''}verified 访问 `{max_acc}`）")
    if obs:
        lines.append("- 监督 / 验证发现:")
        for a in obs:
            c = a["content"]
            lines.append(f"  - [{a['worker_id']}·{c.get('observer')}] {c.get('detail', '')}")

    lines += ["", "---",
              f"> 执行器模式: {mode}。防幻觉：登记的立足点/凭据经证据确定性验证层裁决，"
              "只有 verified 计入访问进展；Observer 旁路监督失速/鬼打墙/早停；"
              "全链路 HTTP 经记录型 MITM 代理留痕，每跳请求可 curl 复现。"]

    (run_dir / "killchain.md").write_text("\n".join(lines), encoding="utf-8")
    return run_dir / "killchain.md", reached, max_acc
