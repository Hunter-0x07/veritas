"""Kill chain 报告：攻击路径（立足点推进，含并行分支）+ 每跳 PoC + 舰队执行归属 + 真实复现命令。"""
from __future__ import annotations

import pathlib
import time

from ..core.state import meets_goal, rank


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
        lines.append(f"{indent}{arrow}`{f['access_level']}` · {f['label']}"
                     + (f"  ({f['location']})" if f["location"] else ""))
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
        ev = (f["props"] or {}).get("evidence", "")
        lines.append(f"### `{f['access_level']}` — {f['label']}")
        if f["location"]:
            lines.append(f"- 位置: `{f['location']}`")
        if ev:
            lines.append(f"- 证据/PoC:\n\n  ```\n  {ev.strip()[:800]}\n  ```")
        lines.append("")

    lines += ["## 战利品 · 凭据", ""]
    lines += [f"- [{c['kind']}] `{c['username']}:{c['secret']}` ← {c['source']}" for c in creds] or ["- （无）"]
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

    lines += ["", "---",
              f"> 执行器模式: {mode}。证据纪律：登记的立足点/凭据均由 solver 的真实输出支撑；"
              "结论可信性与 MITM 全链路留痕见 M4 后续刀。"]

    (run_dir / "killchain.md").write_text("\n".join(lines), encoding="utf-8")
    return run_dir / "killchain.md", reached, max_acc
