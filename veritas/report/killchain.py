"""Kill chain 报告：攻击路径（立足点推进）+ 战利品 + 漏洞证据。"""
from __future__ import annotations

import pathlib
import time

from ..core.state import meets_goal, rank


async def generate(board, task_id: str, target: str, goal: str, out_root: str = "veritas_runs"):
    footholds = await board.footholds(task_id)
    creds = await board.credentials(task_id)
    loots = await board.loot(task_id)
    findings = await board.findings(task_id)
    max_acc = await board.max_access(task_id)
    reached = meets_goal(max_acc, goal)

    run_dir = pathlib.Path(out_root) / task_id
    run_dir.mkdir(parents=True, exist_ok=True)
    chain = sorted(footholds, key=lambda f: rank(f["access_level"]))

    lines = [
        "# Veritas Kill Chain 报告", "",
        f"- 目标: `{target}`",
        f"- Goal: `{goal}` · 达成: {'✅ 是' if reached else '❌ 否'}（最终 `{max_acc}`）",
        f"- 任务: `{task_id}` · {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
        "## Kill Chain（访问权限推进路径）", "",
        "  →  ".join(f"`{f['access_level']}`" for f in chain) or "（无）", "",
    ]
    for f in chain:
        lines.append(f"- **{f['access_level']}** · {f['label']}")

    lines += ["", "## 战利品 · 凭据", ""]
    lines += [f"- [{c['kind']}] `{c['username']}:{c['secret']}` ← {c['source']}" for c in creds] or ["- （无）"]
    lines += ["", "## 战利品 · 数据", ""]
    lines += [f"- [{lo['kind']}] {lo['summary']}" for lo in loots] or ["- （无）"]
    lines += ["", "## 漏洞（可走的边）", ""]
    lines += [f"- [{fd['severity'] or '?'}] {fd['type']} — {fd['reproduction']}" for fd in findings] or ["- （无）"]
    lines += ["", "---",
              "> M0：执行器为脚本化 mock 桩，用于证明攻击图推进闭环；真实执行器 M1+ 逐个替换。"]

    (run_dir / "killchain.md").write_text("\n".join(lines), encoding="utf-8")
    return run_dir / "killchain.md", reached, max_acc
