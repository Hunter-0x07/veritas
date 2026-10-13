"""报告与结束交付。即便无发现也生成报告（含覆盖度、事实、无发现结论）——可审计。"""
from __future__ import annotations

import json
import pathlib
import time

from .board import Board


async def generate(board: Board, task_id: str, target: str, out_root: str = "veritas_runs") -> pathlib.Path:
    done, total = await board.coverage(task_id)
    facts = await board.nodes_by_kind(task_id, "fact")
    findings = await board.nodes_by_kind(task_id, "finding")
    confirmed = [f for f in findings if f["state"] == "confirmed"]

    run_dir = pathlib.Path(out_root) / task_id
    run_dir.mkdir(parents=True, exist_ok=True)

    findings_json = [{"state": f["state"], **f["payload"]} for f in findings]
    (run_dir / "findings.json").write_text(
        json.dumps(findings_json, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "run.json").write_text(json.dumps({
        "task_id": task_id, "target": target, "coverage": f"{done}/{total}",
        "facts": len(facts), "findings": len(findings), "confirmed": len(confirmed),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    def by(state):
        return [f for f in findings if f["state"] == state]
    refuted, insufficient = by("refuted"), by("insufficient")

    lines = [
        f"# Veritas 渗透测试报告", "",
        f"- 目标: `{target}`", f"- 任务: `{task_id}`",
        f"- 资产覆盖度: **{done}/{total}**",
        f"- 裁决: **{len(confirmed)}** 确认 · {len(refuted)} 证伪 · {len(insufficient)} 证据不足", "",
        "## 已确认漏洞", "",
    ]
    if confirmed:
        for f in confirmed:
            p = f["payload"]
            ev = p.get("evidence", {}) or {}
            sev = f"[{p.get('severity')}] " if p.get("severity") else ""
            lines += [f"### {sev}{p.get('title') or p.get('type')}  @ `{p.get('asset','?')}`",
                      f"- 类型: `{p.get('type')}` · oracle: `{ev.get('oracle') or '-'}`",
                      f"- 复现: {p.get('reproduction','')}", ""]
    else:
        lines += ["> 本次测试在覆盖范围内**未确认**任何漏洞。", ""]

    if refuted or insufficient:
        lines += ["## 其他裁决（可审计）", ""]
        for f in refuted + insufficient:
            p = f["payload"]
            lines += [f"- **{f['state']}** · {p.get('title') or p.get('type')} @ `{p.get('asset','?')}` "
                      f"— {p.get('reproduction','') or (p.get('evidence',{}) or {}).get('error','')}"]
        lines += [""]

    lines += ["## 已核验事实", ""]
    lines += [f"- {f['payload'].get('summary','')}" for f in facts] or ["- （无）"]
    lines += ["", "## 说明",
              "- 所有漏洞须经确定性验证（W2）才记为已确认；未达证据阈值者记为 Insufficient。",
              "- 本报告由 Veritas 自动生成，仅用于已授权范围内的测试。"]
    report_path = run_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
