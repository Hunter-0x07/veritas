"""跨 run 策略记忆（cross-run strategy memory）：把【已验证】成功 kill chain 蒸馏成策略，
新 run 遇到相似目标时检索复用为【提示】——让引擎"越打越聪明"。

两条铁律（与项目一致）：
1. **脱敏**：策略只记【动作 / 漏洞路径 / 技能】，**绝不记跨 run 的凭据 / secret / loot 值**——
   否则把目标 A 的口令带进目标 B 的 run 既泄密又越界。故 approach 只存通用动作描述（web/ssti、
   命令执行回环、DCSync…），不存含 secret 的原始命令（AD 的 verify_command 里带域口令！）。
2. **提示永不驱动 verdict**：策略是建议、不是证据。verifier/prober 本就从真实世界底物重推 verdict，
   即便提示误导 solver，结论仍锚在真实输出上——记忆 ≠ 证明。

v1 轻量确定性：Postgres 存 + 标签/关键词检索（不上向量库）。纯函数（distill/fingerprint/
relevance）可脱离 DB 单测；capture 为薄的 DB 包装。
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from .state import rank

log = logging.getLogger("veritas.memory")

# label / finding 里常见的漏洞/手法关键词 → 归一化标签（用于指纹与检索）
_VULN_KEYWORDS = {
    "命令注入": "command-injection", "command inj": "command-injection", "cmd inj": "command-injection",
    "rce": "rce", "命令执行": "rce",
    "sqli": "sqli", "sql 注入": "sqli", "sql注入": "sqli", "union": "sqli",
    "ssti": "ssti", "lfi": "lfi", "文件包含": "lfi", "路径遍历": "lfi",
    "ssrf": "ssrf", "xxe": "xxe", "xss": "xss", "idor": "idor", "越权": "idor",
    "open redirect": "open-redirect", "开放重定向": "open-redirect",
    "kerberoast": "kerberoast", "asrep": "asrep-roast", "dcsync": "dcsync",
    "pivot": "lateral-pivot", "横向": "lateral-pivot", "ssh": "ssh-lateral",
    "提权": "privesc", "privesc": "privesc", "sudo": "privesc",
}


def _norm_vulns(text: str) -> list[str]:
    t = (text or "").lower()
    return sorted({tag for kw, tag in _VULN_KEYWORDS.items() if kw in t})


def _host_tag(target: str) -> str:
    """目标 host 当 app 签名标签（http://lab-edge:8080 → app:lab-edge）。"""
    h = ""
    try:
        h = urlsplit(target if "://" in (target or "") else "//" + (target or "")).hostname or ""
    except ValueError:
        h = ""
    return f"app:{h.lower()}" if h else ""


def _approach(replay, access_level: str) -> str:
    """从 replay 配方蒸馏【通用动作描述】——脱敏：不保留原始命令（可能含域口令/hash），只留手法骨架。"""
    r = replay if isinstance(replay, dict) else {}
    pt = r.get("probe_type")
    if pt:
        inj = r.get("injection") or "query"
        return f"web/{pt}（注入位置 {inj}）"
    if r.get("command_template"):
        return "命令执行回环（RCE / 命令注入）"
    if r.get("verify_command"):
        return "DCSync 抓域 hash（域凭据路径）"
    return f"达到 {access_level}（approach 未记录）"


def distill_strategy(target: str, footholds, findings, activity=None) -> "dict | None":
    """把一个 run 的成功结果蒸馏成一条策略（纯函数）。无 verified 进展 → None。
    只取 verified 且 rank>external 的立足点（成功才成策略）；steps/tags/summary 全脱敏。"""
    foots = [dict(f) for f in (footholds or [])]
    finds = [dict(x) for x in (findings or [])]
    # finding_id/foothold_id → type，给步骤匹配漏洞类型
    find_by_fid = {}
    find_types = []
    for fd in finds:
        ft = (fd.get("type") or "").strip().lower()
        if ft:
            find_types.append(ft)
            if fd.get("foothold_id") is not None:
                find_by_fid[fd["foothold_id"]] = ft

    won = sorted([f for f in foots if f.get("verdict") == "verified" and rank(f.get("access_level") or "") > rank("external")],
                 key=lambda f: rank(f.get("access_level") or ""))
    if not won:
        return None

    steps = []
    tags = set()
    for f in won:
        access = f.get("access_level") or ""
        label = f.get("label") or ""
        props = f.get("props") or {}
        vuln = find_by_fid.get(f.get("id")) or (_norm_vulns(label) or [""])[0]
        steps.append({"access_level": access, "label": label, "vuln_type": vuln,
                      "approach": _approach(props.get("replay"), access)})
        tags.add(access)
        if vuln:
            tags.add(vuln)
        tags.update(_norm_vulns(label))

    for ft in find_types:
        tags.update(_norm_vulns(ft) or [ft])
    ht = _host_tag(target)
    if ht:
        tags.add(ht)
    max_access = won[-1].get("access_level") or ""
    path = "→".join(s["access_level"] for s in steps)
    tags.add(f"path:{path}")

    first_vuln = next((s["vuln_type"] for s in steps if s["vuln_type"]), "")
    summary = (f"{first_vuln}：" if first_vuln else "") + " → ".join(s["access_level"] for s in steps)
    return {"tags": sorted(t for t in tags if t), "summary": summary, "steps": steps, "max_access": max_access}


def fingerprint_tags(target: str, assets=None, findings=None) -> list[str]:
    """给【检索】算当前目标的粗指纹标签：target host + 已知服务（asset props）+ 已发现漏洞类型。"""
    tags = set()
    ht = _host_tag(target)
    if ht:
        tags.add(ht)
    for a in (assets or []):
        a = dict(a)
        props = a.get("props") or {}
        for s in (props.get("services") or []):
            tags.add(str(s).lower())
        if a.get("type"):
            tags.add(str(a["type"]).lower())
    for fd in (findings or []):
        fd = dict(fd)
        ft = (fd.get("type") or "").strip().lower()
        if ft:
            tags.update(_norm_vulns(ft) or [ft])
    return sorted(t for t in tags if t)


def relevance(query_tags, strat_tags) -> int:
    """标签重叠计分（检索排序用）。path:/app: 这类强信号在 distill 里已入标签，重叠即加分。"""
    return len(set(t.lower() for t in (query_tags or [])) & set(t.lower() for t in (strat_tags or [])))


async def capture(board, task_id: str, target: str) -> "int | None":
    """run 结束时蒸馏并落库（薄 DB 包装）。返回新 strategy id 或 None（无成功进展/异常）。"""
    try:
        footholds = await board.footholds(task_id)
        findings = await board.findings(task_id)
        strat = distill_strategy(target, footholds, findings)
        if strat is None:
            return None
        sid = await board.add_strategy(task_id, target, strat["tags"], strat["summary"],
                                       strat["steps"], strat["max_access"])
        log.info("跨 run 策略记忆：已蒸馏 1 条策略（tags=%s · max=%s）", strat["tags"][:6], strat["max_access"])
        return sid
    except Exception as e:  # noqa: BLE001  记忆失败不应影响主流程
        log.warning("策略记忆蒸馏失败（不影响本次 run 结论）: %s", e)
        return None


def format_hints(rows, max_hints: int = 3) -> str:
    """把检索到的策略记录格式化成注入给 solver 的提示块（脱敏·明确仅供参考）。"""
    rows = list(rows or [])[:max_hints]
    if not rows:
        return ""
    lines = ["# 舰队历史策略（跨 run 记忆·仅供参考，务必亲自验证，绝不据此直接上报战果）"]
    for r in rows:
        r = dict(r)
        appr = "；".join(s.get("approach", "") for s in (r.get("steps") or []) if s.get("approach"))
        lines.append(f"- 相似目标曾 {r.get('summary','')}（最高 {r.get('max_access','')}）"
                     + (f"；手法：{appr}" if appr else ""))
    return "\n".join(lines)
