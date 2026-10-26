"""killchain_viz 确定性单测（纯 stdlib）。合成一段【形如真实 AD/横向 run】的底物，验 build_payload
分类/过滤/统计/脱敏正确、export_html 产出自包含单文件。`.venv/bin/python tests/report/test_killchain_viz.py`
"""
import sys, os, tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.report import killchain_viz as viz

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")


def sample():
    """形如真实 run：external→shell→root→domain_admin（AD）+ 一条 unproven(web)+一条 refuted(伪 root)。"""
    footholds = [
        {"id": 1, "label": "external@target", "access_level": "external", "location": "http://lab-edge:8080",
         "verdict": "verified", "props": {}, "created_at": 1000},
        {"id": 2, "label": "shell@lab-member", "access_level": "shell", "location": "lab-member",
         "verdict": "verified", "created_at": 2000,
         "props": {"evidence": "uid=0(root) gid=0(root)", "replay": {"command_template": "curl -s -G 'http://lab-member/ping' --data-urlencode 'host=127.0.0.1; {CMD}'"},
                   "probe": {"method": "nonce_echo", "tier": "low", "verdict": "proven", "trust": "deterministic", "detail": "nonce 回显且 uid=0", "command": "curl ... echo vzABC; id"}}},
        {"id": 3, "label": "root@lab-member", "access_level": "root", "location": "lab-member",
         "verdict": "verified", "props": {"evidence": "uid=0(root)"}, "created_at": 2500},
        {"id": 4, "label": "domain_admin@lab-dc", "access_level": "domain_admin", "location": "lab-dc.veritas.lab",
         "verdict": "verified", "created_at": 4000,
         "props": {"evidence": "labadmin:500:...:...:::", "probe": {"method": "re_dcsync", "tier": "high", "verdict": "proven", "trust": "deterministic", "detail": "重跑 DCSync 命中 RID-500", "command": "impacket-secretsdump ... -just-dc"}}},
        {"id": 5, "label": "web_user@app", "access_level": "web_user", "location": "http://lab-edge:8080/app",
         "verdict": "unproven", "created_at": 1800,
         "props": {"probe_judge": {"detail": "LLM-judge：unclear", "trust": "llm-judged"}}},
        {"id": 6, "label": "root@lab-member(伪)", "access_level": "root", "location": "lab-member",
         "verdict": "refuted", "created_at": 2600,
         "props": {"probe": {"method": "nonce_echo", "tier": "low", "verdict": "refuted", "trust": "deterministic", "detail": "nonce 未回显"}}},
    ]
    edges = [
        {"src": 1, "dst": 2, "rel": "exploits"}, {"src": 2, "dst": 3, "rel": "privesc"},
        {"src": 3, "dst": 4, "rel": "pivots_to"}, {"src": 1, "dst": 5, "rel": "exploits"},
        {"src": 2, "dst": 6, "rel": "privesc"},
        {"src": 3, "dst": 999, "rel": "pivots_to"},   # 指向非立足点 → 应被过滤
    ]
    creds = [
        {"id": 1, "kind": "password", "username": "webdev", "secret": "SuperSecret123", "source": "config.ini", "verdict": "verified"},
        {"id": 2, "kind": "hash", "username": "svc-sql", "secret": "aad3b435b51404ee", "source": "kerberoast", "verdict": "verified"},
        {"id": 3, "kind": "password", "username": "fakeuser", "secret": "wrongpw", "source": "guess", "verdict": "refuted"},
    ]
    loot = [{"kind": "data", "summary": "config.ini 域凭据"}, {"kind": "flag", "summary": "krbtgt NT hash"}]
    findings = [{"type": "rce", "severity": "critical", "reproduction": "/ping?host=;id"},
                {"type": "sqli", "severity": "high", "reproduction": "id=1' OR 1=1--"}]
    activity = [
        {"worker_id": "s0", "content": {"kind": "initial_access", "ok": True, "summary": "edge recon"}, "created_at": 900},
        {"worker_id": "s0", "content": {"exec": "curl -s 'http://lab-member/ping?host=127.0.0.1;id'", "rc": 0, "out": "uid=0(root)"}, "created_at": 1900},
        {"worker_id": "s0", "content": {"exec": "curl ... echo vzABC; id", "rc": 0, "out": "vzABC uid=0(root)", "probe": "nonce_echo", "verdict": "proven", "tier": "low", "trust": "deterministic", "subject": "foothold:shell@lab-member"}, "created_at": 2050},
        {"worker_id": "s0", "content": {"exec": "nmap -p- 203.0.113.9", "rc": 1, "out": "[autonomy] needs_approval", "gate": "needs_approval", "category": "broad_scan", "noise": "medium"}, "created_at": 2100},
        {"worker_id": "s0", "content": {"exec": "curl http://198.51.100.9/", "rc": 1, "out": "[scope] denied", "gate": "scope_denied"}, "created_at": 2150},
        {"worker_id": "s0", "content": {"exec": "curl ... echo vzBAD; id", "rc": 1, "out": "(static)", "probe": "nonce_echo", "verdict": "refuted", "tier": "low", "trust": "deterministic", "subject": "foothold:root@lab-member(伪)"}, "created_at": 2600},
        {"worker_id": "s0", "content": {"exec": "impacket-secretsdump ... -just-dc", "rc": 0, "out": "labadmin:500:...", "probe": "re_dcsync", "verdict": "proven", "tier": "high", "trust": "deterministic", "subject": "foothold:domain_admin@lab-dc"}, "created_at": 3900},
        {"worker_id": "observer", "content": {"observer": "needs_approval", "detail": "1 条破坏性动作因审批门被拦（broad_scan）"}, "created_at": 4200},
    ]
    flows = [
        {"method": "GET", "url": "http://lab-member/ping?host=127.0.0.1;id", "host": "lab-member", "status": 200,
         "req_headers": {"User-Agent": "curl", "Host": "lab-member"}, "req_body": None, "resp_body": "uid=0(root)"},
        {"method": "POST", "url": "http://lab-edge:8080/login", "host": "lab-edge", "status": 302,
         "req_headers": {"Content-Type": "application/x-www-form-urlencoded"}, "req_body": "u=a&p=b", "resp_body": "redirect"},
    ]
    return footholds, edges, creds, loot, findings, activity, flows


def main():
    global _fail
    f, e, c, lo, fi, ac, fl = sample()
    p = viz.build_payload("task_demo01", "http://lab-edge:8080", "domain_admin", "domain_admin", "live",
                          f, e, c, lo, fi, ac, fl)

    print("[build_payload] 结构 / 过滤 / 分类")
    check("节点数", len(p["nodes"]), 6)
    check("指向非立足点的边被过滤", len(p["edges"]), 5)
    check("goal 达成", p["meta"]["reached"], True)
    nd = {n["id"]: n for n in p["nodes"]}
    check("root 节点 rank", nd[3]["rank"], 6)
    check("domain_admin rank", nd[4]["rank"], 7)
    check("probe 被 slim（domain_admin）", nd[4]["probe"]["verdict"], "proven")
    check("judge 透出（web_user unproven）", bool(nd[5]["judge"]), True)
    check("replay 保留（shell）", "command_template" in (nd[2]["replay"] or {}), True)

    print("[build_payload] 时间线分类")
    types = {}
    for ev in p["timeline"]:
        types[ev["type"]] = types.get(ev["type"], 0) + 1
    check("fleet 事件", types.get("fleet"), 1)
    check("exec 事件", types.get("exec"), 1)      # 仅 1 条纯 exec（其余带 probe/gate 归类走）
    check("probe 事件", types.get("probe"), 3)
    check("gate 事件", types.get("gate"), 2)
    check("observer 事件", types.get("observer"), 1)

    print("[build_payload] 统计 / 脱敏")
    s = p["stats"]
    check("verified", s["verified"], 4)
    check("refuted", s["refuted"], 1)
    check("unproven", s["unproven"], 1)
    check("scope_denied", s["scope_denied"], 1)
    check("needs_approval", s["needs_approval"], 1)
    check("observer_flags", s["observer_flags"], 1)
    check("findings", s["findings"], 2)
    check("loot", s["loot"], 2)
    secrets = [cr["secret"] for cr in p["credentials"]]
    check("凭据明文已脱敏（不含真实 secret）", all("SuperSecret123" not in x and "aad3b435b51404ee" not in x for x in secrets), True)
    check("脱敏为圆点", all(set(x) <= {"•"} for x in secrets if x), True)
    check("masked 标记", p["meta"]["masked"], True)

    print("[export_html] 自包含单文件")
    out = os.path.join(tempfile.mkdtemp(), "killchain.html")
    viz.export_html(p, out, title="Veritas Demo")
    html = open(out, encoding="utf-8").read()
    check("文件已写", os.path.exists(out), True)
    check("含 SVG 画布", '<svg id="svg"' in html, True)
    check("含回放控件", 'id="play"' in html, True)
    check("payload 注入", 'const VZ =' in html and "task_demo01" in html, True)
    check("标题替换", "<title>Veritas Demo</title>" in html, True)
    check("HTML 里也不含真实 secret", "SuperSecret123" not in html, True)
    check("占位符已全部替换", ("__VZ_PAYLOAD__" not in html and "__VZ_TITLE__" not in html), True)

    print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_killchain_viz)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
