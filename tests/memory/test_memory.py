"""跨 run 策略记忆 · 确定性单测（纯 stdlib，`.venv/bin/python tests/memory/test_memory.py`）。
验 distill/fingerprint/relevance/format_hints + capture 编排 + 脱敏（跨 run 不泄 secret）。
"""
import sys, os, asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.core import memory as m

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")


def ad_chain():
    """形如真实 AD run：external→shell(命令注入)→root→domain_admin(DCSync)，带一条 refuted 噪声。
    注意 verify_command 里【故意塞了假口令 PASSWORD】——用来验脱敏绝不外泄。"""
    foots = [
        {"id": 1, "access_level": "external", "verdict": "verified", "label": "external@t", "props": {}},
        {"id": 2, "access_level": "shell", "verdict": "verified", "label": "shell@lab-edge 命令注入",
         "props": {"replay": {"command_template": "curl -s -G 'http://lab-edge/ping' --data-urlencode 'h=1;{CMD}'"}}},
        {"id": 3, "access_level": "root", "verdict": "verified", "label": "root@lab-edge", "props": {}},
        {"id": 4, "access_level": "domain_admin", "verdict": "verified", "label": "da@lab-dc svc-sql",
         "props": {"replay": {"verify_command": "impacket-secretsdump veritas.lab/webdev:PASSWORD@lab-dc -just-dc"}}},
        {"id": 9, "access_level": "root", "verdict": "refuted", "label": "root@lab-edge(伪)", "props": {}},
    ]
    finds = [{"type": "command-injection", "foothold_id": 2}, {"type": "kerberoast", "foothold_id": 4}]
    return foots, finds


print("[distill_strategy]")
foots, finds = ad_chain()
s = m.distill_strategy("http://lab-edge:8080", foots, finds)
check("出策略（非 None）", s is not None, True)
check("只收 verified 且 >external（4 verified 里去掉 external+refuted → 3 步）", len(s["steps"]), 3)
check("步骤按 rank 升序", [x["access_level"] for x in s["steps"]], ["shell", "root", "domain_admin"])
check("tags 含漏洞/路径/app", all(t in s["tags"] for t in ["command-injection", "kerberoast", "app:lab-edge"]), True)
check("summary 带首漏洞+路径", s["summary"], "command-injection：shell → root → domain_admin")
check("max_access", s["max_access"], "domain_admin")
check("★脱敏：假口令 PASSWORD 绝不出现在策略里", "PASSWORD" not in str(s), True)
check("★脱敏：DCSync 原始命令不落（只留通用手法）", "secretsdump" not in str(s), True)
check("domain_admin 步 approach 为通用描述", s["steps"][-1]["approach"], "DCSync 抓域 hash（域凭据路径）")

print("[distill_strategy 边界]")
check("无 verified>external → None",
      m.distill_strategy("x", [{"id": 1, "access_level": "external", "verdict": "verified", "label": "e", "props": {}}], []), None)
check("全 refuted → None",
      m.distill_strategy("x", [{"id": 1, "access_level": "shell", "verdict": "refuted", "label": "s", "props": {}}], []), None)
check("空 → None", m.distill_strategy("x", [], []), None)

print("[fingerprint_tags / relevance]")
fp = m.fingerprint_tags("http://lab-edge:8080", [{"type": "host", "props": {"services": ["ssh", "http"]}}],
                        [{"type": "sqli"}])
check("指纹含 app/服务/漏洞", all(t in fp for t in ["app:lab-edge", "ssh", "http", "sqli"]), True)
check("relevance 重叠计数", m.relevance(["command-injection", "app:lab-edge", "zzz"], s["tags"]), 2)
check("relevance 大小写无关", m.relevance(["COMMAND-INJECTION"], ["command-injection"]), 1)

print("[format_hints]")
block = m.format_hints([{"summary": s["summary"], "max_access": "domain_admin", "steps": s["steps"]}], 3)
check("提示块有'仅供参考'纪律", "仅供参考" in block, True)
check("提示块不泄 secret", "PASSWORD" not in block, True)
check("空输入 → 空串", m.format_hints([], 3), "")

print("[code-review 修复①：_norm_vulns 词边界，不吃子串误命中]")
check("'web source leak' 不误标 rce", "rce" not in m._norm_vulns("web source leak"), True)
check("'resource exhaustion' 不误标 rce", "rce" not in m._norm_vulns("resource exhaustion"), True)
check("'sshd service' 不误标 ssh-lateral", "ssh-lateral" not in m._norm_vulns("sshd service"), True)
check("'got RCE shell' 仍标 rce（独立词）", "rce" in m._norm_vulns("got RCE shell"), True)
check("'command injection /ping' 仍标 command-injection（前缀）", "command-injection" in m._norm_vulns("command injection /ping"), True)
check("'union select 1' 标 sqli", "sqli" in m._norm_vulns("union select 1"), True)
check("'ssh 横向' 标 ssh-lateral+lateral-pivot",
      {"ssh-lateral", "lateral-pivot"} <= set(m._norm_vulns("ssh 横向")), True)

print("[code-review 修复③：_approach 按 label 区分 SSH pivot]")
check("ssh 横向 pivot 不误标 RCE",
      m._approach({"command_template": "sshpass ... {CMD}"}, "shell", "ssh 横向: deploy@internal"),
      "SSH 横向 pivot（凭据复用到内网主机）")
check("web 命令注入仍标 RCE",
      m._approach({"command_template": "curl ...{CMD}"}, "root", "root@edge 命令注入"),
      "命令执行回环（RCE / 命令注入）")


class StubBoard:
    def __init__(self, foots, finds):
        self.foots, self.finds, self.added = foots, finds, []
    async def footholds(self, t): return self.foots
    async def findings(self, t): return self.finds
    async def add_strategy(self, task_id, target, tags, summary, steps, max_access):
        self.added.append({"tags": tags, "summary": summary, "steps": steps, "max_access": max_access})
        return 42


async def _capture_tests():
    print("[capture 编排（stub board）]")
    sb = StubBoard(*ad_chain())
    sid = await m.capture(sb, "task_x", "http://lab-edge:8080")
    check("capture 返回新 id", sid, 42)
    check("capture 落 1 条", len(sb.added), 1)
    check("capture 落的记录脱敏", "PASSWORD" not in str(sb.added), True)
    sb2 = StubBoard([{"id": 1, "access_level": "external", "verdict": "verified", "label": "e", "props": {}}], [])
    check("无成功进展 → 不落、返 None", await m.capture(sb2, "t", "x"), None)
    check("无成功进展 → added 空", len(sb2.added), 0)

def main():
    asyncio.run(_capture_tests())
    print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_memory)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
