"""安全闸端到端接线单测（async + 假 sandbox/board，**不调 GLM**）。

证明 scope + 审批门真的接进了执行路径：越界命令被拦且沙箱从未被调用、合法内网横向放行、
破坏性动作按 autonomy 策略放/拦；prober 的主动探针也受 scope 约束。
`.venv/bin/python tests/safety/test_wiring.py`
"""
import sys, os, asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.config import ScopeCfg
from veritas.safety import scope as _scope
from veritas.safety.autonomy import AutonomyPolicy
from veritas.executors.web_solver import WebSolverExecutor
from veritas.executors.base import Transition
from veritas.core.prober import Prober, ProbePolicy, INCONCLUSIVE, REFUTED

# 单标签容器名在 engine 侧通常解析不到 → 放行；此处预置为确定性（不依赖真实解析器）
_scope._dns_cache.update({"lab-edge": []})

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")

class FakeSandbox:
    def __init__(self, canned="ok"):
        self.started = True
        self.calls = []
        self.canned = canned
    async def exec(self, cmd, timeout=180):
        self.calls.append(cmd)
        return 0, self.canned

class FakeBoard:
    def __init__(self):
        self.acts = []
    async def write_activity(self, task_id, opp_id, wid, step, content):
        self.acts.append(content)

SC = ScopeCfg(domains=["veritas.lab", "localhost"],
              cidrs=["127.0.0.0/8", "172.16.0.0/12"])

def gates(board, g):
    return [a for a in board.acts if a.get("gate") == g]


async def test_web_solver():
    print("[web_solver._handle] scope + 审批门")
    # approval·fail-closed（外部目标默认）
    sb = FakeSandbox(); bd = FakeBoard()
    ws = WebSolverExecutor(llm=None, sandbox=sb, scope=SC,
                           autonomy=AutonomyPolicy("approval", "deny"))
    tr = Transition()

    # 1) 越界 IP → 拦截，沙箱从未被调用，activity 记 scope_denied
    msg, trusted = await ws._handle("sandbox_exec", {"command": "nmap -sV 203.0.113.9"},
                                    tr, "t1", bd, "s0")
    check("越界命令被拒", "越界" in msg, True)
    check("越界时沙箱未被调用", sb.calls, [])
    check("activity 记 scope_denied", len(gates(bd, "scope_denied")), 1)

    # 2) 合法内网横向 → 放行，沙箱被调用
    msg, trusted = await ws._handle("sandbox_exec", {"command": "ssh root@172.20.0.5 id"},
                                    tr, "t1", bd, "s0")
    check("内网横向放行(沙箱被调用)", sb.calls, ["ssh root@172.20.0.5 id"])
    check("放行返回不可信目标数据标记", trusted, False)

    # 3) 本地但破坏性(approval) → 拦截记 needs_approval，沙箱不再被调用
    before = len(sb.calls)
    msg, trusted = await ws._handle("sandbox_exec", {"command": "rm -rf /var/www"},
                                    tr, "t1", bd, "s0")
    check("破坏性动作被拒", "审批" in msg or "拦截" in msg, True)
    check("破坏性时沙箱未新增调用", len(sb.calls), before)
    check("activity 记 needs_approval", len(gates(bd, "needs_approval")), 1)

    # 4) full_auto（靶场）→ 破坏性也放行
    sb2 = FakeSandbox(); bd2 = FakeBoard()
    ws2 = WebSolverExecutor(llm=None, sandbox=sb2, scope=SC,
                            autonomy=AutonomyPolicy("full_auto", "deny"))
    await ws2._handle("sandbox_exec", {"command": "rm -rf /var/www"}, Transition(), "t2", bd2, "s0")
    check("full_auto 破坏性放行(沙箱被调用)", sb2.calls, ["rm -rf /var/www"])

    # 5) repeat_request 也过 scope（越界 URL 拦截）
    sb3 = FakeSandbox(); bd3 = FakeBoard()
    ws3 = WebSolverExecutor(llm=None, sandbox=sb3, scope=SC, autonomy=AutonomyPolicy("full_auto"))
    msg, _ = await ws3._handle("repeat_request", {"url": "http://evil.example.com/x"},
                               Transition(), "t3", bd3, "s0")
    check("repeat_request 越界被拒", "越界" in msg, True)
    check("repeat_request 越界沙箱未调用", sb3.calls, [])


async def test_prober():
    print("[prober] 主动探针受 scope 约束（lab 策略下也拦越界）")
    pol = ProbePolicy(enabled=True, authorization="lab", budget=8)

    # 凭据重认证：目标越界 → INCONCLUSIVE、沙箱未被调用
    sb = FakeSandbox(canned="[-] STATUS_LOGON_FAILURE")
    pr = Prober(sb, pol, scope=SC)
    res = await pr.probe_credential(
        {"kind": "password", "username": "u", "secret": "pw", "props": {"target": "203.0.113.9"}}, [])
    check("越界凭据探针 INCONCLUSIVE", res.verdict, INCONCLUSIVE)
    check("越界凭据探针沙箱未调用", sb.calls, [])

    # 凭据重认证：目标域内 → 真跑（沙箱被调用），得确定性反证
    sb2 = FakeSandbox(canned="[-] STATUS_LOGON_FAILURE")
    pr2 = Prober(sb2, pol, scope=SC)
    res2 = await pr2.probe_credential(
        {"kind": "password", "username": "u", "secret": "pw", "props": {"target": "172.20.0.5"}}, [])
    check("域内凭据探针沙箱被调用", len(sb2.calls) >= 1, True)
    check("域内凭据探针得确定性反证", res2.verdict, REFUTED)

    # RCE nonce 回环：立足点向量越界 → INCONCLUSIVE、沙箱未被调用
    sb3 = FakeSandbox()
    pr3 = Prober(sb3, pol, scope=SC)
    fo_bad = {"access_level": "shell", "label": "x", "location": "203.0.113.9",
              "props": {"replay": {"command_template": "curl http://203.0.113.9/run?c={CMD}"}}}
    res3 = await pr3.probe_foothold(fo_bad, [], [])
    check("越界 RCE 探针 INCONCLUSIVE", res3.verdict, INCONCLUSIVE)
    check("越界 RCE 探针沙箱未调用", sb3.calls, [])

    # RCE：立足点向量域内 → 真跑（沙箱被调用）
    sb4 = FakeSandbox()
    pr4 = Prober(sb4, pol, scope=SC)
    fo_ok = {"access_level": "shell", "label": "x", "location": "lab-edge",
             "props": {"replay": {"command_template": "curl http://lab-edge/run?c={CMD}"}}}
    await pr4.probe_foothold(fo_ok, [], [])
    check("域内 RCE 探针沙箱被调用", len(sb4.calls) >= 1, True)


async def main():
    await test_web_solver()
    await test_prober()
    print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_wiring)")
    return 1 if _fail else 0

sys.exit(asyncio.run(main()))
