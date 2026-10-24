"""安全闸 · 真 Kali 沙箱集成测试（真 Sandbox + 真 Docker 容器，**不调 GLM**）。

比 test_wiring（假沙箱）更硬：用真实 `runtime.Sandbox` 驱动真 Docker 容器，**canary marker 法**
硬证"被拒命令绝不在容器里执行"——每条被拒命令前缀 `touch /tmp/<marker>`，若安全闸生效则
`sandbox.exec` 根本不会被调用、marker 不会出现在真容器里；一条【放行】对照命令的 marker 则确实
出现（证明路径在该放行时真会执行，ABSENT 不是因为沙箱坏了而假过）。

需 Docker + `veritas-sandbox:latest`；缺任一则优雅 SKIP（退出 0）。board 用假对象（只记 activity），
**不需要 postgres**。网络用 host（被拒命令本就不该跑、放行对照只用 touch/echo，不依赖外网）。
运行：`.venv/bin/python tests/safety/test_sandbox_integration.py`
"""
import sys, os, asyncio, secrets, subprocess
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

IMAGE = "veritas-sandbox:latest"


def _docker_ready() -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", IMAGE],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


if not _docker_ready():
    print(f"SKIP: docker 或镜像 {IMAGE} 不可用（真沙箱集成测试需本地 Docker + 该镜像）")
    sys.exit(0)

from veritas.config import ScopeCfg
from veritas.safety.autonomy import AutonomyPolicy
from veritas.executors.web_solver import WebSolverExecutor
from veritas.executors.base import Transition
from veritas.runtime import Sandbox

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")

class FakeBoard:
    def __init__(self): self.acts = []
    async def write_activity(self, task_id, opp_id, wid, step, content):
        self.acts.append(content)

SC = ScopeCfg(domains=["localhost", "127.0.0.1"], cidrs=["127.0.0.0/8", "172.16.0.0/12"])


async def _marker_present(sb: Sandbox, marker: str) -> bool:
    """直接经真沙箱查 marker 是否存在（绕过安全闸，裸 exec）。"""
    rc, out = await sb.exec(f"test -f /tmp/{marker} && echo PRESENT || echo ABSENT")
    return "PRESENT" in out


async def main():
    global _fail
    n = secrets.token_hex(6)
    sb = Sandbox(f"veritas-safetytest-{n}", network="host")
    board = FakeBoard()
    ws = WebSolverExecutor(llm=None, sandbox=sb, scope=SC,
                           autonomy=AutonomyPolicy("approval", "deny"))
    try:
        await sb.start()
        rc, out = await sb.exec("echo alive")
        check("容器可用（echo alive）", "alive" in out, True)

        # —— scope 越界：前缀 touch 当 canary，命令整体被拒 → marker 绝不出现 ——
        m_sc = f"sc_{n}"
        msg, _ = await ws._handle(
            "sandbox_exec",
            {"command": f"touch /tmp/{m_sc}; curl -s -m 2 http://203.0.113.9/"},
            Transition(), "t", board, "s0")
        check("越界命令被拒（回提示）", "越界" in msg, True)
        check("越界 canary marker 不在真容器里（命令从未执行）",
              await _marker_present(sb, m_sc), False)

        # —— 审批门：破坏性（file_delete）在 approval·fail-closed 下被拦 → marker 绝不出现 ——
        m_au = f"au_{n}"
        msg, _ = await ws._handle(
            "sandbox_exec",
            {"command": f"touch /tmp/{m_au}; rm -rf /tmp/veritas_nx_{n}"},
            Transition(), "t", board, "s0")
        check("破坏性动作被拦（回提示）", ("审批" in msg or "拦截" in msg), True)
        check("审批门 canary marker 不在真容器里（命令从未执行）",
              await _marker_present(sb, m_au), False)

        # —— 放行对照：benign + 域内 → 真执行 → marker 确实出现（证非假过）——
        m_ok = f"ok_{n}"
        msg, trusted = await ws._handle(
            "sandbox_exec",
            {"command": f"touch /tmp/{m_ok}; echo done"},
            Transition(), "t", board, "s0")
        check("放行命令真执行（canary marker 出现在真容器）",
              await _marker_present(sb, m_ok), True)

        # —— repeat_request 越界也被拒（纯 curl 无 marker，断言拦截提示 + 未留痕执行行）——
        before = len([a for a in board.acts if a.get("rc") == 0 and "exec" in a and "gate" not in a])
        msg, _ = await ws._handle(
            "repeat_request", {"url": "http://198.51.100.9/"}, Transition(), "t", board, "s0")
        check("repeat_request 越界被拒", "越界" in msg, True)
        after = len([a for a in board.acts if a.get("rc") == 0 and "exec" in a and "gate" not in a])
        check("repeat_request 越界未产生执行留痕", after, before)

        # activity 侧证：scope_denied / needs_approval 各有记录
        gates = [a.get("gate") for a in board.acts if a.get("gate")]
        check("activity 记 scope_denied", "scope_denied" in gates, True)
        check("activity 记 needs_approval", "needs_approval" in gates, True)
    finally:
        await sb.stop()

    print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_sandbox_integration)")
    return 1 if _fail else 0

sys.exit(asyncio.run(main()))
