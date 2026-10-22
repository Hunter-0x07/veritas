"""执行器注册表。M0 全部走 MockExecutor；M1+ 按 kind 替换为真实执行器。"""
from .base import ExecResult, Executor, Transition
from .mock import MockExecutor


def build_registry(mode: str = "mock", llm=None, sandbox=None,
                   probe_policy=None, scope=None, oob=None) -> dict[str, Executor]:
    mock = MockExecutor()
    reg: dict[str, Executor] = {k: mock for k in mock.kinds}
    if mode == "live" and llm is not None and sandbox is not None:
        from .web_solver import WebSolverExecutor
        ws = WebSolverExecutor(llm, sandbox, scope=scope, probe_policy=probe_policy, oob=oob)
        for k in ws.kinds:            # initial_access / web_exploit 走真打；internal/lateral 暂留 mock(备 M3)
            reg[k] = ws
    return reg


__all__ = ["Executor", "ExecResult", "Transition", "build_registry"]
