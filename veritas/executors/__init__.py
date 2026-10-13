"""执行器注册表。M0 全部走 MockExecutor；M1+ 按 kind 替换为真实执行器。"""
from .base import ExecResult, Executor, Transition
from .mock import MockExecutor


def build_registry(mode: str = "mock") -> dict[str, Executor]:
    mock = MockExecutor()
    reg: dict[str, Executor] = {k: mock for k in mock.kinds}
    # M1+：reg["initial_access"] = WebSolverExecutor(...) 等真实执行器在此覆盖
    return reg


__all__ = ["Executor", "ExecResult", "Transition", "build_registry"]
