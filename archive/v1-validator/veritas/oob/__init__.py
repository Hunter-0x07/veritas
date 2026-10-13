"""带外验证（OOB）：SSRF/RCE/盲注/XXE 的公共底座。

W2 提供接口 + NoopOOB（未配置时）。真实 interactsh 接入留后续——本地靶场
（Juice Shop）的 SQLi/XSS 用布尔差分/执行级即可确定性验证，不依赖带外。
"""
from .base import OOBProvider, NoopOOB

__all__ = ["OOBProvider", "NoopOOB"]
