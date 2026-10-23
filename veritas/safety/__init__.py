"""安全闸：碰真·授权外部目标（HackerOne 式）前的边界与分级自主。

- `scope`：授权边界——从命令抽【连接目标】主机/IP，比对 domains + CIDR，域外拒绝、
  本地命令放行、内网横向不误杀。堵"GLM 被域凭据勾引往 scope 外主机乱撞"的实测事故。
- `autonomy`：分级自主/审批门（HITL）——破坏性 / 高噪声动作在 approval 模式下 fail-closed
  拦截+记录，与 verifier 的 safe-probe 分级（low/medium/high · lab/external）对齐复用。

纯逻辑、无 I/O、无 core/runtime 依赖：可被 config（ScopeCfg.allows_cmd）、executor、prober
复用，也便于确定性单测。
"""
from __future__ import annotations

from . import autonomy, scope

__all__ = ["scope", "autonomy"]
