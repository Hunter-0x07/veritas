"""分级自主 / 审批门（HITL）：破坏性·高噪声动作在 approval 模式下 fail-closed 拦截+记录。

第一性与 scope 同源：真实目标是 HackerOne 这类【授权外部目标】，限速 / 检测 / ToS / 账号锁定
决定了不能随便做破坏性或高噪声动作。于是把动作按【破坏性 / 噪声】分级，策略按目标授权档决定
是否要人工审批：
  - 靶场（authorization=lab）→ full_auto：试验台，全放行。
  - 外部授权目标（authorization=external，默认）→ approval：破坏性/高噪声动作要人工审批。

与 verifier 的 safe-probe（core/prober.py 的 low/medium/high · lab/external）**对齐复用**同一套
噪声档与授权档，不另造词表：prober 管"主动重探针该不该发"，autonomy 管"solver 自己要跑的
破坏性/高噪声命令该不该放"，两者互补覆盖执行面。

当前引擎是全自动舰队、无人在环（core/engine.py），所以 approval 模式下遇到需审批动作：
  - on_gated=deny（**fail-closed 默认**）：拦截 + 记录（回明确提示给 LLM 换招、落 activity/报告
    标 needs_approval、Observer 交叉核）——这是无人在环时的安全默认。
  - on_gated=allow：放行 + 记录（fail-open，给受监督 run 的选项，仅做遥测不拦）。
真正的交互式【暂停→operator 逐条批准→恢复】UI 留后续，本层先把策略 / 分级 / 审批点抽象 /
留痕落地（审批点 = executor 执行命令处）。

纯 stdlib（re + dataclass），无 I/O：确定性单测。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# —— 动作类别（破坏性 / 噪声递增）——
BENIGN = "benign"
FILE_WRITE = "file_write"
FILE_DELETE = "file_delete"
DESTRUCTIVE = "destructive"
BROAD_SCAN = "broad_scan"
BRUTEFORCE = "bruteforce"

# 噪声档（与 prober 对齐：low/medium/high）
NOISE_LOW = "low"
NOISE_MEDIUM = "medium"
NOISE_HIGH = "high"

_CATEGORY_NOISE = {
    BENIGN: NOISE_LOW,
    FILE_WRITE: NOISE_MEDIUM,
    FILE_DELETE: NOISE_HIGH,
    DESTRUCTIVE: NOISE_HIGH,
    BROAD_SCAN: NOISE_MEDIUM,
    BRUTEFORCE: NOISE_HIGH,
}
# approval 模式下需人工审批的类别
_APPROVAL_CATEGORIES = frozenset({FILE_WRITE, FILE_DELETE, DESTRUCTIVE, BROAD_SCAN, BRUTEFORCE})

# 系统路径（递归删 / 改权限 / 写入 → 破坏性）
_SYS = r"/(?:etc|var|usr|bin|sbin|boot|root|lib|lib64|opt|sys|proc|srv|home)\b"
# 写重定向的系统路径（排除 /dev、/home：/dev/null 与 home 下 scratch 写很常见）
_SYS_WRITE = r"/(?:etc|var|usr|bin|sbin|boot|root|lib|lib64|opt|sys|proc|srv)\b"

# 规则表：按破坏性从高到低，首个命中即定类（精度优先，默认 benign——沙箱内 scratch 写/窄扫描
# /单文件 rm 都不拦，避免误杀正常 recon；只拦明确破坏性/大范围/爆破）。
_RULES = [
    # —— destructive ——
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:", DESTRUCTIVE, "fork bomb"),
    (r"\b(?:mkfs|fdisk|parted|wipefs)\b", DESTRUCTIVE, "磁盘/分区操作"),
    (r"\bdd\b[^\n]*\bof=\s*['\"]?/dev/", DESTRUCTIVE, "dd 写块设备"),
    (r">\s*['\"]?/dev/sd[a-z]", DESTRUCTIVE, "覆写块设备"),
    (r"\b(?:shutdown|reboot|poweroff|halt)\b|\binit\s+[06]\b", DESTRUCTIVE, "关机/重启"),
    (r"\biptables\b[^\n]*\s-[FXZ]\b|\bnft\b[^\n]*\bflush\b", DESTRUCTIVE, "清空防火墙规则"),
    (r"\b(?:userdel|groupdel|deluser)\b", DESTRUCTIVE, "删除账号"),
    (r"\bpasswd\b\s+\S", DESTRUCTIVE, "修改账号口令"),
    (r"\b(?:killall|pkill)\b", DESTRUCTIVE, "批量杀进程"),
    (r"\brm\b(?:\s+-[A-Za-z]+)*\s+['\"]?" + _SYS, DESTRUCTIVE, "删除系统路径"),
    (r"\brm\b[^\n]*\s-[A-Za-z]*r[A-Za-z]*\s+['\"]?/\s*(?:$|[;&|'\"])", DESTRUCTIVE, "rm -r 根目录"),
    (r"\b(?:chown|chmod)\b[^\n]*\s-R\b[^\n]*" + _SYS, DESTRUCTIVE, "递归改系统路径权限"),
    # —— bruteforce ——
    (r"\b(?:hydra|medusa|patator|ncrack)\b", BRUTEFORCE, "在线爆破工具"),
    (r"\b(?:crackmapexec|nxc|netexec)\b[^\n]*(?:-p\s+\S+\.(?:txt|lst)\b|--passwords?\b)",
     BRUTEFORCE, "密码喷洒/字典"),
    # —— broad_scan ——
    (r"\bmasscan\b", BROAD_SCAN, "masscan 大范围扫描"),
    (r"\bnmap\b[^\n]*(?:\s-p-|\b0\.0\.0\.0/0\b|/(?:[0-9]|1[0-9]|2[0-3])\b)",
     BROAD_SCAN, "nmap 全端口/大网段"),
    # —— file_delete（非系统路径的递归删 / 粉碎 / 清空）——
    (r"\brm\b[^\n]*\s-[A-Za-z]*r[A-Za-z]*\b", FILE_DELETE, "递归删除"),
    (r"\b(?:shred|wipe)\b", FILE_DELETE, "粉碎文件"),
    (r"\btruncate\b[^\n]*-s\s*0\b", FILE_DELETE, "清空文件"),
    # —— file_write（写系统路径；sandbox 内 scratch 写不拦）——
    (r"\btee\b[^\n]*\s['\"]?" + _SYS_WRITE, FILE_WRITE, "tee 写系统路径"),
    (r">>?\s*['\"]?" + _SYS_WRITE, FILE_WRITE, "重定向写系统路径"),
]
_COMPILED = [(re.compile(p, re.I), cat, why) for p, cat, why in _RULES]


@dataclass
class Action:
    category: str
    noise: str
    reason: str = ""


@dataclass
class Decision:
    allow: bool            # 是否放行执行
    record: bool           # 是否落留痕（本应审批）
    category: str
    noise: str
    reason: str = ""
    gate: str = ""         # activity 标记：needs_approval | would_require_approval | ""


def classify(cmd: str) -> Action:
    """把一条 shell 命令分到破坏性/噪声类别（默认 benign）。"""
    text = cmd or ""
    for rx, cat, why in _COMPILED:
        if rx.search(text):
            return Action(category=cat, noise=_CATEGORY_NOISE[cat], reason=why)
    return Action(category=BENIGN, noise=NOISE_LOW, reason="")


@dataclass
class AutonomyPolicy:
    """分级自主策略：靶场 full_auto、外部 approval；approval 下破坏性动作按 on_gated 处置。"""
    mode: str = "full_auto"     # full_auto | approval
    on_gated: str = "deny"      # deny（拦截+记录·fail-closed）| allow（放行+记录·fail-open）

    @classmethod
    def from_cfg(cls, auto_cfg=None, probe_cfg=None) -> "AutonomyPolicy":
        """从 config.AutonomyCfg + ProbeCfg 构造。mode=auto → 按 probe.authorization 推导
        （lab→full_auto / external→approval），与 safe-probe 授权档对齐。duck-typed 读属性。"""
        mode = getattr(auto_cfg, "mode", "auto") if auto_cfg is not None else "auto"
        on_gated = getattr(auto_cfg, "on_gated", "deny") if auto_cfg is not None else "deny"
        if mode == "auto":
            authz = getattr(probe_cfg, "authorization", "external") if probe_cfg is not None else "external"
            mode = "full_auto" if authz == "lab" else "approval"
        if mode not in ("full_auto", "approval"):
            mode = "approval"                     # 未知值保守落到 approval
        if on_gated not in ("deny", "allow"):
            on_gated = "deny"
        return cls(mode=mode, on_gated=on_gated)

    def requires_approval(self, action: Action) -> bool:
        return self.mode == "approval" and action.category in _APPROVAL_CATEGORIES

    def gate(self, action: Action) -> Decision:
        """裁决一个动作。full_auto 或 benign → 放行不记；approval 下需审批动作按 on_gated。"""
        if not self.requires_approval(action):
            return Decision(allow=True, record=False, category=action.category,
                            noise=action.noise, reason=action.reason, gate="")
        if self.on_gated == "allow":
            return Decision(allow=True, record=True, category=action.category, noise=action.noise,
                            reason=action.reason, gate="would_require_approval")
        return Decision(allow=False, record=True, category=action.category, noise=action.noise,
                        reason=action.reason, gate="needs_approval")

    def gate_command(self, cmd: str) -> Decision:
        return self.gate(classify(cmd))
