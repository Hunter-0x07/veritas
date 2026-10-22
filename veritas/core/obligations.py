"""举证义务注册表（Obligation Registry）—— verifier Stage 3：面向未知/外部目标的证明模型地基。

Stage 1/2 的"举证义务"（某访问级别该拿什么证明）是**硬编码**在 verifier/prober 里的 if-else，
只覆盖 shell/root/domain_admin。要上 HackerOne 这类【未知外部目标】，漏洞类是 SQLi/LFI/SSRF/
IDOR/认证绕过，且没法预先对每个目标写死判据——于是把"义务"从代码抽成一张**声明式注册表**，
每条目声明该访问类/漏洞类的：举证义务描述、确定性判据(proof)、是否有主动探针(active)、噪声档。

两条路，**确定性永远是脊梁**：
  - 注册表里【有 proof 的类】→ verifier 用它从真实世界底物自推导 verified/refuted（Stage 1/2 的老行为，
    现在改成查表，单一真源）。
  - 注册表里【没有 proof 的类】(proof=None 或根本没登记，如 web_user/web_admin/db_read/业务逻辑) →
    写不出确定性义务 → 走【可复现 PoC + LLM-judge 仅辅助评级】(标 llm-judged 低信任档，绝不单独升
    verified，Observer 交叉核)。`has_deterministic()` 就是这条岔路的开关。

本文件只放【确定性义务】的声明与判定（纯函数、可测、不持任何 IO）；主动探针的执行在 prober，
PoC+LLM-judge 的编排在 executor，Observer 负责对"仅 llm-judged 支撑"的结论交叉核。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

# —— 确定性"效果痕迹"：高熵/结构化串，由目标经真实工具吐出，LLM 造不出（与 verifier/prober 同源）——
_DUMP_RID500 = re.compile(r"(?mi)^[^\s:]+:500:[0-9a-f]{32}:[0-9a-f]{32}:::")   # DCSync/SAM：RID-500 内置域管
_DUMP_KRBTGT = re.compile(r"(?mi)^krbtgt:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::")    # krbtgt（域信任根）
_DUMP_ANY = re.compile(r"(?mi)^[^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::")      # 任一 user:RID:LM:NT 行
_ROOT_ID = re.compile(r"uid=0\(")                                             # id：root
_SHELL_ID = re.compile(r"uid=\d+\(")                                          # id：拿到某用户 shell
_NTHASH_FULL = re.compile(r"^[0-9a-f]{32}$", re.I)                            # 一个 secret 本身就是 NT hash


def _da_proof(out: str, secrets: tuple) -> bool:
    # DCSync 真 dump 到 RID-500 内置域管 / krbtgt 行；或一条 verified 的 NT-hash 出现在真实 dump 里佐证。
    # 不接受"够到 DC / 在 DC 上跑过命令"这种弱证据（任何域用户都能做到，≠ 域管）。
    if _DUMP_RID500.search(out) or _DUMP_KRBTGT.search(out):
        return True
    for s in secrets:
        if s and _NTHASH_FULL.match(s) and s in out and _DUMP_ANY.search(out):
            return True
    return False


@dataclass(frozen=True)
class ObligationSpec:
    key: str                                           # access_level 或 finding_type
    desc: str                                          # 举证义务（人读）
    proof: Optional[Callable[[str, tuple], bool]]      # 确定性判据(真实输出,已验密文)→bool；None=无确定性义务
    active: str = "none"                               # 主动探针类型：nonce_echo|reauth|re_dcsync|none
    noise: str = "none"                                # 主动探针噪声档：low|medium|high|none

    @property
    def deterministic(self) -> bool:
        # 有确定性手段即可：被动判据(proof) 或 主动探针(active)——web 漏洞类的确定性来自主动探针
        # （引擎自选标记/挑战经漏洞点回环），记录输出里没有通用被动痕迹，故 proof 可为 None。
        return self.proof is not None or (self.active not in (None, "", "none"))


# —— 注册表：Stage 1/2 的硬编码义务迁到这里（单一真源）——
# 访问级别类（verifier 的 proof-of-effect 查这张表）
REGISTRY: dict[str, ObligationSpec] = {
    "shell": ObligationSpec(
        "shell", "在该主机上拿到任一用户 shell（id 出 `uid=…(`）",
        lambda out, _s: bool(_SHELL_ID.search(out)), active="nonce_echo", noise="low"),
    "root": ObligationSpec(
        "root", "该主机 root（id 出 `uid=0(`）",
        lambda out, _s: bool(_ROOT_ID.search(out)), active="nonce_echo", noise="low"),
    "domain_admin": ObligationSpec(
        "domain_admin",
        "DCSync 真 dump 到 RID-500 内置域管 / krbtgt 行（或 verified NT-hash 现于真实 dump 佐证）；"
        "不接受'够到 DC'这种弱证据",
        _da_proof, active="re_dcsync", noise="high"),
    # —— Cut 2a：web 漏洞类的【确定性】义务（按 replay.probe_type 键入）。确定性来自【主动探针】
    #    （引擎自选标记/挑战经漏洞点回环），prober 的 _probe_<type> 实现；proof=None（无通用被动痕迹）。
    #    noise=low：都是幂等 HTTP 读式探针，外部授权目标也允许（确认 web 漏洞是 HackerOne 核心用例）。
    "ssti": ObligationSpec(
        "ssti", "引擎自选两数之积出现在响应（模板真求值，而非回显表达式字面）",
        None, active="ssti", noise="low"),
    "sqli": ObligationSpec(
        "sqli", "报错型(破语法 vs 平衡) / 认证绕过(token 差分) / 布尔差分 / union 标记回显 之一成立"
                "（回显 payload 字符串不算）",
        None, active="sqli", noise="low"),
    "lfi": ObligationSpec(
        "lfi", "读到引擎可预测的文件内容（/etc/passwd 的 root:...:0:0: 结构 / 已知主机名等）",
        None, active="lfi", noise="low"),
    "open_redirect": ObligationSpec(
        "open_redirect", "3xx Location 恰为引擎自选的唯一外部 URL（参数真控重定向目标）",
        None, active="open_redirect", noise="low"),
    # Cut 2b：带外（OOB）确定性义务——目标真发起带外请求打中引擎自选 canary（需配 probe.oob_url）
    "ssrf": ObligationSpec(
        "ssrf", "目标服务端发起带外请求、打中引擎自选的唯一 OOB canary（只有真 SSRF 才会回连）",
        None, active="ssrf", noise="low"),
    "xxe": ObligationSpec(
        "xxe", "XML 外部实体被解析展开、回连引擎自选的 OOB canary（只有真 XXE 才会回连）",
        None, active="xxe", noise="low"),
    # web_user / web_admin / idor / 业务逻辑 等：暂无确定性义务（未登记，has_deterministic=False）
    #   → 走 PoC + LLM-judge 低信任辅助评级（executor 编排，Observer 交叉核）。Cut 2b/2c/2d 再补。
}


def obligation(key: str) -> Optional[ObligationSpec]:
    return REGISTRY.get(key)


def has_deterministic(key: str) -> bool:
    """该访问类/漏洞类是否有【确定性举证义务】。False → 走 PoC+LLM-judge 低信任路。"""
    spec = REGISTRY.get(key)
    return bool(spec and spec.deterministic)


def proof_of_effect(access_level: str, out: str, verified_secrets=()) -> bool:
    """世界底物(真实输出)是否满足该访问级别的确定性举证义务。无登记义务 → False（交兜底/LLM-judge）。"""
    spec = REGISTRY.get(access_level)
    if not spec or spec.proof is None:
        return False
    return bool(spec.proof(out, tuple(verified_secrets)))
