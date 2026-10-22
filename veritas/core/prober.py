"""主动探针（proof-of-effect prober）—— verifier Stage 2：主动探世界，不只被动读世界。

Stage 1（`verifier.py`）从【已记录的真实世界底物】(activity 的 exec/rc/out、http_flows)
按每个访问级别的"举证义务"**被动**推导 verdict。Stage 2（本文件）更进一步：由引擎在
solver 上报战果后、verifier 判定前，**主动向世界发起"只有真拿下才能通过"的探针**——
引擎现场自选挑战（随机 nonce / 重认证 / 重跑 DCSync），经该立足点自己的访问向量回环，
拿到确定性的证成或证伪。

为什么主动探针强于被动推导：
  被动推导信任的是 solver 选择记录下来的命令输出；主动探针的挑战由【引擎】选定——
  nonce 是引擎此刻生成的随机串、重认证是引擎亲自跑的——目标只有【真被拿下】才能产出
  引擎要的回应，这是 proof-of-effect 的最强形式。且能**按主机限定**：修掉 Stage 1
  "uid=0 出现在任何输出里就算 root"的松点——nonce 必须经【该立足点的访问向量】回显，
  uid=0 必须和 nonce 在【同一次探针响应】里，才证明"在这台主机上有 root 执行能力"。

safe-probe 策略（第一性原则：真实目标是 HackerOne 这类【授权外部目标】，本地靶场只是
试验台）。外部授权目标不能随便重活（限速 / 检测 / ToS / 账号锁定），所以主动重探按
【噪声 / 破坏性】分级 + 预算约束：
  - low    单次 nonce 回环：幂等、与正常一次请求无异 → 外部 + 靶场都允许。
  - medium 重认证：一次认证尝试（有账号锁定 / 认证日志告警风险）→ 仅授权靶场主动跑。
  - high   重跑 DCSync：会从 DC 复制全域、动静很大 → 仅授权靶场。
  外部目标遇到 medium/high 的声称 → **不主动重探**，降级为【被动 proof-of-effect +
  可复现 PoC（replay/MITM）+ LLM-judge 仅作辅助评级】：LLM-judge 标 `llm-judged` 低信任档、
  Observer 交叉核，**绝不单独把 verdict 抬成 verified**。确定性永远是脊梁——否则就回到
  "谁来验证验证器"的死循环。

职责边界（与 verifier 分工）：Prober 只持【沙箱句柄 + 策略】，产出针对某条声称的
`ProbeResult`（proven/refuted/inconclusive + 可复现命令 + 原始输出），**不碰攻击图、
不裁决图上的 verdict**。verifier 保持纯函数，接收 probe 结果当【数据】，主动结论优先于
Stage 1 被动推导（proven→verified / refuted→refuted / inconclusive→回落被动）。
由持沙箱的 executor 调用本组件（见 `executors/web_solver.py`）。
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field

from .state import rank

log = logging.getLogger("veritas.prober")

PROVEN = "proven"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"

# 噪声 / 破坏性分级
NOISE_LOW = "low"        # 单次 nonce 回环（幂等）
NOISE_MEDIUM = "medium"  # 重认证（一次认证尝试）
NOISE_HIGH = "high"      # 重跑 DCSync（复制全域，很吵）
NOISE_PASSIVE = "passive"  # 不主动探，降级为被动 + PoC

# —— 探针响应里的确定性证据 ——
_ROOT_ID = re.compile(r"uid=0\(")
_SHELL_ID = re.compile(r"uid=\d+\(")
_DUMP_RID500 = re.compile(r"(?mi)^[^\s:]+:500:[0-9a-f]{32}:[0-9a-f]{32}:::")   # DCSync RID-500 内置域管
_DUMP_KRBTGT = re.compile(r"(?mi)^krbtgt:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::")    # krbtgt 域信任根
_AUTH_OK = re.compile(r"(?i)\(Pwn3d!\)|\[\+\]")                               # nxc/netexec 认证成功
# 真·认证/访问被拒（可据此 refuted——世界给了明确反证）
_AUTH_DENIED = re.compile(
    r"(?i)STATUS_LOGON_FAILURE|LOGON_FAILURE|KDC_ERR_PREAUTH_FAILED|STATUS_ACCESS_DENIED|"
    r"ERROR_DS_DRA_ACCESS_DENIED|access[_ ]denied|authentication failed|login failed")
# 基础设施/操作性错误（DC 不健康、网络、服务没应答）——**不是反证**，判 inconclusive
# （保守：宁可 unproven 不乱 refute。如 impacket 的 `[-] RemoteOperations failed: No answer!`
#  只说明 DC 没应答，不说明声称是假的——若据此 refute 会把"DC 临时宕机"误判成"攻击没发生"）。
_OPERATIONAL = re.compile(
    r"(?i)no answer|timed?\s?out|connection (?:refused|reset|error)|could\s?n.?t connect|"
    r"can.?t contact|unreachable|RemoteOperations failed|network error|no route to host|"
    r"name or service not known")
_HOST_TOK = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+)\b", re.I)


@dataclass
class ProbePolicy:
    """safe-probe 策略：谁能开多重的主动探针、总预算多少。"""
    enabled: bool = True
    authorization: str = "external"   # "lab"=授权靶场(各级可) | "external"=外部(仅低噪声)
    budget: int = 8                   # 本次 run 的主动探针执行预算（防对目标连续重活）
    llm_judge: bool = False           # 外部降级路径是否启用 LLM-judge 辅助评级

    @classmethod
    def from_cfg(cls, cfg) -> "ProbePolicy":
        """从 config.ProbeCfg(纯数据，无行为) 构造带行为的策略。duck-typed 读属性，
        避免 config↔core 双向耦合；也兼容直接传 ProbePolicy。"""
        if isinstance(cfg, cls):
            return cfg
        return cls(enabled=getattr(cfg, "enabled", True),
                   authorization=getattr(cfg, "authorization", "external"),
                   budget=getattr(cfg, "budget", 8),
                   llm_judge=getattr(cfg, "llm_judge", False))

    def active_allowed(self, tier: str) -> bool:
        if not self.enabled:
            return False
        if self.authorization == "lab":
            return True                       # 授权靶场：各级主动探针都可（仍受预算约束）
        return tier == NOISE_LOW              # 外部：只允许低噪声（单次 nonce 回环）


@dataclass
class ProbeResult:
    verdict: str                      # proven | refuted | inconclusive
    method: str                       # nonce_echo | reauth | re_dcsync | downgraded | llm_judge
    tier: str                         # low | medium | high | passive
    detail: str = ""
    command: str = ""                 # 探针命令（可复现）
    output: str = ""                  # 原始输出（世界底物）
    trust: str = "deterministic"      # deterministic | llm-judged | none
    nonce: str = ""

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "method": self.method, "tier": self.tier,
                "detail": self.detail, "command": self.command[:500],
                "output": (self.output or "")[:800], "trust": self.trust, "nonce": self.nonce}


def _new_nonce() -> str:
    """引擎自选的随机标记：只有真执行才能原样回显。"""
    return "vz" + secrets.token_hex(8)


def _bare_hosts(text: str) -> list[str]:
    return _HOST_TOK.findall(text or "")


class Prober:
    def __init__(self, sandbox, policy: ProbePolicy, llm=None):
        self.sb = sandbox
        self.policy = policy
        self.llm = llm
        self._spent = 0
        self._cache: dict[tuple, ProbeResult] = {}   # (method,target) 去重，避免对同一目标重复重活

    # ---------- 底层：执行一条探针命令（计入预算） ----------
    async def _run(self, cmd: str, timeout: float = 90) -> tuple[int, str]:
        self._spent += 1
        rc, out = await self.sb.exec(cmd, timeout=timeout)
        return rc, out or ""

    def _budget_left(self) -> bool:
        return self._spent < self.policy.budget

    # ========== 立足点探针 ==========
    async def probe_foothold(self, foothold: dict, proven_creds: list[dict],
                             traces: list[dict]) -> ProbeResult | None:
        """按访问级别选探针。返回 None = 本级别无主动探针（交 Stage 1 被动兜底）。"""
        access = foothold.get("access_level", "")
        r = rank(access)
        if r >= rank("domain_admin"):
            return await self._probe_domain_admin(foothold, proven_creds, traces)
        if r >= rank("shell"):
            return await self._probe_rce(foothold, traces)
        return None   # web_user/web_admin/db_read：Stage 2 暂不主动探（Stage 3 的举证义务注册表）

    async def _probe_rce(self, foothold: dict, traces: list[dict]) -> ProbeResult:
        """shell/root：引擎自选随机 nonce 经该立足点访问向量回环，证 code exec（按主机限定）。"""
        access = foothold.get("access_level", "")
        want_root = rank(access) >= rank("root")
        tier = NOISE_LOW   # 单次 nonce 回环是幂等低噪声，外部也放行
        template = self._replay_template(foothold, traces)
        if not template:
            return ProbeResult(INCONCLUSIVE, "nonce_echo", tier,
                               detail="无 replay/可复现访问向量 → 交被动验证兜底", trust="none")
        if not self.policy.active_allowed(tier) or not self._budget_left():
            return ProbeResult(INCONCLUSIVE, "nonce_echo", NOISE_PASSIVE,
                               detail="策略/预算不允许主动探针 → 降级被动", trust="none")
        nonce = _new_nonce()
        inner = f"echo {nonce}; id" if want_root else f"echo {nonce}"
        cmd = template.replace("{CMD}", inner)
        rc, out = await self._run(cmd, timeout=60)
        echoed = nonce in out
        if not echoed:
            return ProbeResult(REFUTED, "nonce_echo", tier,
                               detail=f"nonce `{nonce}` 未经该立足点回显 → 该向量不具 code exec（反证）",
                               command=cmd, output=out, nonce=nonce)
        if want_root:
            if _ROOT_ID.search(out):
                return ProbeResult(PROVEN, "nonce_echo", tier,
                                   detail=f"nonce 回显且同响应内 `id`=uid=0 → 该主机 root 执行（按向量限定）",
                                   command=cmd, output=out, nonce=nonce)
            if _SHELL_ID.search(out):   # id 跑了但非 root → 该向量只拿到普通 shell（对 root 声称是反证）
                return ProbeResult(REFUTED, "nonce_echo", tier,
                                   detail="nonce 回显但 `id` 非 uid=0 → 该向量非 root（对 root 声称反证）",
                                   command=cmd, output=out, nonce=nonce)
            return ProbeResult(INCONCLUSIVE, "nonce_echo", tier,   # 回显但无 id 输出：保守
                               detail="nonce 回显但无 `id` 输出，root 级别存疑 → 交被动兜底",
                               command=cmd, output=out, nonce=nonce)
        return ProbeResult(PROVEN, "nonce_echo", tier,
                           detail="nonce 原样回显 → 该访问向量确有 code exec",
                           command=cmd, output=out, nonce=nonce)

    async def _probe_domain_admin(self, foothold: dict, proven_creds: list[dict],
                                  traces: list[dict]) -> ProbeResult:
        """domain_admin：授权靶场重跑 DCSync 坐实（认 RID-500/krbtgt）；外部降级为被动+PoC。"""
        tier = NOISE_HIGH
        target = self._dc_target(foothold, traces)
        if not self.policy.active_allowed(tier):
            # 外部：不主动重跑 DCSync（太吵），降级为被动 proof-of-effect + 可复现 PoC
            return ProbeResult(INCONCLUSIVE, "downgraded", NOISE_PASSIVE,
                               detail="外部目标不主动重跑 DCSync（高噪声）→ 降级被动 proof-of-effect + PoC",
                               trust="none")
        if not self._budget_left():
            return ProbeResult(INCONCLUSIVE, "re_dcsync", NOISE_PASSIVE,
                               detail="探针预算耗尽 → 降级被动", trust="none")
        key = ("re_dcsync", target or "")
        if key in self._cache:
            return self._cache[key]
        cmd = self._dcsync_command(foothold, proven_creds, target, traces)
        if not cmd:
            return ProbeResult(INCONCLUSIVE, "re_dcsync", tier,
                               detail="无可复现 DCSync 命令（无 replay.verify_command / 无 DA 凭据 / 无记录）→ 交被动兜底",
                               trust="none")
        rc, out = await self._run(cmd, timeout=180)
        if _DUMP_RID500.search(out) or _DUMP_KRBTGT.search(out):
            res = ProbeResult(PROVEN, "re_dcsync", tier,
                              detail="重跑 DCSync 真实 dump 到 RID-500 内置域管 / krbtgt 行 → domain_admin 坐实",
                              command=cmd, output=out)
        elif _OPERATIONAL.search(out) and not _AUTH_DENIED.search(out):
            res = ProbeResult(INCONCLUSIVE, "re_dcsync", tier,     # DC 没应答/网络问题，非反证（保守）
                              detail="重跑 DCSync 遇基础设施错误(DC 未应答/网络)，非认证反证 → 交被动兜底",
                              command=cmd, output=out)
        elif _AUTH_DENIED.search(out):
            res = ProbeResult(REFUTED, "re_dcsync", tier,
                              detail="重跑 DCSync 认证/复制被明确拒绝 → domain_admin 声称反证",
                              command=cmd, output=out)
        else:
            res = ProbeResult(INCONCLUSIVE, "re_dcsync", tier,
                              detail="重跑 DCSync 未见 RID-500/krbtgt 行也无明确失败 → 交被动兜底",
                              command=cmd, output=out)
        self._cache[key] = res
        return res

    # ========== 凭据探针 ==========
    async def probe_credential(self, cred: dict, traces: list[dict]) -> ProbeResult | None:
        """引擎亲自拿凭据去认证（不信 solver 自述"我破出来了"）：[+]→proven / [-]→refuted。"""
        secret = cred.get("secret", "")
        user = cred.get("username", "")
        kind = cred.get("kind", "password")
        if not secret or not user:
            return None
        tier = NOISE_MEDIUM
        if not self.policy.active_allowed(tier):
            # 外部：不主动重认证（账号锁定 / 日志告警）→ 降级被动（verifier 用 Stage 1 traceable 兜底）
            return ProbeResult(INCONCLUSIVE, "downgraded", NOISE_PASSIVE,
                               detail="外部目标不主动重认证（账号锁定/日志风险）→ 降级被动校验", trust="none")
        if not self._budget_left():
            return ProbeResult(INCONCLUSIVE, "reauth", NOISE_PASSIVE,
                               detail="探针预算耗尽 → 降级被动", trust="none")
        target = self._auth_target(cred, traces)
        if not target:
            return ProbeResult(INCONCLUSIVE, "reauth", tier,
                               detail="无法定位认证目标（无 replay.target / 记录里找不到）→ 交被动兜底", trust="none")
        key = ("reauth", target, user, secret)
        if key in self._cache:
            return self._cache[key]
        if kind == "hash":
            auth = f"-u {_q(user)} -H {_q(secret)}"
        else:
            auth = f"-u {_q(user)} -p {_q(secret)}"
        # nxc/netexec/crackmapexec 任一存在即用；都没有则命令失败→inconclusive（不误判 refuted）。
        # sandbox.exec 已包一层 sh -lc，这里直接给 shell 片段（不再自管 $TOOL 变量，避免嵌套展开坑）。
        cmd = (f"if command -v nxc >/dev/null 2>&1; then nxc smb {_q(target)} {auth}; "
               f"elif command -v netexec >/dev/null 2>&1; then netexec smb {_q(target)} {auth}; "
               f"else crackmapexec smb {_q(target)} {auth}; fi 2>&1")
        rc, out = await self._run(cmd, timeout=90)
        if _AUTH_OK.search(out):
            res = ProbeResult(PROVEN, "reauth", tier,
                              detail=f"引擎重认证 {user}@{target} → [+] 成功（凭据真可用）",
                              command=cmd, output=out)
        elif _OPERATIONAL.search(out) and not _AUTH_DENIED.search(out):
            res = ProbeResult(INCONCLUSIVE, "reauth", tier,       # 连不上/没应答，非凭据反证（保守）
                              detail=f"重认证 {user}@{target} 遇基础设施错误(未应答/网络)，非凭据反证 → 交被动兜底",
                              command=cmd, output=out)
        elif _AUTH_DENIED.search(out):
            res = ProbeResult(REFUTED, "reauth", tier,
                              detail=f"引擎重认证 {user}@{target} → 认证被明确拒绝（凭据反证）",
                              command=cmd, output=out)
        else:
            res = ProbeResult(INCONCLUSIVE, "reauth", tier,
                              detail=f"重认证 {user}@{target} 输出不明确（工具缺失/网络）→ 交被动兜底",
                              command=cmd, output=out)
        self._cache[key] = res
        return res

    # ========== 外部降级：LLM-judge 辅助评级（低信任档，绝不单独抬成 verified） ==========
    async def llm_judge(self, claim: str, poc: str) -> ProbeResult | None:
        """仅外部降级路径用：给 LLM 看【声称 + 可复现 PoC】，让它判 PoC 是否确定性证明该效果。
        产出的 verdict 恒为 inconclusive（不驱动进展），只带 trust='llm-judged' 的辅助信号——
        确定性永远是脊梁，LLM-judge 仅供 Observer 交叉核与人工复核排序。"""
        if self.llm is None or not self.policy.llm_judge:
            return None
        sys = ("你是渗透结论的【辅助】审查员。只依据给出的可复现 PoC（请求+响应）判断：该 PoC 是否"
               "**确定性地**证明了所声称的效果？只回一个词：proves / unclear / contradicts，再跟一句理由。"
               "注意：你的判断是低信任辅助，不是最终裁决；拿不准就 unclear。")
        usr = f"声称：{claim}\n\n可复现 PoC：\n{poc[:3000]}"
        try:
            msg = await self.llm.chat([{"role": "system", "content": sys},
                                       {"role": "user", "content": usr}])
            grade = (getattr(msg, "content", "") or "").strip()
        except Exception as e:  # noqa: BLE001
            log.warning("LLM-judge 调用失败: %s", e)
            return None
        return ProbeResult(INCONCLUSIVE, "llm_judge", NOISE_PASSIVE,
                           detail=f"LLM-judge（低信任辅助）：{grade[:300]}", trust="llm-judged")

    # ---------- 访问向量 / 目标解析（replay 优先，traces 反推兜底） ----------
    @staticmethod
    def _replay_template(foothold: dict, traces: list[dict]) -> str:
        """取"执行任意命令"的可复现模板（含 {CMD} 占位符）。replay 优先，其次从 traces 反推。"""
        replay = (foothold.get("props") or {}).get("replay") or foothold.get("replay") or {}
        if isinstance(replay, dict):
            tpl = replay.get("command_template") or ""
            if "{CMD}" in tpl:
                return tpl
        # traces 反推：找记录里带 {CMD} 风格注入的命令较难通用，这里只认 replay（保守，缺则交被动）
        return ""

    @staticmethod
    def _dc_target(foothold: dict, traces: list[dict]) -> str:
        loc = foothold.get("location") or ""
        hosts = _bare_hosts(loc)
        return hosts[0] if hosts else ""

    def _dcsync_command(self, foothold: dict, proven_creds: list[dict],
                        target: str, traces: list[dict]) -> str:
        """DCSync 重跑命令：replay.verify_command 优先 → 记录里真跑过的 secretsdump/--ntds → 由 DA 凭据构造。"""
        replay = (foothold.get("props") or {}).get("replay") or foothold.get("replay") or {}
        if isinstance(replay, dict) and replay.get("verify_command"):
            return str(replay["verify_command"])
        # 从 traces 反推：找真跑过且像 DCSync 的命令，原样重跑（decision B 的 traces 兜底）
        for t in reversed(traces):
            ex = t.get("exec") or ""
            if ("secretsdump" in ex and "-just-dc" in ex) or ("--ntds" in ex):
                return ex
        # 由 replay.domain + 一条 proven DA 凭据构造（需要域名）
        domain = replay.get("domain") if isinstance(replay, dict) else ""
        if domain and target and proven_creds:
            c = proven_creds[0]
            if c.get("kind") == "hash":
                return (f"impacket-secretsdump -dc-ip {_q(target)} "
                        f"-hashes :{_q(c.get('secret',''))} {_q(domain + '/' + c.get('username',''))}@{_q(target)} -just-dc")
            return (f"impacket-secretsdump -dc-ip {_q(target)} "
                    f"{_q(domain + '/' + c.get('username','') + ':' + c.get('secret',''))}@{_q(target)} -just-dc")
        return ""

    @staticmethod
    def _auth_target(cred: dict, traces: list[dict]) -> str:
        """认证目标：cred.replay.target/props.target 优先 → 记录里用过该 secret 的命令里抽主机。"""
        for src in ((cred.get("replay") or {}), (cred.get("props") or {})):
            if isinstance(src, dict) and src.get("target"):
                return str(src["target"])
        secret = cred.get("secret", "")
        if secret:
            for t in reversed(traces):
                ex = t.get("exec") or ""
                if secret in ex:
                    hosts = _bare_hosts(ex)
                    if hosts:
                        return hosts[0]
        return ""


def _q(s: str) -> str:
    """最小 shell 转义（探针参数来自已记录战果/引擎 nonce，仍统一加引号防意外）。"""
    import shlex
    return shlex.quote(str(s))
