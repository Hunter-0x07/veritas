"""证据确定性验证层（防幻觉）—— Stage 1：验"世界"，不验 solver 的自述。

核心原则：verdict 由系统从【已记录的真实世界底物】(activity 的 exec/rc/out)按每个访问级别的
"举证义务"自行重新推导；solver 上报的 evidence/location 只当线索/锚点，**不作为被验证的对象**。
否则"验证"退化成"核对 LLM 措辞"——调 prompt 就能让它变绿（过拟合某个模型的输出格式），
再跑一次也只证明"模型输出符合预期"，而非"攻击真的发生"。

三态收敛（借 strix 的 closure discipline，搬到系统侧）：
  verified  —— 举证义务达成：世界里有能证明该访问级别的真实痕迹（proof-of-effect）。
  refuted   —— 世界里有明确反证（如拿某口令去认证、输出明确失败）。保守触发，宁可 unproven 不乱 refute。
  unproven  —— 既没证成也没证伪（open_proof_gap）：不计入进展，但记录、上报，绝不冒充成功、也不偷偷丢。

证据强度阶梯（级别越高要越强的证明）：
  用成功的凭据 > 系统可识别的"效果痕迹"(proof-of-effect) > 高熵密文在真实输出里+凭据佐证 > location 真跑过 > 字符串重叠(最弱)。

边界 / 后续（见 PLAN.md M5「面向未知靶场的证明模型」）：
  - Stage 1：被动——只从已记录的真实输出/命令里按义务推导；proof-of-effect 不按主机严格限定。
  - Stage 2（✅ 已接入）：持沙箱的 `core/prober.py` 主动探针（引擎自选 nonce 回环 / 重认证 /
    重跑 DCSync，按主机限定）在本层【判定前】给出 proven/refuted/inconclusive；本层接收它当
    【数据】——**主动结论优先于被动推导**：proven→verified、refuted→refuted、inconclusive→回落
    Stage 1 被动。verifier 自身仍是纯函数、不持沙箱（职责干净可测）。
  - Stage 3：举证义务注册表（按漏洞/访问类）+ LLM-judge 仅作辅助评级（低信任档，Observer 交叉核）；确定性永远是脊梁。
mock 是模拟地真值 → 一律 verified；external/recon 是侦察地真值 → 恒 verified。
"""
from __future__ import annotations

import re

from .state import rank

VERIFIED = "verified"
REFUTED = "refuted"
UNPROVEN = "unproven"

_MIN_TOK = 4          # 参与溯源的 token 最小长度
_MIN_COVER = 0.5      # 字符串重叠兜底的命中比例阈值

# —— 通用"效果痕迹"(proof-of-effect)：高熵/结构化串，由目标经真实工具吐出，LLM 造不出 ——
_DUMP_RID500 = re.compile(r"(?mi)^[^\s:]+:500:[0-9a-f]{32}:[0-9a-f]{32}:::")   # DCSync/SAM dump：RID-500 内置管理员
_DUMP_KRBTGT = re.compile(r"(?mi)^krbtgt:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::")    # krbtgt（域信任根密钥）
_DUMP_ANY = re.compile(r"(?mi)^[^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::")      # 任一 user:RID:LM:NT 行
_ROOT_ID = re.compile(r"uid=0\(")                                             # id：root
_SHELL_ID = re.compile(r"uid=\d+\(")                                          # id：拿到某用户 shell
_NTHASH_FULL = re.compile(r"^[0-9a-f]{32}$", re.I)                            # 一个 secret 本身就是 NT hash
# 明确的认证/利用失败痕迹（用于保守反证）
_AUTH_FAIL = re.compile(
    r"(?i)(STATUS_LOGON_FAILURE|LOGON_FAILURE|KDC_ERR_PREAUTH_FAILED|"
    r"authentication failed|auth(?:entication)? error|access[_ ]denied|permission denied|"
    r"invalid credentials|login failed)"
)


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"\s+", text or "") if len(t) >= _MIN_TOK]


def _traceable(evidence: str, haystack: str) -> bool:
    """最弱兜底：solver 自述证据的 token 过半能在真实输出里逐字找到。"""
    toks = set(_tokens(evidence))
    if not toks:
        return False
    hit = sum(1 for t in toks if t in haystack)
    return hit / len(toks) >= _MIN_COVER


def _host_tokens(location: str) -> list[str]:
    """从 location 抽"裸主机名/IP"候选，去掉括号/空格等人读修饰。

    例：'lab-dc.veritas.lab (203.0.113.10)' → ['lab-dc.veritas.lab', '203.0.113.10']。
    这样 location 带格式也能逐字对到命令里（修掉旧版 `location in cmd` 整串匹配的脆弱）。
    """
    out = []
    for p in re.split(r"[\s(),;]+", location or ""):
        p = p.strip().strip(".")
        if len(p) >= _MIN_TOK and re.search(r"[.\d]", p):   # 像 host/ip（含点或数字）
            out.append(p)
    return out


class Verifier:
    def __init__(self, mode: str = "mock"):
        self.mode = mode

    # ---- Stage 2：主动探针结论优先（持沙箱的 prober 产出，本层只当数据用）----
    @staticmethod
    def _from_probe(probe) -> str | None:
        """把 prober 的 ProbeResult(dict) 翻成 verdict。只认确定性的 proven/refuted；
        inconclusive 或 llm-judged（低信任辅助）→ 返回 None，回落 Stage 1 被动推导。"""
        if not probe:
            return None
        verdict = probe.get("verdict")
        trust = probe.get("trust", "deterministic")
        if trust != "deterministic":          # llm-judged / none 不驱动 verdict（确定性才是脊梁）
            return None
        if verdict == "proven":
            return VERIFIED
        if verdict == "refuted":
            return REFUTED
        return None                            # inconclusive → 回落被动

    # ---- 世界底物 ----
    def _outputs(self, traces: list[dict]) -> str:
        """所有真实命令产出拼成的干草堆（效果痕迹从这里找；真实痕迹与 rc 无关）。"""
        return "\n".join((t.get("out") or "") for t in traces)

    def _ok_commands(self, traces: list[dict]) -> str:
        """rc=0 成功命令拼成的串（location 真跑过 / secret 真用过 从这里找）。"""
        return "\n".join((t.get("exec") or "") for t in traces if t.get("rc") == 0)

    # ---- proof-of-effect：世界痕迹是否满足该访问级别的举证义务 ----
    def _proof_of_effect(self, access_level: str, out: str, verified_secrets) -> bool:
        r = rank(access_level)
        if r >= rank("domain_admin"):
            # DCSync 真 dump 到 RID-500 内置域管 / krbtgt 行
            if _DUMP_RID500.search(out) or _DUMP_KRBTGT.search(out):
                return True
            # 或：一条 verified 的 NT-hash 正好出现在真实 dump 输出里（凭据佐证立足点）
            for s in verified_secrets:
                if s and _NTHASH_FULL.match(s) and s in out and _DUMP_ANY.search(out):
                    return True
            return False
        if r >= rank("root"):
            return bool(_ROOT_ID.search(out))        # id → uid=0
        if r >= rank("shell"):
            return bool(_SHELL_ID.search(out))        # id → 拿到某 shell
        # db_read / web_admin / web_user 暂无通用效果痕迹 → 交给 location/traceable 兜底（Stage 3 补举证义务）
        return False

    def foothold(self, access_level: str, location: str, evidence: str,
                 traces: list[dict], verified_secrets=(), probe=None) -> str:
        if self.mode != "live":
            return VERIFIED
        if rank(access_level) <= rank("recon"):       # 侦察地真值
            return VERIFIED
        pv = self._from_probe(probe)                   # Stage 2：主动证成/证伪优先
        if pv is not None:
            return pv
        out = self._outputs(traces)
        cmd = self._ok_commands(traces)
        # 1) 世界里有满足该级别举证义务的效果痕迹
        if self._proof_of_effect(access_level, out, verified_secrets):
            return VERIFIED
        # domain_admin 必须有 proof-of-effect（DCSync 抓到域密钥才算拿下）——
        # "够到 DC / 在 DC 上跑过命令"任何域用户都能做到，≠ 域管，故不接受下面的弱证据兜底。
        if rank(access_level) >= rank("domain_admin"):
            return UNPROVEN
        # 2) location 真跑过：从 location 抽的主机/IP 在某条 rc=0 命令里出现过（shell/横向：在该主机上成功执行=有访问）
        if any(h in cmd for h in _host_tokens(location)):
            return VERIFIED
        # 3) 最弱兜底：solver 自述证据可溯源到真实输出（保留，但不再是主路）
        if _traceable(evidence, out):
            return VERIFIED
        return UNPROVEN                                # 被动阶段：没证成即 unproven；主动反证留 Stage 2

    def credential(self, secret: str, username: str, traces: list[dict], probe=None) -> str:
        if self.mode != "live":
            return VERIFIED
        pv = self._from_probe(probe)                   # Stage 2：引擎亲自重认证的结论优先
        if pv is not None:
            return pv
        out = self._outputs(traces)
        cmd = self._ok_commands(traces)
        hay = out + "\n" + cmd
        traceable = (bool(secret) and len(secret) >= _MIN_TOK and secret in hay) or \
                    (bool(username) and len(username) >= _MIN_TOK and username in hay)
        if traceable:
            return VERIFIED                            # 真从世界里拿到/破出/用到（如 john 破出的明文、dump 出的 hash）
        # 保守反证：拿这条 secret 去认证的命令、输出明确失败，且没有任何正面痕迹
        if secret and len(secret) >= _MIN_TOK:
            for t in traces:
                if secret in (t.get("exec") or "") and _AUTH_FAIL.search(t.get("out") or ""):
                    return REFUTED
        return UNPROVEN
