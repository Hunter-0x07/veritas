"""分级自主 / 审批门（HITL）：破坏性·高噪声动作在 approval 模式下 fail-closed 拦截+记录。

第一性与 scope 同源：真实目标是 HackerOne 这类【授权外部目标】，限速 / 检测 / ToS / 账号锁定
决定了不能随便做破坏性或高噪声动作。于是把动作按【破坏性 / 噪声】分级，策略按目标授权档决定
是否要人工审批：
  - 靶场（authorization=lab）→ full_auto：试验台，全放行。
  - 外部授权目标（authorization=external，默认）→ approval：破坏性/高噪声动作要人工审批。

与 verifier 的 safe-probe（core/prober.py 的 low/medium/high · lab/external）**对齐复用**同一套
噪声档与授权档，不另造词表：prober 管"主动重探针该不该发"，autonomy 管"solver 自己要跑的
破坏性/高噪声命令该不该放"，两者互补覆盖执行面。

**分类纪律（按命令动词位置判，不扫字符串数据）**：`classify` 先把命令按 `;`/`|`/`&&` 等分段、
shlex 分词，只对每段的【命令动词】(首 token，剥 sudo/env/timeout 等包装，`sh -c '...'` 递归内层)
判关键词——而不是在整条命令串上做子串匹配。否则 `grep passwd <file>`、`echo shutdown`、把
destructive 词放进引号数据/`--data` 载荷的 benign 命令会被误判（见 code-review 修复）。引号内数据
天然是单个 token（非动词），故不触发。解析失败（引号不配对等）才退回保守的整串匹配兜底。

当前引擎是全自动舰队、无人在环（core/engine.py），approval 模式下遇需审批动作：
  - on_gated=deny（**fail-closed 默认**）：拦截 + 记录（回提示给 LLM 换招、落 activity/报告标
    needs_approval、Observer 交叉核）——无人在环时的安全默认。
  - on_gated=allow：放行 + 记录（fail-open，给受监督 run 的选项，仅遥测不拦）。
真正的交互式【暂停→operator 逐条批准→恢复】UI 留后续。审批点 = executor 执行命令处。

纯 stdlib（re + shlex + dataclass），无 I/O：确定性单测。
"""
from __future__ import annotations

import re
import shlex
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
# 类别严重度（跨段取最重；>benign 即需审批）
_CAT_RANK = {BENIGN: 0, FILE_WRITE: 1, FILE_DELETE: 2, BROAD_SCAN: 2, BRUTEFORCE: 3, DESTRUCTIVE: 4}

# 系统路径（删/递归改权限 → 破坏性）；写重定向另用不含 /dev、/home 的集合（/dev/null 与 home scratch 常见）
_SYS = re.compile(r"^/(?:etc|var|usr|bin|sbin|boot|root|lib|lib64|opt|sys|proc|srv|home)\b")
_SYS_WRITE = re.compile(r"^/(?:etc|var|usr|bin|sbin|boot|root|lib|lib64|opt|sys|proc|srv)\b")
_ROOT = re.compile(r"^/+$")
_FORKBOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:")
_RECURSIVE = re.compile(r"^-[A-Za-z]*[rR][A-Za-z]*$")
_BROAD_CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/(\d{1,2})$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NUMISH = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")

_WRAPPERS = {"sudo", "doas", "env", "nohup", "setsid", "stdbuf", "time", "nice", "ionice", "timeout"}
_SUDO_VALUE_FLAGS = {"-u", "-g", "-U", "-C", "-p", "-h", "-t", "-r", "-D", "-n", "--user", "--group"}
_SEP = {";", "|", "||", "&", "&&", "|&", "\n"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh"}

# 解析失败（引号不配对等）才用的保守整串兜底规则（偶发、宁严勿漏）
_FALLBACK = [
    (re.compile(r"\b(?:mkfs|fdisk|parted|wipefs)\b", re.I), DESTRUCTIVE, "磁盘/分区操作"),
    (re.compile(r"\bdd\b[^\n]*\bof=\s*['\"]?/dev/", re.I), DESTRUCTIVE, "dd 写块设备"),
    (re.compile(r"\b(?:shutdown|reboot|poweroff|halt)\b", re.I), DESTRUCTIVE, "关机/重启"),
    (re.compile(r"\b(?:userdel|groupdel|deluser|killall|pkill)\b", re.I), DESTRUCTIVE, "删账号/杀进程"),
    (re.compile(r"\brm\b[^\n]*\s-[A-Za-z]*r", re.I), FILE_DELETE, "递归删除"),
    (re.compile(r"\b(?:hydra|medusa|patator|ncrack)\b", re.I), BRUTEFORCE, "在线爆破工具"),
    (re.compile(r"\bmasscan\b|\bnmap\b[^\n]*\s-p-", re.I), BROAD_SCAN, "大范围扫描"),
]


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


def _act(cat: str, why: str) -> Action:
    return Action(category=cat, noise=_CATEGORY_NOISE[cat], reason=why)


def _worst(a: Action, b: Action) -> Action:
    return a if _CAT_RANK[a.category] >= _CAT_RANK[b.category] else b


def _basename(tok: str) -> str:
    return tok.split("/")[-1].lower()


def _tokenize(s: str) -> list:
    """shell 风格分词：标点（; | & < > 等）成独立 token、引号内数据为单 token。可能抛 ValueError。"""
    lex = shlex.shlex(s, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""          # 关掉 # 注释处理，避免 URL/口令里的 # 截断命令
    return list(lex)


def _strip_wrappers(toks: list) -> list:
    """剥掉前导 env 赋值与 sudo/env/timeout/nice 等包装，露出真正的命令动词（防 `sudo rm -rf /` 漏判）。"""
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if _ENV_ASSIGN.match(t):
            i += 1
            continue
        if _basename(t) in _WRAPPERS:
            i += 1
            while i < n:                       # 跳过该包装自身的选项/数值（sudo -u user、timeout 30…）
                nxt = toks[i]
                if nxt.startswith("-"):
                    takes_val = _basename(nxt) in _SUDO_VALUE_FLAGS
                    i += 1
                    if takes_val and i < n and not toks[i].startswith("-"):
                        i += 1
                    continue
                if _NUMISH.match(nxt):
                    i += 1
                    continue
                break
            continue
        break
    return toks[i:]


def _broad_cidr(tok: str) -> bool:
    m = _BROAD_CIDR.match(tok)
    return bool(m) and int(m.group(1)) <= 23     # /0–/23 视为大网段（/24+ 视为窄）


def _verb_action(verb: str, args: list) -> Action:
    """按命令动词 + 相关参数定类（只认动词位置，不扫数据参数）。"""
    nonflag = [a for a in args if not a.startswith("-")]
    if verb == "rm":
        if any(_ROOT.match(a) or _SYS.search(a) for a in nonflag):
            return _act(DESTRUCTIVE, "删除系统路径")
        if "--recursive" in args or any(_RECURSIVE.match(a) for a in args):
            return _act(FILE_DELETE, "递归删除")
        return _act(BENIGN, "")
    if verb in ("shred", "wipe"):
        return _act(FILE_DELETE, "粉碎文件")
    if verb == "truncate":
        if any(a in ("-s0", "--size=0") for a in args) or ("-s" in args and "0" in args):
            return _act(FILE_DELETE, "清空文件")
        return _act(BENIGN, "")
    if verb == "dd":
        if any(a.startswith("of=/dev/") for a in args):
            return _act(DESTRUCTIVE, "dd 写块设备")
        return _act(BENIGN, "")
    if verb.startswith("mkfs") or verb in ("fdisk", "sfdisk", "cfdisk", "parted", "wipefs"):
        return _act(DESTRUCTIVE, "磁盘/分区操作")
    if verb in ("shutdown", "reboot", "poweroff", "halt"):
        return _act(DESTRUCTIVE, "关机/重启")
    if verb == "init" and ("0" in args or "6" in args):
        return _act(DESTRUCTIVE, "切换运行级")
    if verb in ("iptables", "ip6tables"):
        return _act(DESTRUCTIVE, "改防火墙规则") if any(a in ("-F", "-X", "-Z", "--flush") for a in args) else _act(BENIGN, "")
    if verb == "nft" and "flush" in args:
        return _act(DESTRUCTIVE, "清空防火墙规则")
    if verb in ("userdel", "groupdel", "deluser"):
        return _act(DESTRUCTIVE, "删除账号")
    if verb == "passwd":
        return _act(DESTRUCTIVE, "修改账号口令")
    if verb in ("killall", "pkill"):
        return _act(DESTRUCTIVE, "批量杀进程")
    if verb in ("chown", "chmod"):
        recursive = "--recursive" in args or any(_RECURSIVE.match(a) for a in args) or "-R" in args
        if recursive and any(_SYS.search(a) for a in nonflag):
            return _act(DESTRUCTIVE, "递归改系统路径权限")
        return _act(BENIGN, "")
    if verb == "tee":
        return _act(FILE_WRITE, "tee 写系统路径") if any(_SYS_WRITE.search(a) for a in nonflag) else _act(BENIGN, "")
    if verb in ("hydra", "medusa", "patator", "ncrack"):
        return _act(BRUTEFORCE, "在线爆破工具")
    if verb in ("crackmapexec", "nxc", "netexec"):
        wordlist = any(a.startswith("--password") for a in args)
        for i, a in enumerate(args):
            if a == "-p" and i + 1 < len(args) and args[i + 1].endswith((".txt", ".lst")):
                wordlist = True
        return _act(BRUTEFORCE, "密码喷洒/字典") if wordlist else _act(BENIGN, "")
    if verb == "masscan":
        return _act(BROAD_SCAN, "masscan 大范围扫描")
    if verb == "nmap":
        if "-p-" in args or any(_broad_cidr(a) for a in nonflag):
            return _act(BROAD_SCAN, "nmap 全端口/大网段")
        return _act(BENIGN, "")
    return _act(BENIGN, "")


def _classify_segment(toks: list) -> Action:
    toks = _strip_wrappers(toks)
    worst = _act(BENIGN, "")
    # 重定向写系统路径（> / >> 后跟系统路径）——shell 级，与动词无关
    for j, t in enumerate(toks):
        if t in (">", ">>") and j + 1 < len(toks) and _SYS_WRITE.search(toks[j + 1]):
            worst = _worst(worst, _act(FILE_WRITE, "重定向写系统路径"))
    if not toks:
        return worst
    verb = _basename(toks[0])
    args = toks[1:]
    # sh -c '内层命令' → 递归分类内层串（否则 `sh -c 'rm -rf /'` 会被当 verb=sh 漏判）
    if verb in _SHELLS and "-c" in args:
        ci = args.index("-c")
        if ci + 1 < len(args):
            worst = _worst(worst, classify(args[ci + 1]))
    return _worst(worst, _verb_action(verb, args))


def _fallback(raw: str) -> Action:
    """解析失败时的保守整串兜底（偶发：引号不配对等）。"""
    for rx, cat, why in _FALLBACK:
        if rx.search(raw):
            return _act(cat, why)
    return _act(BENIGN, "")


def classify(cmd: str) -> Action:
    """把一条 shell 命令分到破坏性/噪声类别（默认 benign）。按命令动词位置判，不扫字符串数据。"""
    raw = cmd or ""
    if _FORKBOMB.search(raw):
        return _act(DESTRUCTIVE, "fork bomb")
    worst = _act(BENIGN, "")
    try:
        for line in (raw.splitlines() or [raw]):
            toks = _tokenize(line)
            seg: list = []
            for t in toks:
                if t in _SEP:
                    worst = _worst(worst, _classify_segment(seg))
                    seg = []
                else:
                    seg.append(t)
            worst = _worst(worst, _classify_segment(seg))
    except ValueError:
        return _fallback(raw)
    return worst


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
