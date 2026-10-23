"""授权边界（scope）：从一条命令里抽出【连接目标】主机/IP，比对授权 domains + CIDR。

为什么需要：引擎把 GLM 放进 Kali 沙箱自由 tool-use，模型可能被目标里读到的线索（如
config.ini 里的域凭据）勾引，去打【授权范围外】的主机——实测（task 6661273c36a0）GLM
往已关机的云 DC 与 Docker 网关撞了十几次。scope 是执行前的硬边界：域内放行、域外拒绝。

设计要点（第一性：真实目标是 HackerOne 这类授权外部目标，既要真拦越界、又绝不误杀合法
内网横向）：
  1. 抽的是【连接目标】，不是 payload 数据——URL 只取 authority 主机（query 里内嵌的
     `?redirect=http://evil.com` 不算目标，否则会误杀开放重定向类合法请求）；位于
     `--data`/`-H` 等旗标值里的 FQDN 不抽（那是发给目标的数据，不是我们要连的主机）。
  2. **所有 IPv4/IPv6 字面量一律抽**（位置无关）——这是堵实测事故（撞具体 IP）的高信号项；
     代价是"把某越界 IP 当纯数据发给域内目标"也会被拦（保守偏严，宁可拦错不放过，已文档化）。
  3. 单标签主机名（无点、如内网容器名 `lab-edge`/`lab-internal`）无法做 CIDR 校验 → 放行
     （不误杀横向）；多标签 FQDN 未匹配任一授权域 → 拒绝（`evil.com` 这类限定外部名）。
  4. loopback（沙箱自身 / MITM 代理 / Juice Shop via host 网）恒放行；抽不到主机的本地命令放行。

纯 stdlib（re + ipaddress + shlex），无 I/O：可被 config/executor/prober 复用、确定性单测。
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from urllib.parse import urlsplit

# 其后紧跟的值是发给目标的数据/请求头（payload），不是连接目标——其中的 FQDN 不抽。
# 注意：IP 仍会被全局规则抽到（见模块 docstring 第 2 点）。
_DATA_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
    "-F", "--form", "-H", "--header", "-A", "--user-agent", "-e", "--referer",
    "-b", "--cookie", "--json",
}

_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"`|;,<>]+")
_AT_HOST = re.compile(r"@([A-Za-z0-9._\-]+)")
# 多标签 FQDN（裸 token 形态的位置参数目标，如 `nxc smb dc.lab.local`）
_FQDN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+$")
# 文件名样式后缀（脚本/配置等会被 FQDN 正则误当主机，排除之：secretsdump.py / config.ini …）
_FILE_SUFFIX = re.compile(
    r"(?i)\.(py|txt|sh|bash|conf|cfg|ini|json|ya?ml|log|md|xml|html?|php|pem|key|crt|cer|"
    r"cache|ccache|csv|tsv|db|sqlite|bak|out|tmp|zip|tar|gz|tgz|exe|dll|so|jar|ps1|bat|rb|pl|go)$")


def _valid_ip(s: str):
    """返回 ipaddress 对象或 None（滤掉 999.1.1.1 这类非法 octet / 版本号误报）。"""
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _url_host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").strip(".")
    except ValueError:
        return ""


def _is_fqdn(tok: str) -> bool:
    """裸 token 是否像一个多标签 FQDN 主机（而非文件名/版本号/IP）。"""
    if not _FQDN.match(tok) or _FILE_SUFFIX.search(tok):
        return False
    last = tok.rsplit(".", 1)[-1]
    # 末标签须是字母 TLD（len>=2），排除 IP（末段数字）和 `a.b`/版本号这类
    return last.isalpha() and len(last) >= 2


def extract_targets(cmd: str) -> list[str]:
    """从命令抽【连接目标】主机/IP 候选（小写去重）。抽不到 = 本地命令。"""
    out: list[str] = []
    seen: set[str] = set()

    def add(h: str) -> None:
        h = (h or "").strip().strip(".").lower()
        if h and h not in seen:
            seen.add(h)
            out.append(h)

    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError:
        toks = cmd.split()

    prev = ""
    for tok in toks:
        # (1) 全局 IP：无论位置（含 payload 里的 IP），高信号堵越界
        for m in _IPV4.findall(tok):
            if _valid_ip(m) is not None:
                add(m)
        is_data = prev in _DATA_FLAGS
        if not is_data:
            # (2) URL authority（只取主机，忽略 query 内嵌 URL）
            for um in _URL.finditer(tok):
                add(_url_host(um.group(0)))
            # (3) user@host / domain/user:pass@host（ssh / impacket）
            for am in _AT_HOST.finditer(tok):
                add(am.group(1))
            # (4) 裸多标签 FQDN 位置参数（nxc smb dc.lab.local）
            if _is_fqdn(tok):
                add(tok)
        prev = tok
    return out


def host_in_scope(host: str, domains, cidrs) -> bool:
    """单个主机/IP 是否在授权范围内。"""
    h = (host or "").strip().strip(".").lower()
    if not h:
        return True
    ip = _valid_ip(h)
    if ip is not None and (ip.is_loopback or h == "::1"):
        return True
    if h == "localhost":
        return True
    dset = {str(d).strip().strip(".").lower() for d in (domains or [])}
    if ip is not None:
        if h in dset:                       # 有的配置把 IP 直接写进 domains
            return True
        for c in (cidrs or []):
            try:
                if ip in ipaddress.ip_network(str(c), strict=False):
                    return True
            except ValueError:
                continue
        return False
    # 主机名：精确匹配或子域
    if h in dset:
        return True
    for d in dset:
        if d and h.endswith("." + d):
            return True
    # 单标签未匹配（内网容器名，无法 CIDR 校验）→ 放行，不误杀横向
    if "." not in h:
        return True
    # 多标签 FQDN 未匹配任一授权域 → 拒绝
    return False


def allows(cmd: str, domains, cidrs) -> bool:
    """命令是否只触及授权范围内主机。任一连接目标越界即 False；本地命令 True。"""
    return all(host_in_scope(h, domains, cidrs) for h in extract_targets(cmd))
