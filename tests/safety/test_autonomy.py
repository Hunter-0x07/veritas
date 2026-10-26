"""safety/autonomy 确定性单测（纯 stdlib，`.venv/bin/python tests/safety/test_autonomy.py`）。

验分级：破坏性/大范围/爆破被识别并（approval·fail-closed）拦截；sandbox 内 scratch 写/窄扫描/
单文件删/读命令不误杀；mode 按 authorization 推导。
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.safety.autonomy import (
    AutonomyPolicy, classify, BENIGN, FILE_WRITE, FILE_DELETE,
    DESTRUCTIVE, BROAD_SCAN, BRUTEFORCE)

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")

print("[classify] 破坏性/高噪声")
CASES = {
    # benign（不拦）
    "curl http://t/": BENIGN, "echo hi; id": BENIGN, "cat /etc/passwd": BENIGN,
    "sqlmap -u http://t/?id=1 --batch": BENIGN,
    "nmap -sV -p 80,443 172.20.0.5": BENIGN, "nmap -sn 10.0.0.0/24": BENIGN,
    "curl http://t/ -o /tmp/out.html": BENIGN, "echo x > out.txt": BENIGN,
    "grep -r pass . 2>/dev/null": BENIGN, "rm /tmp/scratch.txt": BENIGN,
    # destructive
    "rm -rf /var/www": DESTRUCTIVE, "rm -rf /": DESTRUCTIVE,
    "dd if=/dev/zero of=/dev/sda": DESTRUCTIVE, "mkfs.ext4 /dev/sdb": DESTRUCTIVE,
    "shutdown -h now": DESTRUCTIVE, "iptables -F": DESTRUCTIVE,
    "killall sshd": DESTRUCTIVE, "passwd root": DESTRUCTIVE, "userdel bob": DESTRUCTIVE,
    # broad scan
    "nmap -p- 172.20.0.5": BROAD_SCAN, "nmap -sS 10.0.0.0/16": BROAD_SCAN,
    "masscan -p1-65535 10.0.0.0/8": BROAD_SCAN,
    # bruteforce
    "hydra -l admin -P rockyou.txt ssh://172.20.0.5": BRUTEFORCE,
    "medusa -h 10.0.0.5 -u root -P pass.txt -M ssh": BRUTEFORCE,
    # file delete / write
    "rm -rf ./build": FILE_DELETE, "shred -u secret.txt": FILE_DELETE,
    "echo pwned > /etc/motd": FILE_WRITE, "tee /etc/hosts": FILE_WRITE,
}
for cmd, want in CASES.items():
    check(f"classify {cmd[:42]}", classify(cmd).category, want)

print("[classify] 按动词位置判（code-review 修复：不扫引号/数据/参数里的关键词）")
FIX = {
    # 关键词出现在【参数/数据/引号】里（非命令动词）→ 不误判（benign）
    "grep passwd /etc/shadow": BENIGN,          # finding 1：grep 是动词，passwd 是参数
    "grep -r passwd /etc/": BENIGN,
    "cat dump.txt | grep passwd": BENIGN,       # 管道后段动词是 grep
    "echo shutdown now": BENIGN,                # finding 2：echo 是动词
    "echo 'please reboot the box'": BENIGN,
    "curl http://t/ --data 'note=shutdown'": BENIGN,   # finding 3 同源：数据非 shell
    "curl http://t/ --data 'x=rm -rf /'": BENIGN,
    "cat /etc/passwd": BENIGN,                  # 读文件不是改口令
    # 真破坏性仍要抓到（含包装/嵌套，防漏判）
    "sudo rm -rf /etc": DESTRUCTIVE,            # 剥 sudo 后动词 rm + 系统路径
    "sudo -u www rm -rf /var/log": DESTRUCTIVE, # sudo 带值选项也要剥对
    "timeout 30 nmap -p- 10.0.0.5": BROAD_SCAN, # 剥 timeout + 数值
    "sh -c 'rm -rf /'": DESTRUCTIVE,            # sh -c 递归内层
    "bash -c 'grep passwd x'": BENIGN,          # sh -c 递归：内层也是 benign
}
for cmd, want in FIX.items():
    check(f"fix {cmd[:44]}", classify(cmd).category, want)

print("[AutonomyPolicy.gate] approval·fail-closed（默认）")
ap = AutonomyPolicy(mode="approval", on_gated="deny")
d = ap.gate_command("rm -rf /var/www")
check("破坏性→拦截", (d.allow, d.record, d.gate), (False, True, "needs_approval"))
d = ap.gate_command("nmap -p- 10.0.0.5")
check("大范围扫描→拦截", d.allow, False)
d = ap.gate_command("curl http://t/")
check("benign→放行不记", (d.allow, d.record), (True, False))

print("[AutonomyPolicy.gate] full_auto（靶场全放行）")
fa = AutonomyPolicy(mode="full_auto")
check("full_auto 破坏性也放行", fa.gate_command("rm -rf /var/www").allow, True)
check("full_auto 不留痕", fa.gate_command("rm -rf /var/www").record, False)

print("[AutonomyPolicy.gate] approval·fail-open（on_gated=allow）")
ao = AutonomyPolicy(mode="approval", on_gated="allow")
d = ao.gate_command("rm -rf /var/www")
check("放行但留痕", (d.allow, d.record, d.gate), (True, True, "would_require_approval"))

print("[from_cfg] mode 推导")
class _P:  # duck-typed ProbeCfg
    def __init__(self, a): self.authorization = a
check("auto + lab → full_auto", AutonomyPolicy.from_cfg(None, _P("lab")).mode, "full_auto")
check("auto + external → approval", AutonomyPolicy.from_cfg(None, _P("external")).mode, "approval")
class _A:
    def __init__(self, m, g="deny"): self.mode, self.on_gated = m, g
check("显式 full_auto", AutonomyPolicy.from_cfg(_A("full_auto"), _P("external")).mode, "full_auto")
check("显式 approval", AutonomyPolicy.from_cfg(_A("approval"), _P("lab")).mode, "approval")
check("非法 mode → approval(保守)", AutonomyPolicy.from_cfg(_A("weird"), _P("lab")).mode, "approval")
check("非法 on_gated → deny(保守)", AutonomyPolicy.from_cfg(_A("approval", "xxx"), _P("x")).on_gated, "deny")
check("默认(无 cfg) external 推导 approval", AutonomyPolicy.from_cfg(None, None).mode, "approval")

print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_autonomy)")
sys.exit(1 if _fail else 0)
