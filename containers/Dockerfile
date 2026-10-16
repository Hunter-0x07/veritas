# Veritas 工具沙箱 —— Kali 全家桶（kali-linux-default，无 GUI）
# 攻击工具在此隔离执行；执行器给它一个 shell 直接跑 CLI（Strix 式 shell-as-executor）。
# kali-linux-default = Kali 标准工具集，含 nmap/sqlmap/metasploit/ffuf/gobuster/nikto/
# wpscan/hydra/john/wfuzz/impacket/crackmapexec/responder 等，覆盖 web 挖洞 → 横向 → 后渗透；
# 不含 everything 的无线/取证/硬件工具，省体积。缺个别工具再 apt install。
FROM kalilinux/kali-rolling

# mitmproxy：全链路 MITM 留痕代理；impacket-scripts/netexec：AD 域攻击工具（Kerberoast/DCSync）。
# 三者 kali-linux-default 名义上已含，但显式钉死防基镜像漂移（第一次 live 曾因缺 AD 工具 rc=127）。
RUN printf 'Acquire::Retries "8";\n' > /etc/apt/apt.conf.d/80retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends kali-linux-default python3-pip mitmproxy \
       impacket-scripts netexec \
    && rm -rf /var/lib/apt/lists/*

# 我们自己写 PoC/脚本用的 Python 库 + AD 域攻击的 BloodHound 采集器
# （impacket / netexec(crackmapexec) / john 已在 kali-linux-default；bloodhound-python 单独补）
RUN pip3 install --no-cache-dir --break-system-packages httpx requests beautifulsoup4 bloodhound

WORKDIR /work
CMD ["sleep", "infinity"]
