# Veritas 工具沙箱 —— Kali 全家桶（kali-linux-default，无 GUI）
# 攻击工具在此隔离执行；执行器给它一个 shell 直接跑 CLI（Strix 式 shell-as-executor）。
# kali-linux-default = Kali 标准工具集，含 nmap/sqlmap/metasploit/ffuf/gobuster/nikto/
# wpscan/hydra/john/wfuzz/impacket/crackmapexec/responder 等，覆盖 web 挖洞 → 横向 → 后渗透；
# 不含 everything 的无线/取证/硬件工具，省体积。缺个别工具再 apt install。
FROM kalilinux/kali-rolling

# mitmproxy：全链路 MITM 留痕用的记录型代理（kali-linux-default 已含，显式声明防基镜像漂移）
RUN printf 'Acquire::Retries "8";\n' > /etc/apt/apt.conf.d/80retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends kali-linux-default python3-pip mitmproxy \
    && rm -rf /var/lib/apt/lists/*

# 我们自己写 PoC/脚本用的 Python 库
RUN pip3 install --no-cache-dir --break-system-packages httpx requests beautifulsoup4

WORKDIR /work
CMD ["sleep", "infinity"]
