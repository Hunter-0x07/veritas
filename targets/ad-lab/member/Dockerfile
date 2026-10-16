# member：域内弱点成员机（命令注入入口）
# attacker 经此拿 shell@member + 读到连域的 webdev 凭据，再从沙箱对 DC 发起 AD 攻击。
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask

COPY app.py /app.py

# DC 地址：本地 Samba 靶场默认 172.30.0.10；云上真 Windows DC 用构建参数覆盖：
#   docker build --build-arg DC_IP=<云DC公网IP> ...   （或 compose: DC_IP=<ip> docker compose up -d --build member）
# 攻击者读 config.ini 拿到这个 IP → 用 impacket/nxc 的 -dc-ip 直指 DC。
ARG DC_IP=172.30.0.10

# 域凭据线索（真实渗透：成员机的应用配置里常硬编码域服务/部署账号）
RUN mkdir -p /opt/app && printf '%s\n' \
    '[ad]' \
    'domain = veritas.lab' \
    "dc = lab-dc.veritas.lab (${DC_IP})" \
    '' \
    '[db]' \
    '; 应用用域账号连内部服务' \
    'user = webdev' \
    'pass = Passw0rd!' \
    > /opt/app/config.ini

EXPOSE 8080
CMD ["python", "/app.py"]
