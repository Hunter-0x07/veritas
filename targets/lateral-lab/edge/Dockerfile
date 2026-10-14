# edge：外网可达的 web 服务，带命令注入漏洞；双网卡（能到内网）
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping openssh-client sshpass netcat-openbsd curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask

COPY app.py /app.py

# 内网横向的凭据线索（真实渗透里常见：配置/备注里留着部署账号）
RUN printf 'internal deploy host: internal-host (ssh)\naccount: deploy\n' > /root/notes.txt \
    && printf 'deploy:Spr1ng!2024\n' > /root/.deploy_creds

EXPOSE 8080
CMD ["python", "/app.py"]
