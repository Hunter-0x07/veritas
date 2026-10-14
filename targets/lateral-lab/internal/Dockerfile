# internal-host：内网 ssh 主机，只在 internal 网络（attacker 直连不到，须经 edge 横向）
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash deploy \
    && echo 'deploy:Spr1ng!2024' | chpasswd \
    && mkdir -p /run/sshd \
    && printf 'FLAG{lateral-movement-reached-internal-host}\n' > /home/deploy/flag.txt \
    && chown deploy:deploy /home/deploy/flag.txt \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
