#!/bin/bash
set -euo pipefail

# 幂等：首次启动才 provision（重启复用已建好的域库）
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    /provision.sh
fi

# krb5.conf 指向本域（smbclient/诊断用；attacker 侧用自己的 -dc-ip）
cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf 2>/dev/null || true

echo "[ad-lab] starting Samba AD DC (domain veritas.lab) ..."
exec samba -i -s /etc/samba/smb.conf
