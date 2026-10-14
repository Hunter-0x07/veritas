# 知识包：认证攻击

目标：拿到有效身份（token/session/凭据）→ 提升访问级别。

## 路径
- **登录绕过**：SQLi（见 sqli 包）、默认/弱口令、逻辑缺陷。
- **JWT**：拿到 token 先解 `echo <jwt> | cut -d. -f2 | base64 -d`，看 `alg`（`none`/弱密钥可伪造）、角色字段（改 `role: admin`）。工具 jwt_tool。
- **爆破**（授权内、克制）：`hydra`、弱口令小字典；别大规模爆破。

## 拿到之后
- 有效凭据/token → `report_credential` + `report_foothold`（web_user / web_admin）。
- admin token → 访问管理接口，常能进一步 dump / 提权 / 拿部署凭据（通往内网横向）。

## Juice Shop
- 管理员 `admin@juice-sh.op`；登录 SQLi 直接拿 admin token（见 sqli 包）。
- 拿到 admin 后看 `/rest/user/whoami`、管理功能、是否能读到内网/部署相关数据。
