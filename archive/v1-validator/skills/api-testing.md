# 知识包：REST API 测试

发现一批 `rest/` / `api/` 端点后，按下面的清单逐个判断该测什么、该登记什么。

## 先摸清每个端点
用 `http_get` 看：需要认证吗？接受什么参数？GET/POST？返回 JSON 结构长啥样？错误信息是否泄露内部细节（SQL 错误、堆栈）。

## 按端点类型找可疑点
- **认证类**（login/register/token/reset-password）：注入（见 sqli 知识包）、弱校验、可枚举用户。
- **查询/搜索类**（search/products/users?id=）：SQL 注入（报错/UNION）、IDOR（改 id 越权读别人数据）。
- **资源对象类**（`/rest/<resource>/<id>`）：IDOR——把 id 换成别人的看是否越权；批量赋值——提交多余字段（如 `role: admin`）看是否被接受。
- **上传/反馈/订单**：存储型 XSS、业务逻辑（改价、改数量为负）。

## 登记原则
- 对注入点 → 用 sqli / xss 知识包的格式 `report_candidate`。
- 其余类型（IDOR/批量赋值/逻辑）当前验证层尚未覆盖，可写成事实（fact）供后续，不要当成已确认漏洞。
- 始终记住：你负责"找全、登记准"，成立与否交验证层。
