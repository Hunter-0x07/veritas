# 知识包：SQL 注入测试

你的职责是**找准可疑注入点并登记（report_candidate）**，不要自己断言成立——验证层会用确定性 oracle 裁决。

## 高危参数（优先登记）
- 登录接口的 `email` / `username`（认证绕过经典点，如 `POST /rest/user/login`）。
- 搜索接口的 `q` / `search` / `keyword`（报错/UNION 型，如 `GET /rest/products/search?q=`）。
- 任何直接进 SQL 的标识符：`id`、`orderId`、`productId`、排序字段 `sort`/`order`。

## 快速探针（判断是否"进了 SQL"）
- 注入单引号 `'`：若返回 **SQL 错误**（如 `SQLITE_ERROR`、`syntax error`、`near "..."`）或 500，说明参数进入了 SQL 语句 → 强可疑，登记。
- 对比 `'`（破坏语法）与 `''`（平衡）：前者报错、后者正常 → 几乎确定是注入点。
- 登录点：`' OR 1=1--` 能登录、`' OR 1=2--` 不能 → 认证绕过。

## 登记 report_candidate 时带全信息
- `type: "sqli"`、`url`、`method`、`param`（注入参数名）。
- `injection`: 查询参数用 `query`，JSON body 用 `json_body`，表单用 `form_body`。
- `base_params`: 同请求的其他必填参数（如 login 的 `password`）。

## 典型例子（Juice Shop）
- `POST /rest/user/login`，`injection: json_body`，`param: email`，`base_params: {"email":"a@a.com","password":"x"}`。
- `GET /rest/products/search`，`injection: query`，`param: q`，`base_params: {"q":"apple"}`。
