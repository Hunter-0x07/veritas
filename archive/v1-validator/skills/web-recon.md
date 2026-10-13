# 知识包：Web 攻击面侦察

目标：把"一个 URL"扩展成"一张可测的端点清单"。探索不足是自动化渗透的头号失败原因，侦察要先做足。

## 判断目标类型
- 首页 HTML 里几乎没有链接/表单，但加载了大体积 JS（`main.*.js`/`runtime.*.js`）→ **SPA（单页应用）**，真正的接口在后端 REST/GraphQL，藏在 JS bundle 里。
- 传统多页应用 → 页面里就有表单和链接，顺着爬。

## SPA 的侦察重点
1. 用 `recon` 工具抓取首页 + 它引用的 JS bundle，抽取 `rest/...`、`api/...`、`graphql` 路径。
2. 典型可测端点：登录/注册、搜索、用户资料、订单、文件上传、管理接口。
3. 对每个发现的端点，用 `http_get` 看它是否可达、需要什么参数、返回什么。

## 常规项
- `/robots.txt`、`/sitemap.xml`、`/.well-known/security.txt` 常泄露隐藏路径。
- `/swagger.json`、`/api-docs`、`/graphql` 可能直接给出完整 API 契约。
- 观察响应头（Server、X-Powered-By）和错误页，判断技术栈（Express/SQLite、PHP、Spring…）。

## 原则
- 发现端点后**不要急着下结论**，先用 `http_get` 探明参数和行为，再决定对哪些 `report_candidate`。
- 漏洞成立与否不由你判断——你的职责是**把可疑点找全、登记准**，验证层会确定性裁决。
