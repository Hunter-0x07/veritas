# 知识包：Web 攻击面侦察

目标：把"一个 URL"扩展成可攻击的端点/功能清单。探索不足是头号失败原因，侦察先做足。

## 判断目标类型
- 首页 HTML 几乎没内容却加载大 JS bundle（`main.*.js`/`runtime.*.js`）→ **SPA**，接口是后端 REST，藏在 JS 里。
- 传统多页应用 → 页面里有表单和链接，顺着爬。

## SPA 侦察（如 Juice Shop）
- 抓 bundle 抽 API：
  `curl -s <target>/ | grep -oE '(main|runtime|polyfills)[.-][A-Za-z0-9]+\.js'`
  再 `curl -s <target>/<bundle.js> | grep -oE '(rest|api)/[A-Za-z0-9_/-]+' | sort -u`
- 典型端点：`/rest/user/login`、`/rest/products/search`、`/rest/user/whoami`、`/api/...`

## 常规
- `/robots.txt` `/sitemap.xml` `/ftp` `/.well-known/security.txt`
- 响应头看技术栈（`X-Powered-By: Express`…）
- 目录/接口爆破：`gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt` 或 `ffuf`

## 原则
拿到端点后，对**登录 / 搜索 / id 类参数 / 上传**重点测注入与越权。你的目标是**拿到访问/数据**，不是列漏洞。
