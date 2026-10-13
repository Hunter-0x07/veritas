# 知识包：XSS 测试

职责同样是**找准可疑点并登记**；是否真执行由验证层用无头浏览器确定性确认——注意：响应里"回显了 payload 字符串"不等于 XSS，必须真执行。

## 三类
- 反射型：参数值被原样写进响应 HTML。
- 存储型：输入被存起来，在别处页面渲染。
- DOM 型：前端 JS 把参数（常来自 URL hash/query）直接写进 DOM，**不经过服务器**。SPA 最常见。

## 重点可疑点
- 搜索框回显（如 Juice Shop 的 `/#/search?q=`，hash 路由 → 典型 DOM XSS）。
- 任何把用户输入拼进 `innerHTML` / `v-html` / `[innerHTML]` / `bypassSecurityTrust*` 的地方。
- 用户名、评论、反馈等会被再次渲染的字段（存储型）。

## 登记 report_candidate 时
- `type: "xss"`。
- DOM/反射型给 `url_template`，用 `{payload}` 占位，例如：
  `http://host/#/search?q={payload}`
- 验证层会用无头浏览器注入带唯一标记的 payload（img onerror / iframe javascript / svg onload），只认真实执行（弹窗或 window 标记）。

## 例子（Juice Shop）
- `type: "xss"`，`url_template: "http://localhost:3000/#/search?q={payload}"`。
