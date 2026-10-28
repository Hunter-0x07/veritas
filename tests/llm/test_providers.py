"""多 provider 预设 · 确定性单测（纯 stdlib，`.venv/bin/python tests/llm/test_providers.py`）。
验 resolve 预设补全 / 别名 / 显式覆盖 / 未知兜底 / 向后兼容；+ LLMClient.__init__ 正确接线（不发请求）。
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from veritas.llm import providers as P
from veritas.config import LLMCfg
from veritas.llm.client import LLMClient

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")

print("[resolve] 预设补全")
check("glm → 智谱兼容端点", P.resolve("glm"),
      {"provider": "glm", "model": "openai/glm-5.3",
       "api_base": "https://open.bigmodel.cn/api/paas/v4", "api_key_env": "GLM_API_KEY"})
check("deepseek → 原生", P.resolve("deepseek"),
      {"provider": "deepseek", "model": "deepseek/deepseek-chat", "api_base": None, "api_key_env": "DEEPSEEK_API_KEY"})
check("openai model", P.resolve("openai")["model"], "openai/gpt-4o")
check("openai key env", P.resolve("openai")["api_key_env"], "OPENAI_API_KEY")
check("anthropic key env", P.resolve("anthropic")["api_key_env"], "ANTHROPIC_API_KEY")

print("[resolve] 别名")
check("gpt → openai", P.resolve("gpt")["provider"], "openai")
check("claude → anthropic", P.resolve("claude")["provider"], "anthropic")
check("GPT 大写/空格 → openai", P.resolve("  GPT ")["provider"], "openai")
check("zhipu → glm", P.resolve("zhipu")["model"], "openai/glm-5.3")

print("[resolve] 显式覆盖 / 向后兼容 / 未知")
check("model 覆盖预设", P.resolve("glm", model="openai/glm-4.6")["model"], "openai/glm-4.6")
check("api_base 覆盖预设", P.resolve("deepseek", api_base="http://local:8000")["api_base"], "http://local:8000")
check("key_env 覆盖预设", P.resolve("openai", api_key_env="MY_KEY")["api_key_env"], "MY_KEY")
# 向后兼容：无 provider、纯显式字段（旧 dispatch 风格）
check("无 provider → 纯显式", P.resolve("", model="openai/glm-5.3", api_base="https://x", api_key_env="GLM_API_KEY"),
      {"provider": None, "model": "openai/glm-5.3", "api_base": "https://x", "api_key_env": "GLM_API_KEY"})
check("未知 provider + 无 model → model None", P.resolve("grok")["model"], None)
check("未知 provider + 显式 model → 用显式", P.resolve("grok", model="xai/grok")["model"], "xai/grok")
check("available 列表", P.available(), ["anthropic", "deepseek", "glm", "openai"])

print("[LLMClient] 接线（不发请求）")
c = LLMClient(LLMCfg(provider="deepseek"))
check("client 解析 model", c.model, "deepseek/deepseek-chat")
check("client 记 key_env", c.api_key_env, "DEEPSEEK_API_KEY")
check("client 记 provider", c.provider, "anthropic" if False else "deepseek")
c2 = LLMClient(LLMCfg(provider="claude", model="anthropic/claude-x"))
check("client model 覆盖", c2.model, "anthropic/claude-x")
check("client provider 别名归一", c2.provider, "anthropic")
# 向后兼容：旧 dispatch（provider 默认 glm + 显式 model/api_base）
c3 = LLMClient(LLMCfg(provider="glm", model="openai/glm-5.3", api_base="https://open.bigmodel.cn/api/paas/v4",
                      api_key_env="GLM_API_KEY"))
check("向后兼容 glm", (c3.model, c3.api_base, c3.api_key_env),
      ("openai/glm-5.3", "https://open.bigmodel.cn/api/paas/v4", "GLM_API_KEY"))
# 未知 provider 且无 model → 构造应报错
try:
    LLMClient(LLMCfg(provider="nope", model=""))
    check("未知 provider 无 model 应报错", "no-raise", "raise")
except ValueError:
    check("未知 provider 无 model 报错", "raise", "raise")

print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_providers)")
sys.exit(1 if _fail else 0)
