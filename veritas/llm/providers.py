"""多 provider 预设（LiteLLM 路由）：一键在 GLM / DeepSeek / OpenAI(GPT) / Anthropic(Claude) 间切换。

LiteLLM 已统一各家的 tool-use（OpenAI 风格 function calling）与响应格式（choices[0].message.
tool_calls），所以切 provider 时 executor/web_solver 代码零改动——只换 model 路由 + 端点 + key。

用法（dispatch.yaml）：`llm.provider: deepseek` 即可，预设补全 model/api_base/api_key_env；想覆盖
就在 llm 块里显式写 model/api_base/api_key_env（显式优先）。不填 provider → 纯用显式字段（向后兼容）。

注意：各家 model id 会随版本漂移——预设给的是【起步建议】，以你 key 实际可用的为准，用 llm.model 覆盖。
"""
from __future__ import annotations

# provider → 预设（model 路由 / 端点 / key 环境变量）
PRESETS: dict = {
    # GLM：智谱，OpenAI 兼容端点（litellm 用 openai/ 前缀 + 自定义 api_base）
    "glm": {"model": "openai/glm-5.3", "api_base": "https://open.bigmodel.cn/api/paas/v4",
            "api_key_env": "GLM_API_KEY"},
    # DeepSeek：litellm 原生 provider（无需 api_base）
    "deepseek": {"model": "deepseek/deepseek-chat", "api_base": None, "api_key_env": "DEEPSEEK_API_KEY"},
    # OpenAI(GPT)：litellm 原生
    "openai": {"model": "openai/gpt-4o", "api_base": None, "api_key_env": "OPENAI_API_KEY"},
    # Anthropic(Claude)：litellm 原生（model id 随版本漂移，以你 key 可用的为准）
    "anthropic": {"model": "anthropic/claude-sonnet-5-5", "api_base": None,
                  "api_key_env": "ANTHROPIC_API_KEY"},
}

# 常见别名 → 规范 provider 名
ALIASES: dict = {
    "gpt": "openai", "chatgpt": "openai", "oai": "openai",
    "claude": "anthropic", "ds": "deepseek",
    "zhipu": "glm", "bigmodel": "glm", "chatglm": "glm",
}


def canonical(provider: "str | None") -> str:
    p = (provider or "").strip().lower()
    return ALIASES.get(p, p)


def available() -> list:
    return sorted(PRESETS)


def resolve(provider: "str | None", model: "str | None" = None,
            api_base: "str | None" = None, api_key_env: "str | None" = None) -> dict:
    """按 provider 预设补全路由；显式字段（非空）覆盖预设。provider 空/未知 → 纯用显式字段。
    返回 {provider, model, api_base, api_key_env}（纯函数，不读环境/不发请求）。"""
    p = canonical(provider)
    preset = PRESETS.get(p, {})
    return {
        "provider": p or None,
        "model": (model or "").strip() or preset.get("model"),
        "api_base": (api_base or None) or preset.get("api_base"),
        "api_key_env": (api_key_env or "").strip() or preset.get("api_key_env"),
    }
