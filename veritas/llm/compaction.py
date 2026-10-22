"""冷图压缩（转录压缩）—— M5：控长程 token 成本。

web_solver 的 agentic loop 每步把 tool 结果塞进 messages、每次 `llm.chat` 重发整段历史 → 无限增长
（实测单 run ~1M in tokens）。但攻击图状态在 Postgres、靠 `search_worker_traces` 按需取，所以转录里
的旧 tool 输出是【冗余】——把已沉淀的旧 round-trip 折成确定性 digest，只保留系统提示 + 初始任务 +
最近几轮热前沿。确定性滚动、**零额外 LLM 成本**；细节随时可 search_worker_traces 恢复原文。

借 ARTEX coldgraph 的原则（折冷、留热前沿、去抖到低水位）但作用在【message 转录】而非图总览
（veritas 的 LLM 不看图总览，只看自己的转录）。纯函数、无 IO、可单测。

correctness 核心：**只按完整 round-trip 折叠**（assistant(含 tool_calls) + 其后对应 tool 结果 为一
个不可分单元），绝不留悬空 tool 消息、也不留有 tool_calls 却没结果的 assistant——否则 OpenAI 兼容
端点会因 tool_call 配对不全而报错。
"""
from __future__ import annotations

DEFAULT_MAX_CHARS = 200_000      # ≈50K tokens：messages 超过此量就压缩
DEFAULT_KEEP_RECENT = 6          # 保留最近 N 个完整 round-trip（热前沿）
_LOW_WATER = 0.6                 # 折到 max_chars×0.6 以下（去抖，避免每步都触发）
_DIGEST_TAG = "[冷转录摘要]"       # digest 消息识别标记（再压缩时并入，不重复累积成多条）
_MAX_DIGEST_CHARS = 8000         # digest 整体封顶（保留较近的折叠内容）
_ARG_CHARS = 120                 # 每条命令参数保留字符
_OUT_CHARS = 180                 # 每条输出尾保留字符


# ---- tool_call 读取（兼容 dict 与 litellm 对象）----
def _tc_list(m: dict) -> list:
    return m.get("tool_calls") or []


def _tc_id(tc):
    return tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)


def _tc_fn(tc) -> tuple[str, str]:
    fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", None)
    if isinstance(fn, dict):
        return str(fn.get("name", "")), str(fn.get("arguments", ""))
    if fn is not None:
        return str(getattr(fn, "name", "")), str(getattr(fn, "arguments", ""))
    return "", ""


def _msg_chars(m: dict) -> int:
    n = len(str(m.get("content") or ""))
    for tc in _tc_list(m):
        name, args = _tc_fn(tc)
        n += len(name) + len(args)
    return n


def _total_chars(messages: list) -> int:
    return sum(_msg_chars(m) for m in messages)


def _segment(messages: list) -> list[list[dict]]:
    """把（preamble 之后的）消息切成 round-trip 单元：assistant(含 tool_calls)+其后 tool 结果 为一单元；
    其余（assistant 文本 / user 推进语 / 旧 digest）各自单条成单元。保证折叠时单元不可分、配对不破。"""
    units: list[list[dict]] = []
    i, n = 0, len(messages)
    while i < n:
        m = messages[i]
        if m.get("role") == "assistant" and _tc_list(m):
            unit = [m]
            j = i + 1
            while j < n and messages[j].get("role") == "tool":
                unit.append(messages[j])
                j += 1
            units.append(unit)
            i = j
        else:
            units.append([m])
            i += 1
    return units


def _is_digest(m: dict) -> bool:
    return m.get("role") == "user" and _DIGEST_TAG in str(m.get("content") or "")


def _render_digest(folded: list[list[dict]]) -> str:
    """确定性滚动：折叠区里每个 tool_call 压成一行 `[name] 参数 → 输出尾`；旧 digest 并入；封顶截断。"""
    carried: list[str] = []
    lines: list[str] = []
    for unit in folded:
        head = unit[0]
        if _is_digest(head):
            carried.append(str(head.get("content") or ""))
            continue
        if head.get("role") == "assistant" and _tc_list(head):
            results = {t.get("tool_call_id"): str(t.get("content") or "") for t in unit[1:]}
            for tc in _tc_list(head):
                name, args = _tc_fn(tc)
                out = results.get(_tc_id(tc), "").replace("\n", " ").strip()
                args_s = args.replace("\n", " ").strip()[:_ARG_CHARS]
                lines.append(f"[{name}] {args_s} → {out[-_OUT_CHARS:]}")
        elif head.get("role") == "assistant":
            c = str(head.get("content") or "").replace("\n", " ").strip()
            if c:
                lines.append(f"[思考] {c[:_OUT_CHARS]}")
        # user 推进语（非 digest）是噪声，跳过
    header = (f"{_DIGEST_TAG} 以下为已压缩的旧探索转录（命令→输出尾摘要；需要原文用 "
              f"search_worker_traces 检索）：\n")
    body = ("\n".join(carried) + ("\n" if carried else "")) + "\n".join(lines)
    digest = header + body
    if len(digest) > _MAX_DIGEST_CHARS:                      # 超长保留较近（尾部）内容
        digest = header + "…(更早省略)…\n" + digest[-(_MAX_DIGEST_CHARS - len(header) - 12):]
    return digest


def compact_messages(messages: list, max_chars: int = DEFAULT_MAX_CHARS,
                     keep_recent: int = DEFAULT_KEEP_RECENT) -> tuple[list, int]:
    """超阈值则把中段旧 round-trip 折成一条 digest；返回 (新 messages, 折叠的消息条数)。
    保留：messages[0](system) + messages[1](初始任务) + 最近 keep_recent 个完整 round-trip + 合并后的 digest。"""
    if len(messages) < 2 or _total_chars(messages) <= max_chars:
        return messages, 0
    preamble = messages[:2]
    units = _segment(messages[2:])
    if len(units) <= keep_recent:
        return messages, 0                                  # 旧单元不够折（热前沿本身就这么多）
    fold = units[:-keep_recent]
    keep = units[-keep_recent:]
    low = int(max_chars * _LOW_WATER)

    def assemble(fold_u, keep_u):
        digest = {"role": "user", "content": _render_digest(fold_u)}
        return preamble + [digest] + [m for u in keep_u for m in u]

    new_messages = assemble(fold, keep)
    # 若近 keep_recent 轮本身仍超低水位，多折几轮，但至少留 2 轮热前沿
    while _total_chars(new_messages) > low and len(keep) > 2:
        fold.append(keep.pop(0))
        new_messages = assemble(fold, keep)
    folded_n = sum(len(u) for u in fold)
    return new_messages, folded_n
