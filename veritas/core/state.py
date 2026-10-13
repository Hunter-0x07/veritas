"""访问权限状态模型：渗透进展用"立足点的访问级别"衡量，不用"发现几个漏洞"。"""
from __future__ import annotations

# 访问级别从低到高；rank 用于度量进展、判定 goal、排序攻击机会价值
ACCESS_RANK: dict[str, int] = {
    "external": 0,       # 外部无权限
    "recon": 1,          # 已侦察，掌握攻击面
    "web_user": 2,       # Web 应用普通用户
    "web_admin": 3,      # Web 应用管理员
    "db_read": 4,        # 能读数据库
    "shell": 5,          # 拿到主机 shell
    "root": 6,           # 主机 root/administrator
    "domain_admin": 7,   # 域管理员
}

# 攻击机会类型 → 意图达成的访问跃迁方向
OPPORTUNITY_KINDS = (
    "initial_access",    # external → web 立足点
    "web_exploit",       # web 立足点内提升（dump / 提权到 admin）
    "internal_recon",    # 从立足点发现内网资产
    "lateral_move",      # 用凭据横向到新主机
    "privesc",           # 本地提权
    "loot",              # 抓取目标数据
)


def rank(access_level: str) -> int:
    return ACCESS_RANK.get(access_level, 0)


def meets_goal(current_max: str, goal_level: str) -> bool:
    return rank(current_max) >= rank(goal_level)
