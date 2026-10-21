# -*- coding: utf-8 -*-
"""
MiniMax Code hook：checkin / health / total
复用 platforms/minimax.py 的成熟实现（OAuth Bearer 认证 + 签名 + 状态判断）。

登录态来源（与桌面端一致）：
- 主链路：客户端 OAuth 凭据 ~/.minimax/auth/prod/cn/mcode-public/auth.json
  （mmoat_* access token，寿命 1 小时；脚本用 refreshToken 自动续期并写回
   客户端自身的凭据文件，写回时与客户端共用同一把跨进程锁）；
- 兜底：旧会话 JWT ~/.minimax/local-runtime.auth.json。

声明式 json_file 无法表达 OAuth 凭据（records 的键名带随机后缀），且账号总积分
需要 Bearer + 签名，故 checkin / health / total 全部由本 hook 接管。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def checkin(platform: dict, dry: bool = False) -> dict:
    from platforms.minimax import MiniMaxCheckin
    inst = MiniMaxCheckin(dry=dry)
    return inst.run()


def health(platform: dict) -> dict:
    from platforms.minimax import MiniMaxCheckin
    return MiniMaxCheckin().health()


def total(platform: dict) -> dict:
    from platforms.minimax import MiniMaxCheckin
    inst = MiniMaxCheckin()
    t = inst.total()
    if isinstance(t, dict):
        t.setdefault("platform", inst.PLATFORM_NAME)
        t.setdefault("available", False)
        t.setdefault("total", None)
        t.setdefault("note", "")
    return t
