# -*- coding: utf-8 -*-
"""
WorkBuddy hook：checkin / health / total
复用 platforms/workbuddy.py 的成熟实现（含 5.6+ 加密凭据自动兼容）。
WorkBuddy 登录态在 5.6+ 为 $wbEncrypted 加密信封，声明式 json_file auth
无法处理，故整体走 hook 完整接管（同 LobsterAI 模式）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def checkin(platform: dict, dry: bool = False) -> dict:
    from platforms.workbuddy import WorkBuddyCheckin
    inst = WorkBuddyCheckin(dry=dry)
    return inst.run()


def health(platform: dict) -> dict:
    from platforms.workbuddy import WorkBuddyCheckin
    return WorkBuddyCheckin().health()


def total(platform: dict) -> dict:
    from platforms.workbuddy import WorkBuddyCheckin
    return WorkBuddyCheckin().total()