# -*- coding: utf-8 -*-
"""
WorkBuddy hook：checkin / health / total
复用 platforms/workbuddy.py 的成熟实现（含 5.6+ 加密凭据自动兼容）。

登录态两条来源：
- 多账号（推荐）：<项目根>/auths/workbuddy-<uid>.json 本地凭据库
  （用 wb_accounts.py 短信登录生成），逐账号展开、脚本自动续期；
- 桌面兜底：auths/ 为空时读取本机客户端 workbuddy-desktop.info。

多账号时 checkin/health/total 返回「逐账号结果列表」，引擎自动展开；
声明式 json_file auth 无法处理加密信封与多账号，故整体走 hook 完整接管
（同 LobsterAI 模式）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _instances(dry: bool = False):
    """按 auths/ 凭据逐账号构造实例；无凭据时回退桌面登录态单实例"""
    from platforms.workbuddy import WorkBuddyCheckin
    return [WorkBuddyCheckin(dry=dry, **kw) for kw in WorkBuddyCheckin.account_specs()]


def checkin(platform: dict, dry: bool = False):
    results = [inst.run() for inst in _instances(dry)]
    return results[0] if len(results) == 1 else results


def health(platform: dict):
    results = [inst.health() for inst in _instances()]
    return results[0] if len(results) == 1 else results


def total(platform: dict):
    display = platform.get("display", "WorkBuddy")
    results = []
    for inst in _instances():
        t = inst.total()
        if isinstance(t, dict) and not t.get("platform"):
            t["platform"] = getattr(inst, "PLATFORM_NAME", display)
        results.append(t)
    return results[0] if len(results) == 1 else results
