# -*- coding: utf-8 -*-
"""
TraeWork hook：checkin / health / total
复用 platforms/traework.py 的成熟实现（信封解密 + 设备证明续期 + 状态/领取）。

登录态两条来源：
- 多账号（推荐）：<项目根>/auths/traework-<uid>.json 本地凭据库
  （用 trae_accounts.py 桌面导入或浏览器 OAuth 生成），逐账号展开、脚本自动续期；
- 桌面兜底：auths/ 为空时读取本机客户端 storage.json 加密信封。

多账号时 checkin/health/total 返回「逐账号结果列表」，引擎自动展开；
声明式 encrypted_json 无法处理加密信封与多账号，故整体走 hook 完整接管
（同 WorkBuddy / LobsterAI 模式）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _instances(dry: bool = False):
    """按 auths/ 凭据逐账号构造实例；无凭据时回退桌面登录态单实例"""
    from platforms.traework import TraeWorkCheckin
    return [TraeWorkCheckin(dry=dry, **kw) for kw in TraeWorkCheckin.account_specs()]


def checkin(platform: dict, dry: bool = False):
    results = [inst.run() for inst in _instances(dry)]
    return results[0] if len(results) == 1 else results


def health(platform: dict):
    results = [inst.health() for inst in _instances()]
    return results[0] if len(results) == 1 else results


def total(platform: dict):
    display = platform.get("display", "TraeWork")
    results = []
    for inst in _instances():
        t = inst.total()
        if isinstance(t, dict) and not t.get("platform"):
            t["platform"] = getattr(inst, "PLATFORM_NAME", display)
        results.append(t)
    return results[0] if len(results) == 1 else results
