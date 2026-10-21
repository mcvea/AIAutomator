# -*- coding: utf-8 -*-
"""
TraeWork hook：checkin / health / total
复用 platforms/traework.py 的成熟实现（信封解密 + 设备证明续期 + 状态/领取）。

登录态两条来源：
- 多账号（可选功能）：<项目根>/auths/traework-<uid>.json 本地凭据库
  （用 trae_accounts.py 桌面导入或浏览器 OAuth 生成），逐账号展开、脚本自动续期；
- 桌面兜底：auths/ 为空时读取本机客户端 storage.json 加密信封。

多账号是**可选功能**，由平台定义 automator/platforms/traework.toml 里的
`multi_account` 开关控制：
- multi_account = true  → 按 auths/ 凭据逐账号展开（凭据库为空则回退单账号）
- multi_account = false → 强制桌面客户端单账号（忽略凭据库，默认值）

多账号时 checkin/health/total 返回「逐账号结果列表」，引擎自动展开；
声明式 encrypted_json 无法处理加密信封与多账号，故整体走 hook 完整接管
（同 WorkBuddy / LobsterAI 模式）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _multi_account_on(platform: dict) -> bool:
    """读取平台定义里的多账号开关（默认关闭 = 单账号模式）"""
    return bool(platform.get("multi_account", False))


def _instances(platform: dict, dry: bool = False):
    """按开关构造实例：多账号展开，或回退桌面登录态单实例"""
    from platforms.traework import TraeWorkCheckin
    if not _multi_account_on(platform):
        _notice_ignored_accounts(platform)
        return [TraeWorkCheckin(dry=dry)]
    return [TraeWorkCheckin(dry=dry, **kw) for kw in TraeWorkCheckin.account_specs()]


def _notice_ignored_accounts(platform: dict):
    """开关关闭但凭据库里有账号时提示一次（避免误以为多账号已生效）"""
    try:
        from platforms import trae_auth
        accounts = trae_auth.list_accounts()
    except Exception:  # noqa: BLE001 - 凭据目录不可读时无需提示
        return
    if accounts:
        print(f"[hook] {platform.get('display', 'TraeWork')}：凭据库中有 {len(accounts)} 个账号，"
              f"但 multi_account 开关为 false（单账号模式）；"
              f"如需多账号请在 automator/platforms/traework.toml 中设 multi_account = true")


def checkin(platform: dict, dry: bool = False):
    results = [inst.run() for inst in _instances(platform, dry)]
    return results[0] if len(results) == 1 else results


def health(platform: dict):
    results = [inst.health() for inst in _instances(platform)]
    return results[0] if len(results) == 1 else results


def total(platform: dict):
    display = platform.get("display", "TraeWork")
    results = []
    for inst in _instances(platform):
        t = inst.total()
        if isinstance(t, dict) and not t.get("platform"):
            t["platform"] = getattr(inst, "PLATFORM_NAME", display)
        results.append(t)
    return results[0] if len(results) == 1 else results
