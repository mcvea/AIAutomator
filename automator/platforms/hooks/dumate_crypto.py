# -*- coding: utf-8 -*-
"""
DuMate hook：decrypt_cookies（AES-256-GCM 解密）/ credits（含 incremental 二次解析）
复用 platforms/dumate.py 的成熟实现。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def decrypt_cookies(encrypted_b64: str, key_file: str) -> list:
    """解密 cookies：AES-256-GCM，密钥在 key_file（32 字节随机数）"""
    import base64
    import json
    from Crypto.Cipher import AES

    from automator import paths
    key_file = paths.resolve_path(key_file)

    with open(key_file, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError(f".cookie-key 长度异常（{len(key)}）")
    payload = base64.b64decode(encrypted_b64)
    iv, tag, ct = payload[:12], payload[12:28], payload[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    data = cipher.decrypt_and_verify(ct, tag)
    cookies = json.loads(data.decode("utf-8"))
    if not isinstance(cookies, list):
        raise ValueError("解密 cookies 格式异常")
    return cookies


def health(platform: dict) -> dict:
    """登录态健康检查：cookies 关键字段过期时间"""
    from platforms.dumate import DuMateCheckin
    inst = DuMateCheckin()
    try:
        inst._load_active_cookies()
        import time
        earliest = None
        for c in inst.cookies:
            if c.get("name") in ("BDUSS", "bce-user-info", "STOKEN"):
                exp = c.get("expirationDate")
                if exp:
                    try:
                        earliest = min(earliest, float(exp)) if earliest else float(exp)
                    except (TypeError, ValueError):
                        continue
        days = None
        if earliest:
            days = max(0, int((earliest - time.time()) // 86400))
        status = "ok"
        msg = "登录态正常"
        if earliest and earliest <= time.time():
            status = "expired"
            msg = "cookies 已过期，请打开百度搭子客户端重新登录"
        elif days is not None and days < 7:
            status = "warn"
            msg = f"登录态剩余 {days} 天，请打开百度搭子重新登录刷新"
        elif days is not None:
            msg = f"登录态剩余 {days} 天"
        return {"platform": "百度搭子 DuMate", "status": status, "days_left": days,
                "message": msg}
    except Exception as e:  # noqa: BLE001
        return {"platform": "百度搭子 DuMate", "status": "expired", "days_left": 0,
                "message": f"无法读取登录态: {e}"}


def credits(platform: dict) -> list:
    """完整积分到期列表（subscription + incremental）"""
    from platforms.dumate import DuMateCheckin
    inst = DuMateCheckin()
    try:
        inst._load_active_cookies()
        import time
        from datetime import datetime

        sc, sb = inst._api_call(
            "/api/dumate/points/quota_overview?timezone=Asia/Shanghai&clientType=desktop&ignoreLoginBonus=true",
            "GET")
        result = inst._unwrap(sb)
        items = []
        now = time.time()
        for sub in result.get("subscription") or []:
            exp = sub.get("expireDate")
            if not exp:
                continue
            items.append({
                "label": "体验套餐" if sub.get("packageType") == "plan_experience" else "订阅套餐",
                "credits": float(sub.get("totalPoints") or 0),
                "expires_at": datetime.fromtimestamp(exp).strftime("%Y-%m-%d"),
                "days_left": max(0, int((float(exp) - now) // 86400)),
                "platform": "百度搭子 DuMate",
            })
        for inc in result.get("incremental") or []:
            exp = inc.get("expireDate")
            if not exp:
                continue
            label = {"login_bonus": "每日登录", "grant_point": "奖励积分",
                     "event_bonus": "活动奖励"}.get(inc.get("source"), "积分")
            items.append({
                "label": label,
                "credits": float(inc.get("totalPoints") or 0),
                "expires_at": datetime.fromtimestamp(exp).strftime("%Y-%m-%d"),
                "days_left": max(0, int((float(exp) - now) // 86400)),
                "platform": "百度搭子 DuMate",
            })
        items.sort(key=lambda x: x["expires_at"])
        return items
    except Exception:  # noqa: BLE001
        return []
