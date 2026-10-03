# -*- coding: utf-8 -*-
"""
LobsterAI hook：checkin / credits
复用 platforms/lobster.py 的成熟实现（slot → context → check_in）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def checkin(platform: dict, dry: bool = False) -> dict:
    from platforms.lobster import LobsterCheckin
    inst = LobsterCheckin(dry=dry)
    return inst.run()


def health(platform: dict) -> dict:
    from platforms.lobster import LobsterCheckin
    return LobsterCheckin().health()


def credits(platform: dict) -> list:
    from platforms.lobster import LobsterCheckin
    inst = LobsterCheckin()
    try:
        inst.token = inst._load_token()
        sc, sb = inst._api("/api/user/profile-summary?firstKeyfrom=official")
        if not (isinstance(sb, dict) and sb.get("code") == 0):
            return []
        data = sb.get("data") or {}
    except Exception:  # noqa: BLE001
        return []

    import time
    from datetime import datetime
    items = []
    now = time.time()
    for item in data.get("creditItems") or []:
        exp = item.get("expiresAt")
        if not exp:
            continue
        try:
            exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            days = max(0, int((exp_dt.timestamp() - now) // 86400))
            items.append({
                "label": item.get("label", "积分"),
                "credits": float(item.get("creditsRemaining") or 0),
                "expires_at": exp_dt.strftime("%Y-%m-%d"),
                "days_left": days,
                "platform": "LobsterAI",
            })
        except Exception:  # noqa: BLE001
            continue
    items.sort(key=lambda x: x["expires_at"])
    return items


def total(platform: dict) -> dict:
    """账户总积分：profile-summary.totalCreditsRemaining"""
    from platforms.lobster import LobsterCheckin
    inst = LobsterCheckin()
    try:
        inst.token = inst._load_token()
        sc, sb = inst._api("/api/user/profile-summary?firstKeyfrom=official")
        if not (isinstance(sb, dict) and sb.get("code") == 0):
            return {"platform": "LobsterAI", "available": False, "total": None}
        data = sb.get("data") or {}
        total = data.get("totalCreditsRemaining")
        if total is None:
            return {"platform": "LobsterAI", "available": False, "total": None}
        return {"platform": "LobsterAI", "available": True,
                "total": float(total), "note": ""}
    except Exception:  # noqa: BLE001
        return {"platform": "LobsterAI", "available": False, "total": None}
