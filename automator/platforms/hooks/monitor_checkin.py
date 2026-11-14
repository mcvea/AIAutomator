# -*- coding: utf-8 -*-
"""
monitor_checkin：手工纳入签到列表的平台（由「平台扫描」生成）

这些平台没有可用的签到接口定义，因此：
- health  → 读本机凭据判读登录态（与扫描页同一套判读器，不联网）
- checkin → 分三种如实回报：
              real    → 不会走到这里（有手写定义的平台直接走真实现）
              none    → no_program「无签到活动」并给出依据（翻过客户端目录得出的结论）
              unknown → skipped「未找到可调用签到接口」，绝不出假成功

当某平台补上真实签到实现（手写平台定义）后，就不再走本 hook。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _entry(platform: dict):
    """按 source_key 找扫描记录"""
    import platform_scan
    key = platform.get("source_key") or platform.get("name")
    data = platform_scan.scan_cached()
    for it in data["found"] + data["not_installed"]:
        if it["key"] == key:
            return it
    return None


def _detail(it) -> str:
    parts = [a.get("detail", "") for a in it["auth"] if a["exists"] and a.get("detail")]
    return "；".join(parts) or "未发现凭据文件"


def health(platform: dict) -> dict:
    display = platform.get("display", platform.get("name", "?"))
    it = _entry(platform)
    if not it:
        return {"platform": display, "status": "expired", "days_left": 0,
                "message": "本机未再发现该平台，请确认是否已卸载"}
    st = __import__("platform_scan")._row_status(it["login_state"])
    status = {"ok": "ok", "warn": "warn", "expired": "expired"}.get(st, "warn")
    return {"platform": display, "status": status, "days_left": None,
            "message": _detail(it)}


def total(platform: dict) -> dict:
    """账户总积分：无签到/积分体系的平台如实说明，不填 0 冒充"""
    import platform_scan
    display = platform.get("display", platform.get("name", "?"))
    sup = platform_scan.checkin_support(platform.get("source_key") or platform.get("name"))
    note = "该平台无积分体系" if sup["level"] == "none" else "签到接口未接入"
    return {"platform": display, "available": False, "total": None, "note": note}


def checkin(platform: dict, dry: bool = False) -> dict:
    import platform_scan
    display = platform.get("display", platform.get("name", "?"))
    key = platform.get("source_key") or platform.get("name")
    sup = platform_scan.checkin_support(key)
    # 平台压根没有签到活动：如实报 no_program，不再挂"待接入"的模糊说法
    if sup["level"] == "none":
        return {"platform": display, "success": True, "status": "no_program",
                "message": f"无签到活动：{sup['note']}", "credits": 0}
    it = _entry(platform)
    state = it["login_state"] if it else "missing"
    if state in ("missing", "expired"):
        msg = "已纳入签到列表；本地未发现有效登录态，请先打开客户端登录一次"
    else:
        msg = f"未找到可调用签到接口（{sup['note']}），当前仅每日巡检登录态"
    if dry:
        msg = "[试跑] " + msg
    return {"platform": display, "success": True, "status": "skipped",
            "message": msg, "credits": 0}
