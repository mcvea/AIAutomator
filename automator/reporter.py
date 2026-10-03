# -*- coding: utf-8 -*-
"""
报告生成：把执行结果、健康检查、积分到期与账户总积分组装为可读文本（日报）。
与生产仓库 notify.py 的卡片逻辑对齐：失败行动提示、健康折叠、积分分档裁剪。
"""
from datetime import datetime

_URGENT_DAYS = 7       # 7 天内到期：全部列出
_SOON_DAYS = 30        # 30 天内到期：最多列 _SOON_MAX_ROWS 条，超出折叠
_SOON_MAX_ROWS = 8


def _icon(status: str) -> str:
    return {"success": "✅", "already": "✅", "failed": "❌",
            "skipped": "➖", "ok": "✅", "warn": "⚠️",
            "expired": "🚨", "unknown": "❓"}.get(status, "❓")


def _format_num(v) -> str:
    """数字显示：整数去小数并加千分位；字符串原样返回"""
    if v is None:
        return ""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    if f == int(f):
        return f"{int(f):,}"
    return f"{f:,.2f}"


def _status_line(results: list) -> str:
    success = sum(1 for r in results if r.get("status") == "success")
    already = sum(1 for r in results if r.get("status") == "already")
    skipped = sum(1 for r in results if r.get("status") == "skipped")
    failed = sum(1 for r in results if r.get("status") == "failed")
    parts = [f"成功 {success}", f"已签 {already}"]
    if skipped:
        parts.append(f"跳过 {skipped}")
    if failed:
        parts.append(f"失败 {failed}")
    line = " · ".join(parts)
    total_credits = sum(float(r.get("credits", 0) or 0) for r in results)
    if total_credits > 0:
        line += f"｜ 本次新增 {_format_num(total_credits)} 积分"
    return line


def _fail_hint(results: list) -> str:
    """失败行动提示：列出平台名（跳过类不提示）"""
    failed = [r for r in results if r.get("status") == "failed"]
    if not failed:
        return ""
    names = "、".join(r.get("platform", "?") for r in failed)
    return f"❌ {names} 签到失败，请打开对应客户端检查登录态；脚本会每日自动重试"


def _total_block(totals: list) -> str:
    """账户总积分概览：可获取的平台展示余额，其余如实标注"""
    if not totals:
        return ""
    lines = []
    for t in totals:
        name = t.get("platform", "?")
        if t.get("available") and t.get("total") is not None:
            line = f"　{name}：{_format_num(t['total'])} 分"
            if t.get("note"):
                line += f"（{t['note']}）"
        else:
            line = f"　{name}：接口未提供"
        lines.append(line)
    return "💰 账户总积分\n" + "\n".join(lines)


def _group_expiry(items: list) -> list:
    """同平台+同标签+同到期日聚合为一行，减少重复行"""
    groups = {}
    order = []
    for it in items:
        key = (it.get("platform", ""), it.get("label", ""), it.get("expires_at", ""))
        if key not in groups:
            groups[key] = {"credits": 0.0, "n": 0, "days_left": it.get("days_left", 0)}
            order.append(key)
        groups[key]["credits"] += float(it.get("credits", 0) or 0)
        groups[key]["n"] += 1
    rows = []
    for k in order:
        plat, label, exp = k
        g = groups[k]
        suffix = f"（{g['n']} 笔）" if g["n"] > 1 else ""
        rows.append(
            f"{plat}·{label}{suffix}：{_format_num(g['credits'])} 分，"
            f"{exp} 到期（剩 {g['days_left']} 天）")
    return rows


def _expiry_block(credits: list) -> str:
    """积分到期提醒：7 天内全列、30 天内限量、30 天外折叠"""
    if not credits:
        return ""
    urgent = [it for it in credits if it.get("days_left", 999) <= _URGENT_DAYS]
    soon = [it for it in credits if _URGENT_DAYS < it.get("days_left", 999) <= _SOON_DAYS]
    later = [it for it in credits if it.get("days_left", 999) > _SOON_DAYS]

    body = []
    for row in _group_expiry(urgent):
        body.append(f"🚨 {row}")
    soon_rows = _group_expiry(soon)
    for row in soon_rows[:_SOON_MAX_ROWS]:
        body.append(f"⚠️ {row}")
    if len(soon_rows) > _SOON_MAX_ROWS:
        body.append(f"⚠️ … 其余 {len(soon_rows) - _SOON_MAX_ROWS} 组积分 30 天内到期")
    if later:
        recent = min(later, key=lambda x: x.get("days_left", 999))
        body.append(
            f"🔸 另有 {len(later)} 笔将于 {recent.get('expires_at')} 之后"
            f"陆续到期（最近剩 {recent.get('days_left')} 天）")
    if not body:
        return ""

    head = "💰 积分到期提醒"
    if urgent:
        head += "：7 天内到期请及时使用！"
    return head + "\n" + "\n".join(body)


def _health_block(healths: list) -> str:
    """登录态健康：全部正常折叠为一行，异常时逐行展开"""
    if not healths:
        return ""
    abnormal = [h for h in healths if h.get("status") != "ok"]
    if not abnormal:
        return f"🔋 登录态健康：全部正常（{len(healths)}/{len(healths)}）"
    lines = [f"🔋 登录态健康：{len(abnormal)}/{len(healths)} 项异常"]
    for h in healths:
        lines.append(f"{_icon(h.get('status'))} {h.get('platform', '?')}：{h.get('message', '')}")
    lines.append("⚠️ 有平台登录态异常，请尽快打开对应客户端登录刷新！")
    return "\n".join(lines)


def build_daily_report(results: list, healths: list = None, credits: list = None,
                       totals: list = None,
                       title: str = "AI 平台自动化日报") -> str:
    """组装日报文本（签到明细 → 汇总 → 总积分 → 到期提醒 → 健康）"""
    healths = healths or []
    credits = credits or []
    totals = totals or []

    lines = []
    for r in results:
        lines.append(f"{_icon(r.get('status'))} {r.get('platform', '?')}：{r.get('message', '')}")

    text = f"🦞 {title}\n\n" + ("\n".join(lines) if lines else "今日无任务")

    summary = _status_line(results)
    hint = _fail_hint(results)
    if hint:
        summary += "\n" + hint
    text += f"\n\n📊 {summary}"

    tb = _total_block(totals)
    if tb:
        text += "\n\n" + tb

    eb = _expiry_block(credits)
    if eb:
        text += "\n\n" + eb

    hb = _health_block(healths)
    if hb:
        text += "\n\n" + hb

    text += f"\n\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return text