# -*- coding: utf-8 -*-
"""
报告生成：把执行结果、健康检查、积分到期与账户总积分组装为可读文本（日报）。
与生产仓库 notify.py 的卡片逻辑对齐：失败行动提示、健康折叠、积分分档裁剪。
"""
from datetime import datetime


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


def _total_block(totals: list, prev_totals: dict | None = None) -> str:
    """账户总积分概览：可获取的平台展示余额与较上次快照的变化，其余如实标注"""
    if not totals:
        return ""
    has_prev = bool(prev_totals)
    lines = []
    for t in totals:
        name = t.get("platform", "?")
        if t.get("available") and t.get("total") is not None:
            line = f"　{name}：{_format_num(t['total'])} 分"
            if has_prev:
                prev = prev_totals.get(name)
                if prev is None:
                    line += "（新增）"
                else:
                    delta = round(float(t["total"]) - float(prev), 2)
                    if delta == 0:
                        line += "（较昨日持平）"
                    else:
                        sign = "+" if delta > 0 else ""
                        line += f"（较昨日 {sign}{_format_num(delta)}）"
            if t.get("note"):
                line += f"（{t['note']}）"
        else:
            line = f"　{name}：接口未提供"
        lines.append(line)
    return "💰 账户总积分\n" + "\n".join(lines)




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
                       totals: list = None, prev_totals: dict | None = None,
                       title: str = "AI 平台自动化日报") -> str:
    """组装日报文本（签到明细 → 汇总 → 总积分（含环比）→ 健康）

    积分到期数据仍会采集（写入日志），但日报不再展示该区块——与生产仓库日报口径一致。
    """
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

    tb = _total_block(totals, prev_totals)
    if tb:
        text += "\n\n" + tb

    hb = _health_block(healths)
    if hb:
        text += "\n\n" + hb

    text += f"\n\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return text