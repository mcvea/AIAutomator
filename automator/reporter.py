# -*- coding: utf-8 -*-
"""
报告生成：把执行结果、健康检查、积分到期信息组装为可读文本（日报/周报模板）。
"""
from datetime import datetime


def _icon(status: str) -> str:
    return {"success": "✅", "already": "⏭️", "failed": "❌",
            "skipped": "⏭️", "ok": "✅", "warn": "⚠️",
            "expired": "🚨", "unknown": "❓"}.get(status, "❓")


def build_daily_report(results: list, healths: list = None, credits: list = None,
                       title: str = "AI 平台自动化日报") -> str:
    """组装日报文本"""
    success = [r for r in results if r.get("status") == "success"]
    already = [r for r in results if r.get("status") == "already"]
    failed = [r for r in results if r.get("status") in ("failed", "skipped")]
    total_credits = sum(r.get("credits", 0) for r in results)

    lines = []
    for r in results:
        lines.append(f"{_icon(r.get('status'))} {r.get('platform', '?')}：{r.get('message', '')}")

    status_line = f"成功 {len(success)} | 已签 {len(already)} | 失败 {len(failed)}"
    if total_credits > 0:
        status_line += f" | 本次新增 {total_credits} 积分"

    text = f"🦞 {title}\n\n" + ("\n".join(lines) if lines else "今日无任务")
    text += f"\n\n📊 {status_line}"

    if credits:
        text += "\n\n💰 积分到期提醒："
        for it in credits:
            icon = "🚨" if it.get("days_left", 999) <= 7 else (
                "⚠️" if it.get("days_left", 999) <= 30 else "🔸")
            text += (f"\n{icon} {it.get('platform', '')}·{it.get('label', '')}："
                     f"{it.get('credits', 0):g} 分，{it.get('expires_at')} 到期"
                     f"（剩 {it.get('days_left')} 天）")
        if any(it.get("days_left", 999) <= 7 for it in credits):
            text += "\n\n🚨 有积分将在 7 天内到期，请及时使用！"

    if healths:
        text += "\n\n🔋 登录态健康："
        for h in healths:
            text += f"\n{_icon(h.get('status'))} {h.get('platform', '?')}：{h.get('message', '')}"
        if any(h.get("status") in ("warn", "expired") for h in healths):
            text += "\n\n⚠️ 有平台登录态快过期/已失效，请尽快登录刷新！"

    text += f"\n\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return text
