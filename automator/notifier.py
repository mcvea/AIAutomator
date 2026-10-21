# -*- coding: utf-8 -*-
"""
通知总线：多通道通知器。
通道类型（平台无关，由用户配置指定）：
    feishu_direct   飞书自建应用直连私聊
    feishu_webhook  飞书群机器人
    stdout          控制台输出（调试）

日报推送（notify_daily）发送飞书 interactive 卡片，结构与生产仓库
notify.py 对齐：标题（有失败自动转红）→ 签到明细 → 汇总 → 总积分
（含较昨日环比）→ 登录态健康（正常折叠）→ 脚注。
积分到期数据仍会采集（写入日志），但卡片不再展示该区块。
"""
import json
import os
import time
import urllib.error
import urllib.request

OPEN_FEISHU = "https://open.feishu.cn"

# 图标语义统一：✅ = 达成（success/already），➖ = 未执行（只读/跳过），❌ = 失败
_STATUS_ICON = {
    "success": "✅",
    "already": "✅",
    "skipped": "➖",
    "failed": "❌",
}
_HEALTH_ICON = {
    "ok": "✅",
    "warn": "⚠️",
    "expired": "🚨",
    "unknown": "❓",
}


def _load_secrets() -> dict:
    """读取 config/secrets.json（凭证），不存在返回空"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "config", "secrets.json")
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _feishu_token(app_id: str, app_secret: str) -> str:
    body = json.dumps({"app_id": app_id, "app_secret": app_secret}).encode("utf-8")
    req = urllib.request.Request(
        OPEN_FEISHU + "/open-apis/auth/v3/tenant_access_token/internal",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        d = json.loads(resp.read().decode("utf-8"))
    if d.get("code") != 0:
        raise RuntimeError(f"获取飞书 token 失败: {d.get('msg')}")
    return d["tenant_access_token"]


def _feishu_send_direct(payload: dict, cfg: dict) -> bool:
    """直连飞书 API 发送消息（text / interactive 通用）"""
    token = _feishu_token(cfg["app_id"], cfg["app_secret"])
    msg_type = payload["msg_type"]
    content = payload["content"]
    body = json.dumps({
        "receive_id": cfg.get("open_id", ""),
        "msg_type": msg_type,
        "content": json.dumps(content, ensure_ascii=False),
    }, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        OPEN_FEISHU + "/open-apis/im/v1/messages?receive_id_type=open_id",
        data=body,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json; charset=utf-8"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            d = json.loads(resp.read().decode("utf-8"))
        if d.get("code") != 0:
            print(f"[notifier] 飞书直连发送失败: code={d.get('code')} msg={d.get('msg')}")
            return False
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[notifier] 飞书直连失败: {e}")
        return False


def _feishu_webhook(payload: dict, webhook: str) -> bool:
    """群机器人发送（text / interactive 卡片通用）"""
    if payload["msg_type"] == "interactive":
        data = json.dumps({"msg_type": "interactive", "card": payload["content"]},
                          ensure_ascii=False).encode("utf-8")
    else:
        data = json.dumps({"msg_type": "text", "content": {"text": payload["content"]["text"]}},
                          ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(webhook, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.loads(resp.read().decode("utf-8"))
        return d.get("code") == 0 or d.get("StatusCode") == 0
    except Exception as e:  # noqa: BLE001
        print(f"[notifier] 飞书 Webhook 失败: {e}")
        return False


# ---------- interactive 卡片组装 ----------

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


def _title(results: list):
    """卡片标题 + 模板颜色；有失败时标题加重警示、模板转红"""
    date_str = time.strftime("%m月%d日")
    failed = [r for r in results if r.get("status") == "failed"]
    if failed:
        return f"⚠️ AI 办公签到日报 · {date_str}（{len(failed)} 项失败）", "red"
    return f"🦞 AI 办公签到日报 · {date_str}", "green"


def _status_counts(results: list) -> tuple:
    success = sum(1 for r in results if r.get("status") == "success")
    already = sum(1 for r in results if r.get("status") == "already")
    skipped = sum(1 for r in results if r.get("status") == "skipped")
    failed = sum(1 for r in results if r.get("status") == "failed")
    return success, already, skipped, failed


def _status_line(results: list) -> str:
    success, already, skipped, failed = _status_counts(results)
    parts = [f"成功 {success}", f"已签 {already}"]
    if skipped:
        parts.append(f"跳过 {skipped}")
    if failed:
        parts.append(f"失败 {failed}")
    line = " · ".join(parts)
    total_credits = sum(float(r.get("credits", 0) or 0) for r in results)
    if total_credits > 0:
        line += f" ｜ 本次新增 {_format_num(total_credits)} 积分"
    return line


def _fail_hint(results: list) -> str:
    """失败行动提示：列出平台名，提示检查登录态（跳过类不提示）"""
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
            line = f"　{name}：**{_format_num(t['total'])} 分**"
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
    return "**💰 账户总积分**\n" + "\n".join(lines)




def _health_block(healths: list) -> str:
    """登录态健康：全部正常折叠为一行，异常时逐行展开"""
    if not healths:
        return ""
    abnormal = [h for h in healths if h.get("status") != "ok"]
    if not abnormal:
        return f"**🔋 登录态健康**：全部正常（{len(healths)}/{len(healths)}）"
    lines = [f"**🔋 登录态健康**：{len(abnormal)}/{len(healths)} 项异常"]
    for h in healths:
        icon = _HEALTH_ICON.get(h.get("status"), "❓")
        lines.append(f"{icon} {h.get('platform', '?')}：{h.get('message', '')}")
    lines.append("⚠️ 有平台登录态异常，请尽快打开对应客户端登录刷新！")
    return "\n".join(lines)


def _build_card(results: list, totals: list, credits_all: list, healths: list,
                prev_totals: dict | None = None) -> dict:
    """组装飞书 interactive 卡片（直连与 Webhook 共用同一结构）

    积分到期数据仍会采集（写入日志），但卡片不再展示该区块——与生产仓库日报口径一致。
    """
    title, template = _title(results)
    elements = []

    if results:
        lines = []
        for r in results:
            icon = _STATUS_ICON.get(r.get("status"), "❓")
            lines.append(f"{icon} **{r.get('platform', '?')}**：{r.get('message', '')}")
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}})
    else:
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": "今日无签到任务"}})

    summary = _status_line(results)
    hint = _fail_hint(results)
    if hint:
        summary += "\n" + hint
    elements.append({"tag": "hr"})
    elements.append({"tag": "div", "text": {"tag": "lark_md", "content": f"**汇总**：{summary}"}})

    tb = _total_block(totals, prev_totals)
    if tb:
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": tb}})
    hb = _health_block(healths)
    if hb:
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": hb}})

    elements.append({"tag": "note",
                     "elements": [{"tag": "plain_text", "content": "由 AIAutomator 定时任务执行"}]})
    return {
        "config": {"wide_screen_mode": True},
        "header": {"template": template,
                   "title": {"tag": "plain_text", "content": title}},
        "elements": elements,
    }


# ---------- 发送入口 ----------

def notify_daily(payload: dict, channels: list = None) -> dict:
    """
    推送日报（结构化 payload → interactive 卡片）：
    payload: {results, totals, credits, healths, report, prev_totals}
    prev_totals: 上次账户总积分快照（可选，{平台名: 数值}，用于日报环比展示）
    返回 {通道名: 是否成功}
    """
    secrets = _load_secrets()
    notify_cfg = secrets.get("notify", {})
    if channels is None:
        channels = notify_cfg.get("channels", ["stdout"])

    results = payload.get("results") or []
    totals = payload.get("totals") or []
    credits = payload.get("credits") or []
    healths = payload.get("healths") or []
    report = payload.get("report") or ""
    prev_totals = payload.get("prev_totals") or {}

    card = _build_card(results, totals, credits, healths, prev_totals)
    card_payload = {"msg_type": "interactive", "content": card}

    out = {}
    for ch in channels:
        if ch == "feishu_direct":
            f = notify_cfg.get("feishu", {})
            if f.get("app_id") and f.get("app_secret") and f.get("open_id"):
                out[ch] = _feishu_send_direct(card_payload, f)
            else:
                out[ch] = False
                print("[notifier] feishu_direct 配置不完整")
        elif ch == "feishu_webhook":
            w = notify_cfg.get("feishu_webhook", "")
            if w:
                out[ch] = _feishu_webhook(card_payload, w)
            else:
                out[ch] = False
        elif ch == "stdout":
            print("[notify] " + (report or "日报已生成").replace("\n", " | "))
            out[ch] = True
        else:
            out[ch] = False
            print(f"[notifier] 未知通道: {ch}")
    return out


def notify(text: str, channels: list = None) -> dict:
    """
    按配置的通道列表发送普通文本消息（兼容模式，供 notify-test / 简单通知）。
    channels: 未指定时读取 config/secrets.json 的 notify 配置
    返回 {通道名: 是否成功}
    """
    secrets = _load_secrets()
    notify_cfg = secrets.get("notify", {})
    if channels is None:
        channels = notify_cfg.get("channels", ["stdout"])

    results = {}
    for ch in channels:
        if ch == "feishu_direct":
            f = notify_cfg.get("feishu", {})
            if f.get("app_id") and f.get("app_secret") and f.get("open_id"):
                results[ch] = _feishu_send_direct(
                    {"msg_type": "text", "content": {"text": text}}, f)
            else:
                results[ch] = False
                print("[notifier] feishu_direct 配置不完整")
        elif ch == "feishu_webhook":
            w = notify_cfg.get("feishu_webhook", "")
            if w:
                results[ch] = _feishu_webhook(
                    {"msg_type": "text", "content": {"text": text}}, w)
            else:
                results[ch] = False
        elif ch == "stdout":
            print("[notify] " + text.replace("\n", " | "))
            results[ch] = True
        else:
            results[ch] = False
            print(f"[notifier] 未知通道: {ch}")
    return results