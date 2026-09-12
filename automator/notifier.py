# -*- coding: utf-8 -*-
"""
通知总线：多通道通知器。
通道类型（平台无关，由用户配置指定）：
    feishu_direct   飞书自建应用直连私聊
    feishu_webhook  飞书群机器人
    stdout          控制台输出（调试）
"""
import json
import os
import urllib.error
import urllib.request

OPEN_FEISHU = "https://open.feishu.cn"


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


def _feishu_send_direct(text: str, cfg: dict) -> bool:
    token = _feishu_token(cfg["app_id"], cfg["app_secret"])
    body = json.dumps({
        "receive_id": cfg.get("open_id", ""),
        "msg_type": "text",
        "content": json.dumps({"text": text}, ensure_ascii=False),
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
        return d.get("code") == 0
    except Exception as e:  # noqa: BLE001
        print(f"[notifier] 飞书直连失败: {e}")
        return False


def _feishu_webhook(text: str, webhook: str) -> bool:
    payload = json.dumps({"msg_type": "text", "content": {"text": text}},
                         ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(webhook, data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.loads(resp.read().decode("utf-8"))
        return d.get("code") == 0 or d.get("StatusCode") == 0
    except Exception as e:  # noqa: BLE001
        print(f"[notifier] 飞书 Webhook 失败: {e}")
        return False


def notify(text: str, channels: list = None) -> dict:
    """
    按配置的通道列表发送消息。
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
                results[ch] = _feishu_send_direct(text, f)
            else:
                results[ch] = False
                print("[notifier] feishu_direct 配置不完整")
        elif ch == "feishu_webhook":
            w = notify_cfg.get("feishu_webhook", "")
            if w:
                results[ch] = _feishu_webhook(text, w)
            else:
                results[ch] = False
        elif ch == "stdout":
            print("[notify] " + text.replace("\n", " | "))
            results[ch] = True
        else:
            results[ch] = False
            print(f"[notifier] 未知通道: {ch}")
    return results
