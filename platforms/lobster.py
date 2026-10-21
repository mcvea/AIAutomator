# -*- coding: utf-8 -*-
"""
LobsterAI（网易有道桌面 Agent）每日签到模块 —— 「每日积分礼」

原理：
  - 登录态：读取本机 LobsterAI 的 SQLite 数据库 kv 表中的 auth_tokens.accessToken
  - 接口（host: lobsterai-server.youdao.com，Bearer token 鉴权）：
      GET  /api/client-activities/slot?placement=desktop_sidebar&clientVersion=...&containerApiVersion=2&platform=...
           -> 返回活动信息（activityCode / configRevision / cardTitle）
      GET  /api/client-activities/{activityCode}/context?configRevision=N
           -> 返回签到状态（state.claimedToday / rewardCredits）
      POST /api/client-activities/{activityCode}/actions/check_in
           -> 执行签到，body {configRevision, idempotencyKey, payload:{}}
  - 错误码：51104=今日已领（AlreadyClaimed）、51100=活动不存在、51101=活动未激活

数据库位置（Windows）：
  %APPDATA%\\LobsterAI\\lobsterai.sqlite   （kv 表）
"""
import json
import os
import sqlite3
import urllib.error
import urllib.request

from platforms.base import BaseCheckin


class LobsterCheckin(BaseCheckin):
    PLATFORM_NAME = "LobsterAI"
    DAILY_CREDITS = 100

    BASE = "https://lobsterai-server.youdao.com"
    CLIENT_VERSION = "2026.9.4"
    PLACEMENT = "desktop_sidebar"

    # 错误码（逆向自 app.asar ActivityServerErrorCode）
    ERR_NOT_FOUND = 51100
    ERR_NOT_ACTIVE = 51101
    ERR_LOGIN_REQUIRED = 51102
    ERR_ACTION_INVALID = 51103
    ERR_ALREADY_CLAIMED = 51104

    DB_CANDIDATES = [
        os.path.join(os.environ.get("APPDATA", ""), "LobsterAI", "lobsterai.sqlite"),
    ]

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.token = ""

    # ---------- 登录态 ----------

    def _locate_db(self) -> str:
        for p in self.DB_CANDIDATES:
            if p and os.path.isfile(p):
                return p
        raise FileNotFoundError("未找到 LobsterAI 数据库，请先打开 LobsterAI 登录一次")

    def _load_token(self) -> str:
        db = self._locate_db()
        conn = sqlite3.connect(db)
        try:
            row = conn.execute("SELECT value FROM kv WHERE key='auth_tokens'").fetchone()
        finally:
            conn.close()
        if not row:
            raise RuntimeError("未找到 LobsterAI 登录态，请先打开 LobsterAI 登录一次")
        token = (json.loads(row[0]) or {}).get("accessToken", "")
        if not token:
            raise RuntimeError("LobsterAI 登录态中缺少 accessToken")
        return token

    # ---------- 网络请求 ----------

    def _api(self, path: str, method: str = "GET", body: dict = None, timeout: int = 20):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 LobsterAI/{self.CLIENT_VERSION}",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.BASE + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return resp.status, json.loads(raw)
                except Exception:  # noqa: BLE001
                    return resp.status, {"raw": raw[:300]}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return e.code, {"raw": raw[:300]}
        except Exception as e:  # noqa: BLE001
            return 0, {"error": str(e)}

    # ---------- 签到主流程 ----------

    def checkin(self) -> dict:
        self.token = self._load_token()

        # 1) 获取活动槽位
        slot_path = (f"/api/client-activities/slot?placement={self.PLACEMENT}"
                     f"&clientVersion={self.CLIENT_VERSION}&containerApiVersion=2&platform=win32")
        sc, sb = self._api(slot_path)
        if not (isinstance(sb, dict) and sb.get("code") == 0):
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "failed",
                "message": f"获取活动信息失败: {sb.get('message') or sb.get('error') or sb}",
                "credits": 0,
            }
        slot_data = (sb.get("data") or {})
        activity = (slot_data.get("activity") or {})
        activity_code = activity.get("activityCode")
        config_revision = activity.get("configRevision")
        if not activity_code or slot_data.get("slotState") != "available":
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "skipped",
                "message": "当前无每日积分礼活动",
                "credits": 0,
            }

        # 2) 查询签到状态
        ctx_path = (f"/api/client-activities/{activity_code}/context"
                    f"?configRevision={config_revision}")
        sc, cb = self._api(ctx_path)
        ctx = (cb.get("data") or {}) if isinstance(cb, dict) else {}
        state = ctx.get("state") or {}

        if state.get("claimedToday"):
            msg = "今日已签到"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "already",
                "message": msg,
                "credits": 0,
            }

        # 只读模式
        if self.dry:
            msg = "只读模式：今日尚未签到，可正常执行"
            if state.get("rewardCredits"):
                msg += f"（可领 {state.get('rewardCredits'):g} 积分）"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "skipped",
                "message": msg,
                "credits": 0,
            }

        # 3) 执行签到（幂等）
        import uuid
        idem_key = f"daily-check-in-{uuid.uuid4()}"
        action_body = {
            "configRevision": config_revision,
            "idempotencyKey": idem_key,
            "payload": {},
        }
        act_path = f"/api/client-activities/{activity_code}/actions/check_in"
        ac, ab = self._api(act_path, "POST", action_body)

        code = (ab or {}).get("code") if isinstance(ab, dict) else None
        if code == self.ERR_ALREADY_CLAIMED:
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "already",
                "message": "今日已签到",
                "credits": 0,
            }
        if code in (self.ERR_NOT_FOUND, self.ERR_NOT_ACTIVE):
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "skipped",
                "message": f"活动不可用（code={code}）",
                "credits": 0,
            }
        if isinstance(ab, dict) and ab.get("code") == 0:
            credits = state.get("rewardCredits") or self.DAILY_CREDITS
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "success",
                "message": f"签到成功，获得 {credits:g} 积分",
                "credits": int(credits),
            }

        msg = (ab or {}).get("message") or (ab or {}).get("error") or "未知错误"
        return {
            "platform": self.PLATFORM_NAME,
            "success": False,
            "status": "failed",
            "message": f"签到未成功（HTTP {ac}）：{msg}",
            "credits": 0,
        }

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        try:
            self.token = self._load_token()
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }
        # 解析 JWT 的 exp（秒）
        import base64
        import time
        days = None
        try:
            parts = self.token.split(".")
            if len(parts) == 3:
                payload = parts[1] + "=" * (-len(parts[1]) % 4)
                p = json.loads(base64.urlsafe_b64decode(payload))
                exp = p.get("exp")
                if exp:
                    days = max(0, int((float(exp) - time.time()) // 86400))
        except Exception:  # noqa: BLE001
            pass

        status = "ok"
        msg = "登录态正常"
        if days is not None and days < 7:
            status = "warn"
            msg = f"登录态剩余 {days} 天，请打开 LobsterAI 客户端重新登录刷新"
        elif days is not None:
            msg = f"登录态剩余 {days} 天"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }

    # ---------- 积分余额与到期 ----------

    def credits(self) -> list:
        """查询 LobsterAI 积分明细与到期时间（profile-summary creditItems）"""
        import time
        try:
            self.token = self._load_token()
            sc, sb = self._api("/api/user/profile-summary?firstKeyfrom=official")
            if not (isinstance(sb, dict) and sb.get("code") == 0):
                return []
            data = sb.get("data") or {}
        except Exception:  # noqa: BLE001
            return []

        items = []
        now = time.time()
        for item in data.get("creditItems") or []:
            exp = item.get("expiresAt")
            if not exp:
                continue
            try:
                from datetime import datetime
                exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                days = max(0, int((exp_dt.timestamp() - now) // 86400))
                expires_str = exp_dt.strftime("%Y-%m-%d")
            except Exception:  # noqa: BLE001
                continue
            items.append({
                "label": item.get("label", "积分"),
                "credits": float(item.get("creditsRemaining") or 0),
                "expires_at": expires_str,
                "days_left": days,
            })
        items.sort(key=lambda x: x["expires_at"])
        return items

    # ---------- 账户总积分 ----------

    def total(self) -> dict:
        """查询账户总积分余额（profile-summary.totalCreditsRemaining）"""
        try:
            self.token = self._load_token()
            sc, sb = self._api("/api/user/profile-summary?firstKeyfrom=official")
            if not (isinstance(sb, dict) and sb.get("code") == 0):
                return {"available": False, "total": None}
            data = sb.get("data") or {}
            total = data.get("totalCreditsRemaining")
            if total is None:
                return {"available": False, "total": None}
            return {
                "available": True,
                "total": float(total),
                "note": "",
            }
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None}

    # ---------- 账户总余额 ----------

    def balance(self) -> dict:
        """查询 LobsterAI 账户总余额（profile-summary.totalCreditsRemaining）

        Lobster 服务端仅提供剩余总额口径（与上游 lobsterai2api 一致），
        无总量/已用拆分，故 total 与 remain 同值。
        """
        try:
            self.token = self._load_token()
            sc, sb = self._api("/api/user/profile-summary?firstKeyfrom=official")
            if not (isinstance(sb, dict) and sb.get("code") == 0):
                return {"available": False, "total": None, "remain": None, "used": None}
            data = sb.get("data") or {}
            remain = data.get("totalCreditsRemaining")
            if remain is None:
                return {"available": False, "total": None, "remain": None, "used": None}
            return {
                "available": True,
                "total": float(remain),
                "remain": float(remain),
                "used": None,
                "note": "",
            }
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None, "remain": None, "used": None}
