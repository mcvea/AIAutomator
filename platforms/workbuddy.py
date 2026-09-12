# -*- coding: utf-8 -*-
"""
WorkBuddy（腾讯 AI 办公工作台）每日签到模块

原理：签到 = 带登录态的 HTTP 请求。
登录态读取自本机 WorkBuddy 桌面客户端自动写入的凭据文件
（%LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\workbuddy-desktop.info），
使用其中的 auth.accessToken 调用官方计费接口完成签到。

接口均为幂等操作：重复调用只会提示"已领过"，不会扣任何积分，可放心反复执行。

参考社区已验证信息：
- 状态查询(只读): POST /v2/billing/meter/checkin-activity-status
- 执行签到(写):   POST /v2/billing/meter/daily-checkin
"""
import json
import os
import time
import urllib.error
import urllib.request

from platforms.base import BaseCheckin


class WorkBuddyCheckin(BaseCheckin):
    PLATFORM_NAME = "WorkBuddy"
    DAILY_CREDITS = 100

    # 登录态文件候选路径（依次探测）
    AUTH_FILE_CANDIDATES = [
        # 常规路径（计划任务运行时 LOCALAPPDATA 为真实用户目录）
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"),
        # 兜底真实路径
        r"C:\Users\USER\AppData\Local\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info",
        os.path.join(os.path.expanduser("~"), ".workbuddy", "auth", "workbuddy-desktop.info"),
    ]

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.auth_data = None
        self.auth_file = self._locate_auth_file()

    # ---------- 内部工具 ----------

    def _locate_auth_file(self):
        """定位登录态文件"""
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                return path
        raise FileNotFoundError(
            "未找到 WorkBuddy 登录态文件，请先打开 WorkBuddy 客户端登录一次")

    def _load_auth(self):
        """读取登录态 JSON，提取 token 与域名"""
        with open(self.auth_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        auth = data.get("auth") or {}
        account = data.get("account") or {}
        token = auth.get("accessToken")
        domain = auth.get("domain") or "www.workbuddy.cn"
        uid = account.get("uid", "")
        if not token:
            raise RuntimeError("登录态文件中未找到 accessToken，请重新登录 WorkBuddy")
        return token, domain, uid, auth

    def _token_expired(self, auth: dict) -> bool:
        """检查 accessToken 是否过期（expiresAt 为毫秒时间戳）"""
        expires_at = auth.get("expiresAt")
        if not expires_at:
            return False
        return time.time() * 1000 > float(expires_at)

    def _http_json(self, method: str, url: str, token: str, uid: str, payload=None):
        """发 HTTP 请求并解析 JSON 响应"""
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0 Safari/537.36"),
        }
        if uid:
            headers["X-User-Id"] = uid

        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"HTTP {e.code}: {detail}") from e

    # ---------- 对外接口 ----------

    def checkin(self) -> dict:
        token, domain, uid, auth = self._load_auth()

        if self._token_expired(auth):
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "failed",
                "message": "登录态已过期，请打开 WorkBuddy 客户端重新登录刷新",
                "credits": 0,
            }

        base = f"https://{domain}"

        # 1) 先查询今日签到状态（只读，安全）
        status_data = None
        try:
            status = self._http_json(
                "POST",
                f"{base}/v2/billing/meter/checkin-activity-status",
                token, uid, payload={},
            )
            status_data = status.get("data") if isinstance(status, dict) else None
        except Exception:  # noqa: BLE001 - 状态查询失败不阻塞，直接尝试签到
            status_data = None

        streak_days = status_data.get("streak_days") if status_data else None

        # 今日已签：识别多种字段写法
        if isinstance(status_data, dict):
            already_checked = (
                status_data.get("today_checked_in") is True
                or status_data.get("checkedIn") is True
                or status_data.get("alreadyCheckedIn") is True
            )
            if already_checked:
                msg = "今日已签到，无需重复领取"
                if streak_days:
                    msg += f"（已连签 {streak_days} 天）"
                return {
                    "platform": self.PLATFORM_NAME,
                    "success": True,
                    "status": "already",
                    "message": msg,
                    "credits": 0,
                }

        # 只读模式：到这里就停，不执行签到
        if self.dry:
            msg = "只读模式：今日尚未签到，可正常执行"
            if streak_days:
                msg += f"（当前连签 {streak_days} 天）"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "skipped",
                "message": msg,
                "credits": 0,
            }

        # 2) 执行每日签到（幂等；已签时服务端返回 HTTP 400）
        try:
            result = self._http_json(
                "POST",
                f"{base}/v2/billing/meter/daily-checkin",
                token, uid, payload={},
            )
        except RuntimeError as e:
            err_text = str(e)
            if "已签到" in err_text or "10001" in err_text or "already" in err_text.lower():
                msg = "今日已签到，无需重复领取"
                if streak_days:
                    msg += f"（已连签 {streak_days} 天）"
                return {
                    "platform": self.PLATFORM_NAME,
                    "success": True,
                    "status": "already",
                    "message": msg,
                    "credits": 0,
                }
            raise

        text = json.dumps(result, ensure_ascii=False)

        # 判定结果
        if ("already" in text.lower() or "已签" in text or
                "重复" in text or result.get("alreadyCheckedIn") is True):
            msg = "今日已签到，无需重复领取"
            if streak_days:
                msg += f"（已连签 {streak_days} 天）"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "already",
                "message": msg,
                "credits": 0,
            }

        # 提取积分信息（响应字段各异，尽力而为；缺失时用每日额度兜底展示）
        credits = self._extract_credits(result) or self.DAILY_CREDITS
        msg = "签到成功"
        if credits:
            msg += f"，获得 {credits} 积分"
        if streak_days:
            msg += f"（连签 {streak_days + 1} 天）"
        return {
            "platform": self.PLATFORM_NAME,
            "success": True,
            "status": "success",
            "message": msg,
            "credits": credits,
        }

    @staticmethod
    def _extract_credits(result: dict) -> int:
        """从签到响应中尽力提取获得的积分数量"""
        candidates = [
            result.get("credits"), result.get("points"), result.get("amount"),
            result.get("reward"), result.get("gainCredits"), result.get("earnedCredits"),
        ]
        for c in candidates:
            if isinstance(c, (int, float)) and c > 0:
                return int(c)
        if isinstance(result.get("data"), dict):
            for k in ("credits", "points", "amount", "reward", "gainCredits"):
                v = result["data"].get(k)
                if isinstance(v, (int, float)) and v > 0:
                    return int(v)
        return 0

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        try:
            token, domain, uid, auth = self._load_auth()
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }
        now_ms = time.time() * 1000
        expires_at = auth.get("expiresAt")
        refresh_expires = auth.get("refreshExpiresAt")
        days = None
        if expires_at:
            days = max(0, int((float(expires_at) - now_ms) / 86400000))
        status = "ok"
        msg = "登录态正常"
        if expires_at and float(expires_at) <= now_ms:
            status = "expired"
            msg = "登录态已过期，请打开 WorkBuddy 客户端重新登录"
        elif days is not None and days < 7:
            status = "warn"
            msg = f"登录态剩余 {days} 天，请尽快打开 WorkBuddy 登录刷新"
        elif days is not None:
            msg = f"登录态剩余 {days} 天"
        if refresh_expires and status == "ok":
            r_days = max(0, int((float(refresh_expires) - now_ms) / 86400000))
            if r_days < 7:
                status = "warn"
                msg += f"（refreshToken 剩余 {r_days} 天）"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }
