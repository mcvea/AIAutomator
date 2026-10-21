# -*- coding: utf-8 -*-
"""
百度搭子 DuMate（千帆桌面客户端）每日签到模块

原理：
  - 登录态：读取本机 DuMate 客户端 auth.json 中的加密 cookies
    （AES-256-GCM，密钥在 userData/.cookie-key 的 32 字节随机数，
    格式 base64(iv(12) + authTag(16) + ciphertext)，逆向自 app.asar）
  - 接口（经 console.bce.baidu.com，cookie 鉴权）：
      GET  /api/dumate/points/loginBonusInfo  每日登录奖励信息（只读）
      POST /api/dumate/points/loginBonus      领取每日登录奖励（幂等）
  - 请求头：Cookie（按域名匹配）+ csrftoken（bce-user-info cookie 值）

登录态文件（Windows）：
  %APPDATA%\\qianfan-desktop-app\\auth.json
  %APPDATA%\\qianfan-desktop-app\\.cookie-key
"""
import base64
import json
import os
import urllib.error
import urllib.request

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None

from platforms.base import BaseCheckin


class DuMateCheckin(BaseCheckin):
    PLATFORM_NAME = "百度搭子 DuMate"
    DAILY_CREDITS = 500

    API_BASE = "https://console.bce.baidu.com"
    LOGIN_BONUS_INFO_PATH = "/api/dumate/points/loginBonusInfo"
    LOGIN_BONUS_PATH = "/api/dumate/points/loginBonus"
    TARGET_HOST = "console.bce.baidu.com"

    APP_DIR_CANDIDATES = [
        os.path.join(os.environ.get("APPDATA", ""), "qianfan-desktop-app"),
    ]

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.app_dir = self._locate_app_dir()
        self.cookies = []

    # ---------- 登录态读取与解密 ----------

    def _locate_app_dir(self) -> str:
        for d in self.APP_DIR_CANDIDATES:
            if d and os.path.isdir(d):
                return d
        raise FileNotFoundError("未找到 DuMate 数据目录，请先打开百度搭子客户端登录一次")

    def _load_key(self) -> bytes:
        key_file = os.path.join(self.app_dir, ".cookie-key")
        if not os.path.isfile(key_file):
            raise FileNotFoundError("未找到 .cookie-key，请重新登录百度搭子")
        with open(key_file, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise RuntimeError(f".cookie-key 长度异常（{len(key)}）")
        return key

    def _decrypt_cookies(self, key: bytes, encrypted_b64: str) -> list:
        if AES is None:
            raise RuntimeError("缺少 pycryptodome 依赖，请执行: pip install pycryptodome")
        payload = base64.b64decode(encrypted_b64)
        iv, tag, ct = payload[:12], payload[12:28], payload[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        data = cipher.decrypt_and_verify(ct, tag)
        cookies = json.loads(data.decode("utf-8"))
        if not isinstance(cookies, list):
            raise RuntimeError("解密 cookies 格式异常")
        return cookies

    def _load_active_cookies(self) -> list:
        """读取并解密当前激活账号的 cookies"""
        with open(os.path.join(self.app_dir, "auth.json"), "r", encoding="utf-8") as f:
            auth = json.load(f)

        active_id = auth.get("activeProfileId", "")
        profiles = auth.get("accountProfiles") or []
        profile = None
        for p in profiles:
            if isinstance(p, dict) and p.get("profileId") == active_id:
                profile = p
                break
        if profile is None and profiles:
            profile = profiles[0]
        if not profile:
            raise RuntimeError("未找到已登录账号，请打开百度搭子登录")

        encrypted = profile.get("encryptedCookies")
        if not encrypted:
            raise RuntimeError("未找到加密 cookies，请重新登录百度搭子")

        key = self._load_key()
        self.cookies = self._decrypt_cookies(key, encrypted)
        return self.cookies

    # ---------- 请求头构造 ----------

    @staticmethod
    def _domain_match(hostname: str, domain: str) -> bool:
        if not domain:
            return True
        d = domain[1:] if domain.startswith(".") else domain
        return hostname == d or hostname.endswith("." + d)

    def _build_cookie_header(self) -> str:
        hostname = self.TARGET_HOST
        matched = [c for c in self.cookies if self._domain_match(hostname, c.get("domain"))]
        parts = []
        for c in matched:
            val = str(c.get("value", "")).strip('"\'')
            if any(ch in val for ch in ":|;= \t"):
                val = f'"{val}"'
            parts.append(f"{c.get('name')}={val}")
        return "; ".join(parts)

    def _extract_csrftoken(self) -> str:
        hostname = self.TARGET_HOST
        for c in self.cookies:
            if c.get("name") == "bce-user-info" and self._domain_match(hostname, c.get("domain")):
                return str(c.get("value", "")).strip('"\'')
        return ""

    # ---------- 网络请求 ----------

    def _api_call(self, path: str, method: str = "GET", body: dict = None,
                  timeout: int = 30):
        url = self.API_BASE + path
        headers = {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.API_BASE,
            "Referer": self.API_BASE + "/",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
        }
        cookie_str = self._build_cookie_header()
        if cookie_str:
            headers["Cookie"] = cookie_str
        csrf = self._extract_csrftoken()
        if csrf:
            headers["csrftoken"] = csrf

        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
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

    @staticmethod
    def _unwrap(data) -> dict:
        """响应解包：{code:0, message, result} 或 {success:true}"""
        if not isinstance(data, dict):
            return {}
        if data.get("code") == 0 or data.get("success") is True:
            result = data.get("result")
            return result if isinstance(result, dict) else {}
        return {}

    # ---------- 签到主流程 ----------

    def checkin(self) -> dict:
        self._load_active_cookies()

        # 1) 查询每日登录奖励信息（只读）
        sc, sb = self._api_call(self.LOGIN_BONUS_INFO_PATH, "GET")
        info = self._unwrap(sb)

        sign_days = info.get("signInDays") or []
        total_times = info.get("totalTimes")

        # 判定今日是否已领取：signInDays 含今天的日期字符串
        import datetime
        today = datetime.date.today().isoformat()
        if any(str(d).startswith(today) for d in sign_days):
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
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "skipped",
                "message": msg,
                "credits": 0,
            }

        # 2) 领取每日登录奖励（幂等）
        cc, cb = self._api_call(self.LOGIN_BONUS_PATH, "POST", body={})
        result = self._unwrap(cb)
        claimed = result.get("success") if isinstance(result, dict) else None
        if claimed is False or (cb.get("code") not in (0, None) and cb.get("success") is not True):
            # 领取结果包含 success 字段或 code
            pass

        # 再查一次状态确认
        sc2, sb2 = self._api_call(self.LOGIN_BONUS_INFO_PATH, "GET")
        info2 = self._unwrap(sb2)
        sign_days2 = info2.get("signInDays") or []
        if any(str(d).startswith(today) for d in sign_days2):
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "success",
                "message": f"签到成功，获得 {self.DAILY_CREDITS} 积分",
                "credits": self.DAILY_CREDITS,
            }

        msg = (cb or {}).get("message") or "领取未确认成功"
        return {
            "platform": self.PLATFORM_NAME,
            "success": False,
            "status": "failed",
            "message": f"签到未成功：{msg}",
            "credits": 0,
        }

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        try:
            cookies = self._load_active_cookies()
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }

        # 取关键登录 cookie（BDUSS / bce-user-info）的最早过期时间
        import time
        earliest = None
        for c in cookies:
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
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }

    # ---------- 积分余额与到期 ----------

    def credits(self) -> list:
        """查询 DuMate 积分套餐与到期时间（quota_overview）"""
        import time
        from datetime import datetime, timedelta
        try:
            self._load_active_cookies()
            sc, sb = self._api_call(
                "/api/dumate/points/quota_overview?timezone=Asia/Shanghai&clientType=desktop&ignoreLoginBonus=true",
                "GET")
            result = self._unwrap(sb)
        except Exception:  # noqa: BLE001
            return []

        items = []
        now = time.time()
        # 订阅套餐
        for sub in result.get("subscription") or []:
            exp = sub.get("expireDate")
            if not exp:
                continue
            items.append({
                "label": "体验套餐" if sub.get("packageType") == "plan_experience" else "订阅套餐",
                "credits": float(sub.get("totalPoints") or 0),
                "expires_at": datetime.fromtimestamp(exp).strftime("%Y-%m-%d"),
                "days_left": max(0, int((float(exp) - now) // 86400)),
            })
        # 增量积分
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
            })
        # 按最近到期排序
        items.sort(key=lambda x: x["expires_at"])
        return items

    # ---------- 账户总积分 ----------

    def total(self) -> dict:
        """查询账户剩余可用积分（quota_overview.result.totalPoints - usedPoints）"""
        try:
            self._load_active_cookies()
            sc, sb = self._api_call(
                "/api/dumate/points/quota_overview?timezone=Asia/Shanghai"
                "&clientType=desktop&ignoreLoginBonus=true",
                "GET")
            result = self._unwrap(sb)
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None}
        total = result.get("totalPoints")
        used = result.get("usedPoints")
        if total is None:
            return {"available": False, "total": None}
        total_f = float(total)
        used_f = float(used or 0)
        return {
            "available": True,
            "total": round(total_f - used_f, 2),
            "note": "",
        }

    # ---------- 账户总余额 ----------

    def balance(self) -> dict:
        """查询 DuMate 账户总余额（quota_overview：总量/已用/剩余）

        同一接口复用：result.totalPoints = 积分总量，
        result.usedPoints = 已消耗，remaining = total - used。
        """
        try:
            self._load_active_cookies()
            sc, sb = self._api_call(
                "/api/dumate/points/quota_overview?timezone=Asia/Shanghai"
                "&clientType=desktop&ignoreLoginBonus=true",
                "GET")
            result = self._unwrap(sb)
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None, "remain": None, "used": None}
        total = result.get("totalPoints")
        used = result.get("usedPoints")
        if total is None:
            return {"available": False, "total": None, "remain": None, "used": None}
        total_f = float(total)
        used_f = float(used or 0)
        return {
            "available": True,
            "total": total_f,
            "remain": round(total_f - used_f, 2),
            "used": used_f,
            "note": "",
        }
