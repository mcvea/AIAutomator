# -*- coding: utf-8 -*-
"""
MiniMax Code（MiniMax Agent 桌面端）每日签到模块

原理：签到接口带签名鉴权，签名机制逆向自桌面端 app.asar（社区已验证）：
  - 鉴权头  token: <accessToken>
  - 签名头  x-timestamp / x-signature / yy（详见 _sign_request）
  - 先续期（/v1/api/user/renewal）换新 token（有效期顺延），再查询、领取

接口：
  POST {host}/v1/api/user/renewal          续期登录 -> {"data":{"token":"新JWT"}}
  GET  {host}/minimax-cloud/api/v1/signin/status  签到状态（只读）
  POST {host}/minimax-cloud/api/v1/signin/claim   领取积分（幂等）

登录态读取（Windows）：
  %USERPROFILE%\\.minimax\\auth\\prod\\cn\\mcode-public\\auth.json
  -> records["com.minimax.mcode.oauth.prod.cn<后缀>"].accessToken / refreshToken
"""
import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from platforms.base import BaseCheckin


class MiniMaxCheckin(BaseCheckin):
    PLATFORM_NAME = "MiniMax Code"
    DAILY_CREDITS = 400

    # 国内/国际 host 双候选，依次尝试（真实客户端用 agent.minimaxi.com）
    HOSTS = [
        "https://agent.minimaxi.com",   # 国内（本机实测）
        "https://agent.minimax.io",     # 国际
    ]

    RENEW_PATH = "/v1/api/user/renewal"
    STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
    CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"

    # 登录态文件候选路径
    # 注意：API 鉴权用的是 local-runtime.auth.json 的 JWT（auth.accessToken），
    #       auth.json 里的 mmoat_v5_ 为 OAuth token，仅作兜底
    AUTH_FILE_CANDIDATES = [
        os.path.join(os.path.expanduser("~"), ".minimax", "local-runtime.auth.json"),
        os.path.join(os.path.expanduser("~"), ".minimax", "auth", "prod", "cn",
                     "mcode-public", "auth.json"),
        # 兜底真实路径（应对环境变量重定向）


    ]

    # 设备参数字段顺序（严格对齐桌面端，影响 yy 签名）
    DEVICE_PARAM_ORDER = [
        "device_platform", "biz_id", "app_id", "version_code", "unix",
        "timezone_offset", "is_desktop", "desktop_version", "sys_language",
        "lang", "uuid", "device_id", "os_name", "browser_name", "device_memory",
        "cpu_core_num", "browser_language", "browser_platform", "user_id",
        "op_ticket", "screen_width", "screen_height",
    ]

    # 设备身份（真实值来自本机 LevelDB UNIQUE_USER_ID 与客户端请求日志；
    # 若换机器/重装，请用客户端实际抓包值覆盖，或用 config.json 配置）
    DEFAULT_UUID = "d56f2e80-c269-4b9a-912f-0afefd61ae0e"
    DEFAULT_DEVICE_ID = "67027927"

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.token = None
        self.user_id = ""
        self.cn_config = self._load_cn_config()
        # 注意：签到请求的 device_id 取自客户端真实请求日志，与 cn-config 的
        # USER_HARD_WARE_INFO 不同，优先使用 DEFAULT_DEVICE_ID
        self.device_id = self.DEFAULT_DEVICE_ID
        self.user_id = str(self.cn_config.get("realUserID") or "")

    # ---------- 登录态读取 ----------

    def _load_cn_config(self) -> dict:
        """读取 cn-config（含 realUserID / deviceID）"""
        for path in (
            os.path.join(os.environ.get("APPDATA", ""), "minimax", "minimax-agent-cn-config.json"),

        ):
            if path and os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    user = data.get("user") or {}
                    return {
                        "realUserID": user.get("realUserID", ""),
                        "deviceID": user.get("deviceID", ""),
                        "userName": user.get("userName", ""),
                    }
                except Exception:  # noqa: BLE001
                    continue
        return {}

    def _load_token(self) -> str:
        """提取 API 鉴权 token（优先 local-runtime.auth.json 的 JWT）"""
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    # 优先 auth.accessToken（JWT）
                    auth = data.get("auth") or {}
                    if auth.get("accessToken"):
                        return str(auth["accessToken"])
                    # 回退 records 里的 OAuth token
                    if "records" in data:
                        for key, rec in (data.get("records") or {}).items():
                            if isinstance(rec, dict) and rec.get("accessToken"):
                                return str(rec["accessToken"])
                except Exception:  # noqa: BLE001
                    continue
        raise FileNotFoundError("未找到 MiniMax 登录态，请先打开 MiniMax Code 客户端登录一次")

    # ---------- 签名工具（移植自社区逆向实现） ----------

    @staticmethod
    def _md5_hex(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    @staticmethod
    def _encode_uri_component(s: str) -> str:
        """复刻 JS encodeURIComponent"""
        return re.sub(
            r'([^A-Za-z0-9\-_.!~*\'()])',
            lambda m: '%%%02X' % ord(m.group(1)),
            s,
        )

    def _build_device_params(self) -> dict:
        now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
        values = {
            "device_platform": "web",
            "biz_id": "3",
            "app_id": "3001",
            "version_code": "22201",
            "unix": str(now_ms),
            "timezone_offset": "28800",
            "is_desktop": "1",
            "desktop_version": "",
            "sys_language": "zh",
            "lang": "zh",
            "uuid": self.DEFAULT_UUID,
            "device_id": self.device_id,
            "os_name": "Windows",
            "browser_name": "Chrome",
            "device_memory": "16",
            "cpu_core_num": "4",
            "browser_language": "zh-CN",
            "browser_platform": "Win32",
            "user_id": self.user_id,
            "op_ticket": "undefined",
            "screen_width": "1366",
            "screen_height": "768",
        }
        return {k: values[k] for k in self.DEVICE_PARAM_ORDER}

    def _sign_request(self, path: str, token: str, method: str, body: dict):
        """计算签名与请求头，返回 (url_with_query, headers, body_str)"""
        now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
        now_sec = now_ms // 1000

        params = self._build_device_params()
        params["unix"] = str(now_ms)
        params["client"] = "desktop"

        query = urllib.parse.urlencode(params)
        has_search_params_path = f"{path}?{query}"
        body_str = "" if method.upper() == "GET" else json.dumps(body or {}, ensure_ascii=False)

        x_signature = self._md5_hex(f"{now_sec}I*7Cf%WZ#S&%1RlZJ&C2{body_str}")
        inner = self._md5_hex(str(now_ms))
        yy = self._md5_hex(self._encode_uri_component(has_search_params_path)
                           + "_" + "{}" + inner + "ooui")

        headers = {
            "token": token,
            "yy": yy,
            "x-timestamp": str(now_sec),
            "x-signature": x_signature,
            "origin": "https://agent.minimaxi.com",
            "referer": "https://agent.minimaxi.com/",
            "accept": "application/json, text/plain, */*",
            "user-agent": ("MiniMaxAgent Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) MiniMax/3.0.68 "
                           "Chrome/148.0.7778.280 Safari/537.36"),
        }
        if method.upper() != "GET":
            headers["content-type"] = "application/json"

        url = f"{path}?{query}"
        return url, headers, body_str

    # ---------- 网络请求 ----------

    def _api_call(self, host: str, token: str, path: str, method: str, body: dict,
                  timeout: int = 30):
        """带签名调用接口，返回 (http_status, json)"""
        url, headers, body_str = self._sign_request(path, token, method, body)
        full_url = host + url
        data_bytes = body_str.encode("utf-8") if body_str else None
        req = urllib.request.Request(full_url, data=data_bytes, headers=headers, method=method)
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

    def _renew(self, host: str, token: str):
        """续期登录，返回新 token；失败返回空串"""
        code, data = self._api_call(host, token, self.RENEW_PATH, "POST", {})
        if isinstance(data, dict):
            new_token = ((data.get("data") or {}).get("token") or "").strip()
            if new_token:
                return new_token
        return ""

    @staticmethod
    def _api_ok(data) -> bool:
        if not isinstance(data, dict):
            return False
        br = data.get("base_resp") or {}
        if isinstance(br, dict) and br.get("status_code") == 0:
            return True
        code = data.get("code")
        if isinstance(code, (int, float)) and code in (0, 200):
            return True
        return data.get("success") is True or str(data.get("status", "")).lower() == "success"

    # ---------- 签到主流程 ----------

    def checkin(self) -> dict:
        self.token = self._load_token()
        if not self.token:
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "failed",
                "message": "未找到 MiniMax 登录态，请打开 MiniMax Code 客户端登录一次",
                "credits": 0,
            }

        last_err = ""
        for host in self.HOSTS:
            try:
                return self._checkin_host(host)
            except Exception as e:  # noqa: BLE001
                last_err = f"{host}: {e}"
                continue
        return {
            "platform": self.PLATFORM_NAME,
            "success": False,
            "status": "failed",
            "message": f"所有 host 均失败（{last_err}）",
            "credits": 0,
        }

    def _checkin_host(self, host: str) -> dict:
        token = self.token

        # 1) 先续期，换新 token（有效期顺延）
        new_token = self._renew(host, token)
        if new_token:
            token = new_token

        # 2) 状态查询（只读）
        sc, sb = self._api_call(host, token, self.STATUS_PATH, "GET", {})
        if not self._api_ok(sb):
            raise RuntimeError(f"状态查询异常 HTTP {sc}: {json.dumps(sb, ensure_ascii=False)[:200]}")

        days = ((sb or {}).get("data") or {}).get("days") or []
        today = next((d for d in days if d.get("is_today")), None)
        today_done = bool(today and today.get("status") == 3)

        day_no = today.get("day_no") if today else None

        if today_done:
            msg = "今日已签到"
            if day_no:
                msg += f"（第 {day_no} 天）"
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
            if day_no:
                msg += f"（当前第 {day_no} 天）"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "skipped",
                "message": msg,
                "credits": 0,
            }

        # 3) 领取积分（幂等）
        cc, cb = self._api_call(host, token, self.CLAIM_PATH, "POST", {})
        if not self._api_ok(cb):
            raise RuntimeError(f"领取异常 HTTP {cc}: {json.dumps(cb, ensure_ascii=False)[:200]}")

        cdata = (cb or {}).get("data") or {}
        claim_result = cdata.get("claim_result")
        points = cdata.get("points")
        day_no = cdata.get("day_no") or day_no

        if claim_result == 2:
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "already",
                "message": "今日已签到",
                "credits": 0,
            }

        credits = int(points) if isinstance(points, (int, float)) and points else self.DAILY_CREDITS
        msg = f"签到成功，获得 {credits} 积分"
        if day_no:
            msg += f"（第 {day_no} 天）"
        return {
            "platform": self.PLATFORM_NAME,
            "success": True,
            "status": "success",
            "message": msg,
            "credits": credits,
        }

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        """MiniMax 每次签到都会自动续期（renewal），重点检查续期链路是否可用"""
        try:
            self.token = self._load_token()
            if not self.token:
                raise RuntimeError("无 token")
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }
        # 尝试续期验证（幂等，仅顺延 token）
        for host in self.HOSTS:
            try:
                new_token = self._renew(host, self.token)
                if new_token:
                    return {
                        "platform": self.PLATFORM_NAME,
                        "status": "ok",
                        "days_left": 40,
                        "message": "自动续期正常（每次签到自动顺延约 40 天）",
                    }
            except Exception:  # noqa: BLE001
                continue
        return {
            "platform": self.PLATFORM_NAME,
            "status": "warn",
            "days_left": None,
            "message": "自动续期失败，请打开 MiniMax Code 客户端重新登录",
        }
