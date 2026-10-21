# -*- coding: utf-8 -*-
"""
MiniMax Code（MiniMax Agent 桌面端）每日签到模块

认证机制（2026-10-21 逆向桌面端 app.asar + 实测校正）：
  桌面端所有 agent 接口走 **OAuth Bearer**，不再使用旧的 JWT `token` 头：
    - 凭据：%USERPROFILE%\\.minimax\\auth\\prod\\cn\\mcode-public\\auth.json
            records["com.minimax.mcode.oauth.prod.cn<后缀>"]
            .accessToken(mmoat_*) / .refreshToken(mmort_*) / .expiresAtMs
    - 续期：POST https://account.minimax.cn/oauth2/token
            grant_type=refresh_token & client_id=mcode-public
            & scope=agent.default & audience=agent-backend
            返回新 access_token（+ 新 refresh_token，服务端会轮换但旧 token 仍可用）
    - 请求头：Authorization: Bearer <access_token>
            + 签名头 x-timestamp / x-signature / yy（详见 _sign_request）

  旧机制（仍保留为兜底，勿删）：
    - 登录态：%USERPROFILE%\\.minimax\\local-runtime.auth.json 的 auth.accessToken（JWT）
    - 续期：POST {host}/v1/api/user/renewal 换新 JWT（有效期约 40 天）
      注意：JWT 过期后再调 renewal 会被拒（401 statusInfo.code=1000021），
      若不把续期结果落盘，第 40 天必然全线 401

接口：
  GET  {host}/minimax-cloud/api/v1/signin/status  签到状态（只读）
  POST {host}/minimax-cloud/api/v1/signin/claim   领取积分（幂等）
  POST {host}/matrix/api/v1/commerce/get_membership_info  侧边栏 OP 积分

host：桌面端实际使用 https://agent.minimax.cn（国内），agent.minimaxi.com 作为备用。
"""
import base64
import hashlib
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from platforms.base import BaseCheckin


class MiniMaxCheckin(BaseCheckin):
    PLATFORM_NAME = "MiniMax Code"
    DAILY_CREDITS = 400

    # 国内/国际 host 双候选，依次尝试（桌面端实际用 agent.minimax.cn）
    HOSTS = [
        "https://agent.minimax.cn",     # 国内（桌面端实测）
        "https://agent.minimaxi.com",   # 兼容旧 host
    ]

    RENEW_PATH = "/v1/api/user/renewal"
    STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
    CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"

    # ---------- OAuth 凭据（现行认证链路） ----------

    OAUTH_DIR = os.path.join(os.path.expanduser("~"), ".minimax", "auth", "prod", "cn",
                             "mcode-public")
    OAUTH_CRED_FILE = os.path.join(OAUTH_DIR, "auth.json")
    OAUTH_STATE_FILE = os.path.join(OAUTH_DIR, "auth-state.json")
    OAUTH_LOCK_FILE = os.path.join(OAUTH_DIR, "auth.lock")
    OAUTH_TOKEN_URL = "https://account.minimax.cn/oauth2/token"
    OAUTH_CLIENT_ID = "mcode-public"
    OAUTH_SCOPE = "agent.default"
    OAUTH_AUDIENCE = "agent-backend"
    # 提前多久刷新（秒）——access_token 只有 1 小时寿命
    OAUTH_REFRESH_MARGIN_S = 300
    # 跨进程锁（与桌面端 oauth-core 的 proper-lockfile 协议一致：<file>.lock 目录）
    OAUTH_LOCK_STALE_MS = 30_000

    # ---------- 旧 JWT 登录态（兜底） ----------

    # 注意：API 鉴权用的是 local-runtime.auth.json 的 JWT（auth.accessToken），
    #       auth.json 里的 mmoat_ 为 OAuth token（主链路，见上方 OAuth 段）
    AUTH_FILE_CANDIDATES = [
        os.path.join(os.path.expanduser("~"), ".minimax", "local-runtime.auth.json"),
        os.path.join(os.path.expanduser("~"), ".minimax", "auth", "prod", "cn",
                     "mcode-public", "auth.json"),
    ]

    # 官网账户中心（余额查询，旧 API 计费口径：按 token 计费账户恒为 0）
    BALANCE_HOST = "https://www.minimaxi.com"
    BALANCE_PATH = "/backend/account/token_plan_credit"
    # 账户级 GroupId：仅备用的「按 token 计费」余额接口需要（主接口 OP 积分不依赖）。
    # 该值与账号绑定，**不写死在代码里**：按需设置环境变量 MINIMAX_GROUP_ID
    # （取值来自本人桌面客户端请求日志的 X-Group-Id 头）；未设置则跳过该备用接口。
    GROUP_ID = os.environ.get("MINIMAX_GROUP_ID", "").strip()

    # 客户端侧边栏"积分"真实数据源（OP 积分，2026-10-07 实测命中 17357）
    # 接口：POST agent.minimax.cn/matrix/api/v1/commerce/get_membership_info
    # 响应：op_credit_summary.total_remaining_amount（字符串，如 "17357.397"）
    MEMBERSHIP_HOST = "https://agent.minimax.cn"
    MEMBERSHIP_PATH = "/matrix/api/v1/commerce/get_membership_info"

    # 设备参数字段顺序（严格对齐桌面端，影响 yy 签名）
    DEVICE_PARAM_ORDER = [
        "device_platform", "biz_id", "app_id", "version_code", "unix",
        "timezone_offset", "is_desktop", "desktop_version", "sys_language",
        "lang", "uuid", "device_id", "os_name", "browser_name", "device_memory",
        "cpu_core_num", "browser_language", "browser_platform", "user_id",
        "op_ticket", "screen_width", "screen_height",
    ]

    # 设备身份：与具体机器绑定，**不写死在代码里**。
    # 首选从桌面客户端请求日志自动发现（_discover_client_params，随客户端升级自适应）；
    # 读不到日志时可用环境变量 MINIMAX_UUID / MINIMAX_DEVICE_ID 覆盖。
    DEFAULT_UUID = os.environ.get("MINIMAX_UUID", "").strip()
    DEFAULT_DEVICE_ID = os.environ.get("MINIMAX_DEVICE_ID", "").strip()
    DEFAULT_DESKTOP_VERSION = "3.1.4"
    DEFAULT_VERSION_CODE = "22201"

    # 客户端请求日志目录（用于自动发现 device_id / desktop_version 等参数）
    CLIENT_LOG_DIRS = [
        os.path.join(os.environ.get("APPDATA", ""), "MiniMax", "logs"),
    ]

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.token = None
        self.token_kind = ""          # "oauth" | "jwt"
        self.cn_config = self._load_cn_config()
        self.device_params = None     # 客户端实测参数（惰性发现）
        # 注意：签到请求的 device_id 取自客户端真实请求日志，与 cn-config 的
        # USER_HARD_WARE_INFO 不同，优先使用客户端日志发现值
        self.user_id = str(self.cn_config.get("realUserID") or "")

    def _log(self, msg: str, level: str = "INFO") -> None:
        """输出诊断信息（本仓库无统一日志模块，沿用框架的 print 风格）"""
        try:
            print(f"[{self.PLATFORM_NAME}] {msg}")
        except Exception:  # noqa: BLE001
            pass

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

    def _load_jwt(self) -> str:
        """提取旧 JWT 登录态（local-runtime.auth.json 的 auth.accessToken）"""
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    # 优先 auth.accessToken（JWT）
                    auth = data.get("auth") or {}
                    if auth.get("accessToken"):
                        return str(auth["accessToken"])
                except Exception:  # noqa: BLE001
                    continue
        return ""

    # ---------- OAuth 凭据（现行链路） ----------

    def _read_oauth_credential(self) -> dict:
        """读取桌面端 OAuth 凭据记录（含 refreshToken）"""
        path = self.OAUTH_CRED_FILE
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:  # noqa: BLE001
            return {}
        for _key, rec in (payload.get("records") or {}).items():
            if isinstance(rec, dict) and rec.get("accessToken") and rec.get("refreshToken"):
                out = dict(rec)
                out["_key"] = _key
                return out
        return {}

    def _oauth_access_token(self, force_refresh: bool = False) -> str:
        """取可用 access_token；过期或临期则自动刷新并写回磁盘"""
        cred = self._read_oauth_credential()
        if not cred:
            return ""
        exp_ms = cred.get("expiresAtMs") or 0
        fresh = (exp_ms / 1000 - time.time()) > self.OAUTH_REFRESH_MARGIN_S
        if fresh and not force_refresh:
            return str(cred["accessToken"])

        new_cred = self._refresh_oauth(cred)
        if new_cred:
            return str(new_cred.get("accessToken") or "")
        # 刷新失败：若原 token 尚未过期就继续用它
        if exp_ms / 1000 > time.time():
            return str(cred["accessToken"])
        return ""

    def _refresh_oauth(self, cred: dict) -> dict:
        """用 refresh_token 换新 access_token，并写回 auth.json / auth-state.json"""
        form = {
            "grant_type": "refresh_token",
            "refresh_token": cred.get("refreshToken") or "",
            "client_id": self.OAUTH_CLIENT_ID,
            "scope": self.OAUTH_SCOPE,
            "audience": self.OAUTH_AUDIENCE,
        }
        req = urllib.request.Request(
            self.OAUTH_TOKEN_URL,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            headers={"Accept": "application/json",
                     "Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read().decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                data = {}
            self._log(f"OAuth 刷新失败 HTTP {e.code}: {json.dumps(data, ensure_ascii=False)[:200]}")
            return {}
        except Exception as e:  # noqa: BLE001
            self._log(f"OAuth 刷新异常: {e}")
            return {}

        access_token = str(data.get("access_token") or "")
        if not access_token:
            self._log(f"OAuth 刷新未返回 access_token: {json.dumps(data, ensure_ascii=False)[:200]}")
            return {}

        new_cred = {
            "accessToken": access_token,
            # 服务端会轮换 refresh_token；旧 token 仍可用，这里保留新值
            "refreshToken": str(data.get("refresh_token") or cred.get("refreshToken") or ""),
            "expiresAtMs": int(time.time() * 1000) + int(data.get("expires_in") or 3600) * 1000,
            "generation": int(cred.get("generation") or 0) + 1,
        }
        try:
            self._persist_oauth_credential(cred, new_cred)
        except Exception as e:  # noqa: BLE001
            self._log(f"OAuth 凭据写回失败（不影响本次签到）: {e}")
        return new_cred

    def _persist_oauth_credential(self, old_cred: dict, new_cred: dict) -> None:
        """在跨进程锁内更新 auth.json 与 auth-state.json（generation 必须同步）"""
        with self._auth_lock():
            with open(self.OAUTH_CRED_FILE, "r", encoding="utf-8") as f:
                payload = json.load(f)
            records = payload.get("records") or {}
            key = old_cred.get("_key")
            target = None
            for k, rec in records.items():
                if k == key or (isinstance(rec, dict) and rec.get("accessToken")):
                    target = rec
                    break
            if target is None:
                return
            target["accessToken"] = new_cred["accessToken"]
            target["refreshToken"] = new_cred["refreshToken"]
            target["expiresAtMs"] = new_cred["expiresAtMs"]
            target["generation"] = new_cred["generation"]
            self._atomic_write(self.OAUTH_CRED_FILE,
                               json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

            if os.path.isfile(self.OAUTH_STATE_FILE):
                with open(self.OAUTH_STATE_FILE, "r", encoding="utf-8") as f:
                    state = json.load(f)
                state["status"] = "authenticated"
                state["generation"] = new_cred["generation"]
                state["expiresAtMs"] = new_cred["expiresAtMs"]
                self._atomic_write(self.OAUTH_STATE_FILE,
                                   json.dumps(state, ensure_ascii=False, indent=2) + "\n")

    class _AuthLock:
        """兼容桌面端 proper-lockfile 的跨进程锁（<file>.lock 目录 + 30s stale）"""

        def __init__(self, lock_path: str, stale_ms: int):
            self.lock_dir = lock_path + ".lock"
            self.stale_ms = stale_ms
            self.acquired = False

        def __enter__(self):
            deadline = time.time() + 20
            while True:
                try:
                    os.mkdir(self.lock_dir)
                    self.acquired = True
                    return self
                except FileExistsError:
                    try:
                        age_ms = (time.time() - os.stat(self.lock_dir).st_mtime) * 1000
                    except OSError:
                        age_ms = 0
                    if age_ms > self.stale_ms:
                        shutil.rmtree(self.lock_dir, ignore_errors=True)
                        continue
                    if time.time() > deadline:
                        raise TimeoutError("获取 MiniMax 凭据锁超时（桌面端可能正在刷新）")
                    time.sleep(0.25)
                except Exception:  # noqa: BLE001
                    raise

        def __exit__(self, *exc):
            if self.acquired:
                try:
                    os.rmdir(self.lock_dir)
                except OSError:
                    pass
            return False

    def _auth_lock(self):
        return self._AuthLock(self.OAUTH_LOCK_FILE, self.OAUTH_LOCK_STALE_MS)

    @staticmethod
    def _atomic_write(path: str, text: str) -> None:
        tmp = path + ".tmp-checkin"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ---------- 设备参数自动发现（跟随客户端升级） ----------

    def _discover_client_params(self) -> dict:
        """从客户端最新请求日志解析真实 device_id / uuid / desktop_version 等"""
        if self.device_params is not None:
            return self.device_params
        params = {}
        for log_dir in self.CLIENT_LOG_DIRS:
            if not log_dir or not os.path.isdir(log_dir):
                continue
            try:
                files = sorted(
                    (os.path.join(log_dir, n) for n in os.listdir(log_dir)
                     if n.startswith("api-") and n.endswith(".log")),
                    key=lambda p: os.path.getmtime(p), reverse=True)
            except Exception:  # noqa: BLE001
                continue
            for path in files:
                try:
                    size = os.path.getsize(path)
                    with open(path, "rb") as f:
                        f.seek(max(0, size - 400_000))
                        tail = f.read().decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    continue
                for line in reversed(tail.split("\n")):
                    m = re.search(r"agent\.minimax\.cn/[^?\s]+\?(\S+)", line)
                    if not m:
                        continue
                    q = urllib.parse.parse_qs(m.group(1))
                    got = {k: (v[0] if v else "") for k, v in q.items()}
                    if not got.get("device_id"):
                        continue
                    params = {
                        "uuid": got.get("uuid") or self.DEFAULT_UUID,
                        "device_id": got.get("device_id") or self.DEFAULT_DEVICE_ID,
                        "desktop_version": got.get("desktop_version") or self.DEFAULT_DESKTOP_VERSION,
                        "version_code": got.get("version_code") or self.DEFAULT_VERSION_CODE,
                        "user_id": got.get("user_id") or self.user_id,
                    }
                    break
                if params:
                    break
            if params:
                break

        self.device_params = params or {
            "uuid": self.DEFAULT_UUID,
            "device_id": self.DEFAULT_DEVICE_ID,
            "desktop_version": self.DEFAULT_DESKTOP_VERSION,
            "version_code": self.DEFAULT_VERSION_CODE,
            "user_id": self.user_id,
        }
        if not self.device_params.get("device_id"):
            self._log("未找到客户端设备参数（device_id 为空）：请确认已安装并登录 MiniMax Code "
                      "客户端且产生了请求日志，或设置环境变量 MINIMAX_DEVICE_ID / MINIMAX_UUID",
                      "WARN")
        return self.device_params

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
        client = self._discover_client_params()
        values = {
            "device_platform": "web",
            "biz_id": "3",
            "app_id": "3001",
            "version_code": client.get("version_code") or self.DEFAULT_VERSION_CODE,
            "unix": str(now_ms),
            "timezone_offset": "28800",
            "is_desktop": "1",
            "desktop_version": client.get("desktop_version") or self.DEFAULT_DESKTOP_VERSION,
            "sys_language": "zh",
            "lang": "zh",
            "uuid": client.get("uuid") or self.DEFAULT_UUID,
            "device_id": client.get("device_id") or self.DEFAULT_DEVICE_ID,
            "os_name": "Windows",
            "browser_name": "Chrome",
            "device_memory": "16",
            "cpu_core_num": "4",
            "browser_language": "zh-CN",
            "browser_platform": "Win32",
            "user_id": client.get("user_id") or self.user_id,
            "op_ticket": "undefined",
            "screen_width": "1366",
            "screen_height": "768",
        }
        return {k: values[k] for k in self.DEVICE_PARAM_ORDER}

    def _sign_request(self, path: str, token: str, method: str, body: dict,
                      bearer: str = ""):
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
            "yy": yy,
            "x-timestamp": str(now_sec),
            "x-signature": x_signature,
            "origin": "https://agent.minimax.cn",
            "referer": "https://agent.minimax.cn/",
            "accept": "application/json, text/plain, */*",
            "user-agent": ("MiniMaxAgent Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.280 "
                           "Safari/537.36 MiniMax/3.1.4"),
        }
        # 现行链路：OAuth Bearer；旧链路：token 头
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        if token:
            headers["token"] = token
        if method.upper() != "GET":
            headers["content-type"] = "application/json"

        url = f"{path}?{query}"
        return url, headers, body_str

    # ---------- 网络请求 ----------

    def _api_call(self, host: str, token: str, path: str, method: str, body: dict,
                  timeout: int = 30, bearer: str = ""):
        """带签名调用接口，返回 (http_status, json)"""
        url, headers, body_str = self._sign_request(path, token, method, body, bearer=bearer)
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
        """旧链路续期：换新 JWT（有效期约 40 天）"""
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

    def _prepare_auth(self):
        """准备鉴权：优先 OAuth Bearer（现行），回退旧 JWT"""
        access = self._oauth_access_token()
        if access:
            self.token = ""
            self.token_kind = "oauth"
            return access
        jwt = self._load_jwt()
        if jwt:
            self.token = jwt
            self.token_kind = "jwt"
            return ""
        self.token = ""
        self.token_kind = ""
        return ""

    def checkin(self) -> dict:
        bearer = self._prepare_auth()
        if not bearer and not self.token:
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
                return self._checkin_host(host, bearer)
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

    def _checkin_host(self, host: str, bearer: str) -> dict:
        token = self.token

        # 1) 旧链路：先续期换新 JWT（仅 JWT 模式）
        if not bearer and token:
            new_token = self._renew(host, token)
            if new_token:
                token = new_token
                self._persist_jwt(new_token)

        # 2) 状态查询（只读）
        sc, sb = self._api_call(host, token, self.STATUS_PATH, "GET", {}, bearer=bearer)
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
        cc, cb = self._api_call(host, token, self.CLAIM_PATH, "POST", {}, bearer=bearer)
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

    def _persist_jwt(self, new_jwt: str) -> None:
        """把续期得到的新 JWT 写回 local-runtime.auth.json（避免 40 天后必然过期）"""
        path = os.path.join(os.path.expanduser("~"), ".minimax", "local-runtime.auth.json")
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            auth = data.get("auth")
            if not isinstance(auth, dict) or not auth.get("accessToken"):
                return
            if auth.get("accessToken") == new_jwt:
                return
            auth["accessToken"] = new_jwt
            self._atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            self._log("已将续期后的 JWT 写回 local-runtime.auth.json")
        except Exception as e:  # noqa: BLE001
            self._log(f"JWT 写回失败（不影响本次签到）: {e}")

    # ---------- 账户总余额 ----------

    def balance(self) -> dict:
        """查询 MiniMax Code 侧边栏"积分"（OP 积分，与客户端显示一致）

        主接口：POST agent.minimax.cn/matrix/api/v1/commerce/get_membership_info
          带签名头 + Authorization: Bearer <OAuth token>
          响应 op_credit_summary.total_remaining_amount（如 "17357.397"）
          —— 2026-10-07 实测与客户端侧边栏"积分 17,357"完全吻合。
        备接口：GET www.minimaxi.com/backend/account/token_plan_credit
          按 token 计费（无积分包）的账户三项均为 0，仅作回退。
        """
        bearer = self._oauth_access_token()
        token = "" if bearer else self._load_jwt()
        if not bearer and not token:
            return {"available": False, "total": None, "remain": None, "used": None}

        # 主路径：会员信息（OP 积分，侧边栏口径）
        try:
            url, headers, body_str = self._sign_request(
                self.MEMBERSHIP_PATH, token, "POST", {}, bearer=bearer)
            headers["Origin"] = self.MEMBERSHIP_HOST
            headers["Referer"] = self.MEMBERSHIP_HOST + "/"
            req = urllib.request.Request(
                self.MEMBERSHIP_HOST + url, data=body_str.encode("utf-8"),
                headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            base = data.get("base_resp") or {}
            if isinstance(base, dict) and base.get("status_code") == 0:
                ocs = data.get("op_credit_summary") or {}
                remain_raw = ocs.get("total_remaining_amount")
                if remain_raw is not None:
                    remain = float(str(remain_raw))
                    purchased = ocs.get("purchased_remaining_amount")
                    purchased_f = float(str(purchased)) if purchased is not None else None
                    note = ""
                    if purchased_f and purchased_f > 0:
                        note += "（含购买 + 赠送）"
                    return {
                        "available": True,
                        "total": remain,
                        "remain": remain,
                        "used": purchased_f,
                        "note": note,
                    }
        except Exception:  # noqa: BLE001
            pass  # 回退到 token_plan_credit

        # 备路径：API 计费中心（token_plan_credit）——需账号级 GroupId，
        # 未设置环境变量 MINIMAX_GROUP_ID 时跳过（按 token 计费的账户该接口本就恒为 0）
        if not self.GROUP_ID:
            return {"available": False, "total": None, "remain": None, "used": None}
        try:
            req = urllib.request.Request(
                self.BALANCE_HOST + self.BALANCE_PATH, method="GET", headers={
                    "X-Group-Id": self.GROUP_ID,
                    "Token": token or bearer,
                    "User-Agent": self._sign_request("", "", "GET", {})[1]["user-agent"],
                    "Origin": "https://www.minimaxi.com",
                    "Referer": "https://www.minimaxi.com/",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None, "remain": None, "used": None}

        base = data.get("base_resp") or {}
        if not (isinstance(base, dict) and base.get("status_code") == 0):
            return {"available": False, "total": None, "remain": None, "used": None}
        total = data.get("total_credits")
        used = data.get("used_credits")
        remain = data.get("remaining_credits")
        if total is None and remain is None:
            return {"available": False, "total": None, "remain": None, "used": None}
        return {
            "available": True,
            "total": float(total or 0),
            "remain": float(remain) if remain is not None else None,
            "used": float(used) if used is not None else None,
            "note": "积分包额度" if (total or 0) > 0 else "按 token 计费（无积分包）",
        }

    # ---------- 账户总积分 ----------

    def total(self) -> dict:
        """MiniMax Code 账户剩余可用积分（与 balance() 同口径：OP 积分）"""
        bal = self.balance()
        if bal.get("available") and bal.get("remain") is not None:
            return {
                "available": True,
                "total": bal["remain"],
                "note": bal.get("note", ""),
            }
        return {"available": False, "total": None}

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        """检查鉴权链路：OAuth 凭据有效性 / 旧 JWT 是否可续期"""
        cred = self._read_oauth_credential()
        if cred:
            exp_ms = cred.get("expiresAtMs") or 0
            left_s = int(exp_ms / 1000 - time.time())
            try:
                with self._auth_lock():
                    pass
                lock_ok = True
            except Exception:  # noqa: BLE001
                lock_ok = False
            return {
                "platform": self.PLATFORM_NAME,
                "status": "ok",
                "days_left": max(left_s // 86400, 0),
                "message": (f"OAuth 凭据正常（access_token 剩余 {max(left_s // 60, 0)} 分钟，"
                            f"脚本可自动续期{'，桌面端锁可用' if lock_ok else ''}）"),
            }

        jwt = self._load_jwt()
        if not jwt:
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": "无法读取登录态：请打开 MiniMax Code 客户端登录一次",
            }
        for host in self.HOSTS:
            try:
                new_token = self._renew(host, jwt)
                if new_token:
                    self._persist_jwt(new_token)
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
