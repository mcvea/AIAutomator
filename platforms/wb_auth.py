# -*- coding: utf-8 -*-
"""
WorkBuddy 多账号凭据存储与 Token 自动续期模块

职责：
1. 凭据文件读写：auths/workbuddy-<uid>.json（嵌套格式，与社区项目
   Maquer/workbuddy-checkin、chevy222/workbuddy-cf-checkin 完全兼容）：
       {
         "auth":    {"accessToken": "", "refreshToken": "",
                     "expiresAt": <秒>, "domain": ""},
         "account": {"uid": "", "enterpriseId": "", "nickname": ""},
         "disabled": false
       }
   注意：本格式 expiresAt 为「秒」（社区口径）；桌面客户端登录态文件为「毫秒」，
   两处格式由 platforms/workbuddy.py::_expires_at_ms() 统一归一化。

2. Token 自动续期：POST {copilot.tencent.com | workbuddy.ai}/v2/plugin/auth/token/refresh
   请求头 X-Refresh-Token + X-Auth-Refresh-Source: workbuddy（社区验证口径），
   响应 data.{accessToken, refreshToken, domain, expiresIn}；refreshToken 轮换，
   新凭据原子写回（临时文件 + os.replace）。执行前建议用 is_expiring() 判断
   是否临近过期（默认剩余 <5 天预刷新）。
   接口事实来源：cpa-plugin/workbuddy（billing.go + keepalive.go）逆向口径，
   经 Maquer/workbuddy-checkin 与 chevy222/workbuddy-cf-checkin 交叉验证。

3. 短信登录取凭据（新增账号用）：
   - 发送验证码：POST https://www.workbuddy.cn/v2/plugin/login/send-sms
                 body {"phone": "..."}
   - 验证码登录：POST https://www.workbuddy.cn/v2/plugin/login/token
                 body {"login_method": "phone", "phone": "...", "sms_code": "..."}
                 → data.{accessToken, refreshToken, expiresIn, domain}，
                   uid/昵称/企业ID 从 JWT claims 解析（sub/nickname/enterpriseId）。

安全约定（与项目既有教义一致）：
- Token 绝不打印、绝不写日志；CLI 展示一律走 mask_uid()/summary 脱敏。
- auths/ 目录含等同账号密码的凭据，必须在 .gitignore 中排除（已配置）。
- 全部请求直连官方域名，不经过任何第三方。
"""
import base64
import glob
import json
import os
import re
import time
import urllib.error
import urllib.request

# 项目根目录（本文件位于 <项目根>/platforms/ 下）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 凭据目录：默认 <项目根>/auths/，可用环境变量 WB_AUTHS_DIR 覆盖
_ENV_AUTHS_DIR = "WB_AUTHS_DIR"

# 模拟官方插件客户端（与社区实现同款 UA）
CLIENT_UA = "CLI/2.63.2 CodeBuddy/2.63.2"

# Token 续期端点（国内版 copilot 网关 / 国际版）
REFRESH_URL_CN = "https://copilot.tencent.com/v2/plugin/auth/token/refresh"
REFRESH_URL_GLOBAL = "https://www.workbuddy.ai/v2/plugin/auth/token/refresh"

# 短信登录端点（国内版）
SMS_SEND_URL = "https://www.workbuddy.cn/v2/plugin/login/send-sms"
SMS_LOGIN_URL = "https://www.workbuddy.cn/v2/plugin/login/token"

# 会话彻底失效的响应标记（keepalive.go sessionDeadMarkers 同款）
SESSION_DEAD_MARKERS = ("Offline user session not found", "12153")

# 过期前预刷新余量（社区实践：5 天）
REFRESH_MARGIN_SEC = 5 * 86400

# HTTP 超时
HTTP_TIMEOUT = 30


# ---------- 目录与文件 ----------

# 多账号是**可选功能**：默认由「凭据库里有没有凭据」决定——
# 有凭据则逐账号签到，没有则回退桌面客户端单账号模式。
# 需要强制单账号（或强制多账号）时用环境变量显式指定：
#   AI_CHECKIN_MULTI_ACCOUNT=0 → 强制单账号（忽略凭据库）
#   AI_CHECKIN_MULTI_ACCOUNT=1 → 强制多账号（凭据库为空时仍回退单账号）
MULTI_ACCOUNT_ENV = "AI_CHECKIN_MULTI_ACCOUNT"


def multi_account_enabled(default: bool = True) -> bool:
    """多账号是否启用；未设置环境变量时沿用 default"""
    raw = os.environ.get(MULTI_ACCOUNT_ENV, "").strip().lower()
    if raw in ("0", "false", "off", "no"):
        return False
    if raw in ("1", "true", "on", "yes"):
        return True
    return default


def auths_dir() -> str:
    """凭据目录路径（默认 <项目根>/auths/，WB_AUTHS_DIR 可覆盖）"""
    override = os.environ.get(_ENV_AUTHS_DIR)
    if override:
        return override
    return os.path.join(_PROJECT_ROOT, "auths")


def account_path_for(uid: str) -> str:
    """账号凭据文件路径：auths/workbuddy-<uid>.json"""
    safe = re.sub(r"[^0-9A-Za-z_.-]", "_", str(uid or "")).strip("_") or "unknown"
    return os.path.join(auths_dir(), f"workbuddy-{safe}.json")


def list_account_files() -> list:
    """凭据目录下全部 workbuddy-*.json（按文件名排序）"""
    files = sorted(glob.glob(os.path.join(auths_dir(), "workbuddy-*.json")))
    return [f for f in files if not f.endswith(".tmp")]


def load_account(path: str) -> dict:
    """读取凭据文件；兼容嵌套形（社区/本项目）与扁平形（UI 导入）两种结构"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("凭据文件格式错误：根节点不是 JSON 对象")
    if isinstance(data.get("auth"), dict) and data["auth"].get("accessToken"):
        return data
    if data.get("accessToken"):
        return {
            "auth": {
                "accessToken": data.get("accessToken", ""),
                "refreshToken": data.get("refreshToken", ""),
                "expiresAt": data.get("expiresAt", 0),
                "domain": data.get("domain", ""),
            },
            "account": {
                "uid": data.get("uid", ""),
                "enterpriseId": data.get("enterpriseId", ""),
                "nickname": data.get("nickname", ""),
            },
            "disabled": bool(data.get("disabled", False)),
        }
    raise ValueError("凭据文件缺少 accessToken")


def save_account(path: str, data: dict):
    """原子写回凭据文件（临时文件 + fsync + os.replace，防写坏）"""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------- 账号一览（供调度器/CLI 展示，不含敏感字段） ----------

def _uid_from_filename(path: str) -> str:
    m = re.search(r"workbuddy-(.+)\.json$", os.path.basename(path))
    return m.group(1) if m else ""


def _label_for(uid: str, nickname: str, path: str) -> str:
    """账号展示名：昵称 > UID 尾号 > 文件名"""
    if nickname:
        return nickname
    if uid:
        return f"…{uid[-6:]}"
    stem = re.sub(r"^workbuddy-?", "", os.path.splitext(os.path.basename(path))[0])
    return stem or "账号"


def list_accounts() -> list:
    """扫描凭据目录，返回 [{path, uid, nickname, label, disabled}]（不含 token）"""
    out = []
    for path in list_account_files():
        entry = {"path": path, "uid": "", "nickname": "", "label": "", "disabled": False}
        try:
            data = load_account(path)
            auth = data.get("auth") or {}
            acct = data.get("account") or {}
            entry["uid"] = acct.get("uid") or _uid_from_filename(path)
            entry["nickname"] = acct.get("nickname") or ""
            entry["disabled"] = bool(data.get("disabled"))
        except Exception:  # noqa: BLE001 - 坏文件也列出，运行期会给出明确错误
            entry["uid"] = _uid_from_filename(path)
        entry["label"] = _label_for(entry["uid"], entry["nickname"], path)
        out.append(entry)

    # 去重展示名（同昵称时补 UID 尾号，避免日报行无法区分）
    seen = {}
    for e in out:
        seen[e["label"]] = seen.get(e["label"], 0) + 1
    for e in out:
        if seen[e["label"]] > 1 and e["uid"]:
            e["label"] = f"{e['label']}·{e['uid'][-4:]}"
    return out


# ---------- 时间与脱敏工具 ----------

def _expires_at_sec(data: dict) -> float:
    """归一化到期时间到「秒」：>=1e12 视为毫秒（桌面客户端口径），否则为秒"""
    v = (data.get("auth") or {}).get("expiresAt")
    if not v:
        return 0.0
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0.0
    return v / 1000.0 if v >= 1e12 else v


def is_expiring(data: dict, margin_sec: int | None = None) -> bool:
    """accessToken 是否临近/已经过期（默认 <5 天），需要预刷新"""
    exp = _expires_at_sec(data)
    if not exp:
        return False
    return time.time() + (margin_sec if margin_sec else REFRESH_MARGIN_SEC) > exp


def is_expired(data: dict) -> bool:
    exp = _expires_at_sec(data)
    return bool(exp) and time.time() > exp


def days_left(data: dict) -> int | None:
    """accessToken 剩余天数；无到期信息返回 None"""
    exp = _expires_at_sec(data)
    if not exp:
        return None
    return max(0, int((exp - time.time()) / 86400))


def mask_uid(uid: str) -> str:
    uid = str(uid or "")
    if len(uid) <= 6:
        return uid or "(未知)"
    return "…" + uid[-6:]


def mask_phone(phone: str) -> str:
    phone = str(phone or "")
    if len(phone) >= 7:
        return phone[:3] + "****" + phone[-4:]
    return "***"


def jwt_claims(token: str) -> dict:
    """解析 JWT payload（不校验签名，仅取 claims 供展示/入档）"""
    try:
        parts = str(token).split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1].replace("-", "+").replace("_", "/")
        payload += "=" * ((4 - len(payload) % 4) % 4)
        raw = base64.b64decode(payload)
        claims = json.loads(raw.decode("utf-8", errors="replace"))
        return claims if isinstance(claims, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


# ---------- HTTP ----------

def http_json(method: str, url: str, headers: dict | None = None,
              payload=None, timeout: int = HTTP_TIMEOUT):
    """请求 JSON 接口，统一返回 (status, body_or_None, error_text)

    - 正常与 HTTPError 均尽力解析 JSON 响应体（网关会把业务错误包成 4xx）
    - 网络异常返回 (-1, None, 描述)
    """
    h = {"Accept": "application/json", "User-Agent": CLIENT_UA}
    if headers:
        h.update(headers)
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw:
                return resp.status, {}, ""
            try:
                return resp.status, json.loads(raw), ""
            except json.JSONDecodeError:
                return resp.status, None, f"响应非 JSON: {raw[:200]}"
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw), ""
        except json.JSONDecodeError:
            return e.code, None, f"HTTP {e.code}: {raw[:200]}"
    except Exception as e:  # noqa: BLE001
        return -1, None, f"网络异常: {e}"


def _is_session_dead(text: str) -> bool:
    return any(m in (text or "") for m in SESSION_DEAD_MARKERS)


def _envelope_code_msg(body, err: str):
    """从 {code, msg, data} 信封中取 (code, msg)；无信封时返回 (None, err)"""
    if isinstance(body, dict) and "code" in body:
        return body.get("code"), str(body.get("msg") or "")
    return None, err


# ---------- Token 自动续期 ----------

def refresh_account(path: str, data: dict | None = None, dry: bool = False):
    """刷新账号 Token（refreshToken 轮换并原子写回）。

    返回 (ok, message)。dry=True 时跳过（只读模式零副作用）。
    会话彻底失效（12153 / Offline user session not found）时在凭据文件中
    标记 disabled=true 并附 note，后续运行会提示重新登录。
    """
    if dry:
        return False, "只读模式跳过续期"
    if data is None:
        data = load_account(path)
    auth = data.get("auth") or {}
    rt = auth.get("refreshToken") or ""
    if not rt:
        return False, "凭据缺少 refreshToken，无法自动续期"

    domain = str(auth.get("domain") or "").lower()
    host = domain.split(":")[0]
    url = (REFRESH_URL_GLOBAL
           if host == "workbuddy.ai" or host.endswith(".workbuddy.ai")
           else REFRESH_URL_CN)
    headers = {
        "X-Refresh-Token": rt,
        "X-Auth-Refresh-Source": "workbuddy",
    }
    acct = data.get("account") or {}
    if acct.get("enterpriseId"):
        headers["X-Enterprise-Id"] = acct["enterpriseId"]

    status, body, err = http_json("POST", url, headers=headers, payload={})

    # 会话失效判定：响应中带 12153 / Offline user session not found
    probe = err or json.dumps(body, ensure_ascii=False)[:400]
    if _is_session_dead(probe):
        data["disabled"] = True
        data["note"] = "Session dead (12153), re-login required"
        try:
            save_account(path, data)
        except Exception:  # noqa: BLE001 - 标记失败不掩盖主错误
            pass
        return False, "登录会话已失效（12153），请重新登录（wb_accounts.py add）"

    if body is None:
        return False, f"续期失败：{err or '空响应'}"

    code, msg = _envelope_code_msg(body, err)
    if code is None and err:
        return False, f"续期失败：{err}"
    if code not in (0, None):
        return False, f"续期失败：code={code} {msg}".strip()

    d = body.get("data") or {}
    new_at = d.get("accessToken") or ""
    if not new_at:
        return False, "续期响应缺少 accessToken"

    auth["accessToken"] = new_at
    if d.get("refreshToken"):
        auth["refreshToken"] = d["refreshToken"]
    if d.get("domain"):
        auth["domain"] = str(d["domain"])
    exp_in = d.get("expiresIn") or 0
    if exp_in:
        try:
            auth["expiresAt"] = int(time.time()) + int(exp_in)
        except (TypeError, ValueError):
            pass
    data["auth"] = auth
    data["disabled"] = False
    data.pop("note", None)
    save_account(path, data)
    return True, "Token 已自动续期"


# ---------- 短信登录（新增账号） ----------

def sms_send_code(phone: str):
    """发送短信验证码，返回 (ok, message)"""
    phone = str(phone or "").strip()
    if not phone:
        return False, "手机号为空"
    status, body, err = http_json("POST", SMS_SEND_URL, payload={"phone": phone})
    if body is None:
        return False, f"验证码发送失败：{err or f'HTTP {status}'}"
    code, msg = _envelope_code_msg(body, err)
    if code == 0:
        return True, f"验证码已发送至 {mask_phone(phone)}（约 5 分钟内有效）"
    return False, f"验证码发送失败：code={code} {msg}".strip()


def sms_login(phone: str, sms_code: str):
    """验证码登录，返回 (credential_dict, error_message)

    credential_dict 即 auths/workbuddy-<uid>.json 的完整内容（含明文凭据）；
    注意：绝不可打印该结构。
    """
    phone = str(phone or "").strip()
    sms_code = str(sms_code or "").strip()
    if not (phone and sms_code):
        return None, "手机号或验证码为空"
    payload = {"login_method": "phone", "phone": phone, "sms_code": sms_code}
    status, body, err = http_json("POST", SMS_LOGIN_URL, payload=payload)
    if body is None:
        return None, f"登录失败：{err or f'HTTP {status}'}"
    code, msg = _envelope_code_msg(body, err)
    if code not in (0, None):
        return None, f"登录失败：code={code} {msg}".strip()

    d = body.get("data") or {}
    at = d.get("accessToken") or ""
    rt = d.get("refreshToken") or ""
    if not at:
        return None, "登录响应缺少 accessToken"
    claims = jwt_claims(at)
    uid = claims.get("uid") or claims.get("sub") or ""
    enterprise = claims.get("enterpriseId") or d.get("enterpriseId") or ""
    nickname = claims.get("nickname") or claims.get("name") or ""
    domain = str(d.get("domain") or "www.workbuddy.cn")
    exp_in = d.get("expiresIn") or 0
    try:
        expires_at = int(time.time()) + int(exp_in) if exp_in else 0
    except (TypeError, ValueError):
        expires_at = 0

    cred = {
        "auth": {
            "accessToken": at,
            "refreshToken": rt,
            "expiresAt": expires_at,
            "domain": domain,
        },
        "account": {
            "uid": str(uid),
            "enterpriseId": str(enterprise),
            "nickname": str(nickname),
        },
        "disabled": False,
    }
    return cred, ""
