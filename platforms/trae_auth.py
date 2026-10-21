# -*- coding: utf-8 -*-
"""
TraeWork 多账号凭据存储 / Token 自动续期 / 登录取凭据模块

职责：
1. 凭据文件读写：auths/traework-<uid>.json（嵌套格式）：
       {
         "auth": {
           "accessToken": "", "refreshToken": "",
           "expiresAt": <秒>, "refreshExpiresAt": <秒>,
           "apiHost": "https://api.trae.cn",
           "deviceId": "", "machineId": "",
           "privateKeyPem": "", "publicKeyPem": "",
           "clientId": "en1oxy7wnw8j9n", "platform": "SOLO_PC",
           "appVersion": "1.107.1"
         },
         "account": {"uid": "", "nickname": ""},
         "disabled": false, "source": "desktop-import" | "browser-oauth"
       }
   说明：DeviceID / 设备密钥对（ECDSA P-256）续期时用于构造 DeviceProof 签名。
   设备来源：desktop-import 取本机客户端设备（storage.json 的
   iCubeAuthInfo://icube-dc:<id>，单账号适用）；browser-oauth 每账号生成
   全新独立设备——签到领取按设备维度限流（每设备每日一次），共享设备会触发
   "当前设备今日已经签到"拦截（详见 FAQ-0006）。

2. Token 自动续期（设备证明版 ExchangeToken）：
   POST {apiHost}/trae/api/v3/oauth/ExchangeToken
   canonical = "POST\n{path}\n{clientID}\n{refreshToken}\n{ts}\n{nonce}"，
   DeviceProof.Signature = 设备私钥 ECDSA P-256/SHA-256（低 s 归一化）。
   refreshToken 轮换，新凭据原子写回。注意：官方 RT 为轮换制，同一账号若在
   多处同时消费同一 RT（脚本 + 桌面客户端）可能互相失效，详见 FAQ-0006。

3. 两种凭据获取方式：
   a) 桌面导入 import/desktop_credential()：读本机 TraeWork 桌面端 storage.json
      中加密登录信封（iCubeAuthInfo://icube.cloudide，社区逆向的
      AES-128-CBC + SHA512 完整性校验格式，HEADER/SALT 与 traework.py 同源），
      解密得到 token/refreshToken/过期时间，直接生成凭据文件。
   b) 浏览器 OAuth 登录 login_via_browser()：官网真实网页登录流程（PKCE）——
      生成授权 URL（www.trae.cn/authorization）并打开浏览器，脚本在
      127.0.0.1:17388 接住回调 AuthCode，再调 ExchangeToken 兑换凭据。
      回调端口固定 17388（官网靠探测该端口判断"客户端在线"，被占时须先退出
      Trae 客户端）。AuthCode 兑换不需要设备私钥，只需设备身份里的公钥。

协议事实来源（社区逆向，2026-09 抓包固化，勿按语义改写）：
- L0NE-6/Trae-AutoCheckin 的 trae_sms_login.py（网页 OAuth）与 trae_get_token.py
  （桌面导入），经与生产 platforms/traework.py 既有续期口径交叉验证。

安全约定（与项目既有教义一致）：
- Token / 私钥绝不打印、绝不写日志；CLI 展示一律走 mask_uid() 脱敏。
- auths/ 目录含等同账号密码的凭据，必须在 .gitignore 中排除（已配置）。
- 全部请求直连官方域名，不经过任何第三方。
"""
import base64
import glob
import hashlib
import http.server
import json
import os
import platform
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
except ImportError:  # pragma: no cover
    AES = None

# 项目根目录（本文件位于 <项目根>/platforms/ 下）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 凭据目录：默认 <项目根>/auths/，可用环境变量 WB_AUTHS_DIR 覆盖（与 wb_auth 共用）
_ENV_AUTHS_DIR = "WB_AUTHS_DIR"

# ---------- 协议常量（社区抓包固化，勿改） ----------

CONSOLE_BASE = "https://www.trae.cn"        # 国内授权页域
ACCOUNT_BASE = "https://api.trae.cn"        # 兑换端点兜底 host
ICUBE_BASE = "https://api.trae.com.cn"      # 旧端点域
AUTHORIZE_PATH = "/authorization"
CALLBACK_PATH = "/authorize"
CALLBACK_PORT = 17388                        # ★ 必须固定（官网在线探测端口）
EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
LEGACY_EXCHANGE_PATH = "/cloudide/api/v3/trae/oauth/ExchangeToken"
OAUTH_APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"

# SOLO 线（与本机 TRAE SOLO CN 客户端及生产 traework.py 口径一致）
CLIENT_ID = "en1oxy7wnw8j9n"
PLATFORM_CODE = "SOLO_PC"
DEFAULT_HOST = ACCOUNT_BASE

# 续期请求声明的客户端版本（与生产 traework.py 既有口径一致）
REFRESH_APP_VERSION = "1.107.1"
# 浏览器登录流程声明的版本（社区默认值，可经环境变量覆盖）
LOGIN_APP_VERSION = os.environ.get("TRAE_APP_VERSION") or "3.3.100"
LOGIN_PLUGIN_VERSION = os.environ.get("TRAE_PLUGIN_VERSION") or "2.3.83560"

# 同步请求头版本（兑换时必须存在且为空串，缺了报 20403）
CALLBACK_LOGIN_TIMEOUT = 300

# 加密信封常量（社区逆向，与 traework.py 同源，勿改）
HEADER = bytes([116, 99, 5, 16, 0, 0])
LEFT_SECRET = bytes([
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
])
RIGHT_SECRET = bytes([
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
])
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"

# 过期前预刷新余量（2 天；RT 为轮换制，不宜过期后再补救）
REFRESH_MARGIN_SEC = 2 * 86400

# HTTP 超时
HTTP_TIMEOUT = 30


# ---------- 目录与文件 ----------

def auths_dir() -> str:
    """凭据目录路径（默认 <项目根>/auths/，WB_AUTHS_DIR 可覆盖）"""
    override = os.environ.get(_ENV_AUTHS_DIR)
    if override:
        return override
    return os.path.join(_PROJECT_ROOT, "auths")


def account_path_for(uid: str) -> str:
    """账号凭据文件路径：auths/traework-<uid>.json"""
    safe = re.sub(r"[^0-9A-Za-z_.-]", "_", str(uid or "")).strip("_") or "unknown"
    return os.path.join(auths_dir(), f"traework-{safe}.json")


def list_account_files() -> list:
    """凭据目录下全部 traework-*.json（按文件名排序）"""
    files = sorted(glob.glob(os.path.join(auths_dir(), "traework-*.json")))
    return [f for f in files if not f.endswith(".tmp")]


def load_account(path: str) -> dict:
    """读取凭据文件；兼容嵌套形（本项目）与扁平形（外部导入）两种结构"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("凭据文件格式错误：根节点不是 JSON 对象")
    if isinstance(data.get("auth"), dict) and data["auth"].get("accessToken"):
        data["auth"]["apiHost"] = normalize_api_host(data["auth"].get("apiHost"))
        return data
    if data.get("accessToken"):
        return {
            "auth": {
                "accessToken": data.get("accessToken", ""),
                "refreshToken": data.get("refreshToken", ""),
                "expiresAt": data.get("expiresAt", 0),
                "apiHost": normalize_api_host(data.get("host", "")),
                "deviceId": data.get("deviceId", ""),
                "machineId": data.get("machineId", ""),
                "privateKeyPem": data.get("privateKeyPem", ""),
                "publicKeyPem": data.get("publicKeyPem", ""),
                "clientId": data.get("clientId", CLIENT_ID),
                "platform": data.get("platform", PLATFORM_CODE),
                "appVersion": data.get("appVersion", REFRESH_APP_VERSION),
            },
            "account": {
                "uid": data.get("uid", ""),
                "nickname": data.get("name", "") or data.get("nickname", ""),
            },
            "disabled": bool(data.get("disabled", False)),
            "source": data.get("source", ""),
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


def _uid_from_filename(path: str) -> str:
    m = re.search(r"traework-(.+)\.json$", os.path.basename(path))
    return m.group(1) if m else ""


def _label_for(uid: str, nickname: str, path: str) -> str:
    """账号展示名：昵称 > UID 尾号 > 文件名"""
    if nickname:
        return nickname
    if uid:
        return f"…{uid[-6:]}"
    stem = re.sub(r"^traework-?", "", os.path.splitext(os.path.basename(path))[0])
    return stem or "账号"


def list_accounts() -> list:
    """扫描凭据目录，返回 [{path, uid, nickname, label, disabled}]（不含 token）"""
    out = []
    for path in list_account_files():
        entry = {"path": path, "uid": "", "nickname": "", "label": "", "disabled": False}
        try:
            data = load_account(path)
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
    """归一化到期时间到「秒」：>=1e12 视为毫秒，否则为秒"""
    v = (data.get("auth") or {}).get("expiresAt")
    return _to_epoch(v)


def _to_epoch(value) -> float:
    """把秒/毫秒/ISO 字符串（如 2026-10-30T00:49:53.853Z）统一为秒"""
    if not value:
        return 0.0
    try:
        if isinstance(value, (int, float)):
            v = float(value)
            return v / 1000.0 if v >= 1e12 else v
        s = str(value).strip()
        if re.fullmatch(r"\d+(\.\d+)?", s):
            v = float(s)
            return v / 1000.0 if v >= 1e12 else v
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (TypeError, ValueError):
        return 0.0


def is_expiring(data: dict, margin_sec: int | None = None) -> bool:
    """accessToken 是否临近/已经过期（默认 <2 天），需要预刷新"""
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


def refresh_days_left(data: dict) -> int | None:
    """refreshToken 剩余天数（refreshExpiresAt）；无信息返回 None"""
    v = (data.get("auth") or {}).get("refreshExpiresAt")
    exp = _to_epoch(v)
    if not exp:
        return None
    return max(0, int((exp - time.time()) / 86400))


def mask_uid(uid: str) -> str:
    uid = str(uid or "")
    if len(uid) <= 6:
        return uid or "(未知)"
    return "…" + uid[-6:]


# ---------- 主机归一化 ----------

def normalize_api_host(host: str) -> str:
    """签到 API 主机归一化：回调/授权域 api.trae.com.cn 不提供 v2 接口（404），
    统一映射到 api.trae.cn；空值回退 DEFAULT_HOST。"""
    h = str(host or "").strip().rstrip("/")
    if not h:
        return DEFAULT_HOST
    if h.endswith("trae.com.cn"):
        return DEFAULT_HOST
    return h


# ---------- 本机 storage.json 解密（与 traework.py 同源实现） ----------

def _capture_candidates():
    """客户端 storage.json 候选路径（Windows 优先，兼容少量其它平台）"""
    home = os.path.expanduser("~")
    ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    names = ("TRAE SOLO CN", "Trae CN", "TRAE SOLO", "Trae")
    sub = ("User", "globalStorage", "storage.json")
    out = [os.path.join(ad, n, *sub) for n in names]
    for base in (home, os.path.join(home, ".config")):
        for n in (".trae-cn", ".trae"):
            out.append(os.path.join(base, n, *sub))
    return out


def _locate_storage() -> str:
    for path in _capture_candidates():
        if path and os.path.isfile(path):
            return path
    raise FileNotFoundError("未找到 TraeWork 登录态，请先安装并登录 Trae 客户端一次")


def decrypt_storage_value(encoded: str) -> dict:
    """解密 TraeWork 加密信封（AES-128-CBC + SHA512 完整性校验），返回 JSON"""
    if AES is None:
        raise RuntimeError("缺少 pycryptodome 依赖，请执行: pip install pycryptodome")
    envelope = base64.b64decode(encoded)
    if len(envelope) <= 38 or envelope[:6] != HEADER:
        raise ValueError("TraeWork 加密信封格式不正确")
    random_key = envelope[6:38]
    secret = bytes(a ^ b for a, b in zip(LEFT_SECRET, RIGHT_SECRET))
    derived = hashlib.sha512(hashlib.sha512(random_key).digest() + secret).digest()
    key, iv = derived[:16], derived[16:32]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(envelope[38:]), 16)
    if len(plaintext) < 64:
        raise ValueError("解密内容过短")
    expected_digest, payload = plaintext[:64], plaintext[64:]
    if hashlib.sha512(payload).digest() != expected_digest:
        raise ValueError("TraeWork 登录态完整性校验失败")
    return json.loads(payload.decode("utf-8"))


def read_storage(storage_path: str | None = None):
    """读取本机 storage.json，返回 (path, storage_dict)"""
    path = storage_path or _locate_storage()
    with open(path, "r", encoding="utf-8") as f:
        return path, json.load(f)


# ---------- 设备身份 ----------

def device_identity(storage: dict | None = None, storage_path: str | None = None) -> dict | None:
    """取设备身份：device_id / machine_id / 密钥对。

    优先级：环境变量（TRAE_DEVICE_ID + TRAE_DEVICE_PUB_PEM [+ TRAE_DEVICE_KEY_PEM
    + TRAE_MACHINE_ID]） > 本机 storage.json 的 icube-dc 设备密钥。
    授权 URL 的 device_id 与兑换/续期请求体必须同源，所以只返回一份。
    """
    env_id = (os.environ.get("TRAE_DEVICE_ID") or "").strip()
    env_pub = (os.environ.get("TRAE_DEVICE_PUB_PEM") or "").replace("\\n", "\n").strip()
    if env_id and env_pub:
        return {
            "device_id": env_id,
            "machine_id": (os.environ.get("TRAE_MACHINE_ID") or "").strip(),
            "public_key_pem": env_pub,
            "private_key_pem": (os.environ.get("TRAE_DEVICE_KEY_PEM") or "")
            .replace("\\n", "\n").strip(),
            "from": "env",
        }

    if storage is None:
        try:
            _, storage = read_storage(storage_path)
        except Exception:  # noqa: BLE001
            return None

    device_id = ""
    for k in storage.keys():
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            did = k.split(":", 3)[-1]
            if did.isdigit():
                device_id = did
                break
    if not device_id:
        return None

    encrypted = storage.get(f"iCubeAuthInfo://icube-dc:{device_id}")
    if not encrypted:
        return None
    try:
        dev = decrypt_storage_value(encrypted)
    except Exception:  # noqa: BLE001
        return None
    pub = (dev.get("publicKeyPEM") or "").strip()
    if not pub:
        return None
    return {
        "device_id": device_id,
        "machine_id": str(storage.get("telemetry.machineId") or "").strip(),
        "public_key_pem": pub,
        "private_key_pem": (dev.get("privateKeyPEM") or "").strip(),
        "from": storage_path or "storage.json",
    }


def generate_device() -> dict | None:
    """生成全新设备身份（EC P-256 密钥对 + 随机 16 位 device_id）。

    浏览器 OAuth 添加账号默认使用：签到领取按设备维度限流（每设备每日
    一次），多账号共享客户端设备会触发"当前设备今日已经签到"拦截；
    每账号独立设备互不影响（详见 FAQ-0006）。
    """
    if ECC is None:
        return None
    key = ECC.generate(curve="P-256")
    priv_pem = key.export_key(format="PEM")
    pub_pem = key.public_key().export_key(format="PEM")
    device_id = str(secrets.randbelow(9 * 10 ** 15) + 10 ** 15)
    return {
        "device_id": device_id,
        "machine_id": "",
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem,
        "from": "generated",
    }


def machine_id_of(device: dict) -> str:
    """machineId 缺失时的兜底：由 device_id 派生一个稳定值（URL 与请求体同源）"""
    mid = (device.get("machine_id") or "").strip()
    if mid:
        return mid
    return hashlib.sha256(
        ("trae-oauth-machine:" + device["device_id"]).encode()).hexdigest()[:32]


def installed_plugin_version() -> str:
    """本机客户端插件版本（storage.json 的 iCubeLastVersion），读不到用社区兜底值"""
    if os.environ.get("TRAE_PLUGIN_VERSION"):
        return os.environ["TRAE_PLUGIN_VERSION"]
    try:
        _, storage = read_storage()
        v = str(storage.get("iCubeLastVersion") or "").strip()
        if v:
            return v
    except Exception:  # noqa: BLE001
        pass
    return LOGIN_PLUGIN_VERSION


def system_facts() -> dict:
    """客户端侧系统事实（授权 URL 与兑换请求体共用同一份）"""
    return {
        "os_name": platform.system() or "Windows",
        "os_version": platform.release() or "",
        "device_model": (os.environ.get("TRAE_DEVICE_MODEL") or "").strip(),
        "device_manufacturer": (os.environ.get("TRAE_DEVICE_BRAND") or "").strip(),
        "cpu_brand": (os.environ.get("TRAE_DEVICE_CPU") or "").strip()
        or (platform.processor() or ""),
        "device_name": (os.environ.get("TRAE_DEVICE_NAME") or "").strip()
        or (platform.node() or ""),
    }


# ---------- 设备证明签名（与 traework.py 同口径） ----------

_ECDSA_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def _der_encode_signature(r: int, s: int) -> bytes:
    def _enc(x):
        b = x.to_bytes(32, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b
    rb, sb = _enc(r), _enc(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body


def device_proof_sign(private_key_pem: str, data: bytes) -> str:
    """设备私钥 ECDSA P-256/SHA-256 签名，返回 base64(DER)，含低 s 归一化"""
    key = ECC.import_key(private_key_pem)
    signer = DSS.new(key, "fips-186-3", encoding="der")
    der = signer.sign(SHA256.new(data))
    idx = 2
    if der[1] & 0x80:
        idx += 1
    if der[idx] != 0x02:
        raise ValueError("Missing r integer")
    len_r = der[idx + 1]
    r = int.from_bytes(der[idx + 2:idx + 2 + len_r], "big")
    idx += 2 + len_r
    if der[idx] != 0x02:
        raise ValueError("Missing s integer")
    len_s = der[idx + 1]
    s = int.from_bytes(der[idx + 2:idx + 2 + len_s], "big")
    if s > _ECDSA_N // 2:
        s = _ECDSA_N - s
    return base64.b64encode(_der_encode_signature(r, s)).decode("utf-8")


# ---------- HTTP 基础 ----------

def _post_json(url: str, headers: dict, payload: dict, timeout: int = HTTP_TIMEOUT):
    """POST JSON，返回 (status, text)；网络异常返回 (-1, 描述)"""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return -1, f"网络异常: {e}"


def _jwt_payload(token: str) -> dict:
    """解析 JWT payload（不校验签名，仅取字段）；失败返回 {}"""
    try:
        parts = str(token).split(".")
        if len(parts) < 2:
            return {}
        p = parts[1].replace("-", "+").replace("_", "/")
        p += "=" * ((4 - len(p) % 4) % 4)
        claims = json.loads(base64.b64decode(p))
        return claims if isinstance(claims, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def jwt_uid(token: str) -> str:
    """Trae JWT 的账号 uid（payload.data.id）"""
    claims = _jwt_payload(token)
    d = claims.get("data")
    if isinstance(d, dict):
        return str(d.get("id") or "")
    return ""


def jwt_exp(token: str) -> float:
    """Trae JWT 的到期时间（epoch 秒）"""
    claims = _jwt_payload(token)
    try:
        return float(claims.get("exp") or 0)
    except (TypeError, ValueError):
        return 0.0


# ---------- Token 自动续期（设备证明版 ExchangeToken） ----------

def exchange_token(host: str, refresh_token: str, device: dict,
                   client_id: str = CLIENT_ID, platform_code: str = PLATFORM_CODE,
                   app_version: str | None = None):
    """用 refreshToken + 设备私钥续期，返回 (result_dict, error)。

    result_dict: {"token": ..., "refresh_token": ..., "expires_at": <秒>}。
    error 为空字符串表示成功；否则为人类可读错误。
    """
    if AES is None:
        return None, "缺少 pycryptodome 依赖，请执行: pip install pycryptodome"
    private_key = (device.get("private_key_pem") or "").strip()
    if not (refresh_token and private_key and device.get("device_id")):
        return None, "缺少 refreshToken 或设备密钥，无法自动续期"

    app_version = app_version or REFRESH_APP_VERSION
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    canonical = "\n".join(["POST", EXCHANGE_PATH, client_id,
                           refresh_token, str(ts), nonce])
    try:
        signature = device_proof_sign(private_key, canonical.encode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return None, f"设备私钥签名失败：{e}"

    device_info = {
        "DeviceID": device["device_id"],
        "MachineID": machine_id_of(device),
        "PlatformCode": platform_code,
        "DeviceType": "PC",
        "DeviceName": os.environ.get("USERNAME", "user"),
        "DeviceModel": "",
        "ClientVersion": app_version,
        "DevicePublicKey": device.get("public_key_pem") or "",
        "DeviceBrand": "",
        "DeviceCPU": "",
        "OSInfo": "Windows",
        "OSVersion": platform.release(),
    }
    body = {
        "ClientID": client_id,
        "ClientSecret": "",
        "RefreshToken": refresh_token,
        "DeviceInfo": device_info,
        "DeviceProof": {"Timestamp": ts, "Nonce": nonce, "Signature": signature},
        "IDEVersion": app_version,
    }
    headers = {"Content-Type": "application/json", "x-cloudide-token": ""}
    url = normalize_api_host(host) + EXCHANGE_PATH
    status, text = _post_json(url, headers, body)
    if status == -1:
        return None, text
    try:
        j = json.loads(text)
    except json.JSONDecodeError:
        return None, f"非 JSON 响应（HTTP {status}）：{text[:200]}"

    err = ((j.get("ResponseMetadata") or {}).get("Error") or {})
    code = err.get("Code")
    if code and str(code) != "0":
        return None, (f"code={code}/{err.get('StandardCode') or ''} "
                      f"{err.get('Message') or ''}").strip()
    res = j.get("Result") or {}
    new_token = res.get("Token") or ""
    if not new_token:
        return None, f"响应中未找到 Token（HTTP {status}）"
    return {
        "token": new_token,
        "refresh_token": res.get("RefreshToken") or "",
        "expires_at": jwt_exp(new_token),
    }, ""


def refresh_account(path: str, data: dict | None = None, dry: bool = False):
    """刷新账号 Token（refreshToken 轮换并原子写回）。返回 (ok, message)。

    dry=True 时跳过（只读模式零副作用）。
    """
    if dry:
        return False, "只读模式跳过续期"
    if data is None:
        data = load_account(path)
    auth = data.get("auth") or {}
    rt = (auth.get("refreshToken") or "").strip()
    if not rt:
        return False, "凭据缺少 refreshToken，无法自动续期"

    device = {
        "device_id": auth.get("deviceId") or "",
        "machine_id": auth.get("machineId") or "",
        "private_key_pem": auth.get("privateKeyPem") or "",
        "public_key_pem": auth.get("publicKeyPem") or "",
    }
    result, err = exchange_token(
        auth.get("apiHost") or DEFAULT_HOST, rt, device,
        client_id=auth.get("clientId") or CLIENT_ID,
        platform_code=auth.get("platform") or PLATFORM_CODE,
        app_version=auth.get("appVersion") or REFRESH_APP_VERSION,
    )
    if not result:
        return False, f"续期失败：{err}"

    auth["accessToken"] = result["token"]
    if result.get("refresh_token"):
        auth["refreshToken"] = result["refresh_token"]
    if result.get("expires_at"):
        auth["expiresAt"] = int(result["expires_at"])
    data["auth"] = auth
    data["disabled"] = False
    data.pop("note", None)
    save_account(path, data)
    return True, "Token 已自动续期"


# ---------- 凭据组装 ----------

def _make_credential(auth: dict, uid: str, nickname: str, source: str) -> dict:
    """组装凭据文件内容（统一出口，字段一次对齐）"""
    return {
        "auth": auth,
        "account": {"uid": str(uid or ""), "nickname": str(nickname or "")},
        "disabled": False,
        "source": source,
    }


def desktop_credential(storage_path: str | None = None):
    """桌面导入：解密本机 storage.json 登录信封，返回 (cred, err)"""
    try:
        path, storage = read_storage(storage_path)
    except Exception as e:  # noqa: BLE001
        return None, f"无法读取客户端登录态：{e}"

    encrypted = storage.get(AUTH_KEY)
    if not encrypted:
        return None, "storage.json 中未找到登录态，请先打开 TraeWork 客户端登录一次"
    try:
        auth = decrypt_storage_value(encrypted)
    except Exception as e:  # noqa: BLE001
        return None, f"登录态解密失败：{e}"

    token = (auth.get("token") or "").strip()
    if not token:
        return None, "登录态中未找到 token，请重新登录 TraeWork 客户端"

    device = device_identity(storage=storage, storage_path=path)
    if not device:
        return None, "未找到设备密钥（icube-dc），请重新登录 TraeWork 客户端"

    acct = auth.get("account") if isinstance(auth.get("account"), dict) else {}
    uid = str(auth.get("userId") or acct.get("id") or jwt_uid(token) or "")
    nickname = str(acct.get("username") or acct.get("name") or "")

    expires_at = _to_epoch(auth.get("expiredAt")) or jwt_exp(token)
    auth_out = {
        "accessToken": token,
        "refreshToken": (auth.get("refreshToken") or "").strip(),
        "expiresAt": int(expires_at) if expires_at else 0,
        "refreshExpiresAt": int(_to_epoch(auth.get("refreshExpiredAt")) or 0),
        "apiHost": normalize_api_host(auth.get("host")),
        "deviceId": device["device_id"],
        "machineId": device.get("machine_id") or "",
        "privateKeyPem": device.get("private_key_pem") or "",
        "publicKeyPem": device.get("public_key_pem") or "",
        "clientId": CLIENT_ID,
        "platform": PLATFORM_CODE,
        "appVersion": REFRESH_APP_VERSION,
    }
    return _make_credential(auth_out, uid, nickname, "desktop-import"), ""


# ---------- 浏览器 OAuth 登录（官网真实登录流程 + PKCE） ----------

def pkce_pair():
    """生成 PKCE (verifier, challenge)；challenge = base64url(SHA256(verifier))"""
    verifier = secrets.token_hex(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(device: dict, code_challenge: str, trace_id: str,
                        port: int = CALLBACK_PORT,
                        app_version: str | None = None,
                        plugin_version: str | None = None) -> str:
    """构造官网授权 URL（参数与社区抓包口径一致，勿增删改名）"""
    app_version = app_version or LOGIN_APP_VERSION
    plugin_version = plugin_version or LOGIN_PLUGIN_VERSION
    sysf = system_facts()
    callback = f"http://127.0.0.1:{port}{CALLBACK_PATH}"
    params = [
        ("login_version", "1"),
        ("auth_from", "solo"),
        ("login_channel", "native_ide"),
        ("plugin_version", plugin_version),
        ("auth_type", "local"),
        ("client_id", CLIENT_ID),
        ("redirect", "0"),
        ("login_trace_id", trace_id),
        ("auth_callback_url", callback),
        ("machine_id", machine_id_of(device)),
        ("device_id", device["device_id"]),
        ("x_device_id", device["device_id"]),
        ("x_machine_id", machine_id_of(device)),
        ("x_device_brand", sysf["device_model"]),
        ("x_device_type", sysf["os_name"]),
        ("x_os_version", sysf["os_version"]),
        ("x_env", ""),
        ("x_app_version", app_version),
        ("x_app_type", "stable"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("channel_name", "common"),
        ("hide_saas_login", "true"),
    ]
    return CONSOLE_BASE + AUTHORIZE_PATH + "?" + urllib.parse.urlencode(
        params, quote_via=urllib.parse.quote)


def parse_query(raw: str) -> dict:
    """回调查询串解析：先按 & 切分（原串），再对每段反复解码（≤3 次），最后切 =。

    这样处理官方对 auth_callback_url 的二次编码（值里现成的 %26 不会被误切）。
    """
    out = {}
    for pair in raw.split("&"):
        if not pair:
            continue
        s = pair
        for _ in range(3):
            n = urllib.parse.unquote_plus(s)
            if n == s:
                break
            s = n
        k, _, v = s.partition("=")
        out[k] = v
    return out


def parse_callback(params: dict) -> dict:
    """解析回调参数 → dict（authCodeInfo 解析失败必须抛错，由上层兜住）"""
    def _param(keys):
        for k in keys:
            v = (params.get(k) or "").strip()
            if v:
                return v
        return ""

    info = {"auth_code": "", "refresh_token": "",
            "host": _param(("host",)),
            "trace": _param(("loginTraceID", "login_trace_id")),
            "uid": "", "name": ""}
    raw = params.get("authCodeInfo")
    if raw and raw.strip():
        data = json.loads(raw)
        ac = str(data.get("AuthCode") or "").strip()
        if ac:
            info["auth_code"] = ac
    if not info["auth_code"]:
        info["auth_code"] = _param(("code",))
    for k in ("refreshToken", "refresh_token", "RefreshToken"):
        v = (params.get(k) or "").strip().strip('"').strip()
        if v:
            info["refresh_token"] = v
            break
    user_info = {}
    raw_ui = params.get("userInfo") or params.get("user_info") or params.get("UserInfo")
    if raw_ui:
        try:
            user_info = json.loads(raw_ui)
        except ValueError:
            user_info = {}
    if isinstance(user_info, dict):
        info["uid"] = str(user_info.get("UserID") or user_info.get("userId")
                         or _param(("UserID", "userId", "user_id")) or "")
        for k in ("ScreenName", "NickName", "nickname", "nickName", "name",
                  "userName", "email"):
            v = str(user_info.get(k) or "").strip()
            if v:
                info["name"] = v
                break
        if not info["name"]:
            info["name"] = _param(("userName", "user_name", "nickname"))
    return info


def _find_token(node, keys):
    """递归在响应中寻找 Token 字段（键名大小写不敏感）"""
    if isinstance(node, dict):
        for k in keys:
            v = node.get(k)
            if isinstance(v, str) and v:
                return v
        for k, v in node.items():
            if any(k.lower() == kk.lower() for kk in keys) and isinstance(v, str) and v:
                return v
        for v in node.values():
            r = _find_token(v, keys)
            if r:
                return r
    elif isinstance(node, list):
        for item in node:
            r = _find_token(item, keys)
            if r:
                return r
    return None


def _dig(node, path):
    for key in path:
        if not isinstance(node, dict):
            return ""
        node = node.get(key)
    return str(node or "")


def _try_exchange_variant(tag: str, url: str, payload: dict, device: dict,
                          app_version: str):
    """单个兑换变体；返回 (tokens|None, 错误文本)"""
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": f"Trae/{app_version}",
        "x-device-id": device["device_id"],
        "x-app-id": OAUTH_APP_ID,
        "x-platform-code": PLATFORM_CODE,
        "x-cloudide-token": "",   # 必须存在且为空串（缺了报 20403）
    }
    status, text = _post_json(url, headers, payload)
    if status == -1:
        return None, f"{tag}: {text}"
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        return None, f"{tag}: 非 JSON 响应（HTTP {status}）: {text[:180]}"
    code = _dig(body, ("ResponseMetadata", "Error", "Code"))
    if code and code != "0":
        msg = _dig(body, ("ResponseMetadata", "Error", "Message"))
        std = _dig(body, ("ResponseMetadata", "Error", "StandardCode"))
        return None, f"{tag}: code={code}/{std} {msg}"
    top = body.get("code")
    if isinstance(top, int) and top != 0:
        return None, f"{tag}: code={top} {body.get('message') or ''}"
    access = _find_token(body, ("AccessToken", "access_token", "token", "Jwt", "JWT"))
    refresh = _find_token(body, ("RefreshToken", "refresh_token"))
    if access and refresh:
        return {"accessToken": access, "refreshToken": refresh}, ""
    if access and not refresh:
        return None, f"{tag}: 响应缺少 RefreshToken（无法续期，已拒绝）"
    return None, f"{tag}: 响应中未找到 Token（键：{' | '.join(sorted(body.keys()))[:160]}）"


def exchange_auth_code(host: str, auth_code: str, verifier: str, device: dict,
                       app_version: str | None = None):
    """AuthCode 兑换凭据：三段变体链（主端点 DeviceInfo → 旧端点 AuthCode → 旧端点 Code）"""
    app_version = app_version or LOGIN_APP_VERSION
    sysf = system_facts()
    main_url = (host or DEFAULT_HOST).rstrip("/") + EXCHANGE_PATH
    legacy_url = ICUBE_BASE + LEGACY_EXCHANGE_PATH

    main_payload = {
        "ClientID": CLIENT_ID,
        "AuthCode": auth_code,
        "CodeVerifier": verifier,
        "DeviceInfo": {
            "DeviceID": device["device_id"],
            "MachineID": machine_id_of(device),
            "PlatformCode": PLATFORM_CODE,
            "DeviceType": "PC",
            "DeviceName": sysf["device_name"],
            "DeviceModel": sysf["device_model"],
            "ClientVersion": app_version,
            "DevicePublicKey": device.get("public_key_pem") or "",
            "DeviceBrand": sysf["device_manufacturer"],
            "DeviceCPU": sysf["cpu_brand"],
            "OSInfo": sysf["os_name"],
            "OSVersion": sysf["os_version"],
        },
        "IDEVersion": app_version,
    }

    def _legacy_payload(code_key):
        return {
            "ClientID": CLIENT_ID,
            code_key: auth_code,
            "CodeVerifier": verifier,
            "DeviceID": device["device_id"],
            "PlatformCode": PLATFORM_CODE,
        }

    variants = [
        ("ExchangeToken/DeviceInfo", main_url, main_payload),
        ("ExchangeToken/AuthCode", legacy_url, _legacy_payload("AuthCode")),
        ("ExchangeToken/Code", legacy_url, _legacy_payload("Code")),
    ]
    errors = []
    for tag, url, payload in variants:
        tokens, err = _try_exchange_variant(tag, url, payload, device, app_version)
        if tokens:
            return tokens, ""
        errors.append(err)
    return None, "全部兑换变体失败 → " + " | ".join(errors)


def _html_page(ok: bool, title: str, lines: list) -> str:
    color = "#12b76a" if ok else "#f04438"
    icon = "✅" if ok else "❌"
    esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
    body = "".join(f"<p>{esc(x)}</p>" for x in lines)
    return (f"<!doctype html><html><head><meta charset=\"utf-8\"><title>{esc(title)}</title>"
            "<style>body{margin:0;font-family:system-ui,'Microsoft YaHei',sans-serif;background:#0b1220;"
            "color:#e5e7eb;display:flex;min-height:100vh;align-items:center;justify-content:center}"
            ".card{background:#111a2e;border:1px solid #1f2a44;border-radius:14px;padding:32px 40px;"
            f"max-width:560px}}h1{{font-size:20px;margin:0 0 12px;color:{color}}}"
            "p{margin:6px 0;color:#cbd5e1;line-height:1.6;font-size:14px}</style></head><body>"
            f"<div class=\"card\"><h1>{icon} {esc(title)}</h1>{body}</div></body></html>")


def _serve_until_callback(port: int, timeout: int, process):
    """监听回调；process(params) → ('probe',) 或 ('result', ok, title, lines)。

    返回 None 表示拿到结果；"TIMEOUT" 表示超时；其它字符串为错误。
    """
    state = {"done": False}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype):
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def do_OPTIONS(self):
            self._send(204, "", "text/plain; charset=utf-8")

        def do_HEAD(self):
            self._send(200, "", "text/plain; charset=utf-8")

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def _handle(self):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            verdict = process(parse_query(query))
            if verdict[0] == "probe":
                self._send(200, "ok", "text/plain; charset=utf-8")
                return
            _, ok, title, lines = verdict
            self._send(200, _html_page(ok, title, lines), "text/html; charset=utf-8")
            state["done"] = True

    try:
        httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        return (f"端口 {port} 被占用（{e}）。\n"
                "   多半是 Trae 客户端正在运行 —— 先退出客户端再试。")
    httpd.timeout = 1.0
    deadline = time.monotonic() + timeout
    try:
        while not state["done"] and time.monotonic() < deadline:
            httpd.handle_request()
    finally:
        httpd.server_close()
    return None if state["done"] else "TIMEOUT"


def login_via_browser(timeout: int = CALLBACK_LOGIN_TIMEOUT, open_browser: bool = True,
                      log=print):
    """浏览器 OAuth 登录：返回 (cred, err)。

    登录/短信/滑块全部发生官网页面内，脚本只接 AuthCode 并兑换凭据。
    """
    if AES is None:
        return None, "缺少 pycryptodome 依赖，请执行: pip install pycryptodome"

    # 优先环境变量覆盖（device_identity 的 from="env"）；默认生成全新独立
    # 设备——多账号共享客户端设备会被"当前设备今日已经签到"按设备拦截
    device = device_identity()
    if not device or device.get("from") != "env":
        device = generate_device()
    if not device:
        return None, ("无法生成设备身份（缺少 pycryptodome 依赖）；\n"
                      "   或设置 TRAE_DEVICE_ID + TRAE_DEVICE_PUB_PEM 环境变量。")

    trace_id = secrets.token_hex(16)
    verifier, challenge = pkce_pair()
    plugin_version = installed_plugin_version()
    url = build_authorize_url(device, challenge, trace_id,
                              plugin_version=plugin_version)

    log("── TraeWork 浏览器登录（OAuth · SOLO 线） ──")
    log(f"设备身份：{device['device_id']}（来源: {str(device.get('from'))[:60]}）")
    log("授权链接：")
    log("  " + url)
    if open_browser:
        try:
            webbrowser.open(url)
            log("已尝试打开默认浏览器；没弹出就手动复制上面的链接。")
        except Exception:  # noqa: BLE001
            log("打不开浏览器，请手动复制上面的链接。")

    outcome = {"tokens": None, "error": None, "info": None}

    def process(params):
        if str(params.get("error") or "").strip():
            outcome["error"] = f"授权被拒绝: {params['error']}"
            return ("result", False, "已取消授权",
                    ["你在授权页拒绝了本次登录，可以关闭本页。"])
        if not any(k in params for k in ("authCodeInfo", "code", "accessToken",
                                         "access_token", "refreshToken",
                                         "refresh_token")):
            return ("probe",)   # 官网在线探测：回 ok 继续等
        lt = params.get("loginTraceID") or params.get("login_trace_id") or ""
        if lt and lt != trace_id:
            outcome["error"] = "回调 loginTraceID 校验失败（可能的 CSRF）"
            return ("result", False, "登录失败", ["登录校验失败，请重新发起登录。"])
        try:
            cb = parse_callback(params)
        except Exception as e:  # noqa: BLE001
            outcome["error"] = f"authCodeInfo 解析失败: {e}"
            return ("result", False, "登录失败", ["登录信息不完整，请重新授权。"])
        if not cb["auth_code"] and not cb["refresh_token"]:
            outcome["error"] = "回调带凭据参数，但既无 AuthCode 也无 refreshToken"
            return ("result", False, "登录失败", ["登录信息不完整，请重新授权。"])
        log(f"收到回调：uid={cb['uid'] or '-'} name={cb['name'] or '-'} "
            f"host={cb['host'] or '-'}")
        if cb["auth_code"]:
            log("AuthCode 已到手，正在兑换 Token …")
            tokens, err = exchange_auth_code(cb["host"], cb["auth_code"],
                                             verifier, device)
        else:
            log("回调直接带回 refreshToken，跳过兑换")
            tokens, err = {"accessToken": "", "refreshToken": cb["refresh_token"]}, ""
        if not tokens:
            outcome["error"] = err
            return ("result", False, "登录失败", ["Token 兑换失败：", err, "请重新发起登录。"])
        outcome["tokens"] = tokens
        outcome["info"] = cb
        shown = cb["name"] or cb["uid"] or "-"
        return ("result", True, "登录成功",
                [f"账号 {shown} 的凭据已获取，可以关闭本页（浏览器）。",
                 "回到终端查看结果。"])

    log(f"等待浏览器回调（最长 {timeout} 秒）…")
    err = _serve_until_callback(CALLBACK_PORT, timeout, process)
    if err == "TIMEOUT":
        return None, f"等待超时（{timeout} 秒）未收到回调"
    if err:
        return None, err
    if outcome["error"]:
        return None, outcome["error"]

    tokens = outcome["tokens"]
    cb = outcome["info"]
    uid = cb["uid"] or jwt_uid(tokens["accessToken"])
    nickname = cb["name"] or ""
    expires_at = jwt_exp(tokens["accessToken"])

    auth_out = {
        "accessToken": tokens["accessToken"],
        "refreshToken": tokens["refreshToken"],
        "expiresAt": int(expires_at) if expires_at else 0,
        "refreshExpiresAt": 0,
        "apiHost": normalize_api_host(cb["host"] or DEFAULT_HOST),
        "deviceId": device["device_id"],
        "machineId": device.get("machine_id") or "",
        "privateKeyPem": device.get("private_key_pem") or "",
        "publicKeyPem": device.get("public_key_pem") or "",
        "clientId": CLIENT_ID,
        "platform": PLATFORM_CODE,
        "appVersion": REFRESH_APP_VERSION,
    }
    return _make_credential(auth_out, uid, nickname, "browser-oauth"), ""
