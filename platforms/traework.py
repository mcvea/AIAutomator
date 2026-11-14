# -*- coding: utf-8 -*-
"""
TraeWork CN（字节 AI 办公平台）每日签到模块

原理：
  - 登录态支持两种来源：
    - 多账号模式（推荐）：读取 auths/traework-<uid>.json 本地凭据文件
      （由 trae_accounts.py 桌面导入或浏览器 OAuth 登录生成），临近过期
      自动续期（设备证明版 ExchangeToken，refreshToken 轮换，见
      platforms/trae_auth.py），一个文件一个账号，调度器经 account_specs()
      展开为多个实例逐账号签到；
    - 桌面模式（兜底）：auths/ 为空时读取本机 TraeWork 桌面端 storage.json
      中加密的登录信封（iCubeAuthInfo://icube.cloudide，AES-128-CBC +
      SHA512 完整性校验），解密得到 accessToken（社区逆向实现）。
  - 接口（POST，空 JSON body）：
      状态查询  {host}/trae/api/v2/ug/checkin_credits/status
      领取积分  {host}/trae/api/v2/ug/checkin_credits/claim
  - 鉴权头：Authorization: Cloud-IDE-JWT {token}，x-device-id: {数字设备id}。
    claim 存在设备级风控（9074/每日一设备）：本机客户端已注册的真设备号走
    轻量头直签；非注册设备号（浏览器 OAuth 合成设备等）改发全套客户端头 +
    uid 派生 15 位稳定伪设备号（trae-mate device_map 算法），两账号各持
    独立设备号互不抢占每日签到名额。

登录态文件（Windows）：
  %APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
"""
import base64
import gzip
import hashlib
import json
import os
import platform
import time
import urllib.error
import urllib.request
import uuid
import zlib

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
except ImportError:  # pragma: no cover
    AES = None

from platforms.base import BaseCheckin

try:  # 多账号凭据存储（缺失时退化为桌面单账号模式）
    from platforms import trae_auth
except Exception:  # noqa: BLE001
    trae_auth = None


class TraeWorkCheckin(BaseCheckin):
    PLATFORM_NAME = "TraeWork"
    CLIENT_NAME = "TraeWork"   # 供子类（Trae CN）覆盖提示文案
    DAILY_CREDITS = 150

    HOST = "https://api.trae.cn"
    STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
    CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
    EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
    CLIENT_ID = "en1oxy7wnw8j9n"
    APP_VERSION = "1.107.1"

    # 加密信封常量（社区逆向，勿改）
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
    AUTH_FILE_CANDIDATES = [
        os.path.join(os.environ.get("APPDATA", ""), "TRAE SOLO CN", "User",
                     "globalStorage", "storage.json"),
    ]
    _client_device_cache: dict = {}

    def __init__(self, dry: bool = False, account: dict | None = None):
        super().__init__(dry=dry)
        # account: {"path": 凭据文件, "label": 展示名}；None = 桌面模式
        self.account = account or None
        self.auth_file = None
        self.host = self.HOST
        if self.account is not None:
            self.auth_file = self.account.get("path")
            label = str(self.account.get("label") or "").strip()
            if label:
                self.PLATFORM_NAME = f"TraeWork·{label}"
        self.token = ""
        self.device_id = ""
        self.user_id = ""
        self.refresh_token = ""
        self.device_key_pem = ""
        self.device_pub_pem = ""
        self.machine_id = ""

    # ---------- 多账号展开（供调度器使用） ----------

    @classmethod
    def account_specs(cls) -> list:
        """多账号实例规格：auths/ 凭据文件优先；为空回退桌面单账号 [{}]。

        返回 kwargs 列表（如 {"account": {...}}），调度器据此逐账号构造实例。
        此处不做文件有效性校验，凭据错误延迟到运行期以失败的签到行呈现。
        多账号为可选功能：设 AI_CHECKIN_MULTI_ACCOUNT=0 可强制单账号模式。
        """
        if trae_auth is None:
            return [{}]
        if not trae_auth.multi_account_enabled():
            return [{}]
        try:
            accounts = trae_auth.list_accounts()
        except Exception:  # noqa: BLE001 - 凭据目录不可读时回退桌面模式
            accounts = []
        if not accounts:
            return [{}]
        return [{"account": acc} for acc in accounts]

    # ---------- 解密登录态 ----------

    @staticmethod
    def _sha512(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

    def _decrypt_auth_info(self, encoded: str) -> dict:
        """解密 TraeWork 登录信封，返回登录态 JSON"""
        if AES is None:
            raise RuntimeError("缺少 pycryptodome 依赖，请执行: pip install pycryptodome")

        envelope = base64.b64decode(encoded)
        if len(envelope) <= 38 or envelope[:6] != self.HEADER:
            raise ValueError(f"{self.CLIENT_NAME} 登录信封格式不正确")

        random_key = envelope[6:38]
        secret = bytes(a ^ b for a, b in zip(self.LEFT_SECRET, self.RIGHT_SECRET))
        derived = self._sha512(self._sha512(random_key) + secret)
        key, iv = derived[:16], derived[16:32]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(envelope[38:]), 16)

        if len(plaintext) < 64:
            raise ValueError("解密内容过短")
        expected_digest, payload = plaintext[:64], plaintext[64:]
        if self._sha512(payload) != expected_digest:
            raise ValueError(f"{self.CLIENT_NAME} 登录态完整性校验失败")
        return json.loads(payload.decode("utf-8"))

    def _locate_storage(self) -> str:
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                return path
        raise FileNotFoundError(
            f"未找到 {self.CLIENT_NAME} 登录态，请先打开 {self.CLIENT_NAME} 桌面端登录一次")

    def _load_credential(self):
        """读取并解密登录态，返回 (token, device_id, user_id)"""
        if self.account is not None:
            return self._load_credential_from_store()
        storage_path = self._locate_storage()
        with open(storage_path, "r", encoding="utf-8") as f:
            storage = json.load(f)

        encrypted = storage.get(self.AUTH_KEY)
        if not encrypted:
            raise RuntimeError(f"storage.json 中未找到登录态，请登录 {self.CLIENT_NAME}")

        auth = self._decrypt_auth_info(encrypted)
        token = (auth.get("token") or "").strip()
        if not token:
            raise RuntimeError(f"登录态中未找到 token，请重新登录 {self.CLIENT_NAME}")

        # 提取数字设备 id（iCubeAuthInfo://icube-dc:<numeric> 键）
        device_id = ""
        for k in storage.keys():
            if k.startswith("iCubeAuthInfo://icube-dc:"):
                did = k.split(":", 3)[-1]
                if did.isdigit():
                    device_id = did
                    break
        if not device_id:
            device_id = str(storage.get("telemetry.devDeviceId") or "").strip()

        # 解密设备密钥对（自动续期用）
        device_key_pem = ""
        device_pub_pem = ""
        if device_id:
            dev_enc = storage.get(f"iCubeAuthInfo://icube-dc:{device_id}")
            if dev_enc:
                try:
                    dev = self._decrypt_auth_info(dev_enc)
                    device_key_pem = (dev.get("privateKeyPEM") or "").strip()
                    device_pub_pem = (dev.get("publicKeyPEM") or "").strip()
                except Exception:  # noqa: BLE001
                    pass

        self.token = token
        self.device_id = device_id
        self.user_id = str(auth.get("userId") or "")
        self.refresh_token = (auth.get("refreshToken") or "").strip()
        self.device_key_pem = device_key_pem
        self.device_pub_pem = device_pub_pem
        self.machine_id = str(storage.get("telemetry.machineId") or "").strip()

        return self.token, self.device_id, self.user_id

    def _load_credential_from_store(self):
        """从 auths/ 多账号凭据文件读取（trae_accounts.py 生成）"""
        if trae_auth is None:
            raise RuntimeError("缺少 platforms/trae_auth.py，无法读取多账号凭据文件")
        data = trae_auth.load_account(self.auth_file)
        if data.get("disabled"):
            note = data.get("note") or "凭据已失效"
            raise RuntimeError(f"账号凭据已失效（{note}），请运行 trae_accounts.py add 重新登录")
        # 只读模式零副作用；常规模式临近过期先续期（2 天余量，refreshToken 轮换落盘）
        if not self.dry and trae_auth.is_expiring(data):
            ok, msg = trae_auth.refresh_account(self.auth_file, data)
            if ok:
                data = trae_auth.load_account(self.auth_file)
            elif trae_auth.is_expired(data):
                raise RuntimeError(f"Token 已过期且自动续期失败：{msg}")
        auth = data.get("auth") or {}
        account = data.get("account") or {}
        token = auth.get("accessToken")
        if not token and not self.dry:
            # 浏览器登录可能只回 refreshToken：先续期一次补齐
            ok, msg = trae_auth.refresh_account(self.auth_file, data)
            if ok:
                data = trae_auth.load_account(self.auth_file)
                auth = data.get("auth") or {}
                token = auth.get("accessToken")
            else:
                raise RuntimeError(f"凭据缺少 accessToken 且自动续期失败：{msg}")
        if not token:
            raise RuntimeError("凭据文件中未找到 accessToken，请运行 trae_accounts.py add 重新登录")
        self.token = str(token)
        self.device_id = str(auth.get("deviceId") or "")
        self.machine_id = str(auth.get("machineId") or "")
        self.refresh_token = str(auth.get("refreshToken") or "")
        self.device_key_pem = str(auth.get("privateKeyPem") or "")
        self.device_pub_pem = str(auth.get("publicKeyPem") or "")
        self.user_id = str(account.get("uid") or "")
        self.host = str(auth.get("apiHost") or self.HOST)
        return self.token, self.device_id, self.user_id

    # ---------- 自动续期（ExchangeToken） ----------

    _N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    @staticmethod
    def _der_encode_signature(r: int, s: int) -> bytes:
        def _enc(x):
            b = x.to_bytes(32, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return b
        rb, sb = _enc(r), _enc(s)
        body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
        return b"\x30" + bytes([len(body)]) + body

    def _ecdsa_sign(self, data: bytes) -> str:
        """设备私钥 ECDSA P-256/SHA-256 签名，返回 base64(DER)，含低 s 归一化"""
        key = ECC.import_key(self.device_key_pem)
        signer = DSS.new(key, 'fips-186-3', encoding='der')
        der = signer.sign(SHA256.new(data))

        # 解析 DER 提取 r/s
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

        if s > self._N // 2:
            s = self._N - s
        return base64.b64encode(self._der_encode_signature(r, s)).decode("utf-8")

    def _exchange_token(self) -> bool:
        """用 refreshToken + 设备私钥续期 token。成功返回 True"""
        if self.account is not None:
            return self._exchange_token_from_store()
        if not (self.refresh_token and self.device_key_pem and self.device_pub_pem and self.device_id):
            return False

        ts = int(time.time())
        nonce = os.urandom(16).hex()
        canonical = "\n".join(["POST", self.EXCHANGE_PATH, self.CLIENT_ID,
                               self.refresh_token, str(ts), nonce])
        try:
            signature = self._ecdsa_sign(canonical.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return False

        device_info = {
            "DeviceID": self.device_id,
            "MachineID": self.machine_id or "",
            "PlatformCode": "SOLO_PC",
            "DeviceType": "PC",
            "DeviceName": os.environ.get("USERNAME", "user"),
            "DeviceModel": "",
            "ClientVersion": self.APP_VERSION,
            "DevicePublicKey": self.device_pub_pem,
            "DeviceBrand": "",
            "DeviceCPU": "",
            "OSInfo": "Windows",
            "OSVersion": platform.release(),
        }
        body = {
            "ClientID": self.CLIENT_ID,
            "ClientSecret": "",
            "RefreshToken": self.refresh_token,
            "DeviceInfo": device_info,
            "DeviceProof": {"Timestamp": ts, "Nonce": nonce, "Signature": signature},
            "IDEVersion": self.APP_VERSION,
        }
        headers = {"Content-Type": "application/json", "x-cloudide-token": ""}
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.HOST + self.EXCHANGE_PATH, data=payload,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                j = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            return False

        err = (j.get("ResponseMetadata") or {}).get("Error")
        if err:
            return False
        res = j.get("Result") or {}
        new_token = res.get("Token")
        if not new_token:
            return False
        self.token = new_token
        if res.get("RefreshToken"):
            self.refresh_token = res["RefreshToken"]
        return True

    def _exchange_token_from_store(self) -> bool:
        """账号模式：续期凭据文件中的 Token（refreshToken 轮换落盘）；成功返回 True"""
        if trae_auth is None or self.account is None:
            return False
        if self.dry:
            return False  # 只读模式零副作用
        try:
            ok, _msg = trae_auth.refresh_account(self.auth_file)
        except Exception:  # noqa: BLE001
            return False
        if ok:
            try:
                self._load_credential_from_store()
            except Exception:  # noqa: BLE001 - 内存未同步不影响已落盘的新凭据
                pass
        return ok

    # ---------- 网络请求 ----------

    @classmethod
    def _local_client_device_id(cls) -> str:
        """本机客户端注册设备号（storage.json 的 iCubeAuthInfo://icube-dc:<数字> 键），进程内缓存"""
        if "v" in cls._client_device_cache:
            return cls._client_device_cache["v"]
        value = ""
        try:
            for path in cls.AUTH_FILE_CANDIDATES:
                if path and os.path.isfile(path):
                    with open(path, "r", encoding="utf-8") as f:
                        storage = json.load(f)
                    for k in storage:
                        if k.startswith("iCubeAuthInfo://icube-dc:"):
                            did = k.split(":", 3)[-1]
                            if did.isdigit():
                                value = did
                                break
                    break
        except Exception:  # noqa: BLE001
            value = ""
        cls._client_device_cache["v"] = value
        return value

    @classmethod
    def _derive_bytes(cls, seed: str, salt: str, n: int) -> bytes:
        """trae-mate device_map 确定性派生（SHA-256 流，4 字节计数器，对齐其测试向量）"""
        data = f"{salt}:{seed}".encode("utf-8")
        out = b""
        i = 0
        while len(out) < n:
            out += hashlib.sha256(data + i.to_bytes(4, "big")).digest()
            i += 1
        return out[:n]

    @classmethod
    def _pseudo_device_id(cls, uid: str) -> str:
        return "".join(str(b % 10) for b in cls._derive_bytes(uid, "devid", 16)[:15])

    @classmethod
    def _pseudo_market_uuid(cls, uid: str) -> str:
        bs = bytearray(cls._derive_bytes(uid, "market", 16))
        bs[6] = (bs[6] & 0x0F) | 0x40
        bs[8] = (bs[8] & 0x3F) | 0x80
        h = bytes(bs).hex()
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    @classmethod
    def _pseudo_session_id(cls, uid: str) -> str:
        return cls._derive_bytes(uid, "sess", 32).hex()

    def _use_pseudo_device(self) -> bool:
        """claim 设备风控：多账号凭据设备号非本机客户端注册号 → 走伪设备头"""
        if self.account is None:
            return False
        client_did = self._local_client_device_id()
        if not client_did:
            return True
        return (self.device_id or "") != client_did

    def _request_headers(self) -> dict:
        token = self.token
        auth = (token if str(token).startswith("Cloud-IDE-JWT ")
                else f"Cloud-IDE-JWT {token}")
        if not self._use_pseudo_device():
            return {
                "content-type": "application/json",
                "authorization": auth,
                "x-device-id": self.device_id or "",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            }
        uid = str(self.user_id or "")
        return {
            "content-type": "application/json",
            "authorization": auth,
            "accept": "*/*",
            "accept-encoding": "gzip, deflate",
            "accept-language": "zh-CN",
            "user-agent": "VSCode 1.107.1 (TRAE SOLO CN)",
            "x-market-client-id": "VSCode 1.107.1",
            "x-market-user-id": self._pseudo_market_uuid(uid),
            "x-user-region": "CN",
            "x-device-id": self._pseudo_device_id(uid),
            "x-lgw-req-sdk-type": "3",
            "package-type": "stable_cn",
            "x-lscbd-aid": "787976",
            "x-lscbd-platform": "windows",
            "app-version": "0.1.45",
            "x-tt-trace-id": "00-%s-01" % uuid.uuid4().hex[:16],
            "vscode-sessionid": self._pseudo_session_id(uid),
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "none",
            "x-request-id": str(uuid.uuid4()),
        }

    @staticmethod
    def _decode_body(resp) -> str:
        raw = resp.read()
        ce = (getattr(resp, "headers", None).get("Content-Encoding", "")
              if getattr(resp, "headers", None) else "")
        if ce == "gzip":
            raw = gzip.decompress(raw)
        elif ce == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        return raw.decode("utf-8", errors="replace")

    def _api_call(self, path: str, body: dict = None, timeout: int = 30):
        """调用 Trae 接口，返回 (http_status, json)"""
        headers = self._request_headers()
        payload = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(self.host + path, data=payload,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = self._decode_body(resp)
                try:
                    return resp.status, json.loads(raw)
                except Exception:  # noqa: BLE001
                    return resp.status, {"raw": raw[:300]}
        except urllib.error.HTTPError as e:
            raw = self._decode_body(e)
            try:
                return e.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return e.code, {"raw": raw[:300]}
        except Exception as e:  # noqa: BLE001
            return 0, {"error": str(e)}

    @staticmethod
    def _api_ok(data) -> bool:
        if not isinstance(data, dict):
            return False
        code = data.get("code")
        if isinstance(code, (int, float)) and code in (0, 200):
            return True
        if isinstance(code, str) and code.strip() in ("0", "200"):
            return True
        return data.get("success") is True or str(data.get("status", "")).lower() == "success"

    # ---------- 签到主流程 ----------

    def checkin(self) -> dict:
        self.token, self.device_id, self.user_id = self._load_credential()

        # 1) 状态查询
        sc, sb = self._api_call(self.STATUS_PATH)
        if isinstance(sb, dict) and sb.get("checked_in"):
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "already",
                "message": "今日已签到",
                "credits": 0,
            }

        # 鉴权失败：尝试自动续期后重试
        if self._is_auth_failure(sc, sb):
            renewed = self._exchange_token()
            if renewed:
                sc, sb = self._api_call(self.STATUS_PATH)
                if isinstance(sb, dict) and sb.get("checked_in"):
                    return {
                        "platform": self.PLATFORM_NAME,
                        "success": True,
                        "status": "already",
                        "message": "今日已签到（已自动续期登录态）",
                        "credits": 0,
                    }
            if self._is_auth_failure(sc, sb):
                return {
                    "platform": self.PLATFORM_NAME,
                    "success": False,
                    "status": "failed",
                    "message": f"鉴权失败且自动续期未生效，请打开 {self.CLIENT_NAME} 桌面端重新登录",
                    "credits": 0,
                }

        # 只读模式
        if self.dry:
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "skipped",
                "message": "只读模式：今日尚未签到，可正常执行",
                "credits": 0,
            }

        # 2) 领取积分（幂等）
        cc, cb = self._api_call(self.CLAIM_PATH)
        if self._is_auth_failure(cc, cb):
            renewed = self._exchange_token()
            if renewed:
                cc, cb = self._api_call(self.CLAIM_PATH)
            if self._is_auth_failure(cc, cb):
                return {
                    "platform": self.PLATFORM_NAME,
                    "success": False,
                    "status": "failed",
                    "message": f"领取时鉴权失败且自动续期未生效，请打开 {self.CLIENT_NAME} 桌面端重新登录",
                    "credits": 0,
                }

        if self._api_ok(cb):
            data = cb.get("data") or {}
            points = data.get("points") or cb.get("points")
            credits = int(points) if isinstance(points, (int, float)) and points else self.DAILY_CREDITS
            msg = cb.get("message") or cb.get("msg") or ""
            if msg == "success" or not msg:
                msg = f"签到成功，获得 {credits} 积分"
            return {
                "platform": self.PLATFORM_NAME,
                "success": True,
                "status": "success",
                "message": msg,
                "credits": credits,
            }

        msg = (cb or {}).get("message") or (cb or {}).get("msg") or "未知错误"
        return {
            "platform": self.PLATFORM_NAME,
            "success": False,
            "status": "failed",
            "message": f"签到未成功（HTTP {cc}）：{msg}",
            "credits": 0,
        }

    @staticmethod
    def _is_auth_failure(http_status: int, data) -> bool:
        if http_status in (401, 403):
            return True
        if isinstance(data, dict):
            code = data.get("code")
            if isinstance(code, (int, float)) and code in (401, 403, 1001):
                return True
        return False

    # ---------- 账户总积分 ----------

    def total(self) -> dict:
        """TraeWork 账户剩余可用额度（与 balance() 同口径：usage_summary 剩余）"""
        bal = self.balance()
        if bal.get("available") and bal.get("remain") is not None:
            return {
                "available": True,
                "total": bal["remain"],
                "note": "",
            }
        return {"available": False, "total": None}

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        if self.account is not None:
            return self._health_from_store()
        try:
            self._load_credential()
            storage_path = self._locate_storage()
            with open(storage_path, "r", encoding="utf-8") as f:
                storage = json.load(f)
            auth = self._decrypt_auth_info(storage.get(self.AUTH_KEY))
            expired_at = auth.get("expiredAt")
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }

        days = None
        if expired_at:
            from datetime import datetime, timezone
            try:
                exp_dt = datetime.fromisoformat(str(expired_at).replace("Z", "+00:00"))
                now_dt = datetime.now(timezone.utc)
                days = max(0, int((exp_dt - now_dt).total_seconds() // 86400))
            except Exception:  # noqa: BLE001
                pass

        status = "ok"
        msg = "登录态正常"
        if days is not None and days < 7:
            status = "warn"
            msg = (f"登录态剩余 {days} 天，请打开 {self.CLIENT_NAME} 桌面端登录刷新"
                       f"（脚本也会自动尝试续期）")
        elif days is not None:
            msg = f"登录态剩余 {days} 天（脚本可自动续期）"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }

    def _health_from_store(self) -> dict:
        """账号模式健康检查：以凭据文件中到期时间计算（token 约 14 天 / RT 半年）"""
        relogin_hint = "请运行 trae_accounts.py add 重新登录"
        if trae_auth is None:
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": "缺少 platforms/trae_auth.py",
            }
        try:
            data = trae_auth.load_account(self.auth_file)
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取凭据文件：{e}",
            }
        if data.get("disabled"):
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"账号凭据已失效，{relogin_hint}",
            }
        days = trae_auth.days_left(data)
        status = "ok"
        if trae_auth.is_expired(data):
            status = "expired"
            msg = f"登录态已过期（脚本会尝试自动续期），{relogin_hint}"
        elif days is not None and days < 7:
            status = "warn"
            msg = f"登录态剩余 {days} 天（脚本将自动续期）"
        elif days is not None:
            msg = f"登录态剩余 {days} 天（脚本可自动续期）"
        else:
            msg = "登录态正常（到期时间未知）"
        r_days = trae_auth.refresh_days_left(data)
        if r_days is not None and r_days < 14 and status == "ok":
            status = "warn"
            msg += f"（refreshToken 剩余 {r_days} 天，届时需重新登录）"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }

    # ---------- 账户总余额 ----------

    def balance(self) -> dict:
        """查询 TraeWork 账户总余额（usage_summary：总量/已用/剩余）

        接口：POST /trae/api/v2/pay/ide_user_ent_usage（body {"require_usage": true}）
        口径来自社区项目 trae-work-checkin-plus（balance.js）与 Trae-AutoCheckin：
          usage_summary.total_amount    账户总用量额度
          usage_summary.consumed_amount 已消耗
          remaining = total - consumed
        """
        try:
            self._load_credential()
            sc, sb = self._api_call(
                "/trae/api/v2/pay/ide_user_ent_usage", body={"require_usage": True})
            if self._is_auth_failure(sc, sb) and self._exchange_token():
                sc, sb = self._api_call(
                    "/trae/api/v2/pay/ide_user_ent_usage", body={"require_usage": True})
        except Exception:  # noqa: BLE001
            return {"available": False, "total": None, "remain": None, "used": None}

        usage = (sb.get("usage_summary") or {}) if isinstance(sb, dict) else {}
        total = usage.get("total_amount")
        consumed = usage.get("consumed_amount")
        if total is None:
            return {"available": False, "total": None, "remain": None, "used": None}
        total_f = float(total)
        consumed_f = float(consumed or 0)
        return {
            "available": True,
            "total": total_f,
            "remain": round(total_f - consumed_f, 2),
            "used": consumed_f,
            "note": "",
        }
