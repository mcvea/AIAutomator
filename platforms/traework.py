# -*- coding: utf-8 -*-
"""
TraeWork CN（字节 AI 办公平台）每日签到模块

原理：
  - 登录态：读取本机 TraeWork 桌面端 storage.json 中加密的登录信封
    （iCubeAuthInfo://icube.cloudide，AES-128-CBC + SHA512 完整性校验），
    解密得到 accessToken（社区逆向实现）
  - 接口（POST，空 JSON body）：
      状态查询  {host}/trae/api/v2/ug/checkin_credits/status
      领取积分  {host}/trae/api/v2/ug/checkin_credits/claim
  - 鉴权头：Authorization: Cloud-IDE-JWT {token}，x-device-id: {数字设备id}

登录态文件（Windows）：
  %APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
"""
import base64
import hashlib
import json
import os
import platform
import time
import urllib.error
import urllib.request

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
except ImportError:  # pragma: no cover
    AES = None

from platforms.base import BaseCheckin


class TraeWorkCheckin(BaseCheckin):
    PLATFORM_NAME = "TraeWork"
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

    def __init__(self, dry: bool = False):
        super().__init__(dry=dry)
        self.token = ""
        self.device_id = ""
        self.user_id = ""
        self.refresh_token = ""
        self.device_key_pem = ""
        self.device_pub_pem = ""
        self.machine_id = ""

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
            raise ValueError("TraeWork 登录信封格式不正确")

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
            raise ValueError("TraeWork 登录态完整性校验失败")
        return json.loads(payload.decode("utf-8"))

    def _locate_storage(self) -> str:
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                return path
        raise FileNotFoundError("未找到 TraeWork 登录态，请先打开 TraeWork 桌面端登录一次")

    def _load_credential(self):
        """读取并解密登录态，返回 (token, device_id, user_id)"""
        storage_path = self._locate_storage()
        with open(storage_path, "r", encoding="utf-8") as f:
            storage = json.load(f)

        encrypted = storage.get(self.AUTH_KEY)
        if not encrypted:
            raise RuntimeError("storage.json 中未找到登录态，请登录 TraeWork")

        auth = self._decrypt_auth_info(encrypted)
        token = (auth.get("token") or "").strip()
        if not token:
            raise RuntimeError("登录态中未找到 token，请重新登录 TraeWork")

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
        signer = DSS.new(key, 'fips-186-3')
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

    # ---------- 网络请求 ----------

    def _api_call(self, path: str, body: dict = None, timeout: int = 30):
        """调用 Trae 接口，返回 (http_status, json)"""
        token = self.token
        headers = {
            "content-type": "application/json",
            "authorization": token if str(token).startswith("Cloud-IDE-JWT ")
            else f"Cloud-IDE-JWT {token}",
            "x-device-id": self.device_id or "",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
        payload = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(self.HOST + path, data=payload,
                                     headers=headers, method="POST")
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
                    "message": "鉴权失败且自动续期未生效，请打开 TraeWork 桌面端重新登录",
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
                    "message": "领取时鉴权失败且自动续期未生效，请打开 TraeWork 桌面端重新登录",
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

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
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
            msg = f"登录态剩余 {days} 天，请打开 TraeWork 桌面端登录刷新（脚本也会自动尝试续期）"
        elif days is not None:
            msg = f"登录态剩余 {days} 天（脚本可自动续期）"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }
