# -*- coding: utf-8 -*-
"""
WorkBuddy（腾讯 AI 办公工作台）每日签到模块

原理：签到 = 带登录态的 HTTP 请求。支持两种登录态来源：

- 多账号模式（推荐）：读取 auths/workbuddy-<uid>.json 本地凭据文件
  （由 wb_accounts.py 短信登录生成，独立会话），临近过期自动续期
  （refreshToken 轮换，见 platforms/wb_auth.py），一个文件一个账号，
  调度器经 account_specs() 展开为多个实例逐账号签到；
- 桌面模式（兜底）：auths/ 为空时读取本机 WorkBuddy 桌面客户端写入的凭据文件
  （%LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\workbuddy-desktop.info），
  使用其中的 auth.accessToken 调用官方计费接口完成签到（与历史行为一致）。

WorkBuddy 5.6.0+ 起，登录态文件中的敏感字段（accessToken / refreshToken /
nickname 等）升级为 $wbEncrypted 加密信封（AES-256-GCM）。本模块自动兼容：
- accessToken 为明文字符串（5.5.x 旧版）→ 直接使用；
- accessToken 为加密信封（5.6+）→ 通过 WorkBuddy 客户端自身运行时
  （ELECTRON_RUN_AS_NODE 管道模式 + 内建原生绑定密钥，见 wb_helper.js）
  在内存中瞬态解密，密钥与明文绝不落盘、绝不写日志；
- 解密失败/运行时缺失 → Fail-Closed 阻断，绝不把畸形鉴权头发往服务端。

接口均为幂等操作：重复调用只会提示"已领过"，不会扣任何积分，可放心反复执行。

参考社区已验证信息：
- 状态查询(只读): POST /v2/billing/meter/checkin-activity-status
- 执行签到(写):   POST /v2/billing/meter/daily-checkin
- 端点：https://www.workbuddy.cn 与 https://copilot.tencent.com 均可用
- 幂等：daily-checkin 返回 code=0 成功；code=10001 表示今日已签到
  （网关会包装成 HTTP 400，需看响应体 code/msg）
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from platforms.base import BaseCheckin

try:  # 多账号凭据存储（缺失时退化为桌面单账号模式）
    from platforms import wb_auth
except Exception:  # noqa: BLE001
    wb_auth = None


class WorkBuddyCheckin(BaseCheckin):
    PLATFORM_NAME = "WorkBuddy"
    DAILY_CREDITS = 100

    # 登录态文件候选路径（依次探测，仅桌面模式使用）
    AUTH_FILE_CANDIDATES = [
        # 常规路径（计划任务运行时 LOCALAPPDATA 为真实用户目录）
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"),
        os.path.join(os.path.expanduser("~"), ".workbuddy", "auth", "workbuddy-desktop.info"),
    ]

    def __init__(self, dry: bool = False, account: dict | None = None):
        super().__init__(dry=dry)
        # account: {"path": 凭据文件, "label": 展示名}；None = 桌面模式
        self.account = account or None
        self.auth_data = None
        # WorkBuddy 客户端运行时路径缓存（解密 5.6+ 加密凭据用）
        self.wb_exe = None
        if self.account is not None:
            self.auth_file = self.account.get("path")
            label = str(self.account.get("label") or "").strip()
            if label:
                self.PLATFORM_NAME = f"WorkBuddy·{label}"
        else:
            self.auth_file = self._locate_auth_file()

    # ---------- 多账号展开（供调度器使用） ----------

    @classmethod
    def account_specs(cls) -> list:
        """多账号实例规格：auths/ 凭据文件优先；为空回退桌面单账号 [{}]。

        返回 kwargs 列表（如 {"account": {...}}），调度器据此逐账号构造实例。
        此处不做文件有效性校验，凭据错误延迟到运行期以失败的签到行呈现。
        多账号为可选功能：设 AI_CHECKIN_MULTI_ACCOUNT=0 可强制单账号模式。
        """
        if wb_auth is None:
            return [{}]
        if not wb_auth.multi_account_enabled():
            return [{}]
        try:
            accounts = wb_auth.list_accounts()
        except Exception:  # noqa: BLE001 - 凭据目录不可读时回退桌面模式
            accounts = []
        if not accounts:
            return [{}]
        return [{"account": acc} for acc in accounts]

    # ---------- 内部工具 ----------

    def _locate_auth_file(self):
        """定位登录态文件"""
        for path in self.AUTH_FILE_CANDIDATES:
            if path and os.path.isfile(path):
                return path
        raise FileNotFoundError(
            "未找到 WorkBuddy 登录态文件，请先打开 WorkBuddy 客户端登录一次")

    def _load_auth(self):
        """读取登录态 JSON，提取 token 与域名（多账号凭据 / 桌面凭据两条来源）"""
        if self.account is not None:
            return self._load_auth_from_store()
        with open(self.auth_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        auth = data.get("auth") or {}
        account = data.get("account") or {}
        raw_token = auth.get("accessToken")
        domain = auth.get("domain") or "www.workbuddy.cn"
        uid = account.get("uid", "")
        if not raw_token:
            raise RuntimeError("登录态文件中未找到 accessToken，请重新登录 WorkBuddy")
        token = self._resolve_auth_token(raw_token)
        return token, domain, uid, auth

    def _load_auth_from_store(self):
        """从 auths/ 多账号凭据文件读取（wb_accounts.py 短信登录生成）"""
        if wb_auth is None:
            raise RuntimeError("缺少 platforms/wb_auth.py，无法读取多账号凭据文件")
        data = wb_auth.load_account(self.auth_file)
        if data.get("disabled"):
            note = data.get("note") or "会话已失效"
            raise RuntimeError(f"账号会话已失效（{note}），请运行 wb_accounts.py add 重新登录")
        # 只读模式零副作用；常规模式临近过期先续期（5 天余量，refreshToken 轮换落盘）
        if not self.dry and wb_auth.is_expiring(data):
            ok, msg = wb_auth.refresh_account(self.auth_file, data)
            if ok:
                data = wb_auth.load_account(self.auth_file)
            elif wb_auth.is_expired(data):
                raise RuntimeError(f"Token 已过期且自动续期失败：{msg}")
        auth = data.get("auth") or {}
        account = data.get("account") or {}
        token = auth.get("accessToken")
        if not token:
            raise RuntimeError("凭据文件中未找到 accessToken，请运行 wb_accounts.py add 重新登录")
        domain = auth.get("domain") or "www.workbuddy.cn"
        uid = account.get("uid", "")
        return str(token), domain, uid, auth

    def _refresh_store_token(self):
        """账号模式：刷新凭据文件中的 Token；返回 (ok, message)"""
        if wb_auth is None or self.account is None:
            return False, "无凭据存储模块"
        try:
            data = wb_auth.load_account(self.auth_file)
            return wb_auth.refresh_account(self.auth_file, data)
        except Exception as e:  # noqa: BLE001
            return False, f"续期异常：{e}"

    # ---------- 5.6+ 加密凭据兼容 ----------

    def _resolve_auth_token(self, raw) -> str:
        """解析 accessToken 字段：
        - 旧版 5.5.x：明文字符串，直接使用
        - 新版 5.6+：$wbEncrypted 加密信封，调用 WorkBuddy 客户端自身运行时解密
        - 其它/损坏格式：Fail-Closed，绝不把畸形 token 发往服务端
        """
        if isinstance(raw, str):
            token = raw
        elif (isinstance(raw, dict) and raw.get("$wbEncrypted") == 1
              and isinstance(raw.get("envelope"), str)):
            token = self._decrypt_field_via_helper(raw["envelope"])
        else:
            raise RuntimeError(
                "登录态文件中的 accessToken 格式无法识别"
                "（既不是明文也不是 $wbEncrypted 信封），请打开 WorkBuddy 客户端重新登录")
        if not self._is_valid_token(token):
            raise RuntimeError("解密后的 accessToken 无效，请打开 WorkBuddy 客户端重新登录")
        return token

    @staticmethod
    def _is_valid_token(token: str) -> bool:
        """粗略校验 token 形态：非空、ASCII 可打印、三段式（JWT）"""
        if not token or len(token) < 40:
            return False
        try:
            token.encode("ascii")
        except UnicodeEncodeError:
            return False
        return token.count(".") == 2

    def _find_workbuddy_exe(self) -> str:
        """定位 WorkBuddy 客户端运行时（用于解密加密凭据）。

        优先环境变量 WORKBUDDY_EXE，其次常见安装路径，最后查注册表卸载项。
        """
        exe = self.wb_exe
        if exe and os.path.isfile(exe):
            return exe
        candidates = []
        override = os.environ.get("WORKBUDDY_EXE")
        if override:
            candidates.append(override)
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            candidates.append(os.path.join(local, "Programs", "WorkBuddy", "WorkBuddy.exe"))
            candidates.append(os.path.join(local, "Programs", "workbuddy", "WorkBuddy.exe"))
        for env_name in ("PROGRAMFILES", "PROGRAMFILES(X86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(os.path.join(base, "WorkBuddy", "WorkBuddy.exe"))
        try:
            import shutil
            found = shutil.which("WorkBuddy.exe") or shutil.which("workbuddy.exe")
            if found:
                candidates.append(found)
        except Exception:  # noqa: BLE001 - which 失败不影响候选列表
            pass
        if sys.platform == "win32":
            candidates.extend(self._find_wb_exe_from_registry())
        for p in candidates:
            if p and os.path.isfile(p):
                self.wb_exe = p
                return p
        raise RuntimeError(
            "未找到 WorkBuddy 客户端运行时（WorkBuddy.exe），无法解密 5.6+ 加密凭据；"
            "可设置环境变量 WORKBUDDY_EXE 指定其完整路径")

    @staticmethod
    def _find_wb_exe_from_registry() -> list:
        """从 Windows 卸载注册表项中查找 WorkBuddy 安装位置（纯标准库）"""
        found = []
        try:
            import winreg
        except ImportError:
            return found
        roots = [
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for root, subkey in roots:
            try:
                with winreg.OpenKey(root, subkey) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                                if "workbuddy" not in name.lower():
                                    continue
                                # 优先 InstallLocation；为空时用 DisplayIcon（如
                                # "D:\Programs\WorkBuddy\WorkBuddy.exe,0"）兜底
                                exe = ""
                                try:
                                    loc, _ = winreg.QueryValueEx(sub, "InstallLocation")
                                    if loc:
                                        exe = os.path.join(loc, "WorkBuddy.exe")
                                except OSError:
                                    pass
                                if not exe or not os.path.isfile(exe):
                                    try:
                                        icon, _ = winreg.QueryValueEx(sub, "DisplayIcon")
                                        if icon:
                                            exe = icon.split(",")[0].strip('"')
                                    except OSError:
                                        pass
                                if exe and os.path.isfile(exe):
                                    found.append(exe)
                        except OSError:
                            continue
            except OSError:
                continue
        return found

    def _decrypt_field_via_helper(self, envelope: str) -> str:
        """通过 WorkBuddy 客户端运行 wb_helper.js 在内存中解密信封字段。

        原理（与社区 workbuddy-toolkit 同源）：WorkBuddy 是 Electron 应用，
        支持 ELECTRON_RUN_AS_NODE=1 管道模式；其内建原生绑定
        electron_browser_workbuddy_storage.loggerGet() 提供 at-rest 密钥，
        配合信封中的 AES-256-GCM 密文完成瞬时解密。密钥与明文仅存在于
        子进程内存管道中，绝不落盘、绝不打印、绝不写日志。
        """
        exe = self._find_workbuddy_exe()
        helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wb_helper.js")
        if not os.path.isfile(helper):
            raise RuntimeError("缺少解密助手 platforms/wb_helper.js")

        # 屏蔽外部 Node/Electron 注入环境变量，仅开启管道模式
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(("NODE_", "ELECTRON_", "WORKBUDDY_"))}
        env["ELECTRON_RUN_AS_NODE"] = "1"

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                [exe, helper, self.auth_file, "auth.accessToken"],
                capture_output=True, timeout=15, env=env,
                creationflags=flags if flags else 0,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("WorkBuddy 凭据解密超时，请稍后重试") from e
        except OSError as e:
            raise RuntimeError(f"无法启动 WorkBuddy 运行时进行解密: {e}") from e

        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            if "WB_HELPER_ERROR" in err:
                reason = err.replace("WB_HELPER_ERROR: ", "", 1)
                raise RuntimeError(f"WorkBuddy 凭据解密失败: {reason}")
            raise RuntimeError(f"WorkBuddy 凭据解密失败（退出码 {proc.returncode}）: {err}")
        token = proc.stdout.decode("utf-8", errors="replace").strip()
        if not token:
            raise RuntimeError("WorkBuddy 凭据解密返回为空，请打开客户端重新登录")
        return token

    @staticmethod
    def _expires_at_ms(auth: dict, key: str = "expiresAt") -> float:
        """归一化到期时间到「毫秒」：桌面客户端为毫秒戳，auths 凭据文件为秒（社区口径）"""
        v = auth.get(key)
        if not v:
            return 0.0
        try:
            v = float(v)
        except (TypeError, ValueError):
            return 0.0
        return v * 1000 if v < 1e12 else v

    def _token_expired(self, auth: dict) -> bool:
        """检查 accessToken 是否过期（兼容毫秒/秒两种 expiresAt 口径）"""
        ms = self._expires_at_ms(auth)
        if not ms:
            return False
        return time.time() * 1000 > ms

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
            msg = ("登录态已过期，请运行 wb_accounts.py add 重新登录刷新"
                   if self.account is not None
                   else "登录态已过期，请打开 WorkBuddy 客户端重新登录刷新")
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "failed",
                "message": msg,
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

        # 2) 执行每日签到（幂等；已签时服务端返回 HTTP 400 + code=10001）
        try:
            result = self._daily_checkin(base, token, uid)
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

        # 判定结果：code=0 成功；code/msg 表明已签或重复等
        code = result.get("code") if isinstance(result, dict) else None
        msg_text = (result.get("msg") if isinstance(result, dict) else None) or text
        if ("already" in text.lower() or "已签" in text or
                "重复" in text or result.get("alreadyCheckedIn") is True or
                "10001" in text or (code is not None and code != 0 and "已签" in str(msg_text))):
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

    def _daily_checkin(self, base: str, token: str, uid: str):
        """执行每日签到；账号模式下 401/403 时自动续期 Token 并重试一次"""
        try:
            return self._http_json(
                "POST", f"{base}/v2/billing/meter/daily-checkin",
                token, uid, payload={})
        except RuntimeError as e:
            err_text = str(e)
            is_auth_err = "HTTP 401" in err_text or "HTTP 403" in err_text
            if is_auth_err and self.account is not None and not self.dry:
                ok, msg = self._refresh_store_token()
                if ok:
                    token2, domain2, uid2, _auth = self._load_auth()
                    return self._http_json(
                        "POST", f"https://{domain2}/v2/billing/meter/daily-checkin",
                        token2, uid2, payload={})
                if "失效" in msg:
                    raise RuntimeError(
                        f"登录会话已失效，请运行 wb_accounts.py add 重新登录（{msg}）"
                    ) from e
            raise

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
            for k in ("credits", "credit", "points", "amount", "reward", "gainCredits"):
                v = result["data"].get(k)
                if isinstance(v, (int, float)) and v > 0:
                    return int(v)
        return 0

    # ---------- 登录态健康检查 ----------

    def health(self) -> dict:
        relogin_hint = ("请运行 wb_accounts.py add 重新登录"
                        if self.account is not None
                        else "请打开 WorkBuddy 客户端重新登录")
        try:
            if self.account is not None:
                if wb_auth is None:
                    raise RuntimeError("缺少 platforms/wb_auth.py")
                data = wb_auth.load_account(self.auth_file)
                if data.get("disabled"):
                    return {
                        "platform": self.PLATFORM_NAME,
                        "status": "expired",
                        "days_left": 0,
                        "message": f"账号会话已失效，{relogin_hint}",
                    }
                auth = data.get("auth") or {}
                if not auth.get("accessToken"):
                    raise RuntimeError("凭据文件缺少 accessToken")
            else:
                token, domain, uid, auth = self._load_auth()
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "status": "expired",
                "days_left": 0,
                "message": f"无法读取登录态：{e}",
            }
        now_ms = time.time() * 1000
        expires_at = self._expires_at_ms(auth)
        refresh_expires = self._expires_at_ms(auth, "refreshExpiresAt")
        days = None
        if expires_at:
            days = max(0, int((expires_at - now_ms) / 86400000))
        status = "ok"
        msg = "登录态正常"
        if expires_at and expires_at <= now_ms:
            status = "expired"
            msg = f"登录态已过期，{relogin_hint}"
        elif days is not None and days < 7:
            status = "warn"
            msg = f"登录态剩余 {days} 天，请尽快刷新（{relogin_hint}）"
        elif days is not None:
            msg = f"登录态剩余 {days} 天"
        if refresh_expires and status == "ok":
            r_days = max(0, int((refresh_expires - now_ms) / 86400000))
            if r_days < 7:
                status = "warn"
                msg += f"（refreshToken 剩余 {r_days} 天）"
        return {
            "platform": self.PLATFORM_NAME,
            "status": status,
            "days_left": days,
            "message": msg,
        }

    # ---------- 账户总积分 ----------

    def total(self) -> dict:
        """WorkBuddy 账户积分总额（复用 balance() 资源包额度口径）"""
        bal = self.balance()
        if bal.get("available") and bal.get("total") is not None:
            return {
                "available": True,
                "total": bal["total"],
                "note": "",
            }
        return {"available": False, "total": None}

    # ---------- 账户总余额（资源包额度） ----------

    def balance(self) -> dict:
        """查询账户总余额（资源包 Credits 额度，官方 get-user-resource-summary）

        注意与 total() 区分：total() 是「本季签到活动累计积分」；
        balance() 是「账户资源包额度」（主套餐 + 加量包，只读）。
        返回 Packages 各资源包 Cycle*Capacity 求和：
        total=总量 / remain=剩余 / used=已用；失败降级为不可获取。
        """
        try:
            token, domain, uid, auth = self._load_auth()
            base = f"https://{domain}"
            summary = self._http_json(
                "POST",
                f"{base}/billing/meter/get-user-resource-summary",
                token, uid, payload={},
            )
            data = summary.get("data") if isinstance(summary, dict) else None
            packages = (data or {}).get("Packages") or []
            if not packages:
                return {"available": False, "total": None, "remain": None, "used": None}
            total = sum(float(p.get("CycleTotalCapacity") or 0) for p in packages)
            remain = sum(float(p.get("CycleRemainCapacity") or 0) for p in packages)
            used = sum(float(p.get("CycleUsedCapacity") or 0) for p in packages)
            return {
                "available": True,
                "total": total,
                "remain": remain,
                "used": used,
                "note": "资源包额度",
            }
        except Exception:  # noqa: BLE001 - 查询失败降级为不可获取
            return {"available": False, "total": None, "remain": None, "used": None}