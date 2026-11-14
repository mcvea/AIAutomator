# -*- coding: utf-8 -*-
"""
本机 AI 平台扫描（纯标准库，离线优先）

scan() 返回目录清单（catalog）内每个 AI 平台在本机的：
  - 是否安装（目录 / 卸载注册表 / 运行进程三路证据）
  - 版本与安装路径（来自卸载注册表，尽力获取）
  - 凭据文件清单与登录态判读（sqlite_kv / json / 存在性）
  - 接口信息（已接入平台直接读 automator/platforms/*.toml，保证与引擎同步）

判读等级：
  ok       凭据存在且未到期 / 有明确登录痕迹
  expired  凭据存在但已过期
  found    凭据文件存在，但为加密或私有格式，无法本地判定有效性
  missing  未找到凭据
"""
import json
import os
import re
import sqlite3
import subprocess
import time

try:
    import tomllib  # py3.11+
except ImportError:  # pragma: no cover
    tomllib = None

ROOT = os.path.dirname(os.path.abspath(__file__))
APPDATA = os.environ.get("APPDATA", "")
LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
HOME = os.path.expanduser("~")
PROG64 = os.environ.get("ProgramFiles", r"C:\Program Files")
PROG32 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
LPROG = os.path.join(LOCALAPPDATA, "Programs")

_DAY = 86400

# ---------------------------------------------------------------- 目录清单
# auth: 候选凭据文件，fmt 决定判读器；apis 供未接入平台展示（source 标注出处）

CATALOG = [
    # ---- 已接入 AIAutomator 的 5 个平台（接口信息从 TOML 读取）----
    {
        "key": "lobster", "display": "LobsterAI", "vendor": "网易有道",
        "category": "桌面 Agent", "integrated": True,
        "detect": [r"%APPDATA%\LobsterAI"],
        "processes": ["LobsterAI.exe", "Lobster AI.exe"],
        "reg_keywords": ["LobsterAI", "Lobster AI"],
        "auth": [{"path": r"%APPDATA%\LobsterAI\lobsterai.sqlite", "fmt": "sqlite_kv",
                  "kv_key": "auth_tokens", "note": "kv 表 auth_tokens.accessToken"}],
    },
    {
        "key": "workbuddy", "display": "WorkBuddy", "vendor": "腾讯",
        "category": "桌面 Agent", "integrated": True,
        "detect": [r"%LOCALAPPDATA%\CodeBuddyExtension", r"%LOCALAPPDATA%\@genieworkbuddy-desktop-updater"],
        "processes": ["WorkBuddy.exe", "CodeBuddy.exe"],
        "reg_keywords": ["WorkBuddy", "CodeBuddy"],
        "auth": [{"path": r"%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info",
                  "fmt": "json", "expire": "auth.expiresAt", "unit": "ms",
                  "note": "auth.accessToken + expiresAt（5.6+ 加密信封）"}],
    },
    {
        "key": "dumate", "display": "百度搭子 DuMate", "vendor": "百度",
        "category": "桌面 Agent", "integrated": True,
        "detect": [r"%APPDATA%\qianfan-desktop-app"],
        "processes": ["DuMate.exe", "qianfan"],
        "reg_keywords": ["DuMate", "千帆", "百度搭子"],
        "auth": [{"path": r"%APPDATA%\qianfan-desktop-app\auth.json", "fmt": "exists",
                  "note": "AES-256-GCM 加密 cookies（.cookie-key 同目录）"},
                 {"path": r"%APPDATA%\qianfan-desktop-app\.cookie-key", "fmt": "exists"}],
    },
    {
        "key": "traework", "display": "TraeWork", "vendor": "字节跳动",
        "category": "桌面 Agent", "integrated": True,
        "detect": [r"%APPDATA%\TraeWork", r"%APPDATA%\Trae"],
        "processes": ["TraeWork.exe"],
        "reg_keywords": ["TraeWork"],
        "auth": [{"path": r"%APPDATA%\TraeWork\User\globalStorage\state.vscdb", "fmt": "vscode_db"}],
    },
    {
        "key": "minimax", "display": "MiniMax", "vendor": "MiniMax",
        "category": "桌面 Agent", "integrated": True,
        "detect": [r"%LOCALAPPDATA%\MiniMax", r"%APPDATA%\MiniMax"],
        "processes": ["MiniMax.exe", "MiniMax Code.exe"],
        "reg_keywords": ["MiniMax"],
        "auth": [{"path": r"%APPDATA%\MiniMax\User\globalStorage\state.vscdb", "fmt": "vscode_db"},
                 {"path": r"%LOCALAPPDATA%\MiniMax", "fmt": "dir_presence", "note": "当前仅 installer-logs"}],
    },

    # ---- 本机发现、未接入 ----
    {
        "key": "trae-cn", "display": "Trae CN", "vendor": "字节跳动",
        "category": "AI IDE", "integrated": True,
        "detect": [r"%APPDATA%\Trae CN", r"%LOCALAPPDATA%\Programs\Trae CN"],
        "processes": ["Trae CN.exe", "Trae.exe"],
        "reg_keywords": ["Trae CN"],
        "auth": [{"path": r"%APPDATA%\Trae CN\User\globalStorage\storage.json", "fmt": "icube",
                  "field": "iCubeAuthInfo://icube.cloudide",
                  "note": "AES 信封（token / refreshToken / expiredAt），可在线复核"},
                 {"path": r"%APPDATA%\Trae CN\User\globalStorage\state.vscdb", "fmt": "vscode_db",
                  "note": "键名含 user:<id>，可数出登录过的账号痕迹"}],
        "apis": [{"name": "签到状态", "method": "POST",
                  "url": "https://api.trae.cn/trae/api/v2/ug/checkin_credits/status",
                  "auth": "Cloud-IDE-JWT", "source": "平台实现（platforms/trae_cn.py）"},
                 {"name": "领取积分", "method": "POST",
                  "url": "https://api.trae.cn/trae/api/v2/ug/checkin_credits/claim",
                  "auth": "Cloud-IDE-JWT", "source": "平台实现（platforms/trae_cn.py）"},
                 {"name": "总积分", "method": "GET",
                  "url": "https://api.trae.cn/trae/api/v2/ug/usage_summary",
                  "auth": "Cloud-IDE-JWT", "source": "平台实现（platforms/trae_cn.py）"}],
    },
    {
        "key": "trae-solo", "display": "TRAE SOLO CN", "vendor": "字节跳动",
        "category": "AI IDE", "integrated": False,
        "detect": [r"%APPDATA%\TRAE SOLO CN", r"%LOCALAPPDATA%\Programs\TRAE SOLO CN"],
        "processes": ["TRAE SOLO CN.exe"],
        "reg_keywords": ["TRAE SOLO"],
        "auth": [{"path": r"%APPDATA%\TRAE SOLO CN\User\globalStorage\state.vscdb", "fmt": "vscode_db"}],
        "apis": [{"note": "IDE 内置模型代理，无公开稳定 endpoint", "source": "本地推断"}],
    },
    {
        "key": "qoder", "display": "Qoder CN", "vendor": "阿里",
        "category": "AI IDE", "integrated": False,
        "detect": [r"%LOCALAPPDATA%\Programs\Qoder CN", r"%APPDATA%\Qoder CN"],
        "processes": ["Qoder CN.exe"],
        "reg_keywords": ["Qoder"],
        "auth": [{"path": r"%APPDATA%\Qoder CN\User\globalStorage\state.vscdb", "fmt": "vscode_db"}],
        "apis": [{"note": "IDE 内置模型代理", "source": "本地推断"}],
    },
    {
        "key": "antigravity", "display": "Antigravity", "vendor": "Google",
        "category": "AI IDE", "integrated": False,
        "detect": [r"%APPDATA%\Antigravity", r"%LOCALAPPDATA%\Programs\antigravity"],
        "processes": ["Antigravity.exe"],
        "reg_keywords": ["Antigravity"],
        "auth": [{"path": r"%APPDATA%\Antigravity\User\globalStorage\state.vscdb", "fmt": "vscode_db"}],
        "apis": [{"note": "IDE 内置模型代理（Gemini）", "source": "本地推断"}],
    },
    {
        "key": "deepseek", "display": "DeepSeek 桌面版", "vendor": "深度求索",
        "category": "AI 助手", "integrated": False,
        "detect": [r"%APPDATA%\@deepseek-ai", r"%LOCALAPPDATA%\@deepseek-ai",
                   r"%LOCALAPPDATA%\Programs\DeepSeek Harness"],
        "processes": ["DeepSeek.exe", "DeepSeek Harness.exe"],
        "reg_keywords": ["DeepSeek"],
        "auth": [{"path": r"%APPDATA%\@deepseek-ai\dsh-desktop\Local Storage\leveldb", "fmt": "dir_presence",
                  "note": "登录态在 Local Storage（Chromium 加密）"}],
        "apis": [{"url": "https://api.deepseek.com/chat/completions",
                  "note": "OpenAI 兼容；Bearer sk-…；桌面客户端登录态与此 API 独立",
                  "source": "公开文档"}],
    },
    {
        "key": "codex", "display": "OpenAI Codex CLI", "vendor": "OpenAI",
        "category": "CLI Agent", "integrated": False,
        "detect": [r"~\.codex", r"%LOCALAPPDATA%\OpenAI\Codex"],
        "processes": ["codex.exe"],
        "reg_keywords": ["Codex", "OpenAI"],
        "auth": [{"path": r"~\.codex\auth.json", "fmt": "json",
                  "note": "ChatGPT OAuth tokens / OPENAI_API_KEY；缺失即未登录"}],
        "apis": [{"url": "https://api.openai.com/v1", "note": "API Key 模式", "source": "公开文档"},
                 {"url": "https://chatgpt.com/backend-api/", "note": "ChatGPT 登录模式（OAuth）", "source": "公开文档"}],
    },
    {
        "key": "doubao", "display": "豆包桌面版", "vendor": "字节跳动",
        "category": "AI 助手", "integrated": False,
        "detect": [r"%LOCALAPPDATA%\Doubao", r"%APPDATA%\Doubao"],
        "processes": ["Doubao.exe", "DoubaoLinkRouter.exe"],
        "reg_keywords": ["豆包", "Doubao"],
        "auth": [{"path": r"%LOCALAPPDATA%\Doubao\User Data\Default\Network\Cookies", "fmt": "exists",
                  "note": "Chromium Cookies（DPAPI 加密）"}],
        "apis": [{"url": "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
                  "note": "火山方舟 API（需 API Key）；桌面客户端登录态与此独立", "source": "公开文档"}],
    },
    {
        "key": "doudouai", "display": "DoudouAI", "vendor": "未知",
        "category": "AI 工具", "integrated": False,
        "detect": [r"%LOCALAPPDATA%\DoudouAI"],
        "processes": ["DoudouAI.exe"],
        "reg_keywords": ["DoudouAI"],
        "auth": [{"path": r"%LOCALAPPDATA%\DoudouAI", "fmt": "dir_presence"}],
    },
    # ---- 常见但本机未安装（清单占位，装了就能扫到）----
    {
        "key": "cherry-studio", "display": "Cherry Studio", "vendor": "开源",
        "category": "AI 客户端", "integrated": False,
        "detect": [r"%APPDATA%\CherryStudio", r"%LOCALAPPDATA%\Programs\Cherry Studio"],
        "processes": ["Cherry Studio.exe"], "reg_keywords": ["Cherry Studio"],
        "auth": [{"path": r"%APPDATA%\CherryStudio", "fmt": "dir_presence"}],
        "apis": [{"note": "BYOK：用户自带各家 API Key，配置存本地", "source": "公开文档"}],
    },
    {
        "key": "chatbox", "display": "ChatBox", "vendor": "开源",
        "category": "AI 客户端", "integrated": False,
        "detect": [r"%APPDATA%\ChatBox", r"%LOCALAPPDATA%\Programs\Chatbox"],
        "processes": ["Chatbox.exe"], "reg_keywords": ["Chatbox", "ChatBox"],
        "auth": [{"path": r"%APPDATA%\ChatBox", "fmt": "dir_presence"}],
        "apis": [{"note": "BYOK：用户自带各家 API Key", "source": "公开文档"}],
    },
]


# ---------------------------------------------------------------- 基础工具

def _exp(p):
    """展开 %ENV% 与 ~"""
    p = os.path.expandvars(os.path.expanduser(p))
    return p


def _mtime(p):
    try:
        return int(os.path.getmtime(p))
    except OSError:
        return None


def _running_processes():
    """tasklist 一把抓，返回小写进程名集合；失败返回空集"""
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=15).stdout
        names = set()
        for ln in out.splitlines():
            m = re.match(r'^"([^"]+)"', ln.strip())
            if m:
                names.add(m.group(1).lower())
        return names
    except Exception:  # noqa: BLE001
        return set()


def _uninstall_registry():
    """扫卸载注册表 → {显示名小写: {version, install, publisher}}"""
    import winreg
    found = {}
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for root, path in roots:
        try:
            k = winreg.OpenKey(root, path)
        except OSError:
            continue
        with k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                try:
                    sub = winreg.OpenKey(k, winreg.EnumKey(k, i))
                    with sub:
                        def gv(name):
                            try:
                                return winreg.QueryValueEx(sub, name)[0]
                            except OSError:
                                return None
                        disp = gv("DisplayName")
                        if not disp:
                            continue
                        found[disp.lower()] = {
                            "version": gv("DisplayVersion") or "",
                            "install": gv("InstallLocation") or "",
                            "publisher": gv("Publisher") or "",
                        }
                except OSError:
                    continue
    return found


# ---------------------------------------------------------------- 凭据判读器

def _read_json(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _judge_json(p, spec):
    """JSON 凭据：可解析则读过期字段"""
    st = {"path": p, "fmt": "json", "exists": True, "size": os.path.getsize(p),
          "mtime": _mtime(p), "note": spec.get("note", "")}
    try:
        d = _read_json(p)
    except Exception:  # noqa: BLE001
        st.update(state="found", detail="JSON 解析失败（可能加密）")
        return st
    exp = spec.get("expire")
    if exp:
        cur = d
        ok = True
        for part in exp.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and isinstance(cur, (int, float)):
            ts = cur / 1000 if spec.get("unit") == "ms" else cur
            left = ts - time.time()
            st["expires_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            st["state"] = "ok" if left > 0 else "expired"
            if 0 < left < 7 * _DAY:
                st["state"] = "expiring"
            st["detail"] = f"到期时间 {st['expires_at']}"
            st["accounts"] = 1
            st["accounts_kind"] = "real"
            return st
    # 无过期字段：能识别出 token / 账号字段就记 1 个可用账号，否则算不可判读
    if _json_has_credential(d):
        st["accounts"] = 1
        st["accounts_kind"] = "real"
        st.update(state="found", detail="凭据字段存在，过期时间不可判读")
    else:
        st["accounts_kind"] = "unknown"
        st.update(state="found", detail="JSON 存在，无账号/凭据字段可判读")
    return st


def _json_has_credential(d, depth=0):
    """递归找 token/账号类字段（只认键名，不读值，避免误判）"""
    if depth > 3:
        return False
    if isinstance(d, dict):
        for k, v in d.items():
            if re.search(r"(?i)^(access_?token|refresh_?token|id_?token|token|api_?key|"
                         r"account_?id|user_?id|username|email|phone)$", str(k)) and v:
                return True
            if isinstance(v, (dict, list)) and _json_has_credential(v, depth + 1):
                return True
    elif isinstance(d, list):
        return any(_json_has_credential(x, depth + 1) for x in d[:5])
    return False


def _judge_sqlite_kv(p, spec):
    """LobsterAI 模式：kv 表 → auth_tokens.accessToken"""
    st = {"path": p, "fmt": "sqlite_kv", "exists": True,
          "size": os.path.getsize(p), "mtime": _mtime(p),
          "note": spec.get("note", "")}
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        with con:
            row = con.execute(
                "select value from kv where key=?", (spec["kv_key"],)).fetchone()
        con.close()
        if not row:
            st.update(state="missing", detail=f"kv 表无 {spec['kv_key']} 键")
            return st
        raw = row[0]
        try:
            tok = json.loads(raw)
            field = spec.get("token_field", "accessToken")
            has = bool(tok.get(field)) if isinstance(tok, dict) else bool(raw)
            exp = tok.get("expireAt") or tok.get("expiresAt") if isinstance(tok, dict) else None
            if exp:
                ts = exp / 1000 if exp > 1e12 else exp
                left = ts - time.time()
                st["expires_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
                st["state"] = "ok" if left > 0 else "expired"
                if 0 < left < 7 * _DAY:
                    st["state"] = "expiring"
                st["detail"] = f"token 存在，到期 {st['expires_at']}"
            else:
                st.update(state="ok" if has else "missing",
                          detail="token 存在" if has else "token 为空")
        except (ValueError, TypeError):
            st.update(state="found", detail="值非 JSON，无法判读")
        if st.get("state") in ("ok", "expiring", "expired"):
            st["accounts"] = 1
            st["accounts_kind"] = "real"
        elif st.get("state") == "found":
            st["accounts_kind"] = "unknown"
    except sqlite3.Error as e:
        st.update(state="found", detail=f"数据库被占用或不可读：{e}")
    return st


def _judge_vscode_db(p, spec):
    """VS Code 系 IDE：state.vscdb ItemTable 数 user:<id> 键"""
    st = {"path": p, "fmt": "vscode_db", "exists": True,
          "size": os.path.getsize(p), "mtime": _mtime(p),
          "note": spec.get("note", "")}
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        with con:
            ks = [r[0] for r in con.execute("select key from ItemTable")]
        con.close()
    except sqlite3.Error as e:
        st.update(state="found", detail=f"数据库不可读：{e}")
        return st
    uids = set()
    for k in ks:
        m = re.search(r"user[:_](\d{8,})", k)
        if m:
            uids.add(m.group(1))
    if uids:
        st.update(state="ok", accounts=len(uids), accounts_kind="trace",
                  detail=f"{len(uids)} 个账号登录痕迹（token 为 VS Code 加密存储）")
    else:
        st.update(state="missing", accounts=0, accounts_kind="trace",
                  detail=f"{len(ks)} 个键，无账号痕迹 → 未登录")
    return st


def _judge_icube(p, spec):
    """Trae 系 AES 信封（storage.json）：解密读 token 到期，可精确到天"""
    st = {"path": p, "fmt": "icube", "exists": True,
          "size": os.path.getsize(p), "mtime": _mtime(p),
          "note": spec.get("note", "")}
    try:
        storage = _read_json(p)
    except Exception:  # noqa: BLE001
        st.update(state="found", detail="storage.json 解析失败")
        return st
    enc = storage.get(spec.get("field") or "iCubeAuthInfo://icube.cloudide")
    if not enc:
        st.update(state="missing", detail="storage.json 中无登录信封 → 未登录")
        return st
    try:
        from platforms.traework import TraeWorkCheckin
        info = TraeWorkCheckin(dry=True)._decrypt_auth_info(enc)
    except Exception as e:  # noqa: BLE001
        st.update(state="found", detail=f"信封解密失败（{type(e).__name__}），需 pycryptodome")
        return st

    st["accounts"] = 1
    st["accounts_kind"] = "real"
    exp = str(info.get("expiredAt") or "")
    ts = None
    if len(exp) >= 19:
        try:
            from datetime import datetime, timezone
            ts = datetime.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S") \
                       .replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            ts = None
    if ts is None:
        st.update(state="ok", detail="信封可解密，未读到到期时间")
        return st
    left = ts - time.time()
    st["expires_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    st["state"] = "ok" if left > 0 else "expired"
    if 0 < left < 7 * _DAY:
        st["state"] = "expiring"
    tail = "，可自动续期" if info.get("refreshToken") else ""
    st["detail"] = f"token 剩余 {max(0, int(left // _DAY))} 天（到期 {st['expires_at']}）{tail}"
    return st


def _judge_exists(p, spec):
    """存在性判读：文件/目录在即 found"""
    is_dir = os.path.isdir(p)
    st = {"path": p, "fmt": spec.get("fmt", "exists"), "exists": True,
          "mtime": _mtime(p), "note": spec.get("note", "")}
    if is_dir:
        st["detail"] = "目录存在（内部凭据加密或未知格式，账号数不可判读）"
    else:
        st["size"] = os.path.getsize(p)
        st["detail"] = "文件存在（加密或未知格式，账号数不可判读）"
    st["state"] = "found"
    st["accounts_kind"] = "unknown"
    return st


def _judge_auth(p, spec):
    p = _exp(p)
    if not os.path.exists(p):
        return {"path": _exp(p), "fmt": spec.get("fmt"), "exists": False,
                "state": "missing", "note": spec.get("note", "")}
    fmt = spec.get("fmt")
    if fmt == "json":
        return _judge_json(p, spec)
    if fmt == "sqlite_kv":
        return _judge_sqlite_kv(p, spec)
    if fmt == "vscode_db":
        return _judge_vscode_db(p, spec)
    if fmt == "icube":
        return _judge_icube(p, spec)
    return _judge_exists(p, spec)


# ---------------------------------------------------------------- 接口信息

# hook 接管型平台（TOML 无 [platform.apis]），从实现文件常量提取的接口清单
FALLBACK_APIS = {
    "traework": [
        {"name": "签到/积分（hook 接管）", "method": "POST", "url": "https://api.trae.cn",
         "auth": "加密信封 + 设备证明",
         "source": "平台实现（platforms/traework.py）"},
    ],
    "minimax": [
        {"name": "OAuth 续期", "method": "POST", "url": "https://account.minimax.cn/oauth2/token",
         "auth": "refreshToken", "source": "平台实现（platforms/minimax.py）"},
        {"name": "签到/对话（主 host）", "method": "POST", "url": "https://agent.minimax.cn",
         "auth": "Bearer mmoat_* + 签名（1h 寿命自动续期）",
         "source": "平台实现（platforms/minimax.py）"},
        {"name": "余额查询", "method": "GET", "url": "https://www.minimaxi.com",
         "auth": "Bearer + 签名", "source": "平台实现（platforms/minimax.py）"},
    ],
    "workbuddy": [
        {"name": "双域名说明", "method": "-", "url": "https://www.workbuddy.cn 与 https://copilot.tencent.com 均可用",
         "auth": "Bearer token", "source": "平台实现（platforms/workbuddy.py）"},
    ],
    "lobster": [
        {"name": "BASE", "method": "-", "url": "https://lobsterai-server.youdao.com",
         "auth": "Bearer token", "source": "平台实现（platforms/lobster.py）"},
    ],
}


def _toml_apis(toml_path):
    """从已接入平台的 TOML 提取接口清单（与引擎同一份定义）"""
    if not tomllib or not os.path.isfile(toml_path):
        return []
    try:
        with open(toml_path, "rb") as f:
            d = tomllib.load(f)
    except Exception:  # noqa: BLE001
        return []
    apis = []
    for name, api in (d.get("platform", {}).get("apis") or {}).items():
        if not isinstance(api, dict) or not api.get("url"):
            continue
        auth = api.get("auth", "?")
        apis.append({
            "name": name,
            "method": api.get("method", "GET"),
            "url": api["url"],
            "auth": {"bearer": "Bearer token", "raw": "原始头/Cookie",
                     "api_key": "API Key"}.get(auth, auth),
            "source": "平台定义（automator/platforms）",
        })
    return apis


# ---------------------------------------------------------------- 主扫描

def scan():
    """返回 {ts, summary, found:[...], not_installed:[...]}"""
    procs = _running_processes()
    reg = _uninstall_registry()

    found, missing = [], []
    specs = all_specs()
    try:
        specs = specs + discover(specs)      # 自动发现未收录应用（失败不影响主扫描）
    except Exception as e:  # noqa: BLE001
        print(f"[scan] 自动发现失败（已跳过）：{type(e).__name__}: {e}")
    for spec in specs:
        # 手写（非扫描生成）的平台定义 = 真实现，等价于已接入
        integrated = bool(spec.get("integrated")) or has_definition(spec["key"])
        item = {
            "key": spec["key"], "display": spec["display"],
            "vendor": spec.get("vendor", ""), "category": spec.get("category", ""),
            "integrated": integrated,
            "discovered": bool(spec.get("discovered")),
            "catalog": ("discovered" if spec.get("discovered")
                        else ("extra" if spec.get("extra") else "builtin")),
            "install": [], "running": [], "version": "", "publisher": "",
            "auth": [], "apis": [],
        }
        # 安装证据：目录
        installed = False
        for d in spec.get("detect", []):
            p = _exp(d)
            if os.path.isdir(p) or os.path.isfile(p):
                item["install"].append(p)
                installed = True
        # 注册表：版本/发布者
        for kw in spec.get("reg_keywords", []):
            for disp, info in reg.items():
                if kw.lower() in disp:
                    installed = True
                    item["version"] = item["version"] or info["version"]
                    item["publisher"] = item["publisher"] or info["publisher"]
                    if info["install"] and info["install"] not in item["install"]:
                        item["install"].append(info["install"])
        # 运行进程
        for pname in spec.get("processes", []):
            if pname.lower() in procs:
                item["running"].append(pname)
        # 凭据
        for a in spec.get("auth", []):
            item["auth"].append(_judge_auth(a["path"], a))
        # 接口：已接入 → TOML 声明 → hook 兜底 → 目录清单
        if integrated:
            item["apis"] = _toml_apis(
                os.path.join(ROOT, "automator", "platforms", f"{spec['key']}.toml"))
            if not item["apis"]:
                item["apis"] = FALLBACK_APIS.get(spec["key"], [])
            if not item["apis"]:
                item["apis"] = spec.get("apis", [])
        else:
            item["apis"] = spec.get("apis", [])
        # 输出前脱敏：本机绝对路径换写成 %APPDATA% / ~ 形式，不把用户名带给界面与日报
        item["install"] = [_mask_path(p) for p in item["install"]]
        for a in item["auth"]:
            a["path"] = _mask_path(a["path"])
        auth_any = any(a["state"] in ("ok", "expiring", "found") for a in item["auth"])
        item["installed"] = installed or auth_any
        item["login_state"] = _sum_state(item["auth"])
        item["checkin_support"] = checkin_support(spec["key"])["level"]
        item["attached"] = (not integrated) and is_attached(spec["key"])
        (found if item["installed"] else missing).append(item)

    summary = {
        "scanned": len(specs),
        "found": len(found),
        "integrated": sum(1 for i in found if i["integrated"]),
        "discovered": sum(1 for i in found if i["discovered"]),
        "running": sum(1 for i in found if i["running"]),
        "logged_in": sum(1 for i in found if i["login_state"] in ("ok", "expiring")),
    }
    return {"ts": int(time.time()), "summary": summary,
            "found": found, "not_installed": missing}


def _sum_state(auths):
    states = [a["state"] for a in auths if a["exists"]]
    for s in ("expired", "expiring", "ok", "found"):
        if s in states:
            return s
    return "missing" if not states else "missing"


# ---------------------------------------------------------------- 缓存 / 巡检行

_CACHE = {"ts": 0, "data": None}
_CACHE_TTL = 60          # 秒；UI 刷新与每日任务共用，避免重复全盘扫描


def scan_cached(ttl=_CACHE_TTL):
    """带 TTL 的 scan()，供 UI 概览与每日任务复用"""
    now = time.time()
    if _CACHE["data"] and now - _CACHE["ts"] < ttl:
        return _CACHE["data"]
    _CACHE["data"] = scan()
    _CACHE["ts"] = now
    return _CACHE["data"]


def _row_status(state):
    """ok/warn/expired 明确；missing=无登录态；found=凭据存在但加密不可判"""
    return {"ok": "ok", "expiring": "warn", "expired": "expired",
            "missing": "none"}.get(state, "unknown")


def monitor_rows():
    """每日巡检行：本机已发现、但未接入签到引擎且未手工纳入的平台"""
    rows = []
    for it in scan_cached()["found"]:
        if it["integrated"] or it.get("attached"):
            continue
        if it.get("discovered"):
            continue        # 未收录应用不进日报巡检，避免噪声；收录/加入签到后才参与
        detail = "；".join(a.get("detail", "") for a in it["auth"] if a["exists"]) or "未发现凭据文件"
        rows.append({
            "platform": it["display"],
            "category": it["category"],
            "status": _row_status(it["login_state"]),
            "days_left": None,
            "message": detail,
            "source": "本机凭据巡检",
        })
    return rows


# ---------------------------------------------------------------- 账号管理清单

def _mask_path(p):
    """路径脱敏：用户目录 / AppData / 程序目录换写成环境变量写法"""
    if not p:
        return ""
    low = p.lower()
    for base, tag in ((LOCALAPPDATA, "%LOCALAPPDATA%"), (APPDATA, "%APPDATA%"),
                      (PROG64, "%ProgramFiles%"), (PROG32, "%ProgramFiles(x86)%"),
                      (HOME, "~")):
        if base and low.startswith(base.lower()):
            return tag + p[len(base):]
    return p


def inventory():
    """账号管理页的统一清单：本机发现的全部平台，含已接入 / 已加入签到。
    与 scan() 共用一次扫描（60s TTL），按纳管状态分组，账号数取自凭据判读。"""
    data = scan_cached()
    rows = []
    for it in data["found"]:
        if it["integrated"]:
            scope = "integrated"
        elif it.get("attached"):
            scope = "attached"
        else:
            scope = "external"
        files = [{
            "path": _mask_path(a.get("path", "")),
            "state": a["state"],
            "accounts": int(a.get("accounts") or 0),
            "accounts_kind": a.get("accounts_kind") or ("unknown" if not a.get("accounts") else "trace"),
            "expires_at": a.get("expires_at", ""),
            "age_days": _age_days(a.get("mtime")),
            "detail": a.get("detail") or a.get("note") or "",
        } for a in it["auth"] if a.get("exists")]
        # 账号数：真凭据优先（可直接用于签到），其次历史痕迹，都没有才算不可判读
        judged = [f for f in files if f["accounts_kind"] in ("real", "trace")]
        real = [f for f in judged if f["accounts_kind"] == "real" and f["accounts"]]
        if real:
            accounts, acc_kind = sum(f["accounts"] for f in real), "real"
        elif judged:
            accounts, acc_kind = max(f["accounts"] for f in judged), "trace"
        elif files:
            accounts, acc_kind = 0, "unknown"      # 有凭据但格式不可判读
        else:
            accounts, acc_kind = 0, "none"         # 压根没有凭据 = 确定 0 个
        # 登录态校验级别：已接入=可用真实动作确认；能读到到期=本地实证；其余仅文件存在
        if it["integrated"]:
            verify = "api"
        elif any(f["expires_at"] for f in files):
            verify = "expiry"
        else:
            verify = "file"
        ages = [f["age_days"] for f in files if f["age_days"] is not None]
        support = checkin_support(it["key"])
        apis = [{
            "name": a.get("name") or "说明",
            "method": a.get("method") or "-",
            "url": a.get("url") or "",
            "auth": a.get("auth") or "",
            "source": a.get("source") or "",
            "note": a.get("note") or "",
        } for a in it["apis"]]
        rows.append({
            "key": it["key"], "display": it["display"],
            "vendor": it["vendor"], "category": it["category"],
            "version": it["version"], "running": it["running"],
            "scope": scope, "integrated": it["integrated"],
            "attached": bool(it.get("attached")),
            "discovered": bool(it.get("discovered")),
            "catalog": it.get("catalog", "builtin"),
            "login_state": it["login_state"],
            "accounts": accounts, "accounts_kind": acc_kind,
            "verify": verify,
            "checkin_support": support["level"],
            "checkin_note": support["note"],
            "fresh_days": min(ages) if ages else None,
            "mode": ("real" if it["integrated"]
                     else ("monitor" if it.get("attached") else "")),
            "credential": files[0]["path"] if files else "",
            "detail": "；".join(f["detail"] for f in files) or "未发现凭据文件",
            "files": files, "apis": apis, "api_count": len(apis),
        })
    order = {"integrated": 0, "attached": 1, "external": 2}
    rows.sort(key=lambda r: (order[r["scope"]], r["display"].lower()))
    summary = {
        "total": len(rows),
        "integrated": sum(1 for r in rows if r["scope"] == "integrated"),
        "attached": sum(1 for r in rows if r["scope"] == "attached"),
        "external": sum(1 for r in rows if r["scope"] == "external"),
        "discovered": sum(1 for r in rows if r["discovered"]),
        "logged_in": sum(1 for r in rows if r["login_state"] in ("ok", "expiring")),
        "pending": sum(1 for r in rows if r["login_state"] == "found"),
        "accounts": sum(r["accounts"] for r in rows if r["accounts_kind"] == "real"),
        "trace_accounts": sum(r["accounts"] for r in rows if r["accounts_kind"] == "trace"),
        "unknown_accounts": sum(1 for r in rows if r["accounts_kind"] == "unknown"),
    }
    return {"ts": data["ts"], "summary": summary, "rows": rows}


def _age_days(mtime):
    if not mtime:
        return None
    return int(max(0.0, (time.time() - mtime) // _DAY))


# ---------------------------------------------------------------- 签到能力判定
# 逐个翻过客户端安装目录里的接口字面量后得出的结论：
#   none    = 这个平台根本没有"每日签到"这类活动，接协议无从谈起
#   unknown = 有疑似痕迹但拿不到可调用接口（典型是网页版签到，在页面里点）
#   real    = 有签到接口且已实现（手写平台定义）
NO_CHECKIN = {
    "antigravity": "客户端内只有 Google 登录，无签到/积分接口",
    "qoder": "客户端内只有 /users/sign-in（网页登录），无每日签到接口",
    "deepseek": "客户端内未见签到接口（命中的 checkin 字样来自 pnpm 运行时内部）",
    "codex": "Codex CLI 为订阅制，无每日签到/积分活动",
    "doudouai": "客户端目录为空（仅残留），无签到接口",
}
UNSURE_CHECKIN = {
    "doubao": "签到若存在也在网页里完成，客户端内未找到可调用接口",
}


def checkin_support(key):
    """返回 {level, note}：能不能真签到，以及依据"""
    if has_definition(key):
        return {"level": "real", "note": "已实现签到协议"}
    if key in NO_CHECKIN:
        return {"level": "none", "note": NO_CHECKIN[key]}
    if key in UNSURE_CHECKIN:
        return {"level": "unknown", "note": UNSURE_CHECKIN[key]}
    return {"level": "unknown", "note": "未找到可调用的签到接口"}


def sync_enabled():
    """把"已加入签到列表"的平台补进 config/user.toml 的 enabled 列表

    两处状态（.local.toml 文件 / enabled 白名单）会漂移：文件在、白名单没写，
    表现为"UI 显示已加入签到，但每日任务不跑它"。这里做一次性对齐。
    """
    path = os.path.join(ROOT, "config", "user.toml")
    if not os.path.isfile(path):
        return []
    try:
        txt = open(path, encoding="utf-8").read()
    except OSError:
        return []
    m = re.search(r"^\s*enabled\s*=\s*(\[.*?\])", txt, re.M)
    if not m:
        return []
    try:
        names = json.loads(m.group(1))
        if not isinstance(names, list):
            return []
    except ValueError:
        return []
    have = {s["key"] for s in all_specs() if os.path.isfile(platform_file(s["key"]))}
    add = sorted(have - set(names))
    if not add:
        return names
    names = names + add
    new = txt[:m.start(1)] + json.dumps(names, ensure_ascii=False) + txt[m.end(1):]
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(new)
    except OSError:
        return names
    _CACHE["ts"] = 0
    return names


def invalidate():
    """丢弃扫描缓存，让下一次 scan_cached 重新全盘扫"""
    _CACHE["ts"] = 0


# ---------------------------------------------------------------- 清单扩展：覆盖面
# 内置 CATALOG 是"已知清单"；这里提供两件事把覆盖面做成可增长的：
#   1) config/platforms.extra.toml —— 用户收录的平台，与内置清单同等判读
#   2) discover() —— 扫没收录的疑似 AI 应用，识别其凭据格式，可一键收录

EXTRA_TOML = os.path.join(ROOT, "config", "platforms.extra.toml")

# 凭据特征：命中即认为该目录是一个"有登录态"的 AI 客户端
_CRED_MARKERS = [
    (r"User\globalStorage\state.vscdb", "vscode_db", "VS Code 系 IDE 状态库"),
    (r"User\globalStorage\storage.json", "icube", "Trae 系登录信封"),
    (r"Network\Cookies", "exists", "Chromium Cookie 库（加密，仅能判存在）"),
    (r"Local Storage\leveldb", "exists", "Chromium Local Storage（加密，仅能判存在）"),
    (r"auth.json", "json", "JSON 凭据文件"),
]

# 目录名关键词：按"分词"匹配（不是子串），避免 baidunetdisk 这种把 ai 当地名
_AI_WORDS = ("ai", "gpt", "chat", "claude", "gemini", "copilot", "cursor", "trae",
             "qoder", "kimi", "tongyi", "bailian", "deepseek", "doubao", "minimax",
             "llm", "agent", "assistant", "bot", "mate", "spark", "hunyuan", "wenxin")
_DISC_SKIP = {"node_modules", ".git", "Cache", "Code Cache", "GPUCache",
              "Service Worker", "blob_storage", "Crashpad"}


def _name_tokens(name):
    """QwenChatTest → [qwen, chat, test]；baidunetdisk → [baidunetdisk]"""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", s) if t]


def _name_hits(name):
    """分词后精确命中（或 token 以关键词开头），不做反向包含，
    否则 mini → minimax、ai → 任意含 ai 的目录都会误报"""
    for t in _name_tokens(name):
        if len(t) < 2:
            continue
        for w in _AI_WORDS:
            if t == w or (len(w) >= 4 and t.startswith(w)):
                return True
    return False


def extra_specs():
    """读取用户收录的额外平台（config/platforms.extra.toml）"""
    if not tomllib or not os.path.isfile(EXTRA_TOML):
        return []
    try:
        with open(EXTRA_TOML, "rb") as f:
            d = tomllib.load(f)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for s in d.get("platform") or []:
        if isinstance(s, dict) and s.get("key") and s.get("display"):
            s["extra"] = True
            out.append(s)
    return out


def all_specs():
    return CATALOG + extra_specs()


def _slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if len(s) < 2:
        import hashlib
        s = "app-" + hashlib.md5(name.encode("utf-8")).hexdigest()[:6]
    return s[:28]


def _covered_dirs(specs):
    """已收录的目录（用于排除重复发现）；根目录本身不算"已覆盖"，
    否则 %APPDATA% 这类根会把子目录全部误判成重复"""
    roots = {os.path.normcase(x) for x in (APPDATA, LOCALAPPDATA, HOME, PROG64, PROG32) if x}
    out = []
    for s in specs:
        for d in s.get("detect") or []:
            out.append(os.path.normcase(_exp(d)))
        for a in s.get("auth") or []:
            p = _exp(a.get("path", ""))
            out.append(os.path.normcase(p))
            out.append(os.path.normcase(os.path.dirname(p)))
    return [p for p in out if p and p not in roots]


def discover(specs=None):
    """扫未收录的疑似 AI 应用：命中目录名关键词 + 存在已知凭据特征才算

    返回与 CATALOG 同结构的 spec（discovered=True），可直接参与 scan 的组装。
    """
    specs = specs if specs is not None else all_specs()
    covered = _covered_dirs(specs)
    taken = {s["key"] for s in specs}
    known = {s["key"] for s in CATALOG}
    found, seen = [], set()

    for root in (LPROG, LOCALAPPDATA, APPDATA):
        if not root or not os.path.isdir(root):
            continue
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if not _name_hits(name):
                continue
            base = os.path.join(root, name)
            if not os.path.isdir(base):
                continue
            norm = os.path.normcase(base)
            if norm in seen or any(norm == c or norm.startswith(c + os.sep) or
                                   c.startswith(norm + os.sep) for c in covered):
                continue
            seen.add(norm)
            hit = _probe_cred(base)
            if not hit:
                continue
            rel, fmt, note = hit
            key = "disc-" + _slug(name)
            # 与已收录平台同一个应用的不同安装目录 → 跳过，避免 Qoder 出现两行
            if key in taken or any(k and k in key for k in known):
                continue
            taken.add(key)
            found.append({
                "key": key, "display": name, "vendor": "", "category": "未收录",
                "detect": [_mask_path(base)], "processes": [], "reg_keywords": [],
                "auth": [{"path": _mask_path(os.path.join(base, rel)),
                          "fmt": fmt, "note": note}],
                "apis": [{"note": "未收录平台，接口未知（收录后按凭据格式自动判读）",
                          "source": "自动发现"}],
                "discovered": True,
            })
    return found


def _probe_cred(base):
    """在目录内（深度≤3）找已知凭据特征，返回 (相对路径, fmt, note)"""
    for dirpath, dirnames, files in os.walk(base):
        depth = dirpath[len(base):].count(os.sep)
        if depth >= 3:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in _DISC_SKIP]
        low_files = {f.lower(): f for f in files}
        rel_dir = os.path.relpath(dirpath, base)
        for pattern, fmt, note in _CRED_MARKERS:
            tail = pattern.split("\\")[-1]
            if tail.lower() in low_files:
                rel = tail if rel_dir == "." else os.path.join(rel_dir, tail)
                return rel, fmt, note + "（自动发现，未验证）"
    return None


def _toml_escape(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def _write_extra(specs):
    lines = ["# 由「平台扫描 · 未收录应用」收录；可手工编辑，删除对应 [[platform]] 段即移出清单",
             "# 与内置清单同等判读：凭据格式决定能否读到到期时间 / 数出账号数", ""]
    for s in specs:
        lines += [
            "[[platform]]",
            f"key = \"{_toml_escape(s['key'])}\"",
            f"display = \"{_toml_escape(s['display'])}\"",
            f"vendor = \"{_toml_escape(s.get('vendor', ''))}\"",
            f"category = \"{_toml_escape(s.get('category') or 'AI 客户端')}\"",
            "detect = [" + ", ".join(f'"{_toml_escape(d)}"' for d in (s.get("detect") or [])) + "]",
            "processes = [" + ", ".join(f'"{_toml_escape(p)}"' for p in (s.get("processes") or [])) + "]",
            "reg_keywords = [" + ", ".join(f'"{_toml_escape(k)}"' for k in (s.get("reg_keywords") or [])) + "]",
        ]
        for a in s.get("auth") or []:
            lines += ["[[platform.auth]]",
                      f"path = \"{_toml_escape(a.get('path', ''))}\"",
                      f"fmt = \"{_toml_escape(a.get('fmt', 'exists'))}\"",
                      f"note = \"{_toml_escape(a.get('note', ''))}\""]
        lines.append("")
    os.makedirs(os.path.dirname(EXTRA_TOML), exist_ok=True)
    with open(EXTRA_TOML, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def add_to_catalog(key):
    """把自动发现的平台收录进 config/platforms.extra.toml（幂等）"""
    specs = extra_specs()
    if any(s["key"] == key for s in specs):
        spec = next(s for s in specs if s["key"] == key)
        return {"ok": True, "msg": f"{spec['display']} 已在清单中", "created": False}
    spec = next((s for s in discover() if s["key"] == key), None)
    if not spec:
        return {"ok": False, "msg": "未找到该应用，请重新扫描后再试"}
    specs.append(spec)
    _write_extra(specs)
    _CACHE["ts"] = 0
    return {"ok": True, "msg": f"{spec['display']} 已收录进清单", "created": True,
            "file": EXTRA_TOML}


def remove_from_catalog(key):
    """从 extra 清单移出（只动 extra，不碰内置清单与手写平台定义）"""
    specs = extra_specs()
    keep = [s for s in specs if s["key"] != key]
    if len(keep) == len(specs):
        return {"ok": False, "msg": "该平台不在收录清单中"}
    _write_extra(keep)
    _CACHE["ts"] = 0
    return {"ok": True, "msg": "已从收录清单移出"}


# ---------------------------------------------------------------- 手工纳入签到列表

AUTO_MARK = "# 由「平台扫描」自动生成"
PLATFORM_DIR = os.path.join(ROOT, "automator", "platforms")


def _toml_str(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def hand_written_file(key):
    """手写（随仓库分发）的平台定义"""
    return os.path.join(PLATFORM_DIR, f"{key}.toml")


def platform_file(key):
    """扫描生成的平台定义：<key>.local.toml

    单独后缀的原因：这份文件写着本机凭据路径（逐机不同），必须被
    .gitignore 的 *.local.toml 排除，不能和手写定义混在同一个文件名空间里。
    """
    return os.path.join(PLATFORM_DIR, f"{key}.local.toml")


def is_attached(key):
    return os.path.isfile(platform_file(key))


def has_definition(key):
    """该平台是否已有手写定义 —— 视为真实现，已接入引擎"""
    return os.path.isfile(hand_written_file(key))


def template(key, display, vendor="", category="", auth_path="", note=""):
    """生成平台定义骨架：health/checkin 走 monitor_checkin（本地巡检，签到待接入）"""
    lines = [
        AUTO_MARK + "（可手工编辑；删除本文件即移出签到列表）",
        "# 签到接口待接入：当前每日只读本机凭据巡检登录态，不会伪造签到结果",
        "",
        "[platform]",
        f"name = {_toml_str(key)}",
        f"display = {_toml_str(display)}",
        f"vendor = {_toml_str(vendor)}",
        f"category = {_toml_str(category)}",
        "daily_credits = 0",
        "enabled = true",
        'source = "scan"',
        f"source_key = {_toml_str(key)}",
        f"credential_hint = {_toml_str(auth_path)}",
        f"note = {_toml_str(note)}",
        "",
        "[platform.hooks]",
        'checkin = "monitor_checkin"',
        'health = "monitor_checkin"',
        'total = "monitor_checkin"',
        "",
    ]
    return "\n".join(lines)


def register(key):
    """把扫描到的平台写入 automator/platforms/<key>.local.toml（幂等）"""
    data = scan_cached()
    item = next((i for i in data["found"] + data["not_installed"] if i["key"] == key), None)
    if not item:
        return {"ok": False, "msg": f"清单中没有平台 {key}"}
    if item.get("integrated"):
        return {"ok": False, "msg": f"{item['display']} 已由平台定义接入，无需重复添加"}
    if has_definition(key):
        return {"ok": False, "msg": f"{item['display']} 已有手写平台实现，无需加入巡检"}
    if is_attached(key):
        return {"ok": True, "msg": f"{item['display']} 已在签到列表", "created": False}
    auth_path = next((a["path"] for a in item["auth"] if a["exists"]), "")
    note = "；".join(a.get("detail", "") for a in item["auth"] if a["exists"]) or "未发现凭据文件"
    content = template(key, item["display"], item.get("vendor", ""),
                       item.get("category", ""), auth_path, note)
    with open(platform_file(key), "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    _CACHE["ts"] = 0  # 让下一次 scan 重新计算 attached 标记
    sync_enabled()    # 同时补进 enabled 白名单，避免"显示已加入但每日不跑"
    return {"ok": True, "msg": f"{item['display']} 已加入签到列表（签到接口待接入，先按日巡检）",
            "created": True, "file": platform_file(key)}


def unregister(key):
    """移出签到列表：只删自动生成的定义文件"""
    p = platform_file(key)
    if not os.path.isfile(p):
        return {"ok": False, "msg": "该平台不在自动纳管列表"}
    if not is_attached(key):
        return {"ok": False, "msg": "该平台定义不是扫描生成的，拒绝删除"}
    os.remove(p)
    _CACHE["ts"] = 0
    return {"ok": True, "msg": "已移出签到列表", "file": p}


if __name__ == "__main__":
    r = scan()
    print(json.dumps(r["summary"], ensure_ascii=False))
    for i in r["found"]:
        line = f"  {i['display']:<18} {i['category']:<8} 登录={i['login_state']:<8}"
        line += f" 运行中" if i["running"] else ""
        print(line)
    print("未安装:", ", ".join(i["display"] for i in r["not_installed"]))
