# -*- coding: utf-8 -*-
"""
AIAutomator 本地控制台（零依赖 Web UI）

    python ui_server.py            # 启动并自动打开浏览器
    python ui_server.py --port 8765
    python ui_server.py --no-browser

- 仅绑定 127.0.0.1，不对外网暴露
- 长任务（签到/续期等）在后台线程执行，前端轮询取日志
- 全部功能复用 automator 引擎与账号管理脚本，不复制业务逻辑
"""
import argparse
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from automator import engine, config as cfg  # noqa: E402
from automator import notifier  # noqa: E402
from platforms import wb_auth, trae_auth  # noqa: E402

UI_DIR = os.path.join(ROOT, "ui")
VENV_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
PY_EXE = VENV_PY if os.path.isfile(VENV_PY) else sys.executable
LOG_FILE = os.path.join(ROOT, "logs", "task-run.log")
SCHED_TASK = "AIAutomatorDaily"

# ---------------------------------------------------------------- jobs

JOBS = {}          # id -> {kind,status,lines,result,ts}
JOBS_LOCK = threading.Lock()


class _StdoutTap(io.TextIOBase):
    """把引擎/子进程的 stdout 行捕获进 job.lines"""

    def __init__(self, lines):
        self.lines = lines
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self.lines.append(line.rstrip())

    def flush(self):
        pass


def start_job(kind, fn):
    jid = uuid.uuid4().hex[:8]
    job = {"id": jid, "kind": kind, "status": "running",
           "lines": [], "result": None, "ts": time.time()}
    with JOBS_LOCK:
        JOBS[job["id"]] = job

    def target():
        old = sys.stdout
        tap = _StdoutTap(job["lines"])
        sys.stdout = tap
        try:
            job["result"] = fn()
            job["status"] = "done"
        except Exception as e:  # noqa: BLE001
            job["lines"].append(f"[错误] {type(e).__name__}: {e}")
            job["status"] = "error"
        finally:
            sys.stdout = old
            if tap._buf.strip():
                job["lines"].append(tap._buf.rstrip())

    threading.Thread(target=target, daemon=True, name=f"job-{jid}").start()
    return job


def run_stream(kind, argv):
    """跑仓库内的账号管理脚本，逐行透传输出"""
    proc = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace",
                            bufsize=1)
    for line in proc.stdout:
        yield line.rstrip()
    proc.wait()
    yield f"[exit={proc.returncode}]"


# ---------------------------------------------------------------- helpers

def _platform_cards():
    platforms = cfg.load_platforms()
    user = cfg.load_user_config()
    enabled_list = (user.get("platforms") or {}).get("enabled") or None
    cards = []
    for p in platforms:
        on = True if enabled_list is None else p.get("name") in enabled_list
        cards.append({
            "name": p.get("name"),
            "display": p.get("display", p.get("name")),
            "daily_credits": p.get("daily_credits", 0),
            "auth": (p.get("auth") or {}).get("type")
                    or ("本机凭据巡检" if p.get("source") == "scan" else "?"),
            "source": p.get("source", "definition"),
            "enabled": bool(p.get("enabled", True)) and on,
        })
    return cards


def _discovered():
    """本机扫描到的、未接入签到引擎的平台（只读展示，不参与签到）"""
    try:
        import platform_scan
        found = platform_scan.scan_cached()["found"]
    except Exception:  # noqa: BLE001
        return []
    out = []
    for it in found:
        if it["integrated"] or it.get("attached"):
            continue
        out.append({
            "key": it["key"],
            "display": it["display"],
            "vendor": it["vendor"],
            "category": it["category"],
            "version": it["version"],
            "running": it["running"],
            "login_state": it["login_state"],
            "detail": "；".join(a.get("detail", "") for a in it["auth"] if a["exists"]) or "未发现凭据文件",
            "auth_path": next((a["path"] for a in it["auth"] if a["exists"]), ""),
            "api_count": len(it["apis"]),
        })
    return out


def _set_platform_enabled(name, on):
    """写 config/user.toml 的 [platforms] enabled 列表"""
    path = os.path.join(ROOT, "config", "user.toml")
    names = [c["name"] for c in _platform_cards() if c["name"] != name and c["enabled"]]
    if on:
        names.append(name)
    lines = []
    seen = False
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    out, in_platforms = [], False
    for ln in lines:
        if ln.strip().startswith("[platforms]"):
            in_platforms = True
            seen = True
            out.append(ln)
            out.append(f"enabled = {json.dumps(names)}\n")
            out.append("# ↑ 由 UI 维护的启用平台列表\n")
            continue
        if in_platforms and re.match(r"\s*enabled\s*=", ln):
            continue
        if in_platforms and ln.strip().startswith("# ↑ 由 UI"):
            continue
        if ln.strip().startswith("[") and not ln.strip().startswith("[platforms]"):
            in_platforms = False
        out.append(ln)
    if not seen:
        out.insert(0, "[platforms]\n")
        out.insert(1, f"enabled = {json.dumps(names)}\n\n")
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(out)
    return names


def _account_rows(kind):
    store = wb_auth if kind == "wb" else trae_auth
    rows = []
    for acc in store.list_accounts():
        data = None
        try:
            data = store.load_account(acc["path"])
        except Exception:  # noqa: BLE001
            pass
        days = store.days_left(data) if data else None
        expired = store.is_expired(data) if data else False
        rows.append({
            "label": acc.get("label"),
            "uid": store.mask_uid(acc.get("uid") or ""),
            "days_left": ("已过期" if expired else (f"{days} 天" if days is not None else "未知")),
            "disabled": bool(acc.get("disabled")),
            "has_refresh": bool(data and (data.get("auth") or {}).get("refreshToken")) if kind == "wb" else None,
        })
    return rows


def _schedule_status():
    try:
        out = subprocess.run(
            ["schtasks", "/query", "/tn", SCHED_TASK, "/fo", "LIST"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=15).stdout
    except Exception:  # noqa: BLE001
        return {"registered": False}
    reg = SCHED_TASK in out
    nxt, status = "", ""
    for ln in out.splitlines():
        low = ln.strip().lower()
        if "下次运行时间" in ln or "next run time" in low:
            nxt = ln.split(":", 1)[-1].strip()
        if ln.strip().startswith(("状态", "status")) or "状态:" in ln:
            status = ln.split(":", 1)[-1].strip()
    return {"registered": reg, "next_run": nxt, "status": status}


def _totals_history():
    logs = os.path.join(ROOT, "logs")
    snaps = []
    if os.path.isdir(logs):
        for fn in sorted(os.listdir(logs), reverse=True):
            m = re.match(r"^totals-(\d{4}-\d{2}-\d{2})\.json$", fn)
            if m:
                try:
                    with open(os.path.join(logs, fn), "r", encoding="utf-8-sig") as f:
                        snaps.append({"date": m.group(1), "totals": json.load(f)})
                except Exception:  # noqa: BLE001
                    pass
            if len(snaps) >= 7:
                break
    return snaps


_MOJI_MARKS = ("锟", "鐧", "閿", "楠", "濞", "鎴", "鐘")


def _fix_mojibake(s: str) -> str:
    """计划任务控制台把 UTF-8 输出按 GBK 落盘造成双重编码（成功→鐧炬垚）。
    行内被吞掉的字节会变成 '?' 并破坏整行还原，故按 '?' 分段尽力还原。"""
    if not any(m in s for m in _MOJI_MARKS):
        return s
    parts = s.split("?")
    fixed_parts = []
    for p in parts:
        try:
            fixed_parts.append(p.encode("gbk").decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed_parts.append(p)
    fixed = "?".join(fixed_parts)
    return fixed if fixed != s else s


def _log_tail(n=150):
    if not os.path.isfile(LOG_FILE):
        return ["（暂无日志）"]
    with open(LOG_FILE, "rb") as f:
        try:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 200_000))
            data = f.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ["（日志读取失败）"]
    lines = [ln for ln in data.splitlines() if ln.strip()]
    return [_fix_mojibake(ln) for ln in lines[-n:]]


# ---------------------------------------------------------------- job impls

def _job_daily(dry, no_notify):
    out = engine.run_task("daily", dry=dry)
    for r in out["results"]:
        print(f"[{r.get('platform')}] {r.get('status')} - {r.get('message')}")
    if out["report"]:
        print("\n" + out["report"])
        if not dry and not no_notify:
            notifier.notify_daily({
                "results": out["results"],
                "totals": out.get("totals") or [],
                "credits": out.get("credits") or [],
                "healths": out.get("healths") or [],
                "report": out["report"],
                "prev_totals": out.get("prev_totals") or {},
            })
            print("\n[通知] 已推送飞书")
        elif dry:
            print("\n[只读] 试跑完成，未签到未通知")
    return {"results": out["results"], "totals": out["totals"],
            "credits": out["credits"], "healths": out["healths"]}


def _job_scan_health():
    """平台扫描页：对已接入平台做联网登录态校验（走引擎 health hook）"""
    out = []
    for p in cfg.load_platforms(only_enabled=True):
        r = engine.platform_health(p)
        rows = r if isinstance(r, list) else [r]
        for row in rows:
            ok = row.get("status") == "ok"
            out.append({
                "platform": row.get("platform", p.get("name")),
                "status": row.get("status", "unknown"),
                "days_left": row.get("days_left"),
                "message": row.get("message", ""),
            })
            print(f"{out[-1]['platform']}: {row.get('status', '?')} "
                  f"({row.get('days_left') if row.get('days_left') is not None else '-'} 天) "
                  f"{out[-1]['message']}")
    return {"healths": out}


def _job_status():
    """仪表盘刷新：健康 + 总积分，一次拿全"""
    platforms = cfg.load_platforms(only_enabled=True)
    healths, totals = [], []
    for p in platforms:
        r = engine.platform_health(p)
        healths.extend(r if isinstance(r, list) else [r])
    for p in platforms:
        totals.append(engine.platform_total(p))
    for t in totals:
        name = t.get("platform")
        if t.get("available") and t.get("total") is not None:
            print(f"{name}: {t['total']:g} 分")
        else:
            print(f"{name}: 接口未提供")
    return {"healths": healths, "totals": totals}


def _job_credits():
    platforms = cfg.load_platforms(only_enabled=True)
    items = []
    for p in platforms:
        items.extend(engine.platform_credits(p))
    if not items:
        print("暂无积分到期信息")
    for it in items:
        print(f"{it.get('platform')}·{it.get('label')}: {it.get('credits'):g} 分 "
              f"到期 {it.get('expires_at')}（剩 {it.get('days_left')} 天）")
    return {"credits": items}


def _job_notify_test():
    res = notifier.notify("通知通道测试成功！AIAutomator 通知链路正常。")
    for ch, ok in res.items():
        print(f"{'OK' if ok else 'FAIL'} {ch}")
    return {"channels": res}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "AIAutomatorUI/1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    # ---- basics
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except Exception:  # noqa: BLE001
            return {}

    def _guard(self):
        host = self.headers.get("Host", "")
        if host.split(":")[0] not in ("127.0.0.1", "localhost"):
            self._json({"error": "forbidden"}, 403)
            return False
        return True

    def _file(self, rel):
        path = os.path.join(UI_DIR, rel)
        if not os.path.isfile(path):
            self._json({"error": "not found"}, 404)
            return
        ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                 "css": "text/css; charset=utf-8", "png": "image/png",
                 "svg": "image/svg+xml", "ico": "image/x-icon"}.get(
                     rel.rsplit(".", 1)[-1], "application/octet-stream")
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- GET
    def do_GET(self):
        if not self._guard():
            return
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            return self._file("index.html")
        if path.startswith("/static/"):
            return self._file(path[len("/static/"):])
        if path == "/api/overview":
            return self._json({
                "platforms": _platform_cards(),
                "discovered": _discovered(),
                "schedule": _schedule_status(),
                "totals_history": _totals_history(),
                "user_toml_exists": os.path.isfile(os.path.join(ROOT, "config", "user.toml")),
                "notify_configured": bool(notifier._load_secrets().get("notify")),
            })
        if path == "/api/accounts":
            kind = self.path.split("kind=")[-1] if "kind=" in self.path else "wb"
            return self._json({"accounts": _account_rows(kind)})
        if path == "/api/logs":
            return self._json({"lines": _log_tail()})
        if path == "/api/scan":
            import platform_scan
            try:
                platform_scan.invalidate()      # 手动扫描要拿新的，顺手给账号页热缓存
                return self._json(platform_scan.scan_cached())
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        if path == "/api/accounts/platforms":
            import platform_scan
            try:
                data = platform_scan.inventory()
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            managed = {}
            for key, store in (("workbuddy", wb_auth), ("traework", trae_auth)):
                try:
                    managed[key] = len(store.list_accounts())
                except Exception:  # noqa: BLE001
                    managed[key] = None
            anchors = {"workbuddy": "#card-wb", "traework": "#card-trae"}
            for r in data["rows"]:
                r["managed_accounts"] = managed.get(r["key"])
                r["anchor"] = anchors.get(r["key"], "")
            return self._json(data)
        if path.startswith("/api/job/"):
            jid = path.rsplit("/", 1)[-1]
            job = JOBS.get(jid)
            if not job:
                return self._json({"error": "unknown job"}, 404)
            return self._json({k: job[k] for k in ("id", "kind", "status", "lines", "result")})
        return self._json({"error": "not found"}, 404)

    # ---- POST
    def do_POST(self):
        if not self._guard():
            return
        path = self.path.split("?")[0]
        body = self._body()

        # ---- 任务类（后台线程）
        if path == "/api/logs/clear":
            try:
                os.truncate(LOG_FILE, 0)
                return self._json({"ok": True})
            except OSError as e:
                return self._json({"ok": False, "msg": str(e)})
        if path == "/api/run/daily":
            j = start_job("daily", lambda: _job_daily(
                bool(body.get("dry")), bool(body.get("no_notify"))))
            return self._json({"job": j["id"]})
        if path == "/api/run/status":
            j = start_job("status", _job_status)
            return self._json({"job": j["id"]})
        if path == "/api/scan/health":
            j = start_job("scan-health", _job_scan_health)
            return self._json({"job": j["id"]})
        if path == "/api/run/credits":
            j = start_job("credits", _job_credits)
            return self._json({"job": j["id"]})
        if path == "/api/run/notify-test":
            j = start_job("notify-test", _job_notify_test)
            return self._json({"job": j["id"]})

        # ---- 账号脚本类（子进程透传）
        if path == "/api/accounts/job":
            kind, act = body.get("kind"), body.get("action")
            script = {"wb": "wb_accounts.py", "trae": "trae_accounts.py"}.get(kind)
            if not script:
                return self._json({"error": "bad kind"}, 400)
            argv_map = {
                "refresh": [PY_EXE, script, "refresh"],
                "checkin-test": [PY_EXE, script, "checkin-test"],
                "trae-import": [PY_EXE, script, "add"],
                "trae-web": [PY_EXE, script, "add", "--web", "--timeout", "120"],
            }
            argv = argv_map.get(act)
            if not argv:
                return self._json({"error": "bad action"}, 400)

            def fn():
                # 逐行 print → 被 job 的 stdout tap 捕获，前端可实时看到
                for ln in run_stream(kind, argv):
                    print(ln)

            j = start_job(f"{kind}:{act}", fn)
            return self._json({"job": j["id"]})

        if path == "/api/accounts/remove":
            kind, uid = body.get("kind"), body.get("uid") or ""
            script = {"wb": "wb_accounts.py", "trae": "trae_accounts.py"}.get(kind)
            out = subprocess.run([PY_EXE, script, "remove", uid, "--yes"], cwd=ROOT,
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=30)
            return self._json({"ok": out.returncode == 0,
                               "output": ((out.stdout or "") + (out.stderr or "")).strip()[-400:]})

        # ---- WorkBuddy 短信登录（两步）
        if path == "/api/wb/send-code":
            phone = (body.get("phone") or "").strip()
            if not phone:
                return self._json({"ok": False, "msg": "手机号不能为空"})
            ok, msg = wb_auth.sms_send_code(phone)
            return self._json({"ok": bool(ok), "msg": msg})
        if path == "/api/wb/verify":
            phone = (body.get("phone") or "").strip()
            code = (body.get("code") or "").strip()
            if not (phone and code):
                return self._json({"ok": False, "msg": "手机号与验证码必填"})
            cred, err = wb_auth.sms_login(phone, code)
            if err:
                return self._json({"ok": False, "msg": f"登录失败：{err}"})
            acct = cred.get("account") or {}
            uid = acct.get("uid") or ""
            sp = wb_auth.account_path_for(uid or f"phone-{phone[-4:]}")
            wb_auth.save_account(sp, cred)
            days = wb_auth.days_left(cred)
            return self._json({"ok": True,
                               "msg": f"已保存 {acct.get('nickname') or ''} "
                                      f"UID {wb_auth.mask_uid(uid)}，"
                                      f"有效期 {days if days is not None else '未知'} 天"})

        # ---- 计划任务
        if path == "/api/schedule":
            act = body.get("action")
            if act == "setup":
                t = str(body.get("time") or "08:00")
                if not re.match(r"^\d{1,2}:\d{2}$", t):
                    return self._json({"ok": False, "msg": "时间格式应为 HH:MM"})
                argv = ["powershell", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(ROOT, "setup_task.ps1"), "-Time", t]
            elif act == "remove":
                argv = ["powershell", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(ROOT, "setup_task.ps1"), "-Remove"]
            else:
                return self._json({"error": "bad action"}, 400)
            out = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                 encoding="gbk", errors="replace", timeout=60)
            ok = out.returncode == 0
            txt = (out.stdout or out.stderr).strip()[-500:]
            return self._json({"ok": ok, "msg": txt, "schedule": _schedule_status()})

        # ---- 平台启停
        if path == "/api/platform/toggle":
            name, on = body.get("name"), bool(body.get("enabled"))
            names = _set_platform_enabled(name, on)
            return self._json({"ok": True, "enabled": names,
                               "platforms": _platform_cards()})

        # ---- 扫描结果手工纳入 / 移出签到列表
        if path == "/api/platform/attach":
            import platform_scan
            key = body.get("key") or ""
            r = platform_scan.register(key)
            if r.get("ok"):
                _set_platform_enabled(key, True)
            return self._json({**r, "platforms": _platform_cards(),
                               "discovered": _discovered()})

        if path == "/api/platform/detach":
            import platform_scan
            key = body.get("key") or ""
            r = platform_scan.unregister(key)
            if r.get("ok"):
                _set_platform_enabled(key, False)
            return self._json({**r, "platforms": _platform_cards(),
                               "discovered": _discovered()})

        if path == "/api/catalog/add":
            import platform_scan
            r = platform_scan.add_to_catalog(body.get("key") or "")
            return self._json({**r, "discovered": _discovered()})

        if path == "/api/catalog/remove":
            import platform_scan
            r = platform_scan.remove_from_catalog(body.get("key") or "")
            return self._json({**r, "discovered": _discovered()})

        return self._json({"error": "not found"}, 404)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="AIAutomator 本地控制台")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    port = args.port
    for _ in range(20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    else:
        print("没有可用端口")
        return 1

    url = f"http://127.0.0.1:{port}"
    print(f"AIAutomator 控制台: {url}  (Ctrl+C 退出)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
