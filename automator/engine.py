# -*- coding: utf-8 -*-
"""
任务引擎：按任务定义编排执行各平台动作，输出统一结果。

内置动作（任务 steps 中声明）：
    checkin_all      全部平台签到
    health_all       全部平台登录态健康检查
    credits_all      全部平台积分到期盘点
    checkin:<name>   指定平台签到

hook 约定（automator/platforms/hooks/<name>.py）：
    decrypt_auth(enc) -> dict                 登录态解密（encrypted_json）
    decrypt_cookies(enc_b64, key_file) -> list  cookies 解密（cookie_jar）
    signer(url, method, body, headers, token) -> headers  请求签名
    refresh(platform, cred) -> bool | str      token 续期（True/新token）
    checkin/health/total 可返回 dict 或 list（list = 多账号逐账号结果，由引擎展开）
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from automator import config as cfg_mod  # noqa: E402
from automator import apiclient, auth_store, parser, registry  # noqa: E402


# ---------- 工具 ----------

def _render_url(tpl: str, cred: dict) -> str:
    """替换 URL 模板 {{auth.xxx}}（auth.extra.data 中的字段，支持点路径）"""
    data = (cred.get("extra") or {}).get("data") or {}
    extra = cred.get("extra") or {}

    def _get(key: str):
        # 支持 {{cookie_str}} / {{csrf_token}}（extra 顶层）
        if key in extra:
            return extra[key]
        cur = data
        for p in key.split("."):
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return ""
        return cur

    out = tpl
    i = out.find("{{")
    while i >= 0:
        j = out.find("}}", i)
        if j < 0:
            break
        key = out[i + 2:j].strip()
        out = out[:i] + str(_get(key)) + out[j + 2:]
        i = out.find("{{")
    return out


def _build_headers(platform: dict, token: str, cred: dict) -> dict:
    """组装平台定义 extra_headers（支持 {{auth.xxx}} / {{cookie_str}} / {{csrf_token}}）"""
    headers = {}
    data = (cred.get("extra") or {}).get("data") or {}
    extra = cred.get("extra") or {}
    for k, v in (platform.get("extra_headers") or {}).items():
        sv = str(v)
        sv = sv.replace("{{cookie_str}}", str(extra.get("cookie_str", "")))
        sv = sv.replace("{{csrf_token}}", str(extra.get("csrf_token", "")))
        for kk, vv in data.items():
            sv = sv.replace("{{" + kk + "}}", str(vv))
        headers[k] = sv
    return headers


def _make_auth_hook(platform: dict):
    """按 auth.type 构造登录态解密 hook"""
    auth_cfg = platform.get("auth") or {}
    atype = auth_cfg.get("type", "json_file")
    if atype == "encrypted_json":
        fn = registry.load_hook(platform, "auth_decrypt")
        return (lambda enc: getattr(fn, "decrypt_auth", fn)(enc)) if fn else None
    if atype == "cookie_jar":
        fn = registry.load_hook(platform, "cookies_decrypt")
        if not fn:
            return None
        key_file = auth_cfg.get("key_file", "")
        return lambda enc: getattr(fn, "decrypt_cookies", fn)(enc, key_file)
    return None


def _load_cred(platform: dict) -> dict:
    auth_cfg = platform.get("auth") or {}
    return auth_store.resolve_credential(auth_cfg, hook=_make_auth_hook(platform))


# ---------- 平台动作 ----------

def platform_checkin(platform: dict, dry: bool = False) -> dict:
    """单平台签到：auth → refresh(可选) → status(可选) → checkin → parse"""
    display = platform.get("display", platform.get("name", "?"))
    result = {"platform": display, "success": False, "status": "failed",
              "message": "", "credits": 0}

    # 复杂平台：hook_checkin 完整接管（如 LobsterAI 多步流程）
    hook_checkin = registry.load_hook(platform, "checkin")
    if hook_checkin:
        fn = getattr(hook_checkin, "checkin", hook_checkin)
        try:
            return fn(platform, dry=dry)
        except Exception as e:  # noqa: BLE001
            result["message"] = f"hook 签到异常: {e}"
            return result

    try:
        cred = _load_cred(platform)
    except Exception as e:  # noqa: BLE001
        result["message"] = f"登录态读取失败: {e}"
        return result

    # 可选：refresh 前置（token 续期）
    refresh_fn = registry.load_hook(platform, "refresh")
    if refresh_fn:
        try:
            r = getattr(refresh_fn, "refresh", refresh_fn)(platform, cred)
            if isinstance(r, str) and r:
                cred["token"] = r
        except Exception:  # noqa: BLE001
            pass

    token = cred["token"]
    headers = _build_headers(platform, token, cred)
    apis = platform.get("apis") or {}
    signer = registry.load_hook(platform, "signer")

    # 1) 状态查询（可选）
    status_spec = apis.get("checkin_status")
    if status_spec:
        url = _render_url(status_spec.get("url", ""), cred)
        body = status_spec.get("body")
        if isinstance(body, str):
            import json as _json
            try:
                body = _json.loads(body)
            except Exception:  # noqa: BLE001
                body = {}
        sc, sb = apiclient.call(url, status_spec.get("method", "POST"), body or None,
                                token=token, auth_type=status_spec.get("auth", "bearer"),
                                extra_headers=headers, signer=signer)
        if status_spec.get("parse"):
            parser.apply_parse(result, sb, status_spec["parse"])
        if result.get("status") == "already":
            streak = (result.get("meta") or {}).get("streak")
            if streak is not None:
                result["message"] = f"今日已签到（已连签 {streak} 天）"
            else:
                result["message"] = result["message"] or "今日已签到"
            return result

    # 2) 执行签到
    spec = apis.get("checkin") or {}
    if not spec:
        result["message"] = "平台未声明 checkin 接口"
        return result

    if dry:
        result.update(status="skipped", success=True,
                      message="只读模式：今日尚未签到，可正常执行")
        return result

    url = _render_url(spec.get("url", ""), cred)
    body = spec.get("body")
    if isinstance(body, str):
        import json as _json
        try:
            body = _json.loads(body)
        except Exception:  # noqa: BLE001
            body = {}
    sc, sb = apiclient.call(url, spec.get("method", "POST"), body,
                            token=token, auth_type=spec.get("auth", "bearer"),
                            extra_headers=headers, signer=signer)

    if spec.get("parse"):
        parser.apply_parse(result, sb, spec["parse"])

    if result.get("status") == "already":
        result["message"] = result["message"] or "今日已签到"
        result["success"] = True
        return result

    # 兜底判定
    if isinstance(sb, dict):
        code = sb.get("code")
        if code == 0 or sb.get("success") is True:
            result["status"] = "success"
            result["success"] = True
            if result.get("credits"):
                result["message"] = f"签到成功，获得 {result['credits']} 积分"
            else:
                result["credits"] = platform.get("daily_credits", 0)
                result["message"] = f"签到成功，获得 {result['credits']} 积分"
            return result
        if isinstance(code, (int, float)) and code != 0:
            result["message"] = f"签到失败 code={code}: {sb.get('message') or sb.get('msg') or ''}"
            return result
    if sc in (401, 403):
        result["message"] = "鉴权失败，请重新登录客户端"
        return result
    result["message"] = f"签到未成功（HTTP {sc}）：{str(sb)[:120]}"
    return result


def platform_health(platform: dict) -> dict:
    """单平台登录态健康检查（优先 hooks.health）"""
    display = platform.get("display", platform.get("name", "?"))
    health_hook = registry.load_hook(platform, "health")
    if health_hook:
        try:
            r = getattr(health_hook, "health", health_hook)(platform)
            if isinstance(r, list):  # 多账号：hook 可返回逐账号健康列表
                return r
            if isinstance(r, dict) and r.get("platform"):
                return r
        except Exception as e:  # noqa: BLE001
            return {"platform": display, "status": "warn", "days_left": None,
                    "message": f"健康检查异常: {e}"}

    try:
        cred = _load_cred(platform)
    except Exception as e:  # noqa: BLE001
        return {"platform": display, "status": "expired", "days_left": 0,
                "message": f"无法读取登录态: {e}"}

    days = auth_store.days_left(cred.get("expires_at"))
    if days is not None:
        if days < 7:
            return {"platform": display, "status": "warn", "days_left": days,
                    "message": f"登录态剩余 {days} 天，请打开客户端登录刷新"}
        return {"platform": display, "status": "ok", "days_left": days,
                "message": f"登录态剩余 {days} 天"}

    # 无到期字段：尝试 refresh hook 验证
    refresh_fn = registry.load_hook(platform, "refresh")
    if refresh_fn:
        try:
            r = getattr(refresh_fn, "refresh", refresh_fn)(platform, cred)
            if isinstance(r, str) and r:
                return {"platform": display, "status": "ok", "days_left": 30,
                        "message": "自动续期正常（每次任务自动顺延）"}
            if r:
                return {"platform": display, "status": "ok", "days_left": 30,
                        "message": "自动续期正常（每次任务自动顺延）"}
            return {"platform": display, "status": "warn", "days_left": None,
                    "message": "自动续期失败，请打开客户端重新登录"}
        except Exception as e:  # noqa: BLE001
            return {"platform": display, "status": "warn", "days_left": None,
                    "message": f"续期检查异常: {e}"}

    return {"platform": display, "status": "unknown", "days_left": None,
            "message": "平台未提供有效期信息"}


def platform_credits(platform: dict) -> list:
    """单平台积分到期盘点（优先 hooks.credits）"""
    display = platform.get("display", platform.get("name", "?"))
    credits_cfg = platform.get("credits")
    if not credits_cfg or not credits_cfg.get("enabled"):
        return []
    credits_hook = registry.load_hook(platform, "credits")
    if credits_hook:
        try:
            r = getattr(credits_hook, "credits", credits_hook)(platform)
            if isinstance(r, list):
                return r
        except Exception as e:  # noqa: BLE001
            print(f"[engine] {display} 积分盘点 hook 失败: {e}")
            return []
    try:
        cred = _load_cred(platform)
        headers = _build_headers(platform, cred["token"], cred)
        apis = platform.get("apis") or {}
        spec = apis.get(credits_cfg.get("api", "credits"))
        if not spec:
            return []
        url = _render_url(spec.get("url", ""), cred)
        body = spec.get("body")
        if isinstance(body, str):
            import json as _json
            try:
                body = _json.loads(body)
            except Exception:  # noqa: BLE001
                body = None
        sc, sb = apiclient.call(url, spec.get("method", "GET"), body,
                                token=cred["token"],
                                auth_type=spec.get("auth", "bearer"),
                                extra_headers=headers)
        return _extract_credit_items(sb, credits_cfg.get("parse") or {}, display)
    except Exception as e:  # noqa: BLE001
        print(f"[engine] {display} 积分盘点失败: {e}")
        return []


def platform_total(platform: dict) -> dict:
    """单平台账户总积分（优先 hooks.total，失败降级为不可获取）"""
    display = platform.get("display", platform.get("name", "?"))
    total_hook = registry.load_hook(platform, "total")
    if total_hook:
        try:
            r = getattr(total_hook, "total", total_hook)(platform)
            if isinstance(r, list):  # 多账号：hook 可返回逐账号总积分列表
                for item in r:
                    if isinstance(item, dict):
                        item.setdefault("platform", display)
                        item.setdefault("available", False)
                        item.setdefault("total", None)
                        item.setdefault("note", "")
                return r
            if isinstance(r, dict):
                r.setdefault("platform", display)
                r.setdefault("available", False)
                r.setdefault("total", None)
                r.setdefault("note", "")
                return r
        except Exception as e:  # noqa: BLE001
            print(f"[engine] {display} 总积分查询失败: {e}")
    return {"platform": display, "available": False, "total": None, "note": ""}


def _extract_credit_items(body, rules: dict, display: str) -> list:
    """按 credits.parse 规则提取积分到期列表"""
    if not isinstance(body, dict):
        return []
    container = body
    if rules.get("container"):
        for p in rules["container"].split("."):
            if isinstance(container, dict):
                container = container.get(p)
            else:
                return []
    if not isinstance(container, list):
        return []

    items = []
    for raw in container:
        if not isinstance(raw, dict):
            continue
        item = {}
        for k, path in (rules.get("fields") or {}).items():
            v = raw
            for p in path.split("."):
                if isinstance(v, dict):
                    v = v.get(p)
                elif isinstance(v, list) and p.isdigit() and int(p) < len(v):
                    v = v[int(p)]
                else:
                    v = None
                    break
            item[k] = v
        if item.get("expires_ts") and not item.get("expires_at"):
            try:
                from datetime import datetime
                item["expires_at"] = datetime.fromtimestamp(
                    float(item["expires_ts"])).strftime("%Y-%m-%d")
            except Exception:  # noqa: BLE001
                continue
        if item.get("expires_at"):
            try:
                from datetime import datetime
                exp = datetime.strptime(str(item["expires_at"]), "%Y-%m-%d")
                item["days_left"] = max(0, int((exp.timestamp() - time.time()) // 86400))
            except Exception:  # noqa: BLE001
                item["days_left"] = 0
            item["platform"] = display
            items.append(item)
    items.sort(key=lambda x: str(x.get("expires_at", "9999-12-31")))
    return items


# ---------- 任务编排 ----------

def _collect(dst: list, r):
    """结果收集：hook 可能返回单条 dict 或多账号 list"""
    if isinstance(r, list):
        dst.extend(r)
    elif r is not None:
        dst.append(r)


def run_task(task_name: str, dry: bool = False) -> dict:
    """执行任务，返回 {results, healths, credits, totals, report, task}"""
    tasks = cfg_mod.load_task_definitions()
    task = tasks.get(task_name)
    if not task:
        raise KeyError(f"任务不存在: {task_name}，可用: {list(tasks.keys())}")

    steps = task.get("steps") or []
    platforms = cfg_mod.load_platforms(only_enabled=True)

    results, healths, credits_all, totals = [], [], [], []

    for step in steps:
        if step == "checkin_all":
            for p in platforms:
                _collect(results, platform_checkin(p, dry=dry))
        elif step.startswith("checkin:"):
            pname = step.split(":", 1)[1]
            for p in platforms:
                if p.get("name") == pname:
                    _collect(results, platform_checkin(p, dry=dry))
        elif step == "health_all":
            for p in platforms:
                _collect(healths, platform_health(p))
        elif step == "credits_all":
            for p in platforms:
                credits_all.extend(platform_credits(p))
        elif step == "total_all":
            for p in platforms:
                _collect(totals, platform_total(p))

    credits_all.sort(key=lambda x: str(x.get("expires_at", "9999-12-31")))

    report = ""
    if task.get("report"):
        from automator import reporter
        if task["report"] == "daily":
            report = reporter.build_daily_report(results, healths, credits_all,
                                                 totals=totals,
                                                 title=task.get("title", "AI 平台自动化日报"))

    return {"results": results, "healths": healths, "credits": credits_all,
            "totals": totals, "report": report, "task": task_name}
