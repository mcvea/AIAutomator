# -*- coding: utf-8 -*-
"""
登录态管理器：统一处理各平台登录态的发现、读取、过期计算与预警。

支持的 auth.type（平台定义中声明）：
    json_file       明文 JSON 文件，按 token_field 点路径取 token
    sqlite_kv       SQLite kv 表（key/value），取指定 key 的 JSON 字段
    encrypted_json  加密信封（JSON base64），通过 hooks.decrypt_auth 解密后取字段
    cookie_jar      加密 cookies（AES-GCM + key 文件），通过 hooks.decrypt_cookies 解密
"""
import json
import os
import time


class AuthError(Exception):
    pass


def read_json_file(path: str) -> dict:
    from automator import paths
    path = paths.resolve_path(path)
    if not path or not os.path.isfile(path):
        raise AuthError(f"登录态文件不存在: {paths.describe(path)}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_path(obj, path: str):
    cur = obj
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)]
        else:
            return None
    return cur


def resolve_credential(auth_cfg: dict, hook=None) -> dict:
    """
    根据 auth 配置解析出 token 及有效期信息。
    返回：{"token": str, "expires_at": float(ms) 或 None,
           "refresh_expires_at": float(ms) 或 None, "extra": {...}}
    """
    atype = auth_cfg.get("type", "json_file")
    token = ""
    expires_ms = None
    refresh_ms = None
    extra = {}

    if atype == "json_file":
        data = read_json_file(auth_cfg.get("path", ""))
        token = str(_get_path(data, auth_cfg["token_field"]) or "")
        if auth_cfg.get("expires_field"):
            expires_ms = _get_path(data, auth_cfg["expires_field"])
        if auth_cfg.get("refresh_expires_field"):
            refresh_ms = _get_path(data, auth_cfg["refresh_expires_field"])
        extra["data"] = data

    elif atype == "sqlite_kv":
        import sqlite3
        from automator import paths
        db = paths.resolve_path(auth_cfg.get("path", ""))
        if not os.path.isfile(db):
            raise AuthError(f"数据库不存在: {paths.describe(db)}")
        conn = sqlite3.connect(db)
        try:
            row = conn.execute(
                "SELECT value FROM kv WHERE key=?", (auth_cfg["kv_key"],)).fetchone()
        finally:
            conn.close()
        if not row:
            raise AuthError(f"kv 表无 {auth_cfg['kv_key']}")
        data = json.loads(row[0])
        token = str(_get_path(data, auth_cfg["token_field"]) or "")
        extra["data"] = data

    elif atype == "encrypted_json":
        if hook is None:
            raise AuthError("encrypted_json 需要 decrypt_auth hook")
        data = read_json_file(auth_cfg.get("path", ""))
        enc = _get_path(data, auth_cfg.get("encrypted_field", "auth"))
        decrypted = hook(enc)
        token = str(_get_path(decrypted, auth_cfg["token_field"]) or "")
        if auth_cfg.get("expires_field"):
            v = _get_path(decrypted, auth_cfg["expires_field"])
            if v is not None:
                expires_ms = v
        extra["decrypted"] = decrypted

    elif atype == "cookie_jar":
        if hook is None:
            raise AuthError("cookie_jar 需要 decrypt_cookies hook")
        data = read_json_file(auth_cfg.get("path", ""))
        prof = data.get("accountProfiles") or []
        profile = None
        active_id = data.get("activeProfileId", "")
        for p in prof:
            if p.get("profileId") == active_id:
                profile = p
                break
        if profile is None and prof:
            profile = prof[0]
        if not profile:
            raise AuthError("未找到已登录账号")
        key_file = auth_cfg.get("key_file", "")
        cookies = hook(profile.get("encryptedCookies", ""))
        extra["cookies"] = cookies
        # 生成 Cookie 头与 csrf token（供 extra_headers 模板使用）
        target_host = auth_cfg.get("target_host", "")
        if target_host and cookies:
            cookie_str, csrf = build_cookie_header(cookies, target_host)
            extra["cookie_str"] = cookie_str
            extra["csrf_token"] = csrf
        token = ""  # cookie 类平台靠 Cookie 头鉴权，token 字段用于通用性

    if not token and atype != "cookie_jar":
        raise AuthError("未能从登录态解析出 token")

    return {"token": token, "expires_at": expires_ms,
            "refresh_expires_at": refresh_ms, "extra": extra}


def days_left(expires_ms, now_ms=None) -> int | None:
    """毫秒时间戳 → 剩余天数（向下取整，过期返回 0）"""
    if not expires_ms:
        return None
    now_ms = now_ms or time.time() * 1000
    try:
        return max(0, int((float(expires_ms) - now_ms) / 86400000))
    except (TypeError, ValueError):
        return None


def build_cookie_header(cookies: list, hostname: str) -> tuple:
    """按域名匹配 cookies，构造 Cookie 头字符串与 csrf token（bce-user-info）"""
    def domain_match(h: str, d: str) -> bool:
        if not d:
            return True
        dd = d[1:] if d.startswith(".") else d
        return h == dd or h.endswith("." + dd)

    matched = [c for c in cookies if domain_match(hostname, c.get("domain"))]
    parts = []
    csrf = ""
    for c in matched:
        name = c.get("name", "")
        val = str(c.get("value", "")).strip('"\'')
        if any(ch in val for ch in ":|;= \t"):
            val = f'"{val}"'
        parts.append(f"{name}={val}")
        if name == "bce-user-info" and not csrf:
            csrf = str(c.get("value", "")).strip('"\'')
    return "; ".join(parts), csrf
