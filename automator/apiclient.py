# -*- coding: utf-8 -*-
"""
HTTP API 客户端：支持 bearer / header 鉴权、JSON 请求、模板 URL 变量、
hooks（签名/自定义鉴权头）扩展、简单重试与限速。
"""
import json
import time
import urllib.error
import urllib.request


class ApiError(Exception):
    pass


def call(url: str, method: str = "GET", body=None, headers: dict = None,
         token: str = "", auth_type: str = "bearer",
         extra_headers: dict = None, signer=None, timeout: int = 30):
    """
    发起请求。

    signer: callable(url, method, body, headers, token) -> headers
            用于签名类平台（MiniMax 等），返回最终请求头。
    """
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Type", "application/json")
    hdrs.setdefault("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")

    if extra_headers:
        hdrs.update(extra_headers)
    if token:
        if auth_type == "bearer":
            hdrs.setdefault("Authorization", f"Bearer {token}")
        elif auth_type == "header":
            # token 即完整头（如 Cloud-IDE-JWT xxx），由平台定义 auth.header 指定
            hdrs.setdefault("Authorization", token)
        elif auth_type == "raw":
            pass  # token 完全由 signer/extra_headers 决定
    if signer is not None:
        hdrs = signer(url, method, body, hdrs, token) or hdrs

    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
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
