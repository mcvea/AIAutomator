# -*- coding: utf-8 -*-
"""
扩展注册表（hooks）：平台定义中通过 hooks.* 声明需要加载的扩展函数。
复杂平台（加密信封解密、cookies 解密、请求签名）在此注册，配置驱动调用。
"""
import importlib

_REGISTRY = {}


def register(name: str, fn):
    """注册 hook：name → callable"""
    _REGISTRY[name] = fn


def get(name: str):
    if name in _REGISTRY:
        return _REGISTRY[name]
    # 惰性导入 automator.platforms.hooks.<name>
    try:
        mod = importlib.import_module(f"automator.platforms.hooks.{name}")
        return mod
    except ImportError:
        return None


def load_hook(platform_def: dict, kind: str):
    """
    按平台定义的 hooks 声明加载 hook。
    kind: auth_decrypt / cookies_decrypt / signer / refresh
    """
    hooks_cfg = (platform_def.get("hooks") or {})
    name = hooks_cfg.get(kind)
    if not name:
        return None
    hook_mod = get(name)
    if hook_mod is None:
        return None
    if hasattr(hook_mod, "main"):
        return getattr(hook_mod, "main")
    return hook_mod
