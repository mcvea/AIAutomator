# -*- coding: utf-8 -*-
"""
配置中心：加载用户配置 + 平台定义 + 任务定义（TOML）。

目录约定：
    config/user.toml                 用户配置（通知、调度、启用的平台、凭证引用）
    automator/platforms/*.toml       平台声明式定义
    automator/tasks/*.toml           任务定义
"""
import os
import tomllib
from dataclasses import dataclass, field

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTOMATOR_DIR = os.path.join(_ROOT, "automator")
PLATFORMS_DIR = os.path.join(AUTOMATOR_DIR, "platforms")
TASKS_DIR = os.path.join(AUTOMATOR_DIR, "tasks")
USER_CONFIG_DIR = os.path.join(_ROOT, "config")


def _read_toml(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_user_config() -> dict:
    """加载用户配置 config/user.toml，缺失返回空"""
    path = os.path.join(USER_CONFIG_DIR, "user.toml")
    if not os.path.isfile(path):
        return {}
    return _read_toml(path)


def load_platforms(only_enabled: bool = False, enabled_list: list = None) -> list:
    """加载全部平台定义，返回 [{name, display, auth, apis, ...}]"""
    platforms = []
    for fn in sorted(os.listdir(PLATFORMS_DIR)):
        if not fn.endswith(".toml"):
            continue
        try:
            p = _read_toml(os.path.join(PLATFORMS_DIR, fn))
        except Exception as e:  # noqa: BLE001
            print(f"[config] 平台定义加载失败 {fn}: {e}")
            continue
        meta = p.get("platform", {})
        platforms.append(meta)

    if only_enabled:
        user = load_user_config()
        enabled = enabled_list if enabled_list is not None else (user.get("platforms", {}) or {}).get("enabled", [])
        if enabled:
            platforms = [p for p in platforms if p.get("name") in enabled]
    return platforms


def load_task_definitions() -> dict:
    """加载全部任务定义，返回 {任务名: 定义}"""
    tasks = {}
    for fn in sorted(os.listdir(TASKS_DIR)):
        if not fn.endswith(".toml"):
            continue
        try:
            t = _read_toml(os.path.join(TASKS_DIR, fn))
        except Exception as e:  # noqa: BLE001
            print(f"[config] 任务定义加载失败 {fn}: {e}")
            continue
        for name, defn in (t.get("tasks") or {}).items():
            tasks[name] = defn
            tasks[name]["_file"] = fn
    return tasks


def platform_by_name(name: str) -> dict:
    for p in load_platforms():
        if p.get("name") == name:
            return p
    return {}
