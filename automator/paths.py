# -*- coding: utf-8 -*-
"""
路径解析：让平台定义中的路径通用化（开源友好）。

支持的写法（TOML 与代码中均可）：
    %LOCALAPPDATA%\\CodeBuddyExtension\\...
    %APPDATA%\\TRAE SOLO CN\\...
    ~\\.minimax\\...
    ${HOME}/.minimax/...
    普通绝对路径（兼容，但开源时建议用占位符）
"""
import os
import re


def resolve_path(p) -> str:
    """把含环境变量 / ~ 的路径展开为真实绝对路径"""
    if not p:
        return ""
    s = str(p).strip()
    # ~ 与 ~/xxx
    if s == "~" or s.startswith("~\\") or s.startswith("~/"):
        home = os.path.expanduser("~")
        if s == "~":
            return home
        return os.path.join(home, s[2:].replace("/", "\\"))
    # %VAR%
    s = re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), s)
    # ${VAR} / $VAR
    s = re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), s)
    s = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)",
               lambda m: os.environ.get(m.group(1), m.group(0)), s)
    return s


def describe(p) -> str:
    """返回路径的通用描述（用于报错提示），隐藏本机用户目录名"""
    s = resolve_path(p)
    home = os.path.expanduser("~")
    if s.startswith(home):
        s = "~" + s[len(home):]
    return s
