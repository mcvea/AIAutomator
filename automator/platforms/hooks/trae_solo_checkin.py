# -*- coding: utf-8 -*-
r"""
TRAE SOLO CN hook：checkin / health / total / decrypt_auth

复用 platforms/trae_solo.py（继承自 TraeWorkCheckin）：同一套 AES 信封解密、
设备证明续期、状态查询与幂等领取，只是客户端目录与平台名不同。

登录态：%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json
        键 iCubeAuthInfo://icube.cloudide（AES 信封，含 token / refreshToken / expiredAt）
接口：  https://api.trae.cn/trae/api/v2/ug/checkin_credits/status | claim
        https://api.trae.cn/trae/api/v2/ug/usage_summary（总积分口径）

单账号：客户端只保留最近登录的账号，不做多账号展开。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _inst(dry: bool = False):
    from platforms.trae_solo import TraeSoloCheckin
    return TraeSoloCheckin(dry=dry)


def decrypt_auth(enc: str) -> dict:
    """解密 storage.json 中的 AES 登录信封，返回登录态 JSON"""
    return _inst()._decrypt_auth_info(enc)


def checkin(platform: dict, dry: bool = False) -> dict:
    r = _inst(dry=dry).run()
    if isinstance(r, dict):
        r["platform"] = platform.get("display") or r.get("platform")
    return r


def health(platform: dict) -> dict:
    r = _inst().health()
    if isinstance(r, dict):
        r["platform"] = platform.get("display") or r.get("platform")
    return r


def total(platform: dict) -> dict:
    r = _inst().total()
    if isinstance(r, dict):
        r["platform"] = platform.get("display") or r.get("platform")
    return r
