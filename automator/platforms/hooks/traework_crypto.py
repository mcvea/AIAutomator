# -*- coding: utf-8 -*-
"""
TraeWork hook：decrypt_auth / checkin / health
复用 platforms/traework.py 的成熟实现（AES 解密 + 自动续期 + 状态/领取）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def decrypt_auth(enc: str) -> dict:
    """解密 storage.json 中的 AES 登录信封，返回登录态 JSON"""
    from platforms.traework import TraeWorkCheckin
    return TraeWorkCheckin._decrypt_auth_info(enc)


def checkin(platform: dict, dry: bool = False) -> dict:
    from platforms.traework import TraeWorkCheckin
    inst = TraeWorkCheckin(dry=dry)
    return inst.run()


def health(platform: dict) -> dict:
    from platforms.traework import TraeWorkCheckin
    return TraeWorkCheckin().health()
