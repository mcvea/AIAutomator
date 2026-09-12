# -*- coding: utf-8 -*-
"""
MiniMax Code hook：checkin / health
复用 platforms/minimax.py 的成熟实现（续期 + 签名 + 状态判断）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def checkin(platform: dict, dry: bool = False) -> dict:
    from platforms.minimax import MiniMaxCheckin
    inst = MiniMaxCheckin(dry=dry)
    return inst.run()


def health(platform: dict) -> dict:
    from platforms.minimax import MiniMaxCheckin
    return MiniMaxCheckin().health()
