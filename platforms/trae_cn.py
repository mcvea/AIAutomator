# -*- coding: utf-8 -*-
"""Trae CN（字节 Trae IDE 国内版）每日签到模块

与 TraeWork 是同一族产品：登录态同为 `iCubeAuthInfo://icube.cloudide` AES 信封，
签到同为 `api.trae.cn/trae/api/v2/ug/checkin_credits/{status,claim}`。
差异只有三处，因此直接继承 TraeWorkCheckin：

  - 客户端目录：%APPDATA%\\Trae CN\\User\\globalStorage\\storage.json
  - 默认展示名：Trae CN
  - 每日积分：100（status 接口实测 credits=100, extra_credits=100）

单账号：Trae CN 一个客户端只保留最近一次登录的账号，因此不走 auths/ 多账号。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from platforms.traework import TraeWorkCheckin  # noqa: E402


class TraeCNCheckin(TraeWorkCheckin):
    PLATFORM_NAME = "Trae CN"
    CLIENT_NAME = "Trae CN"
    DAILY_CREDITS = 100

    AUTH_FILE_CANDIDATES = [
        os.path.join(os.environ.get("APPDATA", ""), "Trae CN", "User",
                     "globalStorage", "storage.json"),
    ]

    @classmethod
    def account_specs(cls) -> list:
        """单账号：不回退也没有 auths/ 凭据库，固定桌面登录态一个实例"""
        return [{}]
