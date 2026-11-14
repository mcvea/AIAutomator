# -*- coding: utf-8 -*-
"""TRAE SOLO CN（字节 Trae SOLO 国内版）每日签到模块

同族同协议的第三个客户端：登录态同为 `iCubeAuthInfo://icube.cloudide` AES 信封，
签到同为 `api.trae.cn/trae/api/v2/ug/checkin_credits/{status,claim}`。
证据来自客户端自身的 product.json（account.trae.normal = https://api.trae.cn）
与 out/main.js（checkin_credits/status | claim 两条路径字面量），非猜测。

差异只有两处，因此直接继承 TraeWorkCheckin：

  - 客户端目录：%APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
  - 默认展示名：TRAE SOLO CN

单账号：同一客户端只保留最近一次登录的账号，不走 auths/ 多账号。
注意：本机该客户端未登录（storage.json 里只有 icube-dc:<设备号>，无 cloudide 信封），
因此 checkin 会如实报"未登录"，不会伪造成功。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from platforms.traework import TraeWorkCheckin  # noqa: E402


class TraeSoloCheckin(TraeWorkCheckin):
    PLATFORM_NAME = "TRAE SOLO CN"
    CLIENT_NAME = "TRAE SOLO CN"
    DAILY_CREDITS = 0          # 客户端未标定每日额度，等真机签到由 status 返回

    AUTH_FILE_CANDIDATES = [
        os.path.join(os.environ.get("APPDATA", ""), "TRAE SOLO CN", "User",
                     "globalStorage", "storage.json"),
    ]

    @classmethod
    def account_specs(cls) -> list:
        return [{}]
