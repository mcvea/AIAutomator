# -*- coding: utf-8 -*-
"""
平台签到基类：所有平台的签到模块都继承此类，
统一返回结构化结果，便于主调度器汇总和飞书通知。
"""
import abc


class BaseCheckin(abc.ABC):
    """签到平台基类"""

    # 平台显示名称
    PLATFORM_NAME = "未命名平台"
    # 每日可领积分（用于通知展示）
    DAILY_CREDITS = 0

    def __init__(self, dry: bool = False):
        self.dry = dry

    @abc.abstractmethod
    def checkin(self) -> dict:
        """
        执行签到，返回统一结果字典：
        {
            "platform": "平台名",
            "success": True/False,
            "status": "success | already | failed | skipped",
            "message": "人类可读的描述",
            "credits": 本次获得的积分(0表示无),
        }
        """
        raise NotImplementedError

    def run(self) -> dict:
        """安全包装：任何异常都转成 failed 结果，不让单个平台拖垮整体"""
        try:
            return self.checkin()
        except Exception as e:  # noqa: BLE001
            return {
                "platform": self.PLATFORM_NAME,
                "success": False,
                "status": "failed",
                "message": f"执行异常: {e}",
                "credits": 0,
            }

    def health(self) -> dict:
        """
        登录态健康检查，返回：
        {
            "platform": "平台名",
            "status": "ok | warn | expired | unknown",
            "days_left": 剩余天数或 None,
            "message": "描述",
        }
        """
        return {
            "platform": self.PLATFORM_NAME,
            "status": "unknown",
            "days_left": None,
            "message": "未提供登录态有效期信息",
        }

    def credits(self) -> list:
        """
        积分余额与到期时间，返回列表（按最近到期排序）：
        [
            {"label": "描述", "credits": 100, "expires_at": "2026-09-19", "days_left": 7},
        ]
        无法查询到期信息的平台返回空列表。
        """
        return []

    def total(self) -> dict:
        """
        账户总积分余额，可获取时返回，否则 available=False：
        {
            "platform": "平台名",
            "available": True/False,
            "total": 当前总积分或 None,
            "note": "口径说明（如：本季活动累计）",
        }
        """
        return {"available": False, "total": None}

    def balance(self) -> dict:
        """
        账户总余额（资源包额度），可获取时返回，否则 available=False：
        {
            "platform": "平台名",
            "available": True/False,
            "total": 资源包总量或 None,
            "remain": 剩余量或 None,
            "used": 已用量或 None,
            "note": "口径说明（如：资源包额度）",
        }
        未实现余额查询的平台返回默认不可获取。
        """
        return {"available": False, "total": None, "remain": None, "used": None}
