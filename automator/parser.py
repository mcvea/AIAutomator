# -*- coding: utf-8 -*-
"""
声明式解析规则引擎：用点路径表达式从 JSON 响应提取字段、判断状态。

规则语法（平台定义 apis.*.parse 中声明）：
    already:   "data.today_checked_in == true"      布尔/表达式判断（已签到）
    already_contains: "已签到|already"              字符串包含判断
    field_map: {credits: "data.credits", streak: "data.streak_days"}
        field_map: {积分字段: 点路径}
"""
import re


def get_path(obj: dict, path: str, default=None):
    """点路径取值：data.a.b / data.list[0].x（简化支持）"""
    if not path:
        return default
    cur = obj
    # 支持 [n] 索引
    parts = re.split(r"\.|\[|\]", path)
    parts = [p for p in parts if p != ""]
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        else:
            return default
    return cur


def _eval_expr(obj: dict, expr: str) -> bool:
    """计算简单比较表达式：path == value / path != value / path > value 等"""
    for op in ("!=", "==", ">=", "<=", ">", "<"):
        if op in expr:
            left, right = expr.split(op, 1)
            left = left.strip()
            right = right.strip().strip("'\"")
            val = get_path(obj, left)
            if right.lower() in ("true", "false", "null", "none"):
                if right.lower() == "true":
                    return val is True
                if right.lower() == "false":
                    return val is False
                return val is None
            try:
                rv = float(right)
                if isinstance(val, (int, float)):
                    if op == "==":
                        return float(val) == rv
                    if op == "!=":
                        return float(val) != rv
                    if op == ">":
                        return float(val) > rv
                    if op == "<":
                        return float(val) < rv
                    if op == ">=":
                        return float(val) >= rv
                    if op == "<=":
                        return float(val) <= rv
                return False
            except ValueError:
                return str(val) == right
    # 无操作符：视为存在性判断
    return get_path(obj, expr.strip(), None) is not None


def apply_parse(result: dict, body, rules: dict) -> dict:
    """
    应用解析规则到响应 body，更新 result：
    rules 示例：
      {already: "data.today_checked_in == true",
       already_contains: "已签到|already",
       credits: "data.credits",
       fields: {streak: "data.streak_days"}}
    """
    if not isinstance(body, dict):
        body = {}
    if rules.get("already_contains"):
        import json
        text = json.dumps(body, ensure_ascii=False)
        if re.search(rules["already_contains"], text):
            result["status"] = "already"
            result["success"] = True
    if rules.get("already"):
        try:
            if _eval_expr(body, rules["already"]):
                result["status"] = "already"
                result["success"] = True
        except Exception:  # noqa: BLE001
            pass
    if rules.get("credits"):
        v = get_path(body, rules["credits"])
        if isinstance(v, (int, float)) and v > 0:
            result["credits"] = int(v)
    for fname, fpath in (rules.get("fields") or {}).items():
        v = get_path(body, fpath)
        if v is not None:
            result.setdefault("meta", {})[fname] = v
    return result
