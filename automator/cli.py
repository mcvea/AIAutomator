# -*- coding: utf-8 -*-
"""
CLI 管理入口：
    python -m automator list
    python -m automator run daily [--dry]
    python -m automator health
    python -m automator credits
    python -m automator totals
    python -m automator notify-test
"""
import argparse
import sys


def _cmd_list(args):
    from automator import config as cfg
    platforms = cfg.load_platforms()
    tasks = cfg.load_task_definitions()
    print("== 平台 ==")
    for p in platforms:
        mark = "✅" if p.get("enabled", True) else "⏸️"
        auth = p.get("auth", {}).get("type", "?")
        print(f"  {mark} {p.get('name')}（{p.get('display')}）auth={auth} "
              f"每日{p.get('daily_credits', 0)}分")
    print("\n== 任务 ==")
    for name, t in tasks.items():
        print(f"  ▶ {name}: {t.get('title', '')} -> {t.get('steps')}")
    return 0


def _cmd_run(args):
    from automator import engine, notifier
    out = engine.run_task(args.task, dry=args.dry)
    # 控制台输出
    for r in out["results"]:
        print(f"[{r.get('platform')}] {r.get('status')} - {r.get('message')}")
    if args.dry:
        return 0
    if out["report"]:
        print("\n" + "=" * 40)
        print(out["report"])
        # 通知（结构化 payload → interactive 卡片）
        if not args.no_notify:
            notifier.notify_daily({
                "results": out["results"],
                "totals": out.get("totals") or [],
                "credits": out.get("credits") or [],
                "healths": out.get("healths") or [],
                "report": out["report"],
                "prev_totals": out.get("prev_totals") or {},
            })
    return 0


def _cmd_health(args):
    from automator import engine, config as cfg
    platforms = cfg.load_platforms(only_enabled=True)
    for p in platforms:
        h = engine.platform_health(p)
        icon = {"ok": "✅", "warn": "⚠️", "expired": "🚨", "unknown": "❓"}.get(h["status"], "❓")
        print(f"{icon} {h['platform']}：{h['message']}")
    return 0


def _cmd_credits(args):
    from automator import engine, config as cfg
    platforms = cfg.load_platforms(only_enabled=True)
    all_items = []
    for p in platforms:
        all_items.extend(engine.platform_credits(p))
    if not all_items:
        print("暂无积分到期信息")
        return 0
    for it in all_items:
        icon = "🚨" if it.get("days_left", 999) <= 7 else (
            "⚠️" if it.get("days_left", 999) <= 30 else "🔸")
        print(f"{icon} {it.get('platform')}·{it.get('label')}：{it.get('credits'):g} 分 "
              f"到期 {it.get('expires_at')}（剩 {it.get('days_left')} 天）")
    return 0


def _cmd_totals(args):
    from automator import engine, config as cfg
    platforms = cfg.load_platforms(only_enabled=True)
    for p in platforms:
        t = engine.platform_total(p)
        name = t.get("platform", p.get("name"))
        if t.get("available") and t.get("total") is not None:
            note = f"（{t.get('note')}）" if t.get("note") else ""
            print(f"💰 {name}：{t['total']:g} 分{note}")
        else:
            print(f"➖ {name}：接口未提供")
    return 0


def _cmd_notify_test(args):
    from automator import notifier
    results = notifier.notify("🦞 通知通道测试成功！AIAutomator 通知链路正常。")
    for ch, ok in results.items():
        print(f"  {'✅' if ok else '❌'} {ch}")
    return 0 if all(results.values()) else 1


def _cmd_resolve_uid(args):
    """通过手机号/邮箱查询自己的飞书 open_id"""
    import json
    import urllib.request
    from automator import notifier

    secrets = notifier._load_secrets()
    f = (secrets.get("notify") or {}).get("feishu") or {}
    if not (f.get("app_id") and f.get("app_secret")):
        print("❌ 请在 config/secrets.json 中配置 feishu.app_id / app_secret")
        return 1
    body = {}
    if args.mobile:
        body["mobiles"] = [args.mobile]
    elif args.email:
        body["emails"] = [args.email]
    else:
        print("用法: python -m automator resolve-uid --mobile 手机号 | --email 邮箱")
        return 1
    token = notifier._feishu_token(f["app_id"], f["app_secret"])
    req = urllib.request.Request(
        "https://open.feishu.cn/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        d = json.loads(resp.read().decode("utf-8"))
    if d.get("code") != 0:
        print(f"❌ 查询失败: {d.get('msg')}（需应用开通 contact:user.id:readonly 权限）")
        return 1
    users = (d.get("data") or {}).get("user_list") or []
    if not users:
        print("❌ 未找到该手机号/邮箱对应的飞书用户")
        return 1
    for u in users:
        print(f"✅ {u.get('mobile') or u.get('email')} -> open_id: {u.get('user_id')}")
        print("   请将 open_id 填入 config/secrets.json 的 feishu.open_id")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="automator", description="AI 平台自动化任务框架")
    sub = parser.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="列出平台与任务")
    p_list.set_defaults(func=_cmd_list)

    p_run = sub.add_parser("run", help="执行任务")
    p_run.add_argument("task", help="任务名（daily 等）")
    p_run.add_argument("--dry", action="store_true", help="只读模式")
    p_run.add_argument("--no-notify", action="store_true", help="不推送通知")
    p_run.set_defaults(func=_cmd_run)

    p_health = sub.add_parser("health", help="登录态健康检查")
    p_health.set_defaults(func=_cmd_health)

    p_credits = sub.add_parser("credits", help="积分到期盘点")
    p_credits.set_defaults(func=_cmd_credits)

    p_totals = sub.add_parser("totals", help="账户总积分查询")
    p_totals.set_defaults(func=_cmd_totals)

    p_nt = sub.add_parser("notify-test", help="通知通道测试")
    p_nt.set_defaults(func=_cmd_notify_test)

    p_uid = sub.add_parser("resolve-uid", help="查询飞书 open_id")
    p_uid.add_argument("--mobile", help="飞书绑定手机号")
    p_uid.add_argument("--email", help="飞书绑定邮箱")
    p_uid.set_defaults(func=_cmd_resolve_uid)

    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
