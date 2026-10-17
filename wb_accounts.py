#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
WorkBuddy 多账号管理 CLI（短信登录取凭据 / 查看 / 续期 / 删除）

用法：
    python wb_accounts.py add                    # 交互式短信登录，新增/更新账号凭据
    python wb_accounts.py add --phone 138xxxx    # 指定手机号（验证码仍交互输入）
    python wb_accounts.py add --phone 138xxxx --code 123456   # 全非交互（脚本化）
    python wb_accounts.py list                   # 列出全部账号（UID/昵称/剩余天数/状态）
    python wb_accounts.py list --refresh         # 列出并顺带续期临期账号
    python wb_accounts.py refresh [uid]          # 手动续期全部（或指定）账号
    python wb_accounts.py remove <uid> [--yes]   # 删除账号凭据（默认需确认）
    python wb_accounts.py checkin-test [uid]     # 只读模式逐账号试跑签到（不写数据）

说明：
    - 每个账号用「手机号 + 短信验证码」登录一次即可，凭据存入 auths/workbuddy-<uid>.json，
      之后由脚本每日自动续期（refreshToken 轮换落盘），无需再打开桌面客户端。
    - 凭据文件等同账号密码：仅存本机、已 gitignore；本工具输出全程脱敏，不打印 Token。
    - 同一手机号重复执行 add 会覆盖对应账号旧凭据（用于找回/换绑场景）。
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from platforms import wb_auth  # noqa: E402


def _yes(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _remaining_text(data: dict | None) -> str:
    if not data:
        return "-"
    days = wb_auth.days_left(data)
    if days is None:
        return "未知"
    if wb_auth.is_expired(data):
        return "已过期"
    return f"{days} 天"


def cmd_add(args) -> int:
    phone = (args.phone or "").strip() or input("请输入手机号: ").strip()
    if not phone:
        print("未输入手机号")
        return 1
    print(f"向 {wb_auth.mask_phone(phone)} 发送验证码...")
    ok, msg = wb_auth.sms_send_code(phone)
    print(f"  {msg}")
    if not ok:
        return 1

    code = (args.code or "").strip() or input("请输入短信验证码: ").strip()
    if not code:
        print("未输入验证码")
        return 1

    print("登录中...")
    cred, err = wb_auth.sms_login(phone, code)
    if err:
        print(f"  登录失败：{err}")
        return 1

    acct = cred.get("account") or {}
    uid = acct.get("uid") or ""
    path = wb_auth.account_path_for(uid or f"phone-{phone[-4:]}")
    existed = os.path.isfile(path)
    wb_auth.save_account(path, cred)

    nickname = acct.get("nickname") or "(未提供)"
    print("  登录成功")
    print(f"  账号：{nickname}   UID：{wb_auth.mask_uid(uid)}")
    print(f"  凭据：{os.path.relpath(path)}（{'已更新' if existed else '已新增'}）")
    print(f"  有效期：{_remaining_text(cred)}（脚本将每日自动续期）")
    return 0


def cmd_list(args) -> int:
    accounts = wb_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{wb_auth.auths_dir()}")
        print("请先用  python wb_accounts.py add  添加账号")
        return 0

    print(f"凭据目录：{wb_auth.auths_dir()}")
    print(f"共 {len(accounts)} 个账号：")
    for acc in accounts:
        data = None
        try:
            data = wb_auth.load_account(acc["path"])
        except Exception:  # noqa: BLE001 - 运行期会给出明确错误，这里仅展示
            pass

        flags = []
        if acc.get("disabled"):
            flags.append("已失效需重登")
        if data is not None and not (data.get("auth") or {}).get("refreshToken"):
            flags.append("无续期凭证")

        if args.refresh and data is not None and not acc.get("disabled"):
            ok, msg = wb_auth.refresh_account(acc["path"], data)
            flags.append("续期成功" if ok else f"续期失败（{msg}）")
            if ok:
                try:
                    data = wb_auth.load_account(acc["path"])
                except Exception:  # noqa: BLE001
                    pass

        flag_text = ("  ⚠ " + "；".join(flags)) if flags else ""
        print(f"  · {acc['label']}  UID {wb_auth.mask_uid(acc['uid'])}"
              f"  剩余 {_remaining_text(data)}{flag_text}")
    return 0


def cmd_refresh(args) -> int:
    accounts = wb_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{wb_auth.auths_dir()}")
        return 0

    targets = accounts
    if args.uid:
        targets = [a for a in accounts
                   if args.uid in (a.get("uid") or "") or args.uid in (a.get("label") or "")]
        if not targets:
            print(f"未找到匹配账号：{args.uid}")
            return 1

    failed = 0
    for acc in targets:
        if acc.get("disabled"):
            print(f"  · {acc['label']}：已失效，跳过（请重新登录）")
            failed += 1
            continue
        try:
            data = wb_auth.load_account(acc["path"])
        except Exception as e:  # noqa: BLE001
            print(f"  · {acc['label']}：读取失败（{e}）")
            failed += 1
            continue
        ok, msg = wb_auth.refresh_account(acc["path"], data)
        if ok:
            data = wb_auth.load_account(acc["path"])
        print(f"  · {acc['label']}：{msg}（剩余 {_remaining_text(data)}）")
        if not ok:
            failed += 1
    return 1 if failed else 0


def cmd_remove(args) -> int:
    accounts = wb_auth.list_accounts()
    match = [a for a in accounts
             if args.uid and (args.uid == a.get("uid") or args.uid in (a.get("label") or "")
                              or args.uid == os.path.basename(a["path"]))]
    if not match:
        print(f"未找到匹配账号：{args.uid}")
        return 1

    removed = 0
    for acc in match:
        prompt = (f"确认删除 {acc['label']}（UID {wb_auth.mask_uid(acc['uid'])}）"
                  f"的凭据文件？[y/N]：")
        if args.yes or _yes(prompt):
            try:
                os.remove(acc["path"])
                print(f"  已删除 {os.path.basename(acc['path'])}")
                removed += 1
            except OSError as e:
                print(f"  删除失败：{e}")
        else:
            print("  已跳过")
    return 0 if removed else 1


def cmd_checkin_test(args) -> int:
    """只读模式逐账号试跑（查询签到状态，不执行签到、不写任何数据）"""
    from platforms.workbuddy import WorkBuddyCheckin  # 延迟导入，避免无谓依赖

    accounts = wb_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{wb_auth.auths_dir()}")
        return 0
    if args.uid:
        accounts = [a for a in accounts
                    if args.uid in (a.get("uid") or "") or args.uid in (a.get("label") or "")]
        if not accounts:
            print(f"未找到匹配账号：{args.uid}")
            return 1

    print("只读模式（--dry）：仅查询状态，不签到、不续期、不落盘")
    failed = 0
    for acc in accounts:
        inst = WorkBuddyCheckin(dry=True, account=acc)
        result = inst.run()
        icon = "✅" if result.get("status") in ("success", "already") else "❌"
        print(f"  {icon} {result.get('platform')}：{result.get('message')}")
        if result.get("status") in ("failed", "skipped"):
            failed += 1
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WorkBuddy 多账号管理（短信登录 / 查看 / 续期 / 删除）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("add", help="短信登录取凭据（新增/更新账号）")
    p_add.add_argument("--phone", help="手机号（缺省则交互输入）")
    p_add.add_argument("--code", help="短信验证码（缺省则交互输入）")

    p_list = sub.add_parser("list", help="列出全部账号")
    p_list.add_argument("--refresh", action="store_true", help="顺带续期临期账号")

    p_refresh = sub.add_parser("refresh", help="手动续期全部（或指定）账号")
    p_refresh.add_argument("uid", nargs="?", default=None, help="可选：UID 或昵称关键字")

    p_remove = sub.add_parser("remove", help="删除账号凭据")
    p_remove.add_argument("uid", help="UID / 昵称关键字 / 文件名")
    p_remove.add_argument("--yes", action="store_true", help="跳过确认")

    p_test = sub.add_parser("checkin-test", help="只读模式逐账号试跑")
    p_test.add_argument("uid", nargs="?", default=None, help="可选：UID 或昵称关键字")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "add": cmd_add,
        "list": cmd_list,
        "refresh": cmd_refresh,
        "remove": cmd_remove,
        "checkin-test": cmd_checkin_test,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
