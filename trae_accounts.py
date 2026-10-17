#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TraeWork 多账号管理 CLI（登录取凭据 / 查看 / 续期 / 删除 / 试跑）

用法：
    python trae_accounts.py add                  # 桌面导入：读本机客户端登录态生成凭据（默认）
    python trae_accounts.py add --web            # 浏览器登录：官网 OAuth 流程（短信/滑块在网页内完成）
    python trae_accounts.py list                 # 列出全部账号（UID/昵称/剩余天数/状态）
    python trae_accounts.py list --refresh       # 列出并顺带续期临期账号
    python trae_accounts.py refresh [uid]        # 手动续期全部（或指定）账号
    python trae_accounts.py remove <uid> [--yes] # 删除账号凭据（默认需确认）
    python trae_accounts.py checkin-test [uid]   # 只读模式逐账号试跑签到（不写数据）

说明：
    - 凭据存入 auths/traework-<uid>.json，之后由脚本每日自动续期
      （设备证明版 ExchangeToken，refreshToken 轮换落盘），无需再打开桌面客户端。
    - 桌面导入（add）：直接采用本机客户端当前登录账号（含 refreshToken 与设备密钥）。
    - 浏览器登录（add --web）：在弹出的官网页面完成登录（任意账号），回调端口
      固定 17388 —— 登录前请先退出 Trae 客户端，否则端口被占无法接住回调。
    - 同一账号重复 add 会覆盖旧凭据（用于找回/续期场景）。
    - 凭据文件等同账号密码：仅存本机、已 gitignore；本工具输出全程脱敏，不打印 Token。
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from platforms import trae_auth  # noqa: E402


def _yes(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _remaining_text(data: dict | None) -> str:
    if not data:
        return "-"
    days = trae_auth.days_left(data)
    if days is None:
        return "未知"
    if trae_auth.is_expired(data):
        return "已过期"
    return f"{days} 天"


def cmd_add(args) -> int:
    if args.web:
        print("浏览器登录模式（官网 OAuth）：请在弹出的页面完成登录；")
        print("如端口 17388 被占用，请先退出 Trae 客户端。")
        cred, err = trae_auth.login_via_browser(timeout=args.timeout)
    else:
        print("桌面导入模式：读取本机 TraeWork 客户端登录态…")
        cred, err = trae_auth.desktop_credential(args.storage)

    if err:
        print(f"  失败：{err}")
        return 1
    if not (cred.get("auth") or {}).get("refreshToken"):
        print("  警告：凭据中没有 refreshToken，将无法自动续期（建议重新登录）")

    acct = cred.get("account") or {}
    uid = acct.get("uid") or ""
    path = trae_auth.account_path_for(uid or f"login-{int(time.time())}")
    existed = os.path.isfile(path)
    trae_auth.save_account(path, cred)
    print("  获取成功" + ("（已更新）" if existed else "（已新增）"))
    print(f"  账号：{acct.get('nickname') or '(未提供)'}   "
          f"UID：{trae_auth.mask_uid(uid or '')}")
    print(f"  凭据：{os.path.relpath(path)}")
    print(f"  有效期：{_remaining_text(cred)}（脚本将每日自动续期）")
    return 0


def cmd_list(args) -> int:
    accounts = trae_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{trae_auth.auths_dir()}")
        print("请先用  python trae_accounts.py add  添加账号")
        return 0

    print(f"凭据目录：{trae_auth.auths_dir()}")
    print(f"共 {len(accounts)} 个账号：")
    for acc in accounts:
        data = None
        try:
            data = trae_auth.load_account(acc["path"])
        except Exception:  # noqa: BLE001 - 运行期会给出明确错误，这里仅展示
            pass

        flags = []
        if acc.get("disabled"):
            flags.append("已失效需重登")
        if data is not None and not (data.get("auth") or {}).get("refreshToken"):
            flags.append("无续期凭证")

        if args.refresh and data is not None and not acc.get("disabled"):
            ok, msg = trae_auth.refresh_account(acc["path"], data)
            flags.append("续期成功" if ok else f"续期失败（{msg}）")
            if ok:
                try:
                    data = trae_auth.load_account(acc["path"])
                except Exception:  # noqa: BLE001
                    pass

        flag_text = ("  ⚠ " + "；".join(flags)) if flags else ""
        print(f"  · {acc['label']}  UID {trae_auth.mask_uid(acc['uid'])}"
              f"  剩余 {_remaining_text(data)}{flag_text}")
    return 0


def cmd_refresh(args) -> int:
    accounts = trae_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{trae_auth.auths_dir()}")
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
            data = trae_auth.load_account(acc["path"])
        except Exception as e:  # noqa: BLE001
            print(f"  · {acc['label']}：读取失败（{e}）")
            failed += 1
            continue
        ok, msg = trae_auth.refresh_account(acc["path"], data)
        if ok:
            data = trae_auth.load_account(acc["path"])
        print(f"  · {acc['label']}：{msg}（剩余 {_remaining_text(data)}）")
        if not ok:
            failed += 1
    return 1 if failed else 0


def cmd_remove(args) -> int:
    accounts = trae_auth.list_accounts()
    match = [a for a in accounts
             if args.uid and (args.uid == a.get("uid") or args.uid in (a.get("label") or "")
                              or args.uid == os.path.basename(a["path"]))]
    if not match:
        print(f"未找到匹配账号：{args.uid}")
        return 1

    removed = 0
    for acc in match:
        prompt = (f"确认删除 {acc['label']}（UID {trae_auth.mask_uid(acc['uid'])}）"
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
    """只读模式逐账号试跑（查询签到状态，不执行签到、不续期、不写任何数据）"""
    from platforms.traework import TraeWorkCheckin  # 延迟导入，避免无谓依赖

    accounts = trae_auth.list_accounts()
    if not accounts:
        print(f"凭据目录为空：{trae_auth.auths_dir()}")
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
        inst = TraeWorkCheckin(dry=True, account=acc)
        result = inst.run()
        status = result.get("status")
        icon = "✅" if status in ("success", "already", "skipped") else "❌"
        print(f"  {icon} {result.get('platform')}：{result.get('message')}")
        if status == "failed":
            failed += 1
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TraeWork 多账号管理（登录取凭据 / 查看 / 续期 / 删除 / 试跑）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("add", help="登录取凭据（桌面导入 / 浏览器 OAuth）")
    p_add.add_argument("--web", action="store_true",
                       help="走浏览器 OAuth 登录（默认：桌面导入）")
    p_add.add_argument("--timeout", type=int, default=trae_auth.CALLBACK_LOGIN_TIMEOUT,
                       help=f"浏览器登录等待回调秒数（默认 {trae_auth.CALLBACK_LOGIN_TIMEOUT}）")
    p_add.add_argument("--storage", help="桌面导入时指定 storage.json 路径（默认自动探测）")

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
