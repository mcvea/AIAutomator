# AIAutomator —— 国内 AI 办公平台每日自动签到

配置驱动的**国内 AI 办公平台自动签到工具**，每日自动完成多家平台的积分签到，
并通过飞书把**签到结果、登录态健康、积分到期提醒**推送到你的私聊。

本项目为开源设计：**不绑定任何人的登录信息**，克隆到任意机器，按文档配置自己的登录态即可使用。

## ✨ 支持的平台

| 平台 | 每日积分 | 登录态来源 | 说明 |
|------|---------|-----------|------|
| **WorkBuddy**（腾讯） | 100/天，连签7天+1000 | 可选多账号凭据库 `auths/`（`wb_accounts.py` 短信登录），缺省回退本机客户端 | hook 完整接管；5.6+ 加密凭据自动兼容（瞬时解密，零落盘）；多账号自动续期 |
| **MiniMax Code** | 400/天，第4/7天+1000 | `~/.minimax/` OAuth 登录态（自动续期） | 本地签名算法复现；OAuth Bearer 鉴权，access token 1 小时寿命、脚本自动续期 |
| **TraeWork**（字节） | 150/天（会员200） | 可选多账号凭据库 `auths/`（`trae_accounts.py` 桌面导入 / 浏览器登录），缺省回退本机客户端 | hook 完整接管；AES 信封解析 + 设备证明续期；多账号自动续期 |
| **百度搭子 DuMate** | 500/天 | `auth.json` 加密 cookies | 本地 cookies 解析 |
| **LobsterAI**（网易有道） | 100/天（每日积分礼） | SQLite 登录态 | 三步接口流程 |

> ⚠️ 每日积分以各平台当前活动为准，可能变动；本项目仅自动化"领取"操作，
> 积分规则解释权归各平台所有。

## 🚀 快速开始

### 环境要求

- Windows 10/11（计划任务 + 睡眠唤醒特性）
- Python 3.11+（内置 TOML 解析）
- 可选依赖：`pycryptodome`（TraeWork/DuMate 加密解密需要）

```powershell
pip install pycryptodome
```

### 1. 配置平台登录态

各平台需先安装官方桌面客户端并**登录一次**（生成登录态文件），
本项目自动读取登录态，无需手动填 token：

| 平台 | 客户端 | 登录态文件位置（自动识别） |
|------|--------|--------------------------|
| WorkBuddy | WorkBuddy 桌面端 | `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info` |
| MiniMax Code | MiniMax Code 桌面端 | `~\.minimax\auth\prod\cn\mcode-public\auth.json`（OAuth 凭据）<br>`~\.minimax\local-runtime.auth.json`（旧会话 JWT，兜底） |
| TraeWork | TraeWork 桌面端 | `%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json` |
| 百度搭子 | 百度搭子桌面端 | `%APPDATA%\qianfan-desktop-app\auth.json` + `.cookie-key` |
| LobsterAI | LobsterAI 桌面端 | `%APPDATA%\LobsterAI\lobsterai.sqlite` |

> 登录态文件路径均使用环境变量（`%APPDATA%` / `%LOCALAPPDATA%` / `~`），
> 任何 Windows 用户路径都通用，无需修改代码。
> 各平台登录态有效期约 1~2 个月，失效时打开客户端登录一次即可刷新（签到日报会提前预警）。
> MiniMax Code 例外：桌面端现行认证为 **OAuth Bearer**，access token 寿命仅 1 小时，
> 脚本会用 refresh token 自动续期并写回客户端自己的凭据文件（与客户端共用同一把跨进程锁），
> 因此无需人工干预；客户端未运行也能正常签到。
> 设备参数（device_id 等）默认从桌面客户端的本地请求日志自动发现，仓库里不保存任何
> 机器标识；若日志不可读，可用环境变量 `MINIMAX_DEVICE_ID` / `MINIMAX_UUID` 覆盖。
> 备用的「按 token 计费」余额接口需要账号级 GroupId，用 `MINIMAX_GROUP_ID` 提供
> （不设置则跳过该接口，主接口 OP 积分不受影响）。

#### WorkBuddy 多账号（可选，默认关闭）

多账号是**可选功能，默认关闭**——不启用时完全走本机 WorkBuddy 客户端的单账号登录态，
与单账号模式行为一致。启用需两步：

```powershell
# 1) 打开 automator/platforms/workbuddy.toml，把 multi_account = false 改为 true
# 2) 添加账号（每个手机号一个独立会话凭据）
python wb_accounts.py add              # 短信验证码登录，添加/更新一个账号
python wb_accounts.py list             # 查看账号（UID/昵称/剩余天数/状态）
python wb_accounts.py refresh          # 手动续期全部账号
python wb_accounts.py checkin-test     # 只读模式逐账号试跑
```

启用后每日逐个签到、自动续期（refreshToken 轮换），日报按账号独立成行。
凭据保存在本机 `auths/workbuddy-<uid>.json`（已 gitignore，**等同账号密码**：
勿提交、勿外发）；凭据库为空时仍自动回退本机客户端登录态。

#### TraeWork 多账号（可选，默认关闭）

TraeWork 同样支持可选的多账号模式，启用方式与 WorkBuddy 一致
（`automator/platforms/traework.toml` 里 `multi_account = true`）：

```powershell
python trae_accounts.py add            # 桌面导入：取本机客户端当前登录账号
python trae_accounts.py add --web      # 浏览器登录：任意账号（登录前先退出 Trae 客户端）
python trae_accounts.py list           # 查看账号（UID/昵称/剩余天数/状态）
python trae_accounts.py refresh        # 手动续期全部账号
python trae_accounts.py checkin-test   # 只读模式逐账号试跑
```

浏览器登录的回调端口固定 `127.0.0.1:17388`（官网靠探测该端口
判断"客户端在线"，登录时需先退出 Trae 客户端）。凭据保存在本机
`auths/traework-<uid>.json`（已 gitignore，**等同账号密码**：勿提交、勿外发）。

> 每个账号会生成**独立的设备身份**（ECDSA P-256 密钥对 + 随机设备号），
> 因为签到领取按设备维度限流（每设备每日一次），多账号共用同一设备会触发
> "当前设备今日已经签到"拦截。

> 也可以用环境变量临时切换，无需改 TOML：
> `AI_CHECKIN_MULTI_ACCOUNT=0` 强制单账号，`=1` 强制多账号（未设置时按 TOML 开关）。

### 2. 配置飞书通知（可选）

1. [飞书开放平台](https://open.feishu.cn) 创建企业自建应用，开通权限：
   `contact:user.id:readonly`（查 open_id）、`im:message`（发消息）
2. 复制 `config/secrets.example.json` 为 `config/secrets.json`，填入：

```json
{
  "notify": {
    "channels": ["feishu_direct"],
    "feishu": {
      "app_id": "你的 App ID",
      "app_secret": "你的 App Secret",
      "open_id": "你的 open_id"
    }
  }
}
```

3. 查询自己的 open_id（应用需开通通讯录权限）：

```powershell
python -m automator resolve-uid --mobile 你的飞书手机号
```

4. 测试通知：`python -m automator notify-test`

### 3. 手动运行

```powershell
python -m automator list               # 查看平台与任务
python -m automator run daily          # 执行每日任务（签到+健康+积分+总积分+通知）
python -m automator run daily --dry    # 只读试跑（不签到不通知）
python -m automator health             # 登录态健康检查
python -m automator credits            # 积分到期盘点
python -m automator totals             # 账户总积分查询
```

### 4. 设置每日自动执行（Windows 计划任务，支持睡眠唤醒）

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_task.ps1
# 自定义时间：powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Time "09:30"
# 删除任务：  powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Remove
```

计划任务默认每天 **08:00** 执行，电脑睡眠时自动唤醒 → 签到 → 推送飞书 → 回到睡眠。

## 📦 日报内容

每天飞书收到一份 interactive 日报卡片，包含：

- ✅ 各平台签到结果（成功/已签/失败 + 获得积分），有失败时卡片标题转红并附行动提示
- 📊 汇总行（成功/已签/跳过/失败 + 本次新增积分）
- 💰 账户总积分（各平台余额；接口未提供的平台如实标注），并附**较昨日环比**（每日快照 `logs/totals-<date>.json` 供次日对比）
- 🔋 登录态健康（全部正常时折叠为一行，异常时逐行展开并告警）

> 积分到期数据仍会采集（`python -m automator credits` 可单独查看），但日报不再展示该区块。

## 🏗️ 项目结构

```
AIAutomator/
├── automator/
│   ├── __main__.py        # CLI 入口
│   ├── cli.py             # 命令解析
│   ├── engine.py          # 任务引擎
│   ├── config.py          # 配置加载（TOML）
│   ├── auth_store.py      # 登录态管理（json/sqlite/加密/cookies）
│   ├── apiclient.py       # HTTP 客户端
│   ├── parser.py          # 声明式响应解析
│   ├── notifier.py        # 通知总线（interactive 卡片 / text 兼容）
│   ├── reporter.py        # 日报生成
│   ├── paths.py           # 路径解析（环境变量/主目录）
│   ├── platforms/         # 平台声明（TOML）+ hooks（复杂逻辑）
│   └── tasks/             # 任务定义（TOML）
├── platforms/             # 平台实现（登录态读取/接口调用）
│   ├── wb_auth.py         # WorkBuddy 多账号凭据库（读写/续期/短信登录）
│   ├── trae_auth.py       # TraeWork 多账号凭据库（读写/续期/网页 OAuth/桌面导入）
│   └── wb_helper.js       # WorkBuddy 5.6+ 加密凭据瞬时解密助手（零落盘）
├── wb_accounts.py         # WorkBuddy 多账号管理 CLI（短信登录/续期/试跑）
├── trae_accounts.py       # TraeWork 多账号管理 CLI（桌面导入/浏览器登录/续期/试跑）
├── config/
│   ├── user.example.toml  # 用户配置模板
│   └── secrets.example.json  # 凭证模板（复制为 secrets.json）
└── setup_task.ps1         # 计划任务脚本
```

## ➕ 新增平台

新平台 = 新建一个 `automator/platforms/xxx.toml`（声明登录态类型、接口、解析规则），
复杂逻辑（加密/签名/多步流程）在 `automator/platforms/hooks/xxx.py` 中实现，零侵入。

## 🔒 安全说明

- 本项目**不收集、不上传任何登录凭证**：所有登录态仅在本机读取，用于调用对应平台自己的签到接口
- **WorkBuddy 5.6+ 加密凭据**通过 WorkBuddy 客户端自身运行时瞬时解密（`ELECTRON_RUN_AS_NODE` 管道模式），明文只存在于子进程内存管道，**不落盘、不打日志**
- WorkBuddy 多账号模式下，凭据（access/refresh token）仅保存在本机 `auths/`（已 gitignore），用于脚本自动续期；同样不上传、不写日志
- TraeWork 多账号模式下，凭据（access/refresh token 与设备密钥）仅保存在本机 `auths/`（已 gitignore），用于脚本自动续期；同样不上传、不写日志
- **MiniMax Code** 走桌面端现行 OAuth 认证：access token 寿命仅 1 小时，脚本会用 refresh token 自动续期，并**原地写回桌面客户端自己的凭据文件**（`~/.minimax/auth/prod/cn/mcode-public/auth.json` 与 `auth-state.json`），写回时与客户端共用同一把跨进程锁；除此之外不新增任何持久化副本
- 设备参数（device_id 等）会从桌面客户端的**本地请求日志**中只读解析，用于复现客户端签名；不写入、不上传任何日志内容
- 签到接口均为各平台官方接口的幂等调用，重复执行只会提示"已领取"
- 请仅对自己的账号使用，遵守各平台服务条款

## 📄 License

[MIT](LICENSE)

## ⚠️ 免责声明

- 本项目仅供学习与个人自动化使用，仅用于**领取自己账号**在对应平台的每日积分；不提供、不支持代他人操作、批量注册或任何形式的账号买卖/租用场景。多账号模式（WorkBuddy / TraeWork）仅用于管理**你本人名下**的账号，凭据只存本机
- 项目通过解析**本机已有的官方客户端登录态文件**调用平台官方接口，不破解任何服务器端防护，不收集、不存储、不传输任何第三方凭证
- 平台登录态文件格式与接口可能随版本更新变动，本项目不对可用性作任何保证
- 使用本项目即表示你已阅读并同意遵守各平台服务条款；若平台方认为本项目与其服务条款冲突，请自行停止使用
- 本项目与文中提到的任何平台（腾讯、字节跳动、百度、MiniMax、网易有道）均无关联
