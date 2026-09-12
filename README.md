# AIAutomator —— 国内 AI 办公平台每日自动签到

配置驱动的**国内 AI 办公平台自动签到工具**，每日自动完成多家平台的积分签到，
并通过飞书把**签到结果、登录态健康、积分到期提醒**推送到你的私聊。

本项目为开源设计：**不绑定任何人的登录信息**，克隆到任意机器，按文档配置自己的登录态即可使用。

## ✨ 支持的平台

| 平台 | 每日积分 | 登录态来源 | 说明 |
|------|---------|-----------|------|
| **WorkBuddy**（腾讯） | 100/天，连签7天+1000 | 本机客户端 `auth.json` | 纯声明式接入示范 |
| **MiniMax Code** | 400/天，第4/7天+1000 | `~/.minimax/` 登录态 | 签名加密破解 |
| **TraeWork**（字节） | 150/天（会员200） | `storage.json` AES 信封 | 加密解密 + 自动续期 |
| **百度搭子 DuMate** | 500/天 | `auth.json` 加密 cookies | cookies 加密破解 |
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
| MiniMax Code | MiniMax Code 桌面端 | `~\.minimax\local-runtime.auth.json` |
| TraeWork | TraeWork 桌面端 | `%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json` |
| 百度搭子 | 百度搭子桌面端 | `%APPDATA%\qianfan-desktop-app\auth.json` + `.cookie-key` |
| LobsterAI | LobsterAI 桌面端 | `%APPDATA%\LobsterAI\lobsterai.sqlite` |

> 登录态文件路径均使用环境变量（`%APPDATA%` / `%LOCALAPPDATA%` / `~`），
> 任何 Windows 用户路径都通用，无需修改代码。
> 各平台登录态有效期约 1~2 个月，失效时打开客户端登录一次即可刷新（签到日报会提前预警）。

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
python -m automator run daily          # 执行每日任务（签到+健康+积分+通知）
python -m automator run daily --dry    # 只读试跑（不签到不通知）
python -m automator health             # 登录态健康检查
python -m automator credits            # 积分到期盘点
```

### 4. 设置每日自动执行（Windows 计划任务，支持睡眠唤醒）

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_task.ps1
# 自定义时间：powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Time "09:30"
# 删除任务：  powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Remove
```

计划任务默认每天 **08:00** 执行，电脑睡眠时自动唤醒 → 签到 → 推送飞书 → 回到睡眠。

## 📦 日报内容

每天飞书收到一份日报，包含：

- ✅ 各平台签到结果（成功/已签/失败 + 获得积分）
- 💰 积分到期提醒（按最近到期排序，🚨 7 天内、⚠️ 30 天内）
- 🔋 登录态健康（各平台 token 剩余天数，🚨 失效时醒目告警）

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
│   ├── notifier.py        # 通知总线
│   ├── reporter.py        # 日报生成
│   ├── paths.py           # 路径解析（环境变量/主目录）
│   ├── platforms/         # 平台声明（TOML）+ hooks（复杂逻辑）
│   └── tasks/             # 任务定义（TOML）
├── platforms/             # 平台实现（登录态读取/接口调用）
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
- 敏感配置（`config/secrets.json`）已被 `.gitignore` 排除，不会被提交
- 签到接口均为各平台官方接口的幂等调用，重复执行只会提示"已领取"
- 请仅对自己的账号使用，遵守各平台服务条款

## 📄 License

[MIT](LICENSE)
