# AIAutomator —— 通用 AI 平台自动化任务框架（独立项目）

独立于旧版「AI办公签到自动化」项目。代码复用旧项目的平台破解成果（登录态/AES解密/签名），
但**计划任务、飞书通道、配置完全独立**，互不污染。

## 与旧版的关系

| 维度 | 旧版（AI办公签到自动化） | 新版（AIAutomator） |
|------|------------------------|--------------------|
| 入口 | main.py（单文件调度） | python -m automator（CLI 框架） |
| 平台 | platforms/ 硬编码 | platforms/*.toml 声明式 + hooks |
| 计划任务 | LoomyAICheckin | AIAutomatorDaily |
| 飞书通道 | config.json | config/secrets.json（独立） |
| git | 独立仓库 | 独立仓库 |

## 快速开始

```powershell
python -m automator list               # 列平台与任务
python -m automator run daily          # 执行每日任务（签到+健康+积分+通知）
python -m automator run daily --dry    # 只读试跑
python -m automator health             # 登录态健康检查
python -m automator credits            # 积分到期盘点
python -m automator notify-test        # 通知通道测试

# 注册独立计划任务（AIAutomatorDaily，每天 08:00，睡眠唤醒）
powershell -ExecutionPolicy Bypass -File .\setup_task.ps1
```

## 目录

```
AIAutomator/
├── automator/            # 框架核心（引擎/CLI/配置/登录态/通知/报告）
│   ├── platforms/*.toml  # 平台声明式定义
│   ├── platforms/hooks/  # 复杂平台扩展（解密/签名/签到）
│   └── tasks/*.toml      # 任务定义
├── platforms/            # 平台实现（复用旧版破解逻辑，自包含）
├── config/
│   ├── user.toml         # 启用平台、通知偏好（入 git）
│   └── secrets.json      # 飞书凭证（不入 git）
├── setup_task.ps1        # 独立计划任务
└── .gitignore
```

## 新增平台（声明式）

1. 新建 `automator/platforms/xxx.toml`（登录态 + 接口 + 解析规则）
2. 复杂逻辑注册到 `automator/platforms/hooks/xxx.py`
3. `config/user.toml` 的 enabled 列表加入平台名
