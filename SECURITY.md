# 安全策略

## 凭证与敏感数据处理方式

AIAutomator 默认只在内存中使用本机登录态、不持久化任何用户凭证；唯一的例外是
可选启用的多账号模式（WorkBuddy / TraeWork，见第 4 条）：

1. **登录态（各平台 token / cookies）**
   - 仅从**本机官方桌面客户端**已有的登录态文件中读取（路径见 README）
   - 仅在本机内存中用于调用对应平台自己的官方接口
   - 不落盘、不上传、不写入日志、不发送到任何第三方服务
   - WorkBuddy 5.6+ 将敏感字段升级为 `$wbEncrypted` 加密信封：本项目通过 WorkBuddy
     客户端自身运行时（`platforms/wb_helper.js`，`ELECTRON_RUN_AS_NODE` 管道模式）
     在内存中瞬时解密，解密出的明文与密钥**仅存在于子进程内存管道**，绝不落盘、
     绝不写日志；解密失败时 Fail-Closed（直接阻断），绝不把畸形鉴权头发往服务端

2. **通知凭证（如飞书 app_secret）**
   - 仅保存在本地 `config/secrets.json`（模板见 `secrets.example.json`），不上传到任何远程服务
   - 上传/克隆前请确认自己没有把该文件提交到 git 历史：
     ```powershell
     git log --all --full-history -- config/secrets.json
     ```
   - 若曾误提交，请立即在各平台**重置对应密钥**，并使用 `git filter-repo` 等工具改写历史

3. **日志与运行产物**
   - `logs/`、`*.log`、`__pycache__/` 均已被 `.gitignore` 排除
   - 提交前请用 `git status` 确认没有意外跟踪的敏感文件

4. **多账号凭据（WorkBuddy / TraeWork，可选功能）**
   - 通过 `wb_accounts.py` 短信登录 / `trae_accounts.py` 桌面导入或浏览器 OAuth
     生成的凭据保存在本机 `auths/workbuddy-<uid>.json`、`auths/traework-<uid>.json`
     （已被 `.gitignore` 排除）
   - 内容含 accessToken / refreshToken（TraeWork 另含设备密钥），**等同账号密码**：
     脚本仅在本机使用（自动续期 + 调用官方签到接口），不上传、不写入日志；
     请勿提交、勿拷贝外发
   - 未启用多账号功能时不存在该目录，行为与默认单账号模式完全一致

## 发现安全问题

如发现本项目存在安全漏洞或凭证泄露风险，请**不要直接在 Issue 中公开细节**，
优先通过私信联系仓库维护者，或提交仅描述类别（不含细节）的 Issue。

## 免责声明

本项目仅供个人学习与自动化使用，请仅对自己账号操作，并遵守各平台服务条款。详见 README 中的免责声明。
