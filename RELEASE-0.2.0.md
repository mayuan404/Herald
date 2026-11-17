# Herald 0.2.0（原 PhoneBridge）

> 改名 + 去掉自动复制。**Android 包名变了，要卸载旧 App 重装**；Mac 端会从旧名自动迁移数据。

## 改了什么

- 项目从 **PhoneBridge** 改名为 **Herald**（传令官）。
- Mac：`CFBundleIdentifier` → `dev.herald`；首次启动会把
  `~/Library/Application Support/PhoneBridge` 整目录迁到 `.../Herald`，
  并从旧 domain 读取配对码，**手机端不需要重新粘**。
- Android：`applicationId` / 包名 → `dev.herald`。因为包名变了，这是一个新 App：
  旧版需要先卸载，配对码重新粘一次（白名单也要重选）。
- 加密派生字符串 **保持 `|PhoneBridge|v1` 不变**：改名不触碰协议，旧密文/旧配对码继续有效，
  两端升级顺序无所谓。
- **移除「自动复制」**：不再在通知到达时自动写剪贴板。复制验证码改成明确的动作——
  点通知行的「复制」、点整行，或点验证器卡片（会显示「已复制」）。
  理由：自动写剪贴板会覆盖你正在复制的东西，而且经常在你不需要的时候触发。

## 升级方式

- Mac：`mac/build.sh` 会安装到 `~/Applications/Herald.app`；旧 `PhoneBridge.app` 可以删掉。
- Android：卸载旧版 → 装 `Herald-0.2.0.apk` → 重新粘配对码（Mac 菜单栏「配对码」）→ 启动后台服务。

## 安全模型（未变）

应用层 AES-256-GCM 是唯一安全边界：没有配对码不发、Mac 丢明文、msgId 防重放、
TCP 调试口只绑 `127.0.0.1`。详见 README。
