# Herald 0.2.1

> 蓝牙稳定性：修「频繁掉线」和「睡醒后连不上」。

## 根因（来自 Mac 端 debug.log 的实测）

- 断开日志是 `disconnected -`（没有 CB 错误码），也就是**手机端主动 cancelConnection**；
  旧的「链路 5 分钟没回执就重建连接」逻辑会误判，把好链路掐掉；
- `onNotificationSent` 在部分机型/息屏下不回调时，分片队列会永久卡在 in-flight，
  后续消息发不出去，看起来也像断连；
- 合盖唤醒后 CoreBluetooth 不再扫描，旧连接名存实亡但没有 disconnect 回调，App 就永远停在「已断开」；
- Ad-hoc 签名每次重新构建都会换 cdhash，macOS 会把 App 当成新程序，**蓝牙权限要重新授权**——
  没授权时 `CBCentralManager.state` 一直是 `.unknown`，App 静默不扫描。这个现在会在菜单栏明示。

## 改动

**Mac**
- 去掉「5 分钟无回执就重建连接」，不再自己掐链路；
- 新增连接监督器：每 20 秒核对状态，没连接又没在扫描、或扫描 60 秒无结果就重新拉；
- 监听系统唤醒（`NSWorkspace.didWakeNotification`）：丢弃旧连接、重新扫描；
- 非 poweredOn 状态会暂停重连并每 5 秒重试，不会静默卡死；
- 菜单栏新增「蓝牙设置」按钮，状态里直接提示「等待蓝牙授权…」。

**Android**
- 不再主动 `cancelConnection`（这是掉线日志里 `disconnected -` 的来源）；
- 分片发送加 5 秒 in-flight 超时：`onNotificationSent` 不回调时自动重置并重试；
- 广播看门狗：没连上又没在广播时，每 30 秒重新拉一次（HyperOS 会悄悄停广播）。

## 升级

- Mac：替换 App 后**第一次启动要去「系统设置 → 隐私与安全 → 蓝牙」允许 Herald**（ad-hoc 签名，重建后必现）。
- Android：覆盖安装 0.2.1 APK，配对码保留。
