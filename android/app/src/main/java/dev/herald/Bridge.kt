package dev.herald

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.bluetooth.BluetoothStatusCodes
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import org.json.JSONObject
import java.io.OutputStream
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Herald 安卓端
 *
 * 两条直连通道，都不经过服务器：
 *   1. BLE：本机作为 GATT server 广播，Mac 端订阅后把通知推过去；
 *   2. TCP：连接 127.0.0.1:8765（配合 adb reverse，用于联调/无蓝牙时）。
 *
 * 通知读取需要用户在「设置 → 通知使用权」里授权。
 */

/** 应用层加密：与 Mac 端同一套派生规则（SHA-256(code + "|PhoneBridge|v1")）+ AES-256-GCM */
object Secure {
    fun normalize(s: String): String = s.uppercase().filter { it.isLetterOrDigit() }

    fun key(code: String): ByteArray? {
        val norm = normalize(code)
        if (norm.length < 8) return null
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest("$norm|PhoneBridge|v1".toByteArray(Charsets.UTF_8))
    }

    /** 返回 "E1:" + base64(nonce(12) + ciphertext + tag) */
    fun encrypt(plain: ByteArray, code: String): String? {
        val k = key(code) ?: return null
        return try {
            val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(k, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, nonce)
            )
            val ct = cipher.doFinal(plain)
            "E1:" + android.util.Base64.encodeToString(nonce + ct, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("Herald", "encrypt failed: ${e.message}")
            null
        }
    }
}

object Link {
    /** 手机端配对码（空 = 不加密，仅联调用） */
    @Volatile var pairCode: String = ""
    val serviceUUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
    val rxUUID: UUID = UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
    val txUUID: UUID = UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")

    @Volatile var server: BluetoothGattServer? = null
    @Volatile var txChar: BluetoothGattCharacteristic? = null
    @Volatile var central: BluetoothDevice? = null
    @Volatile var connected = false
    /** 前台服务是否在跑。停止按钮点了之后 UI 要能反映出来，别继续显示「已连接」 */
    @Volatile var running = false

    private val queue = ConcurrentLinkedQueue<String>()

    /** 断链时最多攒这么多条：再多就丢最旧的，避免恢复后一次性刷屏 */
    private const val MAX_QUEUE = 50

    /** 最近事件，App 界面里直接显示，方便没有 adb 时排查 */
    private val events = ArrayDeque<String>()

    fun log(msg: String) {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        synchronized(events) {
            events.addLast("$t  $msg")
            while (events.size > 40) events.removeFirst()
        }
        Log.i("Herald", msg)
    }

    fun recentEvents(): List<String> = synchronized(events) { events.toList() }

    private var hbStarted = false

    /** 心跳：只为在长时间没通知时确认链路还活着，间隔不必太密 */
    fun startHeartbeat() {
        if (hbStarted) return
        hbStarted = true
        handler.postDelayed(object : Runnable {
            override fun run() {
                // 积压时不要用心跳继续污染队列
                if (running && connected && queue.size < 20) push("__hb", "heartbeat", "", "")
                handler.postDelayed(this, 60_000)
            }
        }, 60_000)
    }

    /** 把一条通知编码成 JSON 行发出去 */
    fun push(pkg: String, app: String, title: String, text: String) {
        val id = "${System.currentTimeMillis()}-${seq++}"
        val json = JSONObject()
            .put("id", id)
            .put("pkg", pkg)
            .put("app", app)
            .put("title", title)
            .put("text", text)
            .put("time", System.currentTimeMillis() / 1000.0)
            .toString()
        log("收到通知 pkg=$pkg title=${title.take(20)}")
        if (!running) {
            // 服务已停止（或还没启动）：不排队，避免停止后通知还在后台累积
            log("服务未运行，本条忽略")
            return
        }
        // 安全：没有配对码就不发。明文一旦发出去，同频段任何人都能读，
        // 而且 Mac 端现在也会直接丢弃明文——留着这条通道只会让人误以为能用。
        if (pairCode.isEmpty()) {
            log("未设置配对码，本条不发送（明文已禁用）")
            return
        }
        val enc = Secure.encrypt(json.toByteArray(Charsets.UTF_8), pairCode)
        if (enc == null) {
            log("加密失败，本条丢弃")
            return
        }
        val line = enc + "\n"
        pending[id] = Pending(line, 0)
        while (queue.size >= MAX_QUEUE) {
            val dropped = queue.poll()
            if (dropped == null) break
            log("队列已满（$MAX_QUEUE），丢弃最旧一条")
        }
        queue.add(line)
        flush()
        retryLater(id)
    }

    /** 发送必须串行：多条通知同时到时分片会交错，粘成一行 */
    private val sendLock = Any()

    /** 最近一次「发送」与「通知已发出确认」的时间，用来发现死连接 */
    @Volatile private var lastSendAt = 0L
    @Volatile private var lastAckAt = 0L
    @Volatile private var lastSentOkAt = 0L
    @Volatile private var lastRecoverAt = 0L

    // ---- 分片发送（带流控）----
    // Android 的 GATT server 同一时刻只允许有限个未确认的 notification 在途。
    // 之前「20 字节一片 + 每片 sleep 8ms 连发」在拥塞时会丢片/返回错误，
    // 长通知于是残缺、Mac 解不出来、也就没有 ACK，最后触发重发和断链。
    // 现在改成：排队分片，每片等 onNotificationSent 回调后再发下一片。
    private val chunks = java.util.ArrayDeque<ByteArray>()
    @Volatile private var chunkInFlight = false
    @Volatile private var chunkToken = 0

    private data class Pending(var line: String, var tries: Int)
    private val pending = java.util.concurrent.ConcurrentHashMap<String, Pending>()
    private val acked = java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap<String, Boolean>())
    private var seq = 0
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())

    /** Mac 回执：收到 "ACK <id>" 就认为这条已送达 */
    fun onAck(id: String) {
        acked.add(id)
        pending.remove(id)
        log("Mac 已确认 #$id")
    }

    private fun retryLater(id: String) {
        handler.postDelayed({
            val p = pending[id] ?: return@postDelayed
            if (acked.contains(id)) return@postDelayed
            if (p.tries >= 4) {
                pending.remove(id)
                // 以前这里会 cancelConnection「重建连接」，但链路往往是好的，
                // 只是回执慢了：主动断反而制造抖动。交给两端各自的看门狗。
                log("重发 4 次仍无回执，放弃 #$id")
                return@postDelayed
            }
            p.tries += 1
            log("未收到回执，第 ${p.tries} 次重发 #$id")
            queue.add(p.line)
            flush()
        }, 10_000)
    }

    fun markAck() {
        lastAckAt = System.currentTimeMillis()
    }

    /** 真正发出去过的分片才算「链路活着」：有积压且很久一片都发不出去，才怀疑链路死了 */
    private fun linkLooksDead(): Boolean {
        if (!connected) return false
        if (queue.isEmpty()) return false
        if (lastSendAt == 0L) return false
        val now = System.currentTimeMillis()
        return lastSendAt > lastSentOkAt && now - lastSendAt > 60_000
    }

    private fun dropStaleLink() {
        log("蓝牙链路疑似失效，主动断开等 Mac 重连")
        connected = false
        lastAckAt = 0
        lastSendAt = 0
        val dev = central
        central = null
        // 注意：这里**不能**清 txChar。它是 GATT 服务里的特征值，与「当前连接」无关；
        // 清掉之后即使 Mac 重连成功，sendBle 也会一直因为 ch == null 返回 false，
        // 表现就是「已连接但发不出去」，且只能重启 App 才能恢复。
        try { if (dev != null) server?.cancelConnection(dev) } catch (e: Exception) { }
    }

    fun flush() {
        var retryLater = false
        var nextSoon = false
        synchronized(sendLock) {
            val now = System.currentTimeMillis()
            if (linkLooksDead() && now - lastRecoverAt > 300_000) {
                lastRecoverAt = now
                // 以前这里会 cancelConnection「重建连接」，结果链路上只要有一阵没回执，
                // 手机就主动把好好的连接掐掉——用户看到的就是「频繁掉线」。
                // 现在只记录并让重发/心跳继续，断开由系统或 Mac 端决定。
                log("链路疑似无响应，继续重试（不主动断开）")
            }
            if (queue.isNotEmpty()) {
                val chunksPending = synchronized(chunks) { chunks.isNotEmpty() }
                if (chunkInFlight || chunksPending) {
                    nextSoon = true
                } else {
                    val line = queue.peek()
                    if (line != null) {
                        val viaBle = sendBle(line)
                        val viaTcp = !viaBle && sendTcp(line)
                        if (!viaBle && !viaTcp) {
                            log("发送失败：${bleStateText()}；${tcpStateText()}；队列 ${queue.size} 条，稍后重试")
                            retryLater = true
                        } else {
                            queue.poll()
                            log(if (viaBle) "已通过蓝牙发送（队列剩 ${queue.size}）" else "已通过 TCP 发送（队列剩 ${queue.size}）")
                            nextSoon = queue.isNotEmpty()
                        }
                    }
                }
            }
        }
        when {
            retryLater -> scheduleFlush(3_000)
            nextSoon -> handler.postDelayed({ flush() }, 150)
        }
    }

    /** 失败原因：说清楚到底卡在哪一环，别再一律报「蓝牙未连接」 */
    private fun bleStateText(): String = when {
        server == null -> "BLE 服务未就绪"
        txChar == null -> "BLE 特征值丢失"
        central == null -> "BLE 无设备连接"
        !connected -> "BLE 未连接"
        else -> "BLE 已连接但发送被拒"
    }

    private fun tcpStateText(): String =
        if (tcp?.isConnected == true) "TCP 已连但写入失败" else "TCP 未连接"

    @Volatile private var flushScheduled = false

    /** 失败后自动重试一次，而不是干等下一条通知来触发 */
    private fun scheduleFlush(delayMs: Long = 3_000) {
        if (flushScheduled) return
        flushScheduled = true
        handler.postDelayed({
            flushScheduled = false
            flush()
        }, delayMs)
    }

    /** 把一条消息切成 20 字节分片排队，返回 false 表示链路不可用 */
    private fun sendBle(line: String): Boolean {
        if (server == null || txChar == null || central == null || !connected) return false
        val bytes = line.toByteArray(Charsets.UTF_8)
        synchronized(chunks) {
            chunks.clear()   // 新消息优先；没发完的旧分片由 pending 重发兜底
            var offset = 0
            while (offset < bytes.size) {
                val end = minOf(offset + 20, bytes.size)
                chunks.addLast(bytes.copyOfRange(offset, end))
                offset = end
            }
        }
        lastSendAt = System.currentTimeMillis()
        pumpChunks()
        return true
    }

    /** 发下一片；必须等 onNotificationSent 回来再发下一片，否则会丢片 */
    private fun pumpChunks() {
        val srv = server ?: return
        val ch = txChar ?: return
        val dev = central ?: return
        if (!connected) return
        // 「检查 + 置位 + 取片」必须原子，否则 flush 线程和回调线程会各发一片
        val chunk = synchronized(chunks) {
            if (chunkInFlight || chunks.isEmpty()) null
            else { chunkInFlight = true; chunks.removeFirst() }
        } ?: return
        // 某些机型/息屏下 onNotificationSent 可能不回调：5 秒后强制解锁，
        // 否则 chunkInFlight 会一直为 true，后续消息全部卡住、看起来像断连。
        val token = ++chunkToken
        handler.postDelayed({
            val stuck = synchronized(chunks) {
                if (chunkInFlight && chunkToken == token) { chunkInFlight = false; true } else false
            }
            if (stuck) {
                log("分片 5 秒未回调，重置发送状态并重试")
                scheduleFlush(1_500)
            }
        }, 5_000)
        val ok = try {
            ch.value = chunk
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                srv.notifyCharacteristicChanged(dev, ch, false, chunk) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                srv.notifyCharacteristicChanged(dev, ch, false)
                true
            }
        } catch (e: Exception) {
            log("分片发送异常：${e.message}")
            false
        }
        if (!ok) {
            synchronized(chunks) { chunkInFlight = false; chunks.clear() }
            log("分片被拒（拥塞或链路失效），本条等重发")
        }
    }

    /** 连接状态变化时清空发送状态，避免「上一轮 in-flight」把新连接卡死 */
    fun resetSendState() {
        synchronized(chunks) {
            chunks.clear()
            chunkInFlight = false
        }
    }

    /** GATT 每片发完（或失败）后由回调驱动下一片，形成真正的流控 */
    fun onChunkSent(status: Int) {
        synchronized(chunks) {
            chunkInFlight = false
            if (status != BluetoothGatt.GATT_SUCCESS) chunks.clear()
        }
        if (status != BluetoothGatt.GATT_SUCCESS) {
            log("通知发送失败 status=$status")
        } else {
            lastSentOkAt = System.currentTimeMillis()
        }
        pumpChunks()
        val done = synchronized(chunks) { chunks.isEmpty() }
        if (done) {
            handler.postDelayed({ if (queue.isNotEmpty()) flush() }, 40)
        }
    }

    private var tcp: Socket? = null
    private var tcpOut: OutputStream? = null

    private fun sendTcp(line: String): Boolean {
        try {
            if (tcp?.isConnected != true) {
                val s = Socket("127.0.0.1", 8765)
                s.tcpNoDelay = true
                tcp = s
                tcpOut = s.getOutputStream()
            }
            tcpOut?.write(line.toByteArray(Charsets.UTF_8))
            tcpOut?.flush()
            return true
        } catch (e: Exception) {
            try { tcp?.close() } catch (e: Exception) { }
            tcp = null
            tcpOut = null
            return false
        }
    }
}

class BridgeService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Link.pairCode = getSharedPreferences("herald", MODE_PRIVATE)
            .getString("pairCode", "") ?: ""
        Link.running = true
        startForegroundWithChannel()
        Link.startHeartbeat()
        startBle()
        // 广播看门狗：HyperOS 会在息屏/后台把广播悄悄停掉，而系统不回调 onStartFailure。
        // 没连上又没在广播时每 30 秒重新拉一次，否则 Mac 永远扫不到这台手机。
        handler.postDelayed(object : Runnable {
            override fun run() {
                if (Link.running && !Link.connected && !advRunning) startAdvertise("看门狗恢复广播")
                handler.postDelayed(this, 30_000)
            }
        }, 30_000)
    }

    private fun startForegroundWithChannel() {
        val id = "herald"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(id) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(id, "Herald", NotificationManager.IMPORTANCE_MIN)
                )
            }
            val n = Notification.Builder(this, id)
                .setContentTitle("Herald 运行中")
                .setContentText("通知会转发到 Mac，不上传任何服务器")
                .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                .build()
            startForeground(1, n)
        }
    }

    private fun startBle() {
        val mgr = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter: BluetoothAdapter = mgr.adapter ?: return
        if (!adapter.isEnabled) return

        // callback 里要引用 server 本身（sendResponse），初始化表达式里不能直接引用自己，
        // 所以先用一个数组占位，openGattServer 返回后再填。
        val holder = arrayOfNulls<BluetoothGattServer>(1)

        val server = mgr.openGattServer(this, object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
                val isBonded = device?.bondState == BluetoothDevice.BOND_BONDED
                Link.connected = newState == BluetoothGatt.STATE_CONNECTED && device != null
                Link.central = if (newState == BluetoothGatt.STATE_CONNECTED) device else null
                Link.resetSendState()
                if (newState == BluetoothGatt.STATE_CONNECTED && Link.txChar == null) {
                    // 兜底：特征值属于服务，理论上不该为空；万一被清掉，连上时补回来
                    Link.txChar = holder[0]?.getService(Link.serviceUUID)?.getCharacteristic(Link.txUUID)
                }
                // status 很关键：133 = GATT 栈内部错误（常见于配对信息不一致），
                // 8 = 连接超时，19 = 对端主动断开。只打 newState 会让这类问题无法定位。
                Link.log("BLE 连接状态 newState=$newState status=$status 已配对=$isBonded")
                if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                    // 关键修复：不少机型（含小米/HyperOS）在建立连接后会停掉广播，
                    // 断开时不重新广播，Mac 就永远扫不到这台手机——表现为「不会自动重连」。
                    handler.postDelayed({ startAdvertise("断开后恢复广播") }, 800)
                }
                if (newState == BluetoothGatt.STATE_CONNECTED && device != null && !isBonded) {
                    // 不再在连接瞬间自动 createBond()：MIUI/HyperOS 上这条流程很容易失败或
                    // 留下「已配对但链路状态不一致」，而真正的安全边界是应用层 AES-GCM 配对码，
                    // 链路层配对只是可选的额外一层。需要时用户可在系统设置里手动配对。
                    Link.log("已连接（未配对；安全由应用层配对码保证）")
                }
                Link.flush()
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice?,
                requestId: Int,
                descriptor: BluetoothGattDescriptor?,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?
            ) {
                if (device == null) return
                if (responseNeeded) {
                    holder[0]?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
                Link.connected = true
                Link.central = device
                Link.log("Mac 已订阅，通道就绪（配对=${device.bondState == BluetoothDevice.BOND_BONDED}）")
                Link.flush()
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice?,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic?,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?
            ) {
                if (responseNeeded && device != null) {
                    holder[0]?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
                if (characteristic?.uuid == Link.rxUUID && value != null) {
                    val text = String(value, Charsets.UTF_8).trim()
                    if (text.startsWith("ACK ")) Link.onAck(text.removePrefix("ACK ").trim())
                }
            }

            override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
                // addService() 是异步的：在它真正完成前就广播，Mac 端连上来
                // discoverServices 会拿到一张还没填好的服务表，于是找不到 tx
                // 特征、订阅不上，几秒后被 Mac 端当成无效连接踢掉。
                // 这是「连上几秒就断 + 发出去没回执」的来源。
                Link.log("GATT 服务注册完成 status=$status uuid=${service?.uuid}")
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    serviceReady = true
                    startAdvertise("服务就绪")
                } else {
                    handler.postDelayed({ startAdvertise("服务注册失败重试") }, 1_500)
                }
            }

            override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
                // 用 status 判断这一片到底发出去没有；同时驱动下一片（流控）
                Link.onChunkSent(status)
            }
        }) ?: return

        holder[0] = server

        val service = BluetoothGattService(Link.serviceUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val tx = BluetoothGattCharacteristic(
            Link.txUUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        tx.addDescriptor(
            BluetoothGattDescriptor(
                UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"),
                BluetoothGattDescriptor.PERMISSION_READ or
                    BluetoothGattDescriptor.PERMISSION_WRITE
            )
        )
        service.addCharacteristic(tx)
        val rx = BluetoothGattCharacteristic(
            Link.rxUUID,
            // 同时声明「带响应写」和「无响应写」：新版 Mac 端用无响应写回执（不占 ATT 事务），
            // 旧版 Mac 端仍可用带响应写，升级顺序无所谓。
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(rx)

        // openGattServer() 之后立刻 addService() 在部分机型上会失败（返回 false，
        // 服务根本没进 GATT 表）。这时候如果广播照发，Mac 能扫到、能连上，
        // 但 discoverServices 永远是 0 个服务——表现就是「连上了却收不到东西」。
        addServiceWithRetry(server, service, 1)

        Link.server = server
        Link.txChar = tx

        advertiser = adapter.bluetoothLeAdvertiser
        advSettings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .build()
        advData = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(Link.serviceUUID))
            .setIncludeDeviceName(true)
            .build()

        // 正常路径：等 onServiceAdded 回调再广播（见上面）。
        // 兜底：个别机型不回调 onServiceAdded（或有延迟），3 秒后还没广播就自己上。
        handler.postDelayed({
            if (!serviceReady) {
                Link.log("⚠ 服务仍未就绪（onServiceAdded 没回来），广播照发但这台机器大概率发现不了服务")
            }
            if (!advRunning) startAdvertise("服务回调超时兜底")
        }, 6_000)
    }

    private var serviceReady = false

    private fun addServiceWithRetry(server: BluetoothGattServer, service: BluetoothGattService, attempt: Int) {
        val ok = try { server.addService(service) } catch (e: Exception) {
            Link.log("addService 异常：${e.message}")
            false
        }
        Link.log("addService 第 $attempt 次 → $ok")
        if (!ok && attempt < 4) {
            handler.postDelayed({ addServiceWithRetry(server, service, attempt + 1) }, 400L * attempt)
        }
    }

    private var advertiser: BluetoothLeAdvertiser? = null
    private var advSettings: AdvertiseSettings? = null
    private var advData: AdvertiseData? = null
    private var advRunning = false
    private var advRetries = 0
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())

    private val advCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            advRunning = true
            advRetries = 0
            Link.log("蓝牙广播已开启")
        }

        override fun onStartFailure(errorCode: Int) {
            advRunning = false
            Link.log("蓝牙广播失败 code=$errorCode（缺「附近的设备」权限、蓝牙被关，或已被系统停掉）")
            // 广播起不来就等于隐身：退避重试，最多 5 次
            if (advRetries < 5) {
                advRetries += 1
                handler.postDelayed({ startAdvertise("广播失败重试 #$advRetries") }, 2_000L * advRetries)
            }
        }
    }

    /** 幂等：先停再起，断开/失败/被系统停掉后都能把广播拉回来 */
    private fun startAdvertise(tag: String) {
        val adv = advertiser ?: return
        val settings = advSettings ?: return
        val data = advData ?: return
        try { if (advRunning) adv.stopAdvertising(advCallback) } catch (e: Exception) { }
        advRunning = false
        Link.log("$tag（重启广播）")
        try {
            adv.startAdvertising(settings, data, advCallback)
        } catch (e: Exception) {
            Link.log("广播启动异常：${e.message}")
        }
    }

    override fun onDestroy() {
        try { if (advRunning) advertiser?.stopAdvertising(advCallback) } catch (e: Exception) { }
        Link.server?.close()
        Link.server = null
        Link.txChar = null
        Link.central = null
        Link.connected = false
        Link.resetSendState()
        Link.running = false
        serviceReady = false
        Link.log("服务已停止（不再广播、不再转发）")
        super.onDestroy()
    }
}

class NotifListener : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName) return
        val n = sbn.notification
        val extras = n.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = (extras.getCharSequence(Notification.EXTRA_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_BIG_TEXT))?.toString().orEmpty()
        if (title.isEmpty() && text.isEmpty()) return

        // 只转发用户勾选的包，默认放行短信/微信/验证器类
        val prefs = getSharedPreferences("herald", MODE_PRIVATE)
        val allowed = prefs.getStringSet("packages", null)
        if (allowed != null && allowed.isNotEmpty() && !allowed.contains(sbn.packageName)) return

        val app = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(sbn.packageName, 0)).toString()
        } catch (e: Exception) { sbn.packageName }

        // 记录见过的 App：小米可能不给「应用列表」权限，白名单就靠这份记录
        run {
            val seen = prefs.getStringSet("seen", null)?.toMutableSet() ?: mutableSetOf()
            if (seen.add(sbn.packageName)) {
                prefs.edit().putStringSet("seen", seen).apply()
            }
            prefs.edit().putString("label_" + sbn.packageName, app).apply()
        }

        Link.push(sbn.packageName, app, title, text)
    }
}
