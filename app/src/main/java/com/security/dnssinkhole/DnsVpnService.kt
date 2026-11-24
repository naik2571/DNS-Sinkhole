package com.security.dnssinkhole

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

class DnsVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null

    companion object {
        const val ACTION_START = "com.security.dnssinkhole.START"
        const val ACTION_STOP = "com.security.dnssinkhole.STOP"
        var isServiceActive = false
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        if (action == ACTION_STOP) {
            stopSinkhole()
            return START_NOT_STICKY
        }

        startSinkhole()
        return START_STICKY
    }

    private fun startSinkhole() {
        if (isRunning.get()) return
        isRunning.set(true)
        isServiceActive = true

        startForegroundNotification()

        try {
            val builder = Builder()
                .setSession("DNS Sinkhole")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("10.0.0.2")
                .addRoute("10.0.0.2", 32)
                .setBlocking(false)

            vpnInterface = builder.establish()

            workerThread = Thread {
                runVpnLoop()
            }.apply { start() }

        } catch (e: Exception) {
            Log.e("DnsVpnService", "Failed to start VPN interface", e)
            stopSinkhole()
        }
    }

    private fun runVpnLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)
        val buffer = ByteArray(4096)

        var upstreamSocket: DatagramSocket? = null
        try {
            upstreamSocket = DatagramSocket()
            protect(upstreamSocket) // Bypass VPN for our upstream DNS resolver!
            upstreamSocket.soTimeout = 2000
        } catch (e: Exception) {
            Log.e("DnsVpnService", "Upstream socket creation error", e)
        }

        while (isRunning.get()) {
            try {
                val length = inputStream.read(buffer)
                if (length > 28) {
                    // Check IPv4 & UDP (protocol 17 = UDP)
                    val ipVersion = (buffer[0].toInt().shr(4)) and 0x0F
                    val protocol = buffer[9].toInt() and 0xFF

                    if (ipVersion == 4 && protocol == 17) {
                        val ipHeaderLen = (buffer[0].toInt() and 0x0F) * 4
                        val destPort = ((buffer[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                                (buffer[ipHeaderLen + 3].toInt() and 0xFF)

                        if (destPort == 53) {
                            val dnsOffset = ipHeaderLen + 8
                            val dnsLen = length - dnsOffset
                            if (dnsLen > 12) {
                                val dnsPayload = ByteArray(dnsLen)
                                System.arraycopy(buffer, dnsOffset, dnsPayload, 0, dnsLen)

                                val domain = DnsPacketParser.parseDomainName(dnsPayload, 0)
                                val isBlocked = BlocklistManager.isBlocked(domain)

                                DnsLogRepository.addLog(domain, isBlocked)

                                if (isBlocked) {
                                    // Generate sinkhole 0.0.0.0 packet response
                                    val sinkholeDns = DnsPacketParser.buildSinkholeResponse(dnsPayload, dnsLen)
                                    sendUdpResponse(outputStream, buffer, ipHeaderLen, sinkholeDns)
                                } else if (upstreamSocket != null) {
                                    // Forward to Cloudflare (1.1.1.1:53)
                                    val sendPacket = DatagramPacket(
                                        dnsPayload, dnsPayload.size,
                                        InetAddress.getByName("1.1.1.1"), 53
                                    )
                                    upstreamSocket.send(sendPacket)

                                    val respBuf = ByteArray(4096)
                                    val recvPacket = DatagramPacket(respBuf, respBuf.size)
                                    upstreamSocket.receive(recvPacket)

                                    val upstreamDns = ByteArray(recvPacket.length)
                                    System.arraycopy(respBuf, 0, upstreamDns, 0, recvPacket.length)
                                    sendUdpResponse(outputStream, buffer, ipHeaderLen, upstreamDns)
                                }
                            }
                        }
                    }
                }
            } catch (_: java.io.InterruptedIOException) {
                // Read timeout
            } catch (_: Exception) {
                // Non-fatal packet parsing loop
            }

            try { Thread.sleep(20) } catch (_: Exception) {}
        }

        try { upstreamSocket?.close() } catch (_: Exception) {}
        try { inputStream.close() } catch (_: Exception) {}
        try { outputStream.close() } catch (_: Exception) {}
    }

    private fun sendUdpResponse(
        out: FileOutputStream,
        origPacket: ByteArray,
        ipHeaderLen: Int,
        dnsResponse: ByteArray
    ) {
        val totalLen = 20 + 8 + dnsResponse.size
        val packet = ByteArray(totalLen)

        // IP Header
        packet[0] = 0x45.toByte() // IPv4, 20 bytes
        packet[1] = 0x00.toByte()
        packet[2] = ((totalLen shr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[4] = 0x00
        packet[5] = 0x01
        packet[6] = 0x40.toByte() // Don't fragment
        packet[7] = 0x00
        packet[8] = 64.toByte() // TTL
        packet[9] = 17.toByte() // UDP
        // Swap IP src and dst
        System.arraycopy(origPacket, 16, packet, 12, 4) // Src = old Dst
        System.arraycopy(origPacket, 12, packet, 16, 4) // Dst = old Src

        // UDP Header
        // Src Port = 53
        packet[20] = 0x00
        packet[21] = 53.toByte()
        // Dst Port = orig Src Port
        packet[22] = origPacket[ipHeaderLen]
        packet[23] = origPacket[ipHeaderLen + 1]
        val udpLen = 8 + dnsResponse.size
        packet[24] = ((udpLen shr 8) and 0xFF).toByte()
        packet[25] = (udpLen and 0xFF).toByte()
        packet[26] = 0x00 // UDP Checksum optional in IPv4
        packet[27] = 0x00

        // DNS Payload
        System.arraycopy(dnsResponse, 0, packet, 28, dnsResponse.size)

        out.write(packet, 0, totalLen)
    }

    private fun startForegroundNotification() {
        val channelId = "dns_sinkhole_channel"
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "DNS Sinkhole Service",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }

        val notification: Notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("🛡️ DNS Sinkhole Active")
            .setContentText("Neutralizing tracking & telemetry domains 100% on-device.")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .build()

        startForeground(1001, notification)
    }

    private fun stopSinkhole() {
        isRunning.set(false)
        isServiceActive = false
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (_: Exception) {}
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        stopSinkhole()
        super.onDestroy()
    }
}
