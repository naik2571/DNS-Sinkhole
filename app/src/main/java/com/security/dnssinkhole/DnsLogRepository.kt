package com.security.dnssinkhole

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

data class DnsQueryItem(
    val id: Long = System.currentTimeMillis() + (0..999).random(),
    val domain: String,
    val isBlocked: Boolean,
    val queryType: String = "A",
    val timestamp: String = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
)

object DnsLogRepository {
    private val logs = CopyOnWriteArrayList<DnsQueryItem>()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    var totalQueries: Int = 0
        private set
    var blockedQueries: Int = 0
        private set
    var cleanQueries: Int = 0
        private set

    fun addLog(domain: String, isBlocked: Boolean, queryType: String = "A") {
        totalQueries++
        if (isBlocked) blockedQueries++ else cleanQueries++

        val item = DnsQueryItem(domain = domain, isBlocked = isBlocked, queryType = queryType)
        logs.add(0, item)
        if (logs.size > 200) {
            logs.removeAt(logs.size - 1)
        }
        notifyListeners()
    }

    fun getLogs(): List<DnsQueryItem> = logs.toList()

    fun clear() {
        logs.clear()
        totalQueries = 0
        blockedQueries = 0
        cleanQueries = 0
        notifyListeners()
    }

    fun addListener(l: () -> Unit) {
        listeners.add(l)
    }

    fun removeListener(l: () -> Unit) {
        listeners.remove(l)
    }

    private fun notifyListeners() {
        for (l in listeners) {
            try { l() } catch (_: Exception) {}
        }
    }
}
