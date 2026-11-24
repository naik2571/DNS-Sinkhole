package com.security.dnssinkhole

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.security.dnssinkhole.databinding.ActivityMainBinding
import com.security.dnssinkhole.databinding.ItemDnsQueryBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: DnsLogAdapter
    private val VPN_REQUEST_CODE = 404

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupRecyclerView()
        setupListeners()
        updateDashboard()
    }

    private fun setupRecyclerView() {
        adapter = DnsLogAdapter()
        binding.recyclerDnsLogs.layoutManager = LinearLayoutManager(this)
        binding.recyclerDnsLogs.adapter = adapter
    }

    private fun setupListeners() {
        binding.switchVpn.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                val intent = VpnService.prepare(this)
                if (intent != null) {
                    startActivityForResult(intent, VPN_REQUEST_CODE)
                } else {
                    startSinkholeService()
                }
            } else {
                stopSinkholeService()
            }
        }

        binding.btnSimulateTraffic.setOnClickListener {
            simulateTestProbes()
        }

        binding.btnClearLogs.setOnClickListener {
            DnsLogRepository.clear()
            updateDashboard()
        }

        DnsLogRepository.addListener {
            runOnUiThread {
                updateDashboard()
            }
        }
    }

    private fun simulateTestProbes() {
        val testDomains = listOf(
            Pair("telemetry.tracker.com", true),
            Pair("api.github.com", false),
            Pair("doubleclick.net", true),
            Pair("en.wikipedia.org", false),
            Pair("app-measurement.com", true),
            Pair("cloudflare.com", false),
            Pair("graph.facebook.com", true),
            Pair("android.com", false)
        )
        for (item in testDomains) {
            DnsLogRepository.addLog(item.first, item.second)
        }
    }

    private fun startSinkholeService() {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_START
        }
        startService(intent)
        updateDashboard()
    }

    private fun stopSinkholeService() {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_STOP
        }
        startService(intent)
        updateDashboard()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startSinkholeService()
        } else {
            binding.switchVpn.isChecked = false
        }
    }

    private fun updateDashboard() {
        val total = DnsLogRepository.totalQueries
        val blocked = DnsLogRepository.blockedQueries
        val clean = DnsLogRepository.cleanQueries
        val rate = if (total > 0) (blocked.toFloat() / total * 100) else 0f

        binding.tvTotalQueries.text = total.toString()
        binding.tvBlockedCount.text = blocked.toString()
        binding.tvCleanCount.text = clean.toString()
        binding.tvBlockRate.text = String.format("%.1f%% Blocked", rate)

        val isActive = DnsVpnService.isServiceActive
        if (isActive) {
            binding.tvStatusText.text = "SINKHOLE ACTIVE (0% CLOUD, 100% LOCAL)"
            binding.tvStatusText.setTextColor(getColor(R.color.accent_green))
            binding.indicatorDot.backgroundTintList = getColorStateList(R.color.accent_green)
        } else {
            binding.tvStatusText.text = "SINKHOLE IDLE"
            binding.tvStatusText.setTextColor(getColor(R.color.text_secondary))
            binding.indicatorDot.backgroundTintList = getColorStateList(R.color.text_secondary)
        }

        adapter.submitList(DnsLogRepository.getLogs())
    }

    class DnsLogAdapter : RecyclerView.Adapter<DnsLogAdapter.LogViewHolder>() {
        private var list = listOf<DnsQueryItem>()

        fun submitList(newList: List<DnsQueryItem>) {
            list = newList
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): LogViewHolder {
            val binding = ItemDnsQueryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
            return LogViewHolder(binding)
        }

        override fun onBindViewHolder(holder: LogViewHolder, position: Int) {
            holder.bind(list[position])
        }

        override fun getItemCount(): Int = list.size

        class LogViewHolder(private val binding: ItemDnsQueryBinding) : RecyclerView.ViewHolder(binding.root) {
            fun bind(item: DnsQueryItem) {
                binding.tvDomainName.text = item.domain
                binding.tvQueryMeta.text = "Type: " + item.queryType + " | " + item.timestamp

                if (item.isBlocked) {
                    binding.tvBadgeStatus.text = "BLOCKED [0.0.0.0]"
                    binding.tvBadgeStatus.setTextColor(binding.root.context.getColor(R.color.accent_red))
                    binding.tvBadgeStatus.setBackgroundColor(0x33FF1744)
                } else {
                    binding.tvBadgeStatus.text = "ALLOWED [1.1.1.1]"
                    binding.tvBadgeStatus.setTextColor(binding.root.context.getColor(R.color.accent_green))
                    binding.tvBadgeStatus.setBackgroundColor(0x3300E676)
                }
            }
        }
    }
}
