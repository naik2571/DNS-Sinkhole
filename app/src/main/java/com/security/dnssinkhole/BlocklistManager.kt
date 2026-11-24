package com.security.dnssinkhole

import java.util.concurrent.ConcurrentHashMap

object BlocklistManager {

    private val blockedDomains = ConcurrentHashMap<String, Boolean>()

    init {
        // Pre-loaded known trackers, ad networks & telemetry domains
        val defaultList = listOf(
            "google-analytics.com",
            "ssl.google-analytics.com",
            "adservice.google.com",
            "doubleclick.net",
            "pagead2.googlesyndication.com",
            "app-measurement.com",
            "firebaseinstallations.googleapis.com",
            "crashlytics.com",
            "reports.crashlytics.com",
            "graph.facebook.com",
            "b-graph.facebook.com",
            "pixel.facebook.com",
            "ads.facebook.com",
            "telemetry.sdk.com",
            "appsflyer.com",
            "app.appsflyer.com",
            "branch.io",
            "api2.branch.io",
            "adjust.com",
            "app.adjust.com",
            "scorecardresearch.com",
            "sb.scorecardresearch.com",
            "taboola.com",
            "outbrain.com",
            "adnxs.com",
            "ib.adnxs.com",
            "criteo.com",
            "static.criteo.net",
            "advertising.com",
            "quantserve.com",
            "telemetry.tracker.com",
            "analytics.tiktok.com",
            "ads.tiktok.com",
            "ads.twitter.com",
            "admob.com",
            "unityads.unity3d.com"
        )
        for (d in defaultList) {
            blockedDomains[d.lowercase()] = true
        }
    }

    fun isBlocked(domain: String): Boolean {
        val clean = domain.trim().lowercase().removeSuffix(".")
        if (blockedDomains.containsKey(clean)) return true

        // Check suffix matches (e.g. sub.doubleclick.net)
        for (entry in blockedDomains.keys) {
            if (clean == entry || clean.endsWith(".$entry")) {
                return true
            }
        }
        return false
    }

    fun addBlockRule(domain: String) {
        blockedDomains[domain.trim().lowercase().removeSuffix(".")] = true
    }

    fun getBlockedRulesCount(): Int = blockedDomains.size
}
