package com.tunnely.app.rtt

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

/**
 * Represents an installed app that can be tested for RTT.
 * Maps package names to known server targets for latency measurement.
 */
data class AppRttTarget(
    val packageName: String,
    val appName: String,
    val icon: Drawable?,
    val target: RttTarget,
    var selected: Boolean = false,
) {
    companion object {
        /**
         * Well-known Indonesian/global app → server mapping.
         * Package name → RttTarget (host to measure).
         */
        val KNOWN_APPS = mapOf(
            // Google
            "com.google.android.googlequicksearchbox" to RttTarget("Google", "www.google.com", 443),
            "com.google.android.youtube" to RttTarget("YouTube", "www.youtube.com", 443),
            "com.google.android.gm" to RttTarget("Gmail", "mail.google.com", 443),
            "com.google.android.apps.maps" to RttTarget("Google Maps", "maps.google.com", 443),
            "com.google.android.apps.photos" to RttTarget("Google Photos", "photos.google.com", 443),

            // Meta
            "com.instagram.android" to RttTarget("Instagram", "www.instagram.com", 443),
            "com.facebook.katana" to RttTarget("Facebook", "www.facebook.com", 443),
            "com.facebook.orca" to RttTarget("Messenger", "www.messenger.com", 443),
            "com.whatsapp" to RttTarget("WhatsApp", "web.whatsapp.com", 443),
            "com.whatsapp.w4b" to RttTarget("WhatsApp Business", "web.whatsapp.com", 443),

            // TikTok
            "com.zhiliaoapp.musically" to RttTarget("TikTok", "www.tiktok.com", 443),
            "com.ss.android.ugc.trill" to RttTarget("TikTok", "www.tiktok.com", 443),

            // X/Twitter
            "com.twitter.android" to RttTarget("X/Twitter", "x.com", 443),
            "com.x.android" to RttTarget("X/Twitter", "x.com", 443),

            // Indonesian e-commerce
            "com.tokopedia.tkpd" to RttTarget("Tokopedia", "www.tokopedia.com", 443),
            "com.shopee.id" to RttTarget("Shopee", "shopee.co.id", 443),
            "com.bukalapak.android" to RttTarget("Bukalapak", "www.bukalapak.com", 443),
            "com.lazada.android" to RttTarget("Lazada", "www.lazada.co.id", 443),
            "com.tiket.gits" to RttTarget("Tiket.com", "www.tiket.com", 443),

            // Indonesian ride-hailing/fintech
            "com.grabtaxi.passenger" to RttTarget("Grab", "www.grab.com", 443),
            "com.gojek.app" to RttTarget("Gojek", "www.gojek.com", 443),
            "com.gopay" to RttTarget("GoPay", "gopay.co.id", 443),
            "id.co.bri.brimo" to RttTarget("BRImo", "www.bri.co.id", 443),
            "id.co.bankmandiri.mandirionline" to RttTarget("Livin Mandiri", "www.bankmandiri.co.id", 443),
            "com.bca" to RttTarget("BCA Mobile", "www.bca.co.id", 443),
            "id.co.bni.bnimobilebanking" to RttTarget("BNI Mobile", "www.bni.co.id", 443),

            // Streaming
            "com.spotify.music" to RttTarget("Spotify", "open.spotify.com", 443),
            "com.netflix.mediaclient" to RttTarget("Netflix", "www.netflix.com", 443),
            "tv.twitch.android.app" to RttTarget("Twitch", "www.twitch.tv", 443),
            "com.google.android.apps.youtube.music" to RttTarget("YT Music", "music.youtube.com", 443),

            // Messaging
            "org.telegram.messenger" to RttTarget("Telegram", "web.telegram.org", 443),
            "org.thunderbird.thunderbird" to RttTarget("Telegram", "web.telegram.org", 443),
            "com.discord" to RttTarget("Discord", "discord.com", 443),
            "jp.naver.line.android" to RttTarget("LINE", "line.me", 443),
            "com.skype.raider" to RttTarget("Skype", "www.skype.com", 443),

            // Cloud/Storage
            "com.dropbox.android" to RttTarget("Dropbox", "www.dropbox.com", 443),
            "com.google.android.apps.docs" to RttTarget("Google Drive", "drive.google.com", 443),
            "com.microsoft.office.outlook" to RttTarget("Outlook", "outlook.live.com", 443),
            "com.microsoft.teams" to RttTarget("MS Teams", "teams.microsoft.com", 443),

            // Gaming
            "com.mobile.legends" to RttTarget("Mobile Legends", "m.mobilelegends.com", 443),
            "com.garena.game.kgid" to RttTarget("Free Fire", "www.garena.co.id", 443),
            "com.tencent.ig" to RttTarget("PUBG Mobile", "www.pubgmobile.com", 443),
            "com.supercell.clashofclans" to RttTarget("Clash of Clans", "clashofclans.com", 443),

            // News
            "com.cnn.indonesiav2" to RttTarget("CNN Indonesia", "www.cnnindonesia.com", 443),
            "id.co.kompas.app" to RttTarget("Kompas", "www.kompas.com", 443),
            "com.detik.app" to RttTarget("Detik", "www.detik.com", 443),
        )

        /**
         * Query installed apps that have launchers and map to known RTT targets.
         * Returns only apps that have a known server mapping.
         */
        fun queryInstalledTargets(
            pm: PackageManager,
            myPackage: String,
        ): List<AppRttTarget> {
            val launcherPkgs = pm.queryIntentActivities(
                Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
                0
            ).map { it.activityInfo.packageName }.toSet()

            return pm.getInstalledPackages(0)
                .filter { it.packageName != myPackage }
                .filter { it.packageName in launcherPkgs }
                .filter { it.packageName in KNOWN_APPS }
                .mapNotNull { pkg ->
                    val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                    val target = KNOWN_APPS[pkg.packageName] ?: return@mapNotNull null
                    AppRttTarget(
                        packageName = pkg.packageName,
                        appName = pm.getApplicationLabel(appInfo).toString(),
                        icon = pm.getApplicationIcon(appInfo),
                        target = target,
                    )
                }
                .sortedBy { it.appName.lowercase() }
                .distinctBy { it.target.host }  // dedupe same host (e.g., WhatsApp + WA Business)
        }

        /**
         * Fallback: infer host from package name for unknown apps.
         * e.g., "com.example.app" → "www.example.com"
         */
        fun inferHost(packageName: String): String? {
            val parts = packageName.split(".")
            if (parts.size < 2) return null
            // Skip common prefixes
            val skip = setOf("com", "org", "net", "io", "id", "co", "app", "www")
            val domain = parts.firstOrNull { it.lowercase() !in skip } ?: return null
            return "www.$domain.com"
        }
    }
}
