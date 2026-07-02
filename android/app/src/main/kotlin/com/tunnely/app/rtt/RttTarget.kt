package com.tunnely.app.rtt

import androidx.annotation.DrawableRes

/**
 * Represents a test target for RTT measurement.
 * Each target is a well-known service that users care about.
 */
data class RttTarget(
    val name: String,
    val host: String,
    val port: Int = 443,
    @DrawableRes val iconRes: Int = 0,
) {
    companion object {
        /** v3.27.0: 5 most relevant targets for Indonesian market */
        val DEFAULT_TARGETS = listOf(
            RttTarget("Google", "www.google.com", 443),
            RttTarget("Tokopedia", "www.tokopedia.com", 443),
            RttTarget("Instagram", "www.instagram.com", 443),
            RttTarget("WhatsApp", "web.whatsapp.com", 443),
            RttTarget("Cloudflare", "1.1.1.1", 443),
        )
    }
}
