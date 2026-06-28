package com.tunnely.app

import android.app.Application
import com.tunnely.app.vpn.RemoteLogger
import com.tunnely.app.vpn.VpnPreferences

class TunnelyApp : Application() {
    lateinit var prefs: VpnPreferences
        private set

    override fun onCreate() {
        super.onCreate()
        prefs = VpnPreferences(this)
        RemoteLogger.init(this)
    }
}
