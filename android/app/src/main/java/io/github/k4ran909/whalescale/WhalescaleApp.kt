package io.github.k4ran909.whalescale

import android.app.Application

/** Sets up the Go core once per process, for the screens and the VPN service alike. */
class WhalescaleApp : Application() {
    override fun onCreate() {
        super.onCreate()
        initCore()
    }
}
