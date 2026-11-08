package io.github.k4ran909.whalescale

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import mobile.Mobile
import mobile.Platform
import mobile.TunnelConfig
import java.net.InetAddress

/**
 * Runs the tunnel. The Go core asks it for the VPN interface (openTUN) once
 * the network map arrives, and again whenever the routes change.
 */
class WhalescaleVpnService : VpnService(), Platform {
    // One thing at a time: start and stop never overlap.
    @OptIn(ExperimentalCoroutinesApi::class)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))
    private var watcher: NetworkWatcher? = null
    @Volatile
    private var network: Network? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            scope.launch {
                stopTunnel()
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // ACTION_CONNECT from the app, or the system starting an always-on VPN.
        scope.launch { startTunnel() }
        return START_STICKY
    }

    private fun startTunnel() {
        TunnelErrors.last = null
        if (!Mobile.isJoined(stateDir)) {
            TunnelErrors.last = "This device hasn't joined a network yet."
            stopSelf()
            return
        }
        if (watcher == null) {
            watcher = NetworkWatcher(this) { n ->
                network = n
                // Lets Android show the right network (and metering) for the VPN.
                setUnderlyingNetworks(n?.let { arrayOf(it) })
            }.also { it.start() }
        }
        try {
            Mobile.start(stateDir, this, "Android ${Build.VERSION.RELEASE}")
            Prefs.setWantUp(this, true)
        } catch (e: Exception) {
            Log.e(TAG, "start tunnel", e)
            TunnelErrors.last = e.message ?: e.toString()
            stopTunnel()
            stopSelf()
        }
    }

    private fun stopTunnel() {
        Mobile.stop()
        watcher?.stop()
        watcher = null
    }

    /** Called by the Go core: builds the VPN interface it describes. */
    override fun openTUN(cfg: TunnelConfig): Int {
        val b = Builder()
            .setSession("Whalescale")
            .setMtu(cfg.getMTU())
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        for (p in lines(cfg.getAddresses())) {
            val (ip, bits) = prefix(p)
            b.addAddress(ip, bits)
        }
        for (p in lines(cfg.getRoutes())) {
            val (ip, bits) = prefix(p)
            b.addRoute(ip, bits)
        }
        if (cfg.getDNS().isNotEmpty()) b.addDnsServer(cfg.getDNS())
        if (cfg.getSearchDomain().isNotEmpty()) b.addSearchDomain(cfg.getSearchDomain())
        // The app's own traffic (to the control server, relays and peers'
        // real addresses) must not go into the tunnel it carries.
        b.addDisallowedApplication(packageName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false)
        network?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        val pfd = b.establish() ?: throw IllegalStateException("Android didn't allow the VPN (permission revoked?)")
        // Go owns the descriptor from here on, and closes it.
        return pfd.detachFd()
    }

    /** The user turned the VPN off in settings, or another VPN took over. */
    override fun onRevoke() {
        Prefs.setWantUp(this, false)
        scope.launch {
            stopTunnel()
            stopSelf()
        }
    }

    override fun onDestroy() {
        // A stop already queued finishes first; then nothing else runs.
        scope.launch { stopTunnel() }.invokeOnCompletion { scope.cancel() }
        super.onDestroy()
    }

    private fun lines(s: String) = s.split('\n').map { it.trim() }.filter { it.isNotEmpty() }

    private fun prefix(s: String): Pair<InetAddress, Int> {
        val (ip, bits) = s.split('/', limit = 2)
        return InetAddress.getByName(ip) to bits.toInt()
    }

    companion object {
        private const val TAG = "Whalescale"
        const val ACTION_CONNECT = "io.github.k4ran909.whalescale.CONNECT"
        const val ACTION_DISCONNECT = "io.github.k4ran909.whalescale.DISCONNECT"

        fun connect(c: Context) {
            c.startService(Intent(c, WhalescaleVpnService::class.java).setAction(ACTION_CONNECT))
        }

        fun disconnect(c: Context) {
            Prefs.setWantUp(c, false)
            c.startService(Intent(c, WhalescaleVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }
}
