package io.github.k4ran909.whalescale

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import mobile.Mobile

/**
 * Tells the Go core about the phone's own network (Wi-Fi or mobile data):
 * its addresses, so peers on the same Wi-Fi connect directly (Android 11
 * and later don't let Go list them), and its DNS servers, for names outside
 * the mesh. The app is left out of its own VPN, so its default network is
 * always the underlying one.
 */
class NetworkWatcher(context: Context, private val onNetwork: (Network?) -> Unit) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            update(network, lp)
        }

        override fun onLost(network: Network) {
            Mobile.setNetwork("", "")
            onNetwork(null)
        }
    }

    fun start() {
        cm.activeNetwork?.let { n -> cm.getLinkProperties(n)?.let { update(n, it) } }
        cm.registerDefaultNetworkCallback(callback)
    }

    fun stop() {
        runCatching { cm.unregisterNetworkCallback(callback) }
    }

    private fun update(network: Network, lp: LinkProperties) {
        // Go's address parser takes no "%wlan0" scope (and skips link-local
        // addresses anyway).
        fun host(a: java.net.InetAddress) = a.hostAddress?.substringBefore('%') ?: ""
        val addrs = lp.linkAddresses.joinToString("\n") { "${host(it.address)}/${it.prefixLength}" }
        val dns = lp.dnsServers.joinToString("\n") { host(it) }
        Mobile.setNetwork(addrs, dns)
        onNetwork(network)
    }
}
