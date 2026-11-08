package io.github.k4ran909.whalescale

import android.content.Context
import mobile.Mobile
import org.json.JSONObject

/** A peer on the network, as the Go core reports it. */
data class Peer(
    val name: String,
    val address: String,
    val os: String,
    val online: Boolean,
    /** "direct", "relay", "peer-relay", "idle" or "none". */
    val path: String,
)

/** This device's state (Mobile.status). */
data class DeviceStatus(
    /** "logged-out", "down", "connecting" or "connected". */
    val state: String = "logged-out",
    val server: String = "",
    val name: String = "",
    val address: String = "",
    val user: String = "",
    val error: String = "",
    val peers: List<Peer> = emptyList(),
) {
    val joined get() = state != "logged-out"
    val up get() = state == "connecting" || state == "connected"

    companion object {
        fun parse(json: String): DeviceStatus {
            val o = JSONObject(json)
            val peers = o.optJSONArray("peers")?.let { a ->
                (0 until a.length()).map { i ->
                    val p = a.getJSONObject(i)
                    Peer(
                        name = p.optString("name"),
                        address = p.optString("address"),
                        os = p.optString("os"),
                        online = p.optBoolean("online"),
                        path = p.optString("path", "none"),
                    )
                }
            } ?: emptyList()
            return DeviceStatus(
                state = o.optString("state", "logged-out"),
                server = o.optString("server"),
                name = o.optString("name"),
                address = o.optString("address"),
                user = o.optString("user"),
                error = o.optString("error"),
                peers = peers.sortedWith(compareBy({ !it.online }, { it.name })),
            )
        }
    }
}

/** Turns on the Go core's debug messages in logcat for debug builds. */
fun initCore() = Mobile.setDebugLogging(BuildConfig.DEBUG)

/** Where the Go core keeps this device's identity: app-private storage. */
val Context.stateDir: String get() = filesDir.absolutePath

fun Context.deviceStatus(): DeviceStatus = DeviceStatus.parse(Mobile.status(stateDir))

/**
 * Whether the user wants the tunnel up, so it comes back after the app is
 * killed or the phone restarts with always-on VPN.
 */
object Prefs {
    private const val FILE = "whalescale"
    private const val WANT_UP = "want_up"

    fun wantUp(c: Context) = c.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(WANT_UP, false)

    fun setWantUp(c: Context, v: Boolean) =
        c.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(WANT_UP, v).apply()
}

/**
 * Errors from starting the tunnel, which happen in the VPN service where the
 * screen can't see them otherwise.
 */
object TunnelErrors {
    @Volatile
    var last: String? = null
}
