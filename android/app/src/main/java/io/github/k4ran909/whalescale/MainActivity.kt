package io.github.k4ran909.whalescale

import android.app.Activity
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobile.Mobile

val Navy = Color(0xFF1F2EA5)
val Sky = Color(0xFF6989FA)
private val Online = Color(0xFF2E9E5B)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Connected when last used, but the tunnel died with the app (a crash,
        // an update): bring it back. Needs no prompt if permission stands.
        if (Prefs.wantUp(this) && !deviceStatus().up && Mobile.isJoined(stateDir) && VpnService.prepare(this) == null) {
            WhalescaleVpnService.connect(this)
        }
        setContent { WhalescaleTheme { App() } }
    }
}

@Composable
fun WhalescaleTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) {
        darkColorScheme(primary = Sky, onPrimary = Color.White, secondary = Sky, primaryContainer = Navy, onPrimaryContainer = Color.White)
    } else {
        lightColorScheme(primary = Navy, onPrimary = Color.White, secondary = Sky, primaryContainer = Navy, onPrimaryContainer = Color.White)
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/** Polls the Go core's status while the screen is visible. */
@Composable
fun rememberStatus(): Pair<DeviceStatus, () -> Unit> {
    val context = LocalContext.current
    var status by remember { mutableStateOf(DeviceStatus()) }
    var tick by remember { mutableStateOf(0) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(tick) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                status = withContext(Dispatchers.IO) { context.deviceStatus() }
                delay(1000)
            }
        }
    }
    return status to { tick++ }
}

@Composable
fun App() {
    val (status, refresh) = rememberStatus()
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        if (status.joined) HomeScreen(status, refresh) else JoinScreen(onJoined = refresh)
    }
}

@Composable
fun JoinScreen(onJoined: () -> Unit) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var name by remember { mutableStateOf(defaultDeviceName(context)) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        r.contents?.let { code = it.trim(); error = null }
    }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) WhalescaleVpnService.connect(context)
        onJoined()
    }

    fun join() {
        busy = true
        error = null
        scope.launch {
            val err = withContext(Dispatchers.IO) {
                runCatching { Mobile.join(context.stateDir, code.trim(), name.trim()) }.exceptionOrNull()
            }
            busy = false
            if (err != null) {
                error = err.message ?: err.toString()
                return@launch
            }
            // Joining means connecting: ask for the VPN permission now.
            val ask = VpnService.prepare(context)
            if (ask != null) vpnPermission.launch(ask) else {
                WhalescaleVpnService.connect(context)
                onJoined()
            }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(horizontal = 24.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Image(
            painterResource(R.drawable.whale_logo), contentDescription = null,
            Modifier
                .size(96.dp)
                .clip(RoundedCornerShape(24.dp)),
        )
        Text("Join your network", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text(
            "In the dashboard, open Machines → Add device and pick Android. Scan its QR code, or paste the join code.",
            style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = {
                scan.launch(
                    ScanOptions()
                        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        .setPrompt("Point the camera at the join code's QR code")
                        .setBeepEnabled(false)
                        .setOrientationLocked(false),
                )
            },
            enabled = !busy, modifier = Modifier.fillMaxWidth(),
        ) { Text("Scan QR code") }
        OutlinedTextField(
            value = code, onValueChange = { code = it; error = null },
            label = { Text("Join code") }, placeholder = { Text("wsjoin-…") },
            singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth(),
            trailingIcon = {
                TextButton(onClick = { clipboard.getText()?.text?.let { code = it.trim(); error = null } }, enabled = !busy) {
                    Text("Paste")
                }
            },
        )
        OutlinedTextField(
            value = name, onValueChange = { name = it },
            label = { Text("Device name") }, singleLine = true, enabled = !busy,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
        Button(onClick = ::join, enabled = !busy && code.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            else Text("Join")
        }
        Spacer(Modifier.height(8.dp))
        VersionLine()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(status: DeviceStatus, refresh: () -> Unit) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var askSignOut by remember { mutableStateOf(false) }
    var startError by remember { mutableStateOf<String?>(null) }

    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) WhalescaleVpnService.connect(context)
        else startError = "Whalescale needs the VPN permission to connect."
        refresh()
    }
    // The service can't show its own errors; pick them up here.
    LaunchedEffect(status) { TunnelErrors.last?.let { startError = it } }

    fun setUp(on: Boolean) {
        startError = null
        TunnelErrors.last = null
        if (on) {
            val ask = VpnService.prepare(context)
            if (ask != null) vpnPermission.launch(ask) else WhalescaleVpnService.connect(context)
        } else {
            WhalescaleVpnService.disconnect(context)
        }
        refresh()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(
                            painterResource(R.drawable.whale_logo), contentDescription = null,
                            Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(8.dp)),
                        )
                        Spacer(Modifier.width(12.dp))
                        Text("Whalescale", fontWeight = FontWeight.SemiBold)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Navy, titleContentColor = Color.White),
            )
        },
    ) { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp, end = 16.dp,
                top = padding.calculateTopPadding() + 16.dp, bottom = padding.calculateBottomPadding() + 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    when (status.state) {
                                        "connected" -> "Connected"
                                        "connecting" -> "Connecting…"
                                        else -> "Disconnected"
                                    },
                                    style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                                )
                                Text(
                                    status.server.removePrefix("https://").removePrefix("http://"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.75f),
                                )
                            }
                            Switch(
                                checked = status.up, onCheckedChange = ::setUp,
                                colors = SwitchDefaults.colors(checkedTrackColor = Sky, checkedThumbColor = Color.White),
                            )
                        }
                        HorizontalDivider(color = Color.White.copy(alpha = 0.2f))
                        Text("This device", style = MaterialTheme.typography.labelMedium, color = Color.White.copy(alpha = 0.75f))
                        Text(status.name, style = MaterialTheme.typography.titleMedium, color = Color.White)
                        if (status.address.isNotEmpty()) {
                            Text(
                                status.address, fontFamily = FontFamily.Monospace, color = Color.White,
                                modifier = Modifier.clickable {
                                    clipboard.setText(AnnotatedString(status.address))
                                    Toast.makeText(context, "Address copied", Toast.LENGTH_SHORT).show()
                                },
                            )
                        }
                    }
                }
            }
            val problem = startError ?: status.error.takeIf { it.isNotEmpty() && status.up }
            problem?.let { msg ->
                item { Text(msg, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
            }
            item {
                Text(
                    if (status.state == "connected") "Devices (${status.peers.size})" else "Devices",
                    style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp),
                )
            }
            when {
                status.state != "connected" -> item {
                    Text("Connect to see the other devices on your network.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                status.peers.isEmpty() -> item {
                    Text("No other devices yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                else -> items(status.peers, key = { it.name }) { PeerRow(it) }
            }
            item {
                Column(Modifier.fillMaxWidth().padding(top = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    OutlinedButton(onClick = { askSignOut = true }) {
                        Text("Sign out", color = MaterialTheme.colorScheme.error)
                    }
                    Spacer(Modifier.height(12.dp))
                    VersionLine()
                }
            }
        }
    }

    if (askSignOut) {
        AlertDialog(
            onDismissRequest = { askSignOut = false },
            title = { Text("Sign out?") },
            text = { Text("This device leaves the network and is removed from the dashboard. To come back, join with a new code.") },
            confirmButton = {
                TextButton(onClick = {
                    askSignOut = false
                    scope.launch {
                        WhalescaleVpnService.disconnect(context)
                        val err = withContext(Dispatchers.IO) {
                            runCatching { Mobile.signOut(context.stateDir) }.exceptionOrNull()
                        }
                        err?.let { Toast.makeText(context, it.message, Toast.LENGTH_LONG).show() }
                        refresh()
                    }
                }) { Text("Sign out", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { askSignOut = false }) { Text("Cancel") } },
        )
    }
}

@Composable
fun PeerRow(p: Peer) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(if (p.online) Online else MaterialTheme.colorScheme.outlineVariant),
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(p.name, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                Text(
                    listOf(p.address, p.os).filter { it.isNotEmpty() }.joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            PathChip(if (p.online) p.path else "offline")
        }
    }
}

@Composable
fun PathChip(path: String) {
    val (label, color) = when (path) {
        "direct" -> "Direct" to Online
        "relay" -> "Relay" to Sky
        "peer-relay" -> "Peer relay" to Sky
        "idle" -> "Idle" to MaterialTheme.colorScheme.onSurfaceVariant
        "offline" -> "Offline" to MaterialTheme.colorScheme.onSurfaceVariant
        else -> "No path" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        label, style = MaterialTheme.typography.labelMedium, color = color,
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

@Composable
fun VersionLine() {
    Text(
        "Version ${BuildConfig.VERSION_NAME} · core ${remember { Mobile.version() }}",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** The name the phone goes by in its settings, else its model. */
fun defaultDeviceName(c: android.content.Context): String {
    val n = Settings.Global.getString(c.contentResolver, Settings.Global.DEVICE_NAME)
    return (n?.takeIf { it.isNotBlank() } ?: Build.MODEL).trim()
}
