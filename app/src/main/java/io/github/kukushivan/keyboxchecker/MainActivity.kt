package io.github.kukushivan.keyboxchecker

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.stringResource
import io.github.kukushivan.keyboxchecker.R
import androidx.core.app.NotificationCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

private const val CHANNEL_SERVICE = "sentinel_service_channel"
private const val CHANNEL_ALERTS = "sentinel_alerts_channel"
private const val NOTIF_ID_SERVICE = 888
private const val ATTESTATION_ALIAS = "keybox_attestation_key"

// Preference keys
private const val PREF_NAME = "prefs"
private const val KEY_INTERVAL = "interval"
private const val KEY_ENABLED = "enabled"
private const val KEY_LAST_STATUS = "last_status"
private const val KEY_BAN_INTERVAL = "ban_interval"
private const val KEY_NETWORK_MODE = "network_mode"
private const val KEY_REQUIRE_CHARGING = "require_charging"
private const val KEY_REQUIRE_IDLE = "require_idle"
private const val KEY_REQUIRE_BATTERY_NOT_LOW = "require_battery_not_low"
private const val KEY_ALREADY_ALERTED = "already_alerted"

/**
 * Network conditions supported by WorkManager constraints.
 * Each maps to a [NetworkType] constant.
 */
enum class NetMode(val labelResId: Int, val descResId: Int, val networkType: NetworkType) {
    ANY(R.string.net_any, R.string.net_any_desc, NetworkType.CONNECTED),
    UNMETERED(R.string.net_wifi, R.string.net_wifi_desc, NetworkType.UNMETERED),
    NOT_ROAMING(R.string.net_roam, R.string.net_roam_desc, NetworkType.NOT_ROAMING),
    METERED(R.string.net_cell, R.string.net_cell_desc, NetworkType.METERED);

    companion object {
        fun fromOrdinal(ordinal: Int) = entries.getOrElse(ordinal) { ANY }
    }
}

/** Builds WorkManager [Constraints] from the current SharedPreferences. */
fun buildConstraints(context: Context): Constraints {
    val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
    val mode = NetMode.fromOrdinal(prefs.getInt(KEY_NETWORK_MODE, 0))
    val charging = prefs.getBoolean(KEY_REQUIRE_CHARGING, false)
    val idle = prefs.getBoolean(KEY_REQUIRE_IDLE, false)
    val batteryOk = prefs.getBoolean(KEY_REQUIRE_BATTERY_NOT_LOW, false)

    return Constraints.Builder()
        .setRequiredNetworkType(mode.networkType)
        .setRequiresCharging(charging)
        .setRequiresDeviceIdle(idle)
        .setRequiresBatteryNotLow(batteryOk)
        .build()
}

data class CertInfo(
    val index: Int,
    val subjectDN: String,
    val issuerDN: String,
    val serialNumberHex: String,
    val serialNumberDec: String,
    val notBefore: Date,
    val notAfter: Date,
    val sigAlgorithm: String,
    val isRevoked: Boolean,
    val publicKeyAlgorithm: String,
    val version: Int
)

// --- Logic ---
object CheckerLogic {

    private const val GOOGLE_CRL_URL = "https://android.googleapis.com/attestation/status"
    private const val PREF_ETAG = "crl_etag"
    private const val CACHE_FILE = "crl_cache.json"

    fun checkKeyboxDetailed(context: Context): Pair<String, List<CertInfo>> {
        return try {
            val chain = getAttestationChain()
            if (chain.isEmpty()) return "Error: No attestation certificates" to emptyList()

            checkCerts(context, chain)
        } catch (e: Exception) {
            android.util.Log.e("KeyboxChecker", "Check failed", e)
            "Error: ${e.localizedMessage}" to emptyList()
        }
    }


fun checkKeyboxStatus(context: Context): String = checkKeyboxDetailed(context).first

    private fun getAttestationChain(): List<X509Certificate> {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        // Unconditionally delete old keys so we always generate a fresh hardware challenge
        if (ks.containsAlias(ATTESTATION_ALIAS)) {
            ks.deleteEntry(ATTESTATION_ALIAS)
        }

        // Generate key with fresh Attestation Challenge
        val specBuilder = KeyGenParameterSpec.Builder(
            ATTESTATION_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(System.currentTimeMillis().toString().toByteArray())
            
        // Try to force StrongBox on supported devices, fallback to TEE otherwise
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                specBuilder.setIsStrongBoxBacked(true)
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                    initialize(specBuilder.build())
                    generateKeyPair()
                }
            } catch (e: Exception) {
                android.util.Log.w("KeyboxChecker", "StrongBox not supported, falling back to TEE", e)
                ks.deleteEntry(ATTESTATION_ALIAS)
                specBuilder.setIsStrongBoxBacked(false)
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                    initialize(specBuilder.build())
                    generateKeyPair()
                }
            }
        } else {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                initialize(specBuilder.build())
                generateKeyPair()
            }
        }

        val chain = ks.getCertificateChain(ATTESTATION_ALIAS) ?: return emptyList()
        return chain.map { it as X509Certificate }
    }

    /**
     * Downloads the CRL (Certificate Revocation List) with ETag caching support.
     * Returns the raw JSON string.
     */
    private fun fetchCRL(context: Context): String {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val cachedEtag = prefs.getString(PREF_ETAG, null)
        val cacheFile = File(context.filesDir, CACHE_FILE)

        // 5-minute local cache to prevent hammering Google servers and DNS
        if (cacheFile.exists()) {
            val ageMs = System.currentTimeMillis() - cacheFile.lastModified()
            if (ageMs < 5 * 60 * 1000L) {
                android.util.Log.d("KeyboxChecker", "Using fresh local cache (age: ${ageMs / 1000}s). Network skipped.")
                return cacheFile.readText()
            }
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val requestBuilder = Request.Builder().url(GOOGLE_CRL_URL)
        
        // If we have a cached file and an ETag, ask server if it changed
        if (cachedEtag != null && cacheFile.exists()) {
            requestBuilder.addHeader("If-None-Match", cachedEtag)
        }

        return try {
            client.newCall(requestBuilder.build()).execute().use { resp ->
                if (resp.code == 304 && cacheFile.exists()) {
                    // HTTP 304: Not Modified. Use local file.
                    android.util.Log.d("KeyboxChecker", "CRL unchanged (304). Using cache.")
                    return@use cacheFile.readText()
                }

                if (resp.isSuccessful) {
                    // HTTP 200: New data. Save it.
                    val json = resp.body?.string() ?: throw Exception("Empty CRL body")
                    
                    // Save ETag
                    val newEtag = resp.header("ETag")
                    if (newEtag != null) {
                        prefs.edit().putString(PREF_ETAG, newEtag).apply()
                    }
                    
                    // Save File
                    cacheFile.writeText(json)
                    android.util.Log.d("KeyboxChecker", "CRL downloaded and cached.")
                    return@use json
                }

                // Fallback: If network fails but we have cache, use it
                if (cacheFile.exists()) {
                    android.util.Log.w("KeyboxChecker", "Network failed (${resp.code}), using stale cache.")
                    return@use cacheFile.readText()
                }

                throw Exception("Network Error: HTTP ${resp.code}")
            }
        } catch (e: Exception) {
            if (cacheFile.exists()) {
                android.util.Log.w("KeyboxChecker", "Network exception (${e.localizedMessage}), using stale cache.")
                return cacheFile.readText()
            }
            throw e
        }
    }

    private fun checkCerts(context: Context, certs: List<X509Certificate>): Pair<String, List<CertInfo>> {
        return try {
            // Fetch JSON (from Network or Cache)
            val crlJson = fetchCRL(context).lowercase()
            var hasRevoked = false
            val list = certs.mapIndexed { i, cert ->
                val rawSnHex = cert.serialNumber.toString(16).lowercase()
                val paddedSnHex = if (rawSnHex.length % 2 != 0) "0$rawSnHex" else rawSnHex
                val rawSnDec = cert.serialNumber.toString(10)
                
                val isRevoked = crlJson.contains("\"$rawSnHex\"") || 
                                crlJson.contains("\"$paddedSnHex\"") || 
                                crlJson.contains("\"$rawSnDec\"")
                
                if (isRevoked) hasRevoked = true
                CertInfo(i, cert.subjectDN.toString(), cert.issuerDN.toString(), paddedSnHex, rawSnDec,
                    cert.notBefore, cert.notAfter, cert.sigAlgName, isRevoked,
                    cert.publicKey.algorithm, cert.version)
            }
            val status = if (hasRevoked) "Not Certified / Banned" else "Certified"
            status to list
        } catch (e: Exception) {
            android.util.Log.e("KeyboxChecker", "Validation error", e)
            "Error: ${e.localizedMessage}" to certs.mapIndexed { i, cert ->
                val snHex = cert.serialNumber.toString(16).lowercase().let { if (it.length % 2 != 0) "0$it" else it }
                val snDec = cert.serialNumber.toString(10)
                CertInfo(i, cert.subjectDN.toString(), cert.issuerDN.toString(),
                    snHex, snDec, cert.notBefore, cert.notAfter, cert.sigAlgName, false,
                    cert.publicKey.algorithm, cert.version)
            }
        }
    }

    fun updateServiceNotification(context: Context, status: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        
        val intent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        val pi = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        nm.notify(NOTIF_ID_SERVICE, NotificationCompat.Builder(context, CHANNEL_SERVICE)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Keybox Monitor")
            .setContentText("Status: $status | Last: $time")
            .setContentIntent(pi)
            .setOnlyAlertOnce(true).setOngoing(true).setPriority(NotificationCompat.PRIORITY_LOW).build())
    }
}

// --- Service ---
class SentinelService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_SERVICE, "Monitor Status", NotificationManager.IMPORTANCE_LOW).apply {
                        setShowBadge(false); enableLights(false); enableVibration(false); setSound(null, null)
                    })
            }

            val prefs = getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            val lastStatus = prefs.getString(KEY_LAST_STATUS, "Ready") ?: "Ready"
            
            val contentIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            }
            val pi = PendingIntent.getActivity(this, 0, contentIntent, PendingIntent.FLAG_IMMUTABLE)

            startForeground(NOTIF_ID_SERVICE, NotificationCompat.Builder(this, CHANNEL_SERVICE)
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentTitle("Keybox Monitor")
                .setContentText("Status: $lastStatus")
                .setContentIntent(pi)
                .setOngoing(true).setPriority(NotificationCompat.PRIORITY_LOW).build())

            if (prefs.getBoolean(KEY_ENABLED, false)) {
                enqueueWork(this, 5)
            }
            return START_STICKY
        } catch (e: Exception) {
            android.util.Log.e("KeyboxChecker", "Service start failed", e)
            return START_NOT_STICKY
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onTaskRemoved(rootIntent: Intent?) {
        val prefs = getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_ENABLED, false)) {
            val i = Intent(applicationContext, SentinelService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i) else startService(i)
        }
        super.onTaskRemoved(rootIntent)
    }
}

/** Central point for scheduling work with the current constraints. */
fun enqueueWork(context: Context, delayMin: Long) {
    val constraints = buildConstraints(context)
    WorkManager.getInstance(context).enqueueUniqueWork(
        "Sentinel", ExistingWorkPolicy.REPLACE,
        OneTimeWorkRequestBuilder<IntegrityWorker>()
            .setInitialDelay(delayMin, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .addTag("keybox_check")
            .build()
    )
}

// --- Worker ---
class IntegrityWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val prefs = applicationContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_ENABLED, false)) return Result.success()

        return try {
            val status = CheckerLogic.checkKeyboxStatus(applicationContext)
            prefs.edit().putString(KEY_LAST_STATUS, status).apply()
            CheckerLogic.updateServiceNotification(applicationContext, status)

            val isBanned = status.contains("Banned", true)
            val alreadyAlerted = prefs.getBoolean(KEY_ALREADY_ALERTED, false)

            if (isBanned && !alreadyAlerted) {
                sendAlert()
                prefs.edit().putBoolean(KEY_ALREADY_ALERTED, true).apply()
            } else if (!isBanned) {
                prefs.edit().putBoolean(KEY_ALREADY_ALERTED, false).apply()
            }

            val interval = if (isBanned) prefs.getLong(KEY_BAN_INTERVAL, 5L) else prefs.getLong(KEY_INTERVAL, 60L)
            enqueueWork(applicationContext, interval)
            Result.success()
        } catch (e: Exception) {
            android.util.Log.e("KeyboxChecker", "Worker failed", e)
            enqueueWork(applicationContext, 5)
            Result.retry()
        }
    }

    private fun sendAlert() {
        val nm = applicationContext.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ALERTS, "Alerts", NotificationManager.IMPORTANCE_HIGH))
        }
        
        val intent = Intent(applicationContext, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        val pi = PendingIntent.getActivity(applicationContext, 1, intent, PendingIntent.FLAG_IMMUTABLE)

        nm.notify(System.currentTimeMillis().toInt(),
            NotificationCompat.Builder(applicationContext, CHANNEL_ALERTS)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("🚨 KEYBOX BANNED!")
                .setContentText("Your keybox has been revoked!")
                .setContentIntent(pi)
                .setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true).build())
    }
}

// --- UI ---
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { MainScreen() }
            }
        }
        val i = Intent(this, SentinelService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i) else startService(i)
    }
}

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE) }

    var interval by remember { mutableStateOf(prefs.getLong(KEY_INTERVAL, 60L)) }
    var isEnabled by remember { mutableStateOf(prefs.getBoolean(KEY_ENABLED, false)) }
    var currentStatus by remember { mutableStateOf(prefs.getString(KEY_LAST_STATUS, "Ready") ?: "Ready") }
    var isChecking by remember { mutableStateOf(false) }
    var certInfoList by remember { mutableStateOf<List<CertInfo>>(emptyList()) }
    var showCerts by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Condition settings
    var netMode by remember { mutableStateOf(NetMode.fromOrdinal(prefs.getInt(KEY_NETWORK_MODE, 0))) }
    var requireCharging by remember { mutableStateOf(prefs.getBoolean(KEY_REQUIRE_CHARGING, false)) }
    var requireIdle by remember { mutableStateOf(prefs.getBoolean(KEY_REQUIRE_IDLE, false)) }
    var requireBatteryOk by remember { mutableStateOf(prefs.getBoolean(KEY_REQUIRE_BATTERY_NOT_LOW, false)) }

    val scope = rememberCoroutineScope()
    val intervals = listOf(5L to "5m", 60L to "1h", 180L to "3h", 360L to "6h", 720L to "12h", 1440L to "24h")
    val dateFmt = remember { SimpleDateFormat("dd MMM yyyy HH:mm", Locale.getDefault()) }

    LaunchedEffect(Unit) {
        while (true) {
            currentStatus = prefs.getString(KEY_LAST_STATUS, "Ready") ?: "Ready"
            delay(2000)
        }
    }

    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** Re-enqueue the worker with updated constraints (if monitoring is active). */
    fun rescheduleIfActive() {
        if (isEnabled) {
            enqueueWork(context, 0)
        }
    }

    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
        Text("KeyboxChecker", fontSize = 32.sp, fontWeight = FontWeight.ExtraBold,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))

        // ── Status Card ──
        val statusColor = when {
            currentStatus.contains("Certified", true) && !currentStatus.contains("Not", true) -> Color(0xFF2E7D32)
            currentStatus.contains("Banned", true) -> Color(0xFFB71C1C)
            currentStatus.contains("Error", true) -> Color(0xFFE65100)
            else -> MaterialTheme.colorScheme.surface
        }

        Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = statusColor),
            shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(20.dp)) {
                Text(stringResource(R.string.integrity_status), fontSize = 14.sp, color = Color.White.copy(alpha = 0.7f))
                Spacer(Modifier.height(4.dp))
                Text(currentStatus, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
            }
        }

        errorMessage?.let { err ->
            Spacer(Modifier.height(12.dp))
            Card(Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.error_details), fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onErrorContainer)
                    Spacer(Modifier.height(4.dp))
                    Text(err, fontSize = 13.sp, color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }
        }

        Spacer(Modifier.height(20.dp))

        // ── Check Button ──
        Button(onClick = {
            isChecking = true; errorMessage = null; certInfoList = emptyList()
            scope.launch(Dispatchers.IO) {
                try {
                    val (status, certs) = CheckerLogic.checkKeyboxDetailed(context)
                    withContext(Dispatchers.Main) {
                        currentStatus = status; certInfoList = certs; showCerts = certs.isNotEmpty()
                        prefs.edit().putString(KEY_LAST_STATUS, status).apply()
                        CheckerLogic.updateServiceNotification(context, status)
                        isChecking = false
                        if (status.contains("Error", true)) errorMessage = status
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        currentStatus = "Error"; errorMessage = e.localizedMessage ?: "Unknown error"
                        prefs.edit().putString(KEY_LAST_STATUS, "Error").apply()
                        isChecking = false
                    }
                }
            }
        }, modifier = Modifier.fillMaxWidth().height(56.dp), enabled = !isChecking,
            shape = RoundedCornerShape(14.dp)) {
            if (isChecking) {
                CircularProgressIndicator(Modifier.size(24.dp), color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                Spacer(Modifier.width(12.dp)); Text(stringResource(R.string.checking))
            } else {
                Text(stringResource(R.string.check_now), fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
        }

        Spacer(Modifier.height(20.dp))

        // ── Certificate List ──
        if (certInfoList.isNotEmpty()) {
            OutlinedButton(onClick = { showCerts = !showCerts }, modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)) {
                Text(if (showCerts) stringResource(R.string.hide_certs, certInfoList.size)
                     else stringResource(R.string.show_certs, certInfoList.size), fontWeight = FontWeight.Medium)
            }
            AnimatedVisibility(visible = showCerts, enter = expandVertically(), exit = shrinkVertically()) {
                Column {
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.cert_chain), fontSize = 18.sp, fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.height(4.dp))
                    Text(stringResource(R.string.cert_desc), fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                    Spacer(Modifier.height(12.dp))
                    certInfoList.forEach { cert ->
                        CertificateCard(cert, dateFmt)
                        Spacer(Modifier.height(10.dp))
                    }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(20.dp))

        // ── Network Condition ──
        Text(stringResource(R.string.net_cond), fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.net_desc),
            fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        Spacer(Modifier.height(8.dp))
        FlowRow(modifier = Modifier.padding(vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            NetMode.entries.forEach { mode ->
                FilterChip(
                    selected = netMode == mode,
                    onClick = {
                        netMode = mode
                        prefs.edit().putInt(KEY_NETWORK_MODE, mode.ordinal).apply()
                        rescheduleIfActive()
                    },
                    label = {
                        Column(Modifier.padding(vertical = 4.dp)) {
                            Text(stringResource(mode.labelResId), fontSize = 13.sp, fontWeight = FontWeight.Medium)
                            Text(stringResource(mode.descResId), fontSize = 10.sp,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                        }
                    },
                    enabled = !isEnabled
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        // ── Device Conditions ──
        Text(stringResource(R.string.dev_cond), fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.dev_desc),
            fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        Spacer(Modifier.height(8.dp))

        ConditionToggle("Require Charging", "Run only while plugged in", requireCharging, !isEnabled) {
            requireCharging = it
            prefs.edit().putBoolean(KEY_REQUIRE_CHARGING, it).apply()
            rescheduleIfActive()
        }
        ConditionToggle("Battery Not Low", "Skip if battery is low", requireBatteryOk, !isEnabled) {
            requireBatteryOk = it
            prefs.edit().putBoolean(KEY_REQUIRE_BATTERY_NOT_LOW, it).apply()
            rescheduleIfActive()
        }
        ConditionToggle("Device Idle", "Run only when device is idle", requireIdle, !isEnabled) {
            requireIdle = it
            prefs.edit().putBoolean(KEY_REQUIRE_IDLE, it).apply()
            rescheduleIfActive()
        }

        Spacer(Modifier.height(16.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(20.dp))

        // ── Monitoring Interval ──
        Text(stringResource(R.string.mon_int), fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))
        FlowRow(modifier = Modifier.padding(vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            intervals.forEach { (mins, label) ->
                FilterChip(selected = interval == mins, onClick = {
                    interval = mins; prefs.edit().putLong(KEY_INTERVAL, mins).apply()
                    CheckerLogic.updateServiceNotification(context, currentStatus)
                }, label = { Text(label) }, enabled = !isEnabled)
            }
        }

        Spacer(Modifier.height(20.dp))

        // ── Auto-Monitoring Toggle ──
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween) {
            Text(stringResource(R.string.auto_mon), fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Switch(checked = isEnabled, onCheckedChange = { checked ->
                isEnabled = checked; prefs.edit().putBoolean(KEY_ENABLED, checked).apply()
                CheckerLogic.updateServiceNotification(context, currentStatus)
                if (checked) {
                    enqueueWork(context, 0)
                } else {
                    WorkManager.getInstance(context).cancelUniqueWork("Sentinel")
                }
            })
        }
        Spacer(Modifier.height(32.dp))
    }
}

@Composable
fun ConditionToggle(title: String, subtitle: String, checked: Boolean, enabled: Boolean, onChanged: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Text(subtitle, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
        Switch(checked = checked, onCheckedChange = onChanged, enabled = enabled)
    }
}

@Composable
fun CertificateCard(cert: CertInfo, dateFmt: SimpleDateFormat) {
    val label = when (cert.index) {
        0 -> "Leaf (Device Key)"
        1 -> "Intermediate"
        else -> if (cert.subjectDN == cert.issuerDN) "Root" else "Intermediate ${cert.index}"
    }
    val borderColor = if (cert.isRevoked) Color(0xFFEF5350) else Color(0xFF4CAF50)

    Card(Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f)),
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(if (cert.isRevoked) 2.dp else 1.dp,
            borderColor.copy(alpha = if (cert.isRevoked) 0.8f else 0.3f))) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically) {
                Text("#${cert.index} — $label", fontWeight = FontWeight.Bold, fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.primary)
                Surface(shape = RoundedCornerShape(8.dp),
                    color = if (cert.isRevoked) Color(0xFFB71C1C) else Color(0xFF1B5E20)) {
                    Text(if (cert.isRevoked) " REVOKED " else " OK ", fontSize = 11.sp,
                        fontWeight = FontWeight.Bold, color = Color.White,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
                }
            }
            Spacer(Modifier.height(10.dp))
            CertField("Subject", cert.subjectDN)
            CertField("Issuer", cert.issuerDN)
            CertField("Serial (Hex)", cert.serialNumberHex)
            CertField("Serial (Dec)", cert.serialNumberDec)
            CertField("Valid From", dateFmt.format(cert.notBefore))
            CertField("Valid Until", dateFmt.format(cert.notAfter))
            CertField("Sig Algorithm", cert.sigAlgorithm)
            CertField("Public Key", cert.publicKeyAlgorithm)
            CertField("Version", "v${cert.version}")
        }
    }
}

@Composable
fun CertField(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("$label: ", fontSize = 12.sp, fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), modifier = Modifier.width(100.dp))
        Text(value, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurface,
            maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}
