package com.tunnely.app.vpn

import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit

/**
 * Remote debug logger — captures logs and pushes them to the server.
 * Enabled via Settings → "Remote Debug Logging" toggle.
 *
 * Logs are:
 *   1. Buffered in memory (ring buffer, max 500 entries)
 *   2. Flushed to server every FLUSH_INTERVAL_MS
 *   3. Also written to local file for offline capture
 *
 * Usage:
 *   RemoteLogger.init(context)
 *   RemoteLogger.i("TAG", "message")
 *   RemoteLogger.e("TAG", "error", exception)
 */
object RemoteLogger {

    private const val TAG = "RemoteLogger"
    private const val MAX_BUFFER_SIZE = 500
    private const val FLUSH_INTERVAL_MS = 10_000L  // 10 seconds
    private const val MAX_RETRIES = 2
    private const val LOG_FILE_NAME = "tunnely_debug.log"
    private const val MAX_LOG_FILE_SIZE = 2 * 1024 * 1024  // 2MB

    private val logQueue = ConcurrentLinkedQueue<JSONObject>()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    private var context: Context? = null
    private var prefs: VpnPreferences? = null
    private var flushJob: Job? = null
    private var scope: CoroutineScope? = null
    private var logFile: File? = null

    // Device info (cached on init)
    private lateinit var deviceId: String
    private lateinit var deviceModel: String
    private lateinit var appVersion: String

    fun init(ctx: Context) {
        if (context != null) return  // already initialized
        context = ctx.applicationContext
        prefs = VpnPreferences(ctx)

        // Cache device info
        deviceId = Build.ID ?: "unknown"
        deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}"
        appVersion = try {
            ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "unknown"
        } catch (_: Exception) { "unknown" }

        // Setup local log file
        logFile = File(ctx.filesDir, LOG_FILE_NAME)

        // Start flush loop if enabled
        if (prefs?.remoteLogging == true) {
            startFlushLoop()
        }

        i(TAG, "RemoteLogger initialized — device=$deviceModel, version=$appVersion, enabled=${prefs?.remoteLogging}")
    }

    fun setEnabled(enabled: Boolean) {
        prefs?.remoteLogging = enabled
        if (enabled) {
            startFlushLoop()
            i(TAG, "Remote logging ENABLED")
        } else {
            stopFlushLoop()
            // Flush remaining logs one last time
            scope?.launch { flush() }
            Log.i(TAG, "Remote logging DISABLED — flushed remaining logs")
        }
    }

    fun isEnabled(): Boolean = prefs?.remoteLogging == true

    // ─── Logging API ────────────────────────────────────────────────

    fun v(tag: String, msg: String) = log("VERBOSE", tag, msg, null)
    fun d(tag: String, msg: String) = log("DEBUG", tag, msg, null)
    fun i(tag: String, msg: String) = log("INFO", tag, msg, null)
    fun w(tag: String, msg: String) = log("WARN", tag, msg, null)
    fun w(tag: String, msg: String, t: Throwable?) = log("WARN", tag, msg, t)
    fun e(tag: String, msg: String) = log("ERROR", tag, msg, null)
    fun e(tag: String, msg: String, t: Throwable?) = log("ERROR", tag, msg, t)

    // ─── Internal ───────────────────────────────────────────────────

    private fun log(level: String, tag: String, message: String, throwable: Throwable?) {
        // Always log to Android logcat
        when (level) {
            "VERBOSE" -> Log.v(tag, message)
            "DEBUG" -> Log.d(tag, message)
            "INFO" -> Log.i(tag, message)
            "WARN" -> Log.w(tag, message)
            "ERROR" -> Log.e(tag, message)
        }

        // Only buffer if remote logging is enabled
        if (prefs?.remoteLogging != true) return

        val entry = JSONObject().apply {
            put("ts", dateFormat.format(Date()))
            put("level", level)
            put("tag", tag)
            put("msg", message)
            throwable?.let {
                put("stack", getStackTrace(it))
            }
        }

        // Ring buffer — drop oldest if full
        while (logQueue.size >= MAX_BUFFER_SIZE) {
            logQueue.poll()
        }
        logQueue.add(entry)

        // Also write to local file
        writeToFile(entry)
    }

    private fun getStackTrace(t: Throwable): String {
        val sw = StringWriter()
        t.printStackTrace(PrintWriter(sw))
        return sw.toString()
    }

    private fun writeToFile(entry: JSONObject) {
        try {
            val file = logFile ?: return

            // Rotate if too large
            if (file.exists() && file.length() > MAX_LOG_FILE_SIZE) {
                val rotated = File(file.parent, "${LOG_FILE_NAME}.old")
                file.renameTo(rotated)
            }

            FileWriter(file, true).use { fw ->
                fw.append(entry.toString())
                fw.append('\n')
            }
        } catch (_: Exception) {}
    }

    // ─── Flush Loop ─────────────────────────────────────────────────

    private fun startFlushLoop() {
        if (flushJob?.isActive == true) return

        val ctx = context ?: return
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        flushJob = scope!!.launch {
            i(TAG, "Flush loop started — interval=${FLUSH_INTERVAL_MS}ms")
            while (isActive) {
                delay(FLUSH_INTERVAL_MS)
                try {
                    flush()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.w(TAG, "Flush failed: ${e.message}")
                }
            }
        }
    }

    private fun stopFlushLoop() {
        flushJob?.cancel()
        flushJob = null
    }

    private suspend fun flush() {
        if (logQueue.isEmpty()) return

        val p = prefs ?: return
        val baseUrl = "https://${p.serverAddress}"

        // Drain queue into batch
        val batch = JSONArray()
        while (logQueue.isNotEmpty()) {
            val entry = logQueue.poll() ?: break
            batch.put(entry)
        }

        if (batch.length() == 0) return

        val payload = JSONObject().apply {
            put("device_id", deviceId)
            put("device_model", deviceModel)
            put("app_version", appVersion)
            put("tunnel_ip", p.tunnelAddress)
            put("public_key", p.publicKey)
            put("logs", batch)
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        val request = Request.Builder()
            .url("$baseUrl/api/vpn/logs")
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()

        for (attempt in 1..MAX_RETRIES) {
            try {
                val response = client.newCall(request).execute()
                if (response.isSuccessful) {
                    Log.d(TAG, "Flushed ${batch.length()} logs to server")
                    return
                }
                Log.w(TAG, "Flush failed (attempt $attempt): HTTP ${response.code}")
            } catch (e: Exception) {
                Log.w(TAG, "Flush error (attempt $attempt): ${e.message}")
            }
        }

        // If all retries failed, re-add to queue (but don't overflow)
        for (i in 0 until batch.length()) {
            if (logQueue.size < MAX_BUFFER_SIZE) {
                logQueue.add(batch.getJSONObject(i))
            }
        }
    }

    // ─── Dump local log file ────────────────────────────────────────

    fun getLocalLogContents(): String {
        return try {
            logFile?.readText() ?: "(no log file)"
        } catch (_: Exception) {
            "(error reading log file)"
        }
    }

    fun clearLocalLog() {
        try {
            logFile?.delete()
        } catch (_: Exception) {}
    }
}
