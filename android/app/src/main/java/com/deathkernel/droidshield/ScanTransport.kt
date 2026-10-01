package com.deathkernel.droidshield

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

interface ScanTransport {
    fun startScan(onProgress: (Int, String) -> Unit, onComplete: (ScanResult) -> Unit, onError: (String) -> Unit)
}

class HttpScanTransport(private val baseUrl: String, private val token: String) : ScanTransport {
    override fun startScan(onProgress: (Int, String) -> Unit, onComplete: (ScanResult) -> Unit, onError: (String) -> Unit) {
        Thread {
            try {
                onProgress(5, "Connecting to DroidShield scanner")
                val connection = (URL(baseUrl.trimEnd('/') + "/api/v1/scan").openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 8000
                    readTimeout = 120000
                    doOutput = true
                    setRequestProperty("Authorization", "Bearer $token")
                    setRequestProperty("Content-Type", "application/json")
                }
                connection.outputStream.use { it.write(JSONObject().put("hash_apks", true).toString().toByteArray()) }
                onProgress(70, "Receiving forensic report")
                val text = connection.inputStream.bufferedReader().use { it.readText() }
                if (connection.responseCode !in 200..299) error("Scanner HTTP ${connection.responseCode}")
                val root = JSONObject(text)
                if (!root.optBoolean("ok", false)) error(root.optString("error", "Scanner failed"))
                onProgress(90, "Rendering evidence")
                val report = root.getJSONObject("report")
                val risk = report.getJSONObject("risk")
                val findingsJson = report.getJSONArray("findings")
                val findings = buildList {
                    for (i in 0 until findingsJson.length()) {
                        val f = findingsJson.getJSONObject(i)
                        add(ScanFinding(f.optString("severity", "UNKNOWN"), f.optString("title", "Finding"), if (f.isNull("package")) null else f.optString("package", null), f.optString("description", "No description supplied")))
                    }
                }
                val coverage = report.optJSONObject("metadata_coverage")
                val device = report.getJSONObject("device")
                onComplete(ScanResult(device.optString("model", "Android device"), device.optString("android", "unknown"), coverage?.optInt("packages_analyzed", 0) ?: 0, findings, risk.optString("level", "UNKNOWN")))
                connection.disconnect()
            } catch (exc: Exception) { onError(exc.message ?: "Unable to reach scanner") }
        }.start()
    }
}