package com.deathkernel.droidshield

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView

class MainActivity : Activity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var running = false
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var currentCheck: TextView
    private lateinit var scanButton: Button
    private lateinit var appsStat: TextView
    private lateinit var findingsStat: TextView
    private lateinit var result: TextView
    private lateinit var serverUrl: EditText
    private lateinit var serverToken: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        progress = findViewById(R.id.progress)
        currentCheck = findViewById(R.id.currentCheck)
        scanButton = findViewById(R.id.scanButton)
        appsStat = findViewById(R.id.appsStat)
        findingsStat = findViewById(R.id.findingsStat)
        result = findViewById(R.id.result)
        serverUrl = findViewById(R.id.serverUrl)
        serverToken = findViewById(R.id.serverToken)
        scanButton.setOnClickListener { startScan() }
    }

    private fun startScan() {
        if (running) return
        val url = serverUrl.text.toString().trim()
        val token = serverToken.text.toString()
        if (url.isEmpty() || token.isEmpty()) {
            status.text = "SCANNER CONNECTION REQUIRED"
            currentCheck.text = "Enter the DroidShield host URL and bearer token."
            return
        }
        running = true
        scanButton.isEnabled = false
        scanButton.text = "SCANNING..."
        progress.visibility = ProgressBar.VISIBLE
        status.text = "SCANNING DEVICE"
        result.text = "Collecting read-only forensic evidence..."
        val transport = HttpScanTransport(url, token)
        transport.startScan(
            onProgress = { percent, check -> mainHandler.post { progress.progress = percent; currentCheck.text = check } },
            onComplete = { scan -> mainHandler.post { showResult(scan) } },
            onError = { error -> mainHandler.post { showError(error) } }
        )
    }

    private fun showResult(scan: ScanResult) {
        running = false
        progress.progress = 100
        status.text = "SCAN COMPLETE • ${scan.riskLevel}"
        currentCheck.text = "${scan.deviceName} • Android ${scan.androidVersion}"
        appsStat.text = "APPS\n${scan.appsAnalyzed}"
        findingsStat.text = "FINDINGS\n${scan.findings.size}"
        result.text = if (scan.findings.isEmpty()) {
            "No findings were returned. This is not a guarantee that the device is clean."
        } else {
            scan.findings.joinToString("\n\n") { f -> "${f.severity} • ${f.title}\n${f.packageName ?: "Device-level"}\n${f.description}" }
        }
        scanButton.isEnabled = true
        scanButton.text = "START DEEP SCAN"
    }

    private fun showError(error: String) {
        running = false
        status.text = "SCAN FAILED"
        currentCheck.text = error
        result.text = "No security verdict was generated because the scanner did not complete."
        scanButton.isEnabled = true
        scanButton.text = "START DEEP SCAN"
    }
}