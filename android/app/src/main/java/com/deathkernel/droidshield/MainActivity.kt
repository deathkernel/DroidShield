package com.deathkernel.droidshield

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView

class MainActivity : Activity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val transport: ScanTransport = DemoScanTransport()
    private var running = false
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var currentCheck: TextView
    private lateinit var scanButton: Button
    private lateinit var appsStat: TextView
    private lateinit var findingsStat: TextView
    private lateinit var result: TextView

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
        scanButton.setOnClickListener { startScan() }
    }

    private fun startScan() {
        if (running) return
        running = true
        scanButton.isEnabled = false
        scanButton.text = "SCANNING..."
        progress.visibility = ProgressBar.VISIBLE
        progress.progress = 0
        status.text = "SCANNING DEVICE"
        currentCheck.text = "Starting read-only scan"
        result.text = "Collecting evidence..."
        appsStat.text = "APPS\nScanning"
        findingsStat.text = "FINDINGS\n0"
        transport.startScan(
            onProgress = { percent, check -> mainHandler.post { progress.progress = percent; currentCheck.text = check } },
            onComplete = { scanResult -> mainHandler.post { showResult(scanResult) } },
            onError = { error -> mainHandler.post { showError(error) } }
        )
    }

    private fun showResult(scan: ScanResult) {
        running = false
        progress.progress = 100
        status.text = "SCAN COMPLETE • ${scan.riskLevel}"
        currentCheck.text = "Evidence collection complete"
        appsStat.text = "APPS\n${scan.appsAnalyzed}"
        findingsStat.text = "FINDINGS\n${scan.findings.size}"
        result.text = if (scan.findings.isEmpty()) {
            "No findings were returned by the connected scan transport. This does not by itself prove the device is clean."
        } else {
            scan.findings.joinToString("\n\n") { finding ->
                "${finding.severity} • ${finding.title}\n${finding.packageName ?: "Device-level"}\n${finding.description}"
            }
        }
        scanButton.isEnabled = true
        scanButton.text = "START DEEP SCAN"
    }

    private fun showError(error: String) {
        running = false
        status.text = "SCAN FAILED"
        currentCheck.text = error
        result.text = "The scan did not complete. No security verdict was generated."
        scanButton.isEnabled = true
        scanButton.text = "START DEEP SCAN"
    }

    override fun onDestroy() {
        mainHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}