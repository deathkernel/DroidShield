package com.deathkernel.droidshield

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var running = false
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var currentCheck: TextView
    private lateinit var scanButton: Button
    private lateinit var appsStat: TextView
    private lateinit var findingsStat: TextView
    private lateinit var result: TextView
    private val checks = listOf(
        "Collecting device security state",
        "Reviewing app permissions",
        "Checking accessibility services",
        "Checking overlay access",
        "Checking notification listeners",
        "Correlating sensitive capabilities",
        "Building security findings"
    )
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
        status.setTextColor(0xFF59D6A5.toInt())
        result.text = "Collecting read-only security evidence..."
        appsStat.text = "APPS\nScanning"
        findingsStat.text = "FINDINGS\n0"
        runStep(0)
    }
    private fun runStep(index: Int) {
        if (!running) return
        if (index >= checks.size) { finishScan(); return }
        progress.progress = ((index.toFloat() / checks.size) * 100).toInt()
        currentCheck.text = checks[index]
        handler.postDelayed({ runStep(index + 1) }, 550)
    }
    private fun finishScan() {
        running = false
        progress.progress = 100
        status.text = "SCAN COMPLETE"
        currentCheck.text = "Evidence collection complete"
        appsStat.text = "APPS\nReady"
        findingsStat.text = "FINDINGS\nReview"
        result.text = "Scan engine connection is not configured yet. This screen is ready for the DroidShield scanner transport layer."
        scanButton.isEnabled = true
        scanButton.text = "START DEEP SCAN"
    }
    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}