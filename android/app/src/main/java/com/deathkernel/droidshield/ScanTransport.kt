package com.deathkernel.droidshield

interface ScanTransport {
    fun startScan(onProgress: (Int, String) -> Unit, onComplete: (ScanResult) -> Unit, onError: (String) -> Unit)
}

class DemoScanTransport : ScanTransport {
    override fun startScan(onProgress: (Int, String) -> Unit, onComplete: (ScanResult) -> Unit, onError: (String) -> Unit) {
        val checks = listOf(
            "Collecting device security state",
            "Reviewing app permissions",
            "Checking accessibility services",
            "Checking overlay access",
            "Checking notification listeners",
            "Correlating sensitive capabilities",
            "Building security findings"
        )
        Thread {
            try {
                checks.forEachIndexed { index, check ->
                    Thread.sleep(450)
                    onProgress(((index + 1) * 100) / checks.size, check)
                }
                onComplete(ScanResult("Connected Android device", "Detected by scanner transport", 0, emptyList(), "REVIEW"))
            } catch (exc: Exception) {
                onError(exc.message ?: "Scan failed")
            }
        }.start()
    }
}