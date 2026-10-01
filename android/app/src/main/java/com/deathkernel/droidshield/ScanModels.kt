package com.deathkernel.droidshield

data class ScanFinding(
    val severity: String,
    val title: String,
    val packageName: String?,
    val description: String
)

data class ScanResult(
    val deviceName: String,
    val androidVersion: String,
    val appsAnalyzed: Int,
    val findings: List<ScanFinding>,
    val riskLevel: String
)