rule Android_Accessibility_And_Overlay_Triage {
    meta:
        description = "Triage signal for APKs declaring both accessibility and overlay capabilities"
        purpose = "defensive triage; not proof of malware"
    strings:
        $access = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
    condition:
        all of them
}

rule Android_Package_Install_And_SMS_Triage {
    meta:
        description = "Triage signal for APKs combining package installation and SMS capabilities"
        purpose = "defensive triage; not proof of malware"
    strings:
        $install = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $sms1 = "android.permission.SEND_SMS" ascii wide
        $sms2 = "android.permission.RECEIVE_SMS" ascii wide
    condition:
        $install and 1 of ($sms*)
}

rule Android_Dynamic_Code_Loading_Triage {
    meta:
        description = "Triage signal for common dynamic-code loading API names"
        purpose = "defensive triage; manual review required"
    strings:
        $dex = "dalvik.system.DexClassLoader" ascii wide
        $path = "dalvik.system.PathClassLoader" ascii wide
    condition:
        1 of them
}
