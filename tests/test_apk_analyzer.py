from droidshield.apk_analyzer import analyze_manifest_text, extract_urls


def test_manifest_permissions_and_indicators():
    manifest = '''
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <service android:name="com.example.Service"/>
    '''
    result = analyze_manifest_text(manifest)
    assert "android.permission.SYSTEM_ALERT_WINDOW" in result["permissions"]
    assert "overlay-capable" in result["indicators"]
    assert "accessibility-capable" in result["indicators"]
    assert "com.example.Service" in result["services"]


def test_url_extraction():
    result = extract_urls("https://example.com/a http://evil.test/x")
    assert "https://example.com/a" in result
    assert "http://evil.test/x" in result
