from droidshield.apk_analyzer import analyze_manifest_text


def test_manifest_component_exported_state_and_intent_filters():
    manifest = """
    <activity android:name="com.example.BadActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <receiver android:name="com.example.BootReceiver" android:exported="false"/>
    """
    result = analyze_manifest_text(manifest)
    assert "com.example.BadActivity" in result["activities"]
    assert result["exported_components"][0]["name"] == "com.example.BadActivity"
    assert result["intent_filter_count"] == 1
    assert "exported-components" in result["indicators"]
