from droidshield.rules import package_findings


def test_suspicious_name_is_only_a_triage_signal():
    findings = package_findings(["com.example.fakecalculator"])
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].package == "com.example.fakecalculator"


def test_normal_package_has_no_name_finding():
    assert package_findings(["com.android.settings"]) == []
