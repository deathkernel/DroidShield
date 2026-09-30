# DroidShield YARA Rules

The rules in this directory are intentionally conservative triage signatures.

They are not malware verdicts. Android applications can legitimately request
sensitive permissions or use dynamic loading, accessibility, WebView, or other
APIs. A YARA match should be reviewed together with package provenance,
component state, signer identity, runtime evidence, and user-observed behavior.

Use an explicit ruleset:

    droidshield yara sample.apk --rules rules/android_triage.yar

The included rules currently cover:

- Accessibility plus overlay capability
- Package installation plus SMS capability
- Common dynamic-code loading API names

Keep locally maintained additions versioned and test them against known-benign
fixtures before using them in automated incident workflows.
