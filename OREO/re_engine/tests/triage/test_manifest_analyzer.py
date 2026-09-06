"""Unit tests for the manifest triage analyzer."""

from re_engine.analyzers.manifest_analyzer import ManifestAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import ANDROID_NS, FakeApk, fake_manifest_xml, inject_fakes, real_accessor

MANIFEST_BASE = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.triage">
  <application android:label="Triage" android:allowBackup="true">
  {{body}}
  </application>
</manifest>
"""


def _ctx(tmp_path, body=None, raw_manifest=None, **apk_kwargs):
    import zipfile

    from .fixtures import build_zip

    if raw_manifest is None:
        raw_manifest = MANIFEST_BASE.format(body=body or "")
    path = build_zip(
        {"AndroidManifest.xml": raw_manifest.encode()},
        tmp_path / "app.apk",
        compression=zipfile.ZIP_STORED,
    )
    accessor = real_accessor(path)
    manifest = fake_manifest_xml(raw_manifest)
    fake = FakeApk(manifest_xml=manifest, **apk_kwargs)
    inject_fakes(accessor, fake_apk=fake)
    ctx = AnalysisContext()
    ctx.artifacts = accessor
    return ctx, fake


def test_parses_components(tmp_path):
    body = f"""
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".SettingsActivity" android:exported="false"/>
    <service android:name=".SyncService"/>
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <receiver android:name=".AdminReceiver">
      <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>
      </intent-filter>
    </receiver>
    <service android:name=".TapService" android:foregroundServiceType="dataSync">
      <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService"/>
      </intent-filter>
    </service>
    <provider android:name=".DataProvider"/>
    """
    ctx, fake = _ctx(tmp_path, body)
    fake._components_xml_available = True
    ManifestAnalyzer().run(ctx)

    assert len(ctx.components) == 7
    kinds = {c.kind for c in ctx.components}
    assert kinds == {"activity", "service", "receiver", "provider"}


def test_exported_flag_and_main_activity(tmp_path):
    body = f"""
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <activity android:name=".Share"/>
    """
    ctx, _ = _ctx(tmp_path, body, main_activity=".Main")
    ManifestAnalyzer().run(ctx)
    assert ctx.exported_components == [".Main"]
    exported = [c for c in ctx.components if c.name == ".Main"][0]
    assert exported.exported is True
    assert exported.intent_filters == ["android.intent.action.MAIN"]


def test_boot_accessibility_device_admin(tmp_path):
    body = f"""
    <service android:name=".AccService"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <receiver android:name=".Boot">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <receiver android:name=".Admin">
      <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>
      </intent-filter>
    </receiver>
    """
    ctx, _ = _ctx(tmp_path, body)
    ManifestAnalyzer().run(ctx)

    assert ctx.accessibility_components == [".AccService"]
    assert ctx.boot_receivers == [".Boot"]
    assert ctx.device_admin_components == [".Admin"]

    titles = {f.title for f in ctx.findings}
    assert "Accessibility service present" in titles
    assert "Boot receiver present" in titles
    assert "Device-admin receiver present" in titles


def test_debuggable_flagged(tmp_path):
    ctx, _ = _ctx(tmp_path, '<activity android:name=".A"/>')
    ManifestAnalyzer().run(ctx)
    # default manifest has no debuggable -> no finding
    assert not any(f.title == "Debuggable application" for f in ctx.findings)

    raw = MANIFEST_BASE.format(
        body='<activity android:name=".A"/>'
    ).replace(
        'android:allowBackup="true"',
        'android:allowBackup="true" android:debuggable="true"',
    )
    ctx2, _ = _ctx(tmp_path, raw_manifest=raw)
    ManifestAnalyzer().run(ctx2)
    assert any(f.title == "Debuggable application" for f in ctx2.findings)
    assert ctx2.application_flags.get("debuggable") == "true"


def test_declared_permissions_fallback_apk(tmp_path):
    """Permissions surface here through the permission analyzer, not manifest."""
    from re_engine.analyzers.permission_analyzer import PermissionAnalyzer

    body = '<activity android:name=".A"/>'
    ctx, _ = _ctx(
        tmp_path,
        body,
        permissions=["android.permission.INTERNET"],
    )
    ManifestAnalyzer().run(ctx)
    PermissionAnalyzer().run(ctx)
    assert "android.permission.INTERNET" in ctx.permissions


def test_manifest_summary_finding(tmp_path):
    ctx, _ = _ctx(tmp_path, '<activity android:name=".A"/>')
    ManifestAnalyzer().run(ctx)
    assert any(f.analyzer == "manifest" for f in ctx.findings)