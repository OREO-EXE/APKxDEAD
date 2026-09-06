"""Detector-level status rules: TRUE / FALSE / UNKNOWN semantics."""

from __future__ import annotations

from re_engine.behavior.models import BehaviorStatus
from re_engine.behavior.specs import PERM_READ_SMS
from re_engine.dataflow.models import DataFlowFinding, DataFlowResult, FlowStatus

from .fixtures import (
    anti_analysis_dex,
    behavior_context,
    boot_dex,
    contacts_dex,
    crypto_dex,
    crypto_undirected_dex,
    dynamic_load_dex,
    emulator_probe_dex,
    emulator_string_only_dex,
    empty_dex,
    exec_dex,
    giant_method_dex,
    network_only_dex,
    root_probe_dex,
    run_behavior,
    sms_uri_dex,
    su_string_only_dex,
)

_PERM_BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"


def _finding(result, key):
    return next(f for f in result.findings if f.behavior_id == key)


# ---------------------------------------------------------------------------
# PERSISTENCE
# ---------------------------------------------------------------------------


def test_boot_completion_manifest_receiver_true():
    ctx = behavior_context(boot_receivers=["com.app.BootReceiver"])
    result = run_behavior(boot_dex(), context=ctx)
    finding = _finding(result, "persistence.boot_completion")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "high"
    assert any(ref.startswith("manifest:boot_receiver:") for ref in finding.evidence_refs)


def test_boot_completion_permission_only_unknown():
    ctx = behavior_context(permissions=[_PERM_BOOT])
    result = run_behavior(boot_dex(), context=ctx)
    finding = _finding(result, "persistence.boot_completion")
    assert finding.status == BehaviorStatus.UNKNOWN
    assert finding.confidence == "low"
    assert any(ref.startswith("permission:") for ref in finding.evidence_refs)


def test_boot_completion_no_evidence_false():
    result = run_behavior(boot_dex())
    assert _finding(result, "persistence.boot_completion").status == BehaviorStatus.FALSE


def test_foreground_service_manifest_true():
    ctx = behavior_context(foreground_services=["com.app.FgService"])
    result = run_behavior(boot_dex(), context=ctx)
    finding = _finding(result, "persistence.foreground_service")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "high"


def test_background_service_manifest_true():
    ctx = behavior_context(services=["com.app.WorkService"])
    result = run_behavior(boot_dex(), context=ctx)
    assert _finding(result, "persistence.background_service").status == BehaviorStatus.TRUE


def test_accessibility_service_declared_true():
    ctx = behavior_context(accessibility_components=["com.app.A11yService"])
    result = run_behavior(boot_dex(), context=ctx)
    finding = _finding(result, "persistence.accessibility")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "high"


def test_device_admin_declared_true():
    ctx = behavior_context(device_admin_components=["com.app.AdminReceiver"])
    result = run_behavior(boot_dex(), context=ctx)
    assert _finding(result, "persistence.device_admin").status == BehaviorStatus.TRUE


# ---------------------------------------------------------------------------
# DATA COLLECTION
# ---------------------------------------------------------------------------


def test_sms_bytecode_true_with_permission_metadata():
    ctx = behavior_context(permissions=[PERM_READ_SMS])
    result = run_behavior(sms_uri_dex(), context=ctx)
    finding = _finding(result, "collection.sms")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "medium"
    assert PERM_READ_SMS in finding.related_permissions
    assert finding.related_methods
    assert finding.evidence_refs


def test_sms_permission_only_unknown_never_true():
    ctx = behavior_context(permissions=[PERM_READ_SMS])
    result = run_behavior(empty_dex(), context=ctx)
    finding = _finding(result, "collection.sms")
    assert finding.status == BehaviorStatus.UNKNOWN
    assert finding.confidence == "low"


def test_sms_bytecode_links_no_dataflow_without_result():
    result = run_behavior(sms_uri_dex())
    assert _finding(result, "collection.sms").related_data_flows == []


def test_sms_no_evidence_false():
    result = run_behavior(empty_dex())
    assert _finding(result, "collection.sms").status == BehaviorStatus.FALSE


def test_contacts_content_uri_true():
    result = run_behavior(contacts_dex())
    finding = _finding(result, "collection.contacts")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "medium"


def test_collection_bytecode_links_dataflow_result():
    context = behavior_context()
    flow = DataFlowResult(
        findings=[
            DataFlowFinding(
                flow_id="f1",
                source="sms",
                source_method="Lcom/app/UriCollector;->collect()V",
                path=["Lcom/app/UriCollector;->collect()V"],
                sink="exec",
                sink_method="Lcom/app/UriCollector;->collect()V",
                status=FlowStatus.CONFIRMED,
            )
        ]
    )
    from re_engine.behavior.engine import BehaviorEngine
    from re_engine.reconstruct.index import CodeIndex

    engine = BehaviorEngine(
        context=context, index=CodeIndex([sms_uri_dex()]), dataflow=flow
    )
    result = engine.run()
    finding = _finding(result, "collection.sms")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.confidence == "high"
    assert "sms->exec" in finding.related_data_flows[0]


# ---------------------------------------------------------------------------
# COMMAND EXECUTION
# ---------------------------------------------------------------------------


def test_command_execution_true():
    result = run_behavior(exec_dex())
    finding = _finding(result, "execution.command")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.related_methods == ["Lcom/app/Exec;->run()V"]


def test_command_execution_shell_string_unknown():
    ctx = behavior_context(shell_commands=["sh -c \"id\""])
    result = run_behavior(empty_dex(), context=ctx)
    finding = _finding(result, "execution.command")
    assert finding.status == BehaviorStatus.UNKNOWN


def test_native_execution_unknown_when_libraries_shipped():
    ctx = behavior_context(native_libraries=["libc.so"])
    result = run_behavior(empty_dex(), context=ctx)
    finding = _finding(result, "execution.native")
    assert finding.status == BehaviorStatus.UNKNOWN


# ---------------------------------------------------------------------------
# EVASION / DYNAMIC (same-method co-occurrence)
# ---------------------------------------------------------------------------


def test_root_same_method_true():
    result = run_behavior(root_probe_dex())
    finding = _finding(result, "evasion.root_detection")
    assert finding.status == BehaviorStatus.TRUE
    assert any("probe" in m for m in finding.related_methods)


def test_root_string_only_unknown():
    result = run_behavior(su_string_only_dex())
    finding = _finding(result, "evasion.root_detection")
    assert finding.status == BehaviorStatus.UNKNOWN
    assert finding.confidence == "low"


def test_emulator_same_method_true():
    result = run_behavior(emulator_probe_dex())
    finding = _finding(result, "evasion.emulator_detection")
    assert finding.status == BehaviorStatus.TRUE


def test_emulator_string_only_unknown():
    result = run_behavior(emulator_string_only_dex())
    finding = _finding(result, "evasion.emulator_detection")
    assert finding.status == BehaviorStatus.UNKNOWN


def test_downloaded_code_same_method_true():
    result = run_behavior(dynamic_load_dex())
    assert _finding(result, "dynamic.downloaded_code").status == BehaviorStatus.TRUE
    assert _finding(result, "dynamic.class_loading").status == BehaviorStatus.TRUE


def test_downloaded_code_app_wide_unknown():
    result = run_behavior(network_only_dex())
    finding = _finding(result, "dynamic.downloaded_code")
    assert finding.status == BehaviorStatus.UNKNOWN
    assert finding.confidence == "low"
    assert _finding(result, "dynamic.class_loading").status == BehaviorStatus.TRUE


def test_encrypted_payload_same_method_true():
    # crypto + dexclassloader co-located
    from re_engine.reconstruct.index import CodeIndex
    from re_engine.tests.triage.fixtures import FakeDex, FakeDexClass, FakeInstruction

    dex = FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Payload;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    (
                        "load",
                        "()V",
                        "public",
                        [
                            FakeInstruction(
                                "invoke-static",
                                "v0, Ljavax/crypto/Cipher;->doFinal([B)[B",
                            ),
                            FakeInstruction(
                                "new-instance", "v1, Ldalvik/system/DexClassLoader;"
                            ),
                            FakeInstruction("return-void", ""),
                        ],
                        2,
                    )
                ],
            )
        ]
    )
    result = run_behavior(dex)
    assert _finding(result, "dynamic.encrypted_payload").status == BehaviorStatus.TRUE


# ---------------------------------------------------------------------------
# CRYPTOGRAPHY
# ---------------------------------------------------------------------------


def test_crypto_const_mode_attribution():
    result = run_behavior(crypto_dex())
    assert _finding(result, "crypto.encryption").status == BehaviorStatus.TRUE
    assert _finding(result, "crypto.decryption").status == BehaviorStatus.TRUE
    enc_refs = _finding(result, "crypto.encryption").evidence_refs
    assert any("ENCRYPT_MODE" in ref for ref in enc_refs)


def test_crypto_without_mode_const_unknown():
    result = run_behavior(crypto_undirected_dex())
    assert _finding(result, "crypto.encryption").status == BehaviorStatus.UNKNOWN
    assert _finding(result, "crypto.decryption").status == BehaviorStatus.UNKNOWN


def test_crypto_no_evidence_false():
    result = run_behavior(empty_dex())
    assert _finding(result, "crypto.encryption").status == BehaviorStatus.FALSE


# ---------------------------------------------------------------------------
# EVASION aggregates
# ---------------------------------------------------------------------------


def test_control_flow_obfuscation_giant_method():
    result = run_behavior(giant_method_dex())
    finding = _finding(result, "evasion.control_flow_obfuscation")
    assert finding.status == BehaviorStatus.TRUE
    assert any(ref.startswith("giant_method:") for ref in finding.evidence_refs)


def test_anti_analysis_combined_true():
    result = run_behavior(anti_analysis_dex())
    assert _finding(result, "evasion.anti_analysis").status == BehaviorStatus.TRUE
    assert _finding(result, "evasion.anti_analysis").confidence == "high"


def test_anti_analysis_single_technique_unknown():
    result = run_behavior(root_probe_dex())
    finding = _finding(result, "evasion.anti_analysis")
    assert finding.status == BehaviorStatus.UNKNOWN
    assert finding.confidence == "low"


def test_anti_analysis_nothing_false():
    result = run_behavior(empty_dex())
    assert _finding(result, "evasion.anti_analysis").status == BehaviorStatus.FALSE


# ---------------------------------------------------------------------------
# NETWORK
# ---------------------------------------------------------------------------


def test_custom_protocol_scheme_true():
    ctx = behavior_context(urls=["myapp://open?id=42"])
    result = run_behavior(empty_dex(), context=ctx)
    finding = _finding(result, "network.custom_protocol")
    assert finding.status == BehaviorStatus.TRUE
    assert finding.evidence_refs == ["scheme:myapp"]


def test_custom_protocol_standard_schemes_false():
    ctx = behavior_context(urls=["https://example.org/x", "http://a.b/c"])
    result = run_behavior(empty_dex(), context=ctx)
    assert _finding(result, "network.custom_protocol").status == BehaviorStatus.FALSE


def test_network_http_permission_only_unknown():
    ctx = behavior_context(permissions=["android.permission.INTERNET"])
    result = run_behavior(empty_dex(), context=ctx)
    assert _finding(result, "network.http").status == BehaviorStatus.UNKNOWN