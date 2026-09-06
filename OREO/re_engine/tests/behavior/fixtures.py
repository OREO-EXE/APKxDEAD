"""Hermetic fixtures for behavior-reconstruction tests.

Synthetic DEX scenarios (triple of the triage fakes -- methods as tuples) that
exercise manifest-driven persistence, permission-only UNKNOWNs, same-method
co-occurrence for chained/evasion behaviors, crypto const-mode attribution,
giant-method control-flow obfuscation, and the no-evidence case so the behavior
engine is fully testable without androguard.
"""

from __future__ import annotations

from re_engine.reconstruct.index import CodeIndex
from re_engine.tests.triage.fixtures import FakeDex, FakeDexClass, FakeInstruction

SMS_URI = "content://sms/inbox"
SU_PATH = "/system/bin/su"
GOLDFISH = "goldfish"
BUILD_FINGERPRINT_REF = (
    "Landroid/os/Build;->FINGERPRINT Ljava/lang/String;"
)
SMS_MESSAGE_BODY_REF = "Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;"
CIPHER_INIT_REF = "Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V"
RUNTIME_EXEC_REF = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
RUNTIME_GETRUNTIME_REF = "Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"
HTTP_FETCH_REF = "Ljava/net/URL;->openStream()Ljava/io/InputStream;"


def _inst(name, output, string=None):
    return FakeInstruction(name, output, string=string)


def behavior_context(
    permissions=(),
    boot_receivers=(),
    foreground_services=(),
    accessibility_components=(),
    device_admin_components=(),
    services=(),
    shell_commands=(),
    encoded_strings=(),
    urls=(),
    native_libraries=(),
    debuggable=False,
):
    """A bare AnalysisContext with the manifest/permission surface pre-seeded."""
    from re_engine.models.context import AnalysisContext, Component

    ctx = AnalysisContext(apk_path="sample.apk")
    ctx.permissions = list(permissions)
    ctx.boot_receivers = list(boot_receivers)
    ctx.foreground_services = list(foreground_services)
    ctx.accessibility_components = list(accessibility_components)
    ctx.device_admin_components = list(device_admin_components)
    ctx.shell_commands = list(shell_commands)
    ctx.encoded_strings = list(encoded_strings)
    ctx.urls = list(urls)
    ctx.native_libraries = list(native_libraries)
    if debuggable:
        ctx.application_flags["debuggable"] = True
    for name in services:
        ctx.components.append(Component(name=name, kind="service"))
    return ctx


def run_behavior(dex, context=None, options=None):
    """Run the BehaviorEngine hermetically over a FakeDex (+ optional context)."""
    from re_engine.behavior.engine import BehaviorEngine

    context = context or behavior_context()
    engine = BehaviorEngine(
        context=context,
        index=CodeIndex([dex]),
        options=dict(options or {}),
    )
    return engine.run()


def _method(name, descriptor, access, instructions, registers=8):
    return (name, descriptor, access, instructions, registers)


def empty_dex():
    """One trivial method; every behavior should be FALSE or UNKNOWN."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Harmless;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "onCreate",
                        "(Landroid/os/Bundle;)V",
                        "protected",
                        [
                            _inst("const/4", "v0, 0x0"),
                            _inst("return-void", ""),
                        ],
                        registers=1,
                    )
                ],
            )
        ]
    )


def boot_dex():
    """Bytecode-only APK (boot receiver is manifest-side)."""
    return empty_dex()


def sms_collector_dex():
    """Reads an SMS body and leaks it (SmsMessage API)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/SmsCollector;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "collect",
                        "()Ljava/lang/String;",
                        "public",
                        [
                            _inst("invoke-static", f"v0, {SMS_MESSAGE_BODY_REF}"),
                            _inst("move-result-object", "v1"),
                            _inst("return-object", "v1"),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def sms_uri_dex():
    """Reads SMS through a content URI + SmsMessage body."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/UriCollector;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "collect",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SMS_URI}"', SMS_URI),
                            _inst("invoke-static", f"v0, {SMS_MESSAGE_BODY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-static", f"v2, {RUNTIME_EXEC_REF}"),
                        ],
                        registers=3,
                    )
                ],
            )
        ]
    )


def exec_dex():
    """Runtime.exec only (command execution, no root probe)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Exec;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "run",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "ls -la"', "ls -la"),
                            _inst("invoke-static", f"v1, {RUNTIME_EXEC_REF}"),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def root_probe_dex():
    """su string + Runtime.exec co-located, plus a lone su string elsewhere."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/RootProbe;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "probe",
                        "()Z",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SU_PATH}"', SU_PATH),
                            _inst("invoke-static", f"v1, {RUNTIME_EXEC_REF}"),
                            _inst("move-result-object", "v0"),
                            _inst("return-object", "v0"),
                        ],
                        registers=2,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Watcher;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "stash",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SU_PATH}"', SU_PATH),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            ),
        ]
    )


def emulator_probe_dex():
    """goldfish sentinel + Build field + Runtime co-located, plus lone sentinel."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/EmuProbe;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "probe",
                        "()Z",
                        "public",
                        [
                            _inst("const-string", f'v1, "{GOLDFISH}"', GOLDFISH),
                            _inst("sget-object", f"v2, {BUILD_FINGERPRINT_REF}"),
                            _inst("invoke-static", f"v0, {RUNTIME_GETRUNTIME_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst("return-object", "v3"),
                        ],
                        registers=4,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Watcher;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "stash",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{GOLDFISH}"', GOLDFISH),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            ),
        ]
    )


def dynamic_load_dex():
    """Network fetch + DexClassLoader co-located (downloaded code)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/RemoteLoader;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "load",
                        "()V",
                        "public",
                        [
                            _inst("new-instance", "v0, Ljava/net/URL;"),
                            _inst("invoke-static", f"v0, {HTTP_FETCH_REF}"),
                            _inst("move-result-object", "v1"),
                            _inst("const-string", f'v2, "/data/local/tmp/payload.dex"', "/data/local/tmp/payload.dex"),
                            _inst("new-instance", "v3, Ldalvik/system/DexClassLoader;"),
                            _inst("return-void", ""),
                        ],
                        registers=4,
                    )
                ],
            )
        ]
    )


def network_only_dex():
    """Network fetch in one method; DexClassLoader in another (no link)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Fetch;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "fetch",
                        "()V",
                        "public",
                        [
                            _inst("new-instance", "v0, Ljava/net/URL;"),
                            _inst("invoke-static", f"v0, {HTTP_FETCH_REF}"),
                            _inst("return-void", ""),
                        ],
                        registers=1,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Loader;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "load",
                        "()V",
                        "public",
                        [
                            _inst("new-instance", "v1, Ldalvik/system/DexClassLoader;"),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            ),
        ]
    )


def crypto_dex():
    """Cipher.init with const 0x1 (ENCRYPT) and 0x2 (DECRYPT) + doFinal."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Crypto;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "encrypt",
                        "([B)[B",
                        "public",
                        [
                            _inst("const/16", "v1, 0x1"),
                            _inst("invoke-static", f"v0, v1, {CIPHER_INIT_REF}"),
                            _inst("invoke-static", "v2, Ljavax/crypto/Cipher;->doFinal([B)[B"),
                            _inst("move-result-object", "v3"),
                            _inst("return-object", "v3"),
                        ],
                        registers=4,
                    ),
                    _method(
                        "decrypt",
                        "([B)[B",
                        "public",
                        [
                            _inst("const/16", "v1, 0x2"),
                            _inst("invoke-static", f"v0, v1, {CIPHER_INIT_REF}"),
                            _inst("return-object", "v0"),
                        ],
                        registers=3,
                    ),
                ],
            )
        ]
    )


def crypto_undirected_dex():
    """Cipher.init present but no 0x1/0x2 const literal observed."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/VagueCrypto;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "go",
                        "()V",
                        "public",
                        [
                            _inst("invoke-static", f"v0, {CIPHER_INIT_REF}"),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def giant_method_dex():
    """A single method with 2001 instructions (control-flow flattening)."""
    body = [_inst("const/4", "v0, 0x0"), _inst("return-void", "")]
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Giant;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "blob",
                        "()V",
                        "public",
                        [_inst("const/4", "v0, 0x1")] * 2001 + body,
                        registers=1,
                    )
                ],
            )
        ]
    )


def contacts_dex():
    """ContactsContract query + contacts content-URI string."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/ContactsReader;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "read",
                        "()V",
                        "public",
                        [
                            _inst(
                                "const-string",
                                'v1, "content://com.android.contacts"',
                                "content://com.android.contacts",
                            ),
                            _inst(
                                "invoke-static",
                                "v0, v1, Landroid/provider/ContactsContract$Contacts;->query()V",
                            ),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def su_string_only_dex():
    """su sentinel string present with no exec call (root probe UNKNOWN)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Probe;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "stash",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SU_PATH}"', SU_PATH),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def emulator_string_only_dex():
    """goldfish sentinel present with no runtime check (emulator UNKNOWN)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Probe;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "stash",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{GOLDFISH}"', GOLDFISH),
                            _inst("return-void", ""),
                        ],
                        registers=2,
                    )
                ],
            )
        ]
    )


def anti_analysis_dex():
    """Root probe (co-located su+exec) plus a giant flattened method."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/RootProbe;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "probe",
                        "()Z",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SU_PATH}"', SU_PATH),
                            _inst("invoke-static", f"v1, {RUNTIME_EXEC_REF}"),
                            _inst("move-result-object", "v0"),
                            _inst("return-object", "v0"),
                        ],
                        registers=2,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Giant;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "blob",
                        "()V",
                        "public",
                        [_inst("const/4", "v0, 0x1")] * 2001 + [
                            _inst("const/4", "v0, 0x0"),
                            _inst("return-void", ""),
                        ],
                        registers=1,
                    )
                ],
            ),
        ]
    )