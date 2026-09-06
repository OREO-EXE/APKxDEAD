"""Hermetic fixtures for source-to-sink data-flow tests.

Synthetic Smali scenarios (via the triage fakes -- methods as tuples) that
exercise intraprocedural flows, cross-method parameter/return flows, field
hops, callback capture, and the no-evidence case so the data-flow engine is
fully testable without androguard.
"""

from __future__ import annotations

from re_engine.tests.triage.fixtures import FakeDex, FakeDexClass, FakeInstruction

SMS_URI = "content://sms/inbox"
CALL_LOG_URI = "content://call_log/calls"
QUERY_REF = (
    "Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;"
    "Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
)
CURSOR_GET_REF = "Landroid/database/Cursor;->getString(I)Ljava/lang/String;"
BASE64_REF = "Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;"
HTTP_EXEC_REF = (
    "Lorg/apache/http/impl/client/DefaultHttpClient;->execute"
    "(Lorg/apache/http/client/methods/HttpGet;)Lorg/apache/http/client/methods/HttpUriRequest;"
)
RUNTIME_EXEC_REF = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"


def _inst(name, output, string=None):
    return FakeInstruction(name, output, string=string)


def _method(name, descriptor, access, instructions, registers=8):
    return (name, descriptor, access, instructions, registers)


def sms_exfil_dex():
    """A single method: SMS source -> base64 -> HTTP sink (CONFIRMED)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Main;",
                "Landroid/app/Activity;",
                [],
                [],
                [
                    _method(
                        "onCreate",
                        "(Landroid/os/Bundle;)V",
                        "protected",
                        [
                            _inst("const-string", f'v1, "{SMS_URI}"', SMS_URI),
                            _inst("invoke-virtual", f"v0, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst("invoke-static", f"v3, {BASE64_REF}"),
                            _inst("move-result-object", "v4"),
                            _inst("invoke-static", f"v4, {HTTP_EXEC_REF}"),
                        ],
                        registers=5,
                    )
                ],
            )
        ]
    )


def cross_param_dex():
    """Collector passes tainted SMS data into Leak.leak(String) -> HTTP sink.

    Expect one PROBABLE ``sms -> http`` (and ``content_query -> http``) with
    the path spanning collector -> leak.
    """
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Collect;",
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
                            _inst("invoke-virtual", f"v0, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst(
                                "invoke-static",
                                f"v3, Lcom/app/Leak;->leak(Ljava/lang/String;)V",
                            ),
                        ],
                        registers=4,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Leak;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "leak",
                        "(Ljava/lang/String;)V",
                        "public",
                        [
                            # 1 param at registers=5 -> register index 4
                            _inst("invoke-static", f"v4, {HTTP_EXEC_REF}"),
                        ],
                        registers=5,
                    )
                ],
            ),
        ]
    )


def call_log_return_dex():
    """CallLog source in CallLogSource.get() returned to a caller that sinks."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/CallLogSource;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "get",
                        "()Ljava/lang/String;",
                        "public",
                        [
                            _inst(
                                "const-string", f'v1, "{CALL_LOG_URI}"', CALL_LOG_URI
                            ),
                            _inst("invoke-virtual", f"v0, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst("return-object", "v3"),
                        ],
                        registers=5,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/CallLogSink;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "go",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-static",
                                "v0, Lcom/app/CallLogSource;->get()Ljava/lang/String;",
                            ),
                            _inst("move-result-object", "v1"),
                            _inst("invoke-static", f"v1, {RUNTIME_EXEC_REF}"),
                        ],
                        registers=3,
                    )
                ],
            ),
        ]
    )


def field_hop_dex():
    """Writer stores a tainted value into a field; a second method reads and sinks."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Hop;",
                "Ljava/lang/Object;",
                [],
                [("stash", "Ljava/lang/String;")],
                [
                    _method(
                        "collect",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SMS_URI}"', SMS_URI),
                            _inst("invoke-virtual", f"v0, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst(
                                "iput-object",
                                "v3, v4, Lcom/app/Hop;->stash Ljava/lang/String;",
                            ),
                        ],
                        registers=5,
                    ),
                    _method(
                        "flush",
                        "()V",
                        "public",
                        [
                            _inst(
                                "iget-object",
                                "v5, v4, Lcom/app/Hop;->stash Ljava/lang/String;",
                            ),
                            _inst("invoke-static", f"v5, {HTTP_EXEC_REF}"),
                        ],
                        registers=6,
                    ),
                ],
            )
        ]
    )


def callback_capture_dex():
    """register() posts a Runnable whose field was set with tainted data; its
    run() reads that field and logs it (callback capture via instance field)."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/Register;",
                "Ljava/lang/Object;",
                [],
                [("buf", "Ljava/lang/String;")],
                [
                    _method(
                        "register",
                        "()V",
                        "public",
                        [
                            _inst("new-instance", "v0, Lcom/app/Leaker;"),
                            _inst("invoke-direct", "v0, Lcom/app/Leaker;-><init>()V"),
                            _inst(
                                "const-string", f'v1, "{CALL_LOG_URI}"', CALL_LOG_URI
                            ),
                            _inst("invoke-virtual", f"v2, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst(
                                "iput-object",
                                "v3, v0, Lcom/app/Leaker;->buf Ljava/lang/String;",
                            ),
                            _inst(
                                "invoke-virtual",
                                "v0, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z",
                            ),
                        ],
                        registers=4,
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Leaker;",
                "Ljava/lang/Runnable;",
                [],
                [("buf", "Ljava/lang/String;")],
                [
                    _method(
                        "run",
                        "()V",
                        "public",
                        [
                            _inst(
                                "iget-object",
                                "v6, v7, Lcom/app/Leaker;->buf Ljava/lang/String;",
                            ),
                            _inst(
                                "invoke-static",
                                "v6, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
                            ),
                        ],
                        registers=8,
                    )
                ],
            ),
        ]
    )


def no_flow_dex():
    """SMS source API and an HTTP sink API both appear, never connected."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/NoFlow;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "grab",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'v1, "{SMS_URI}"', SMS_URI),
                            _inst("invoke-virtual", f"v0, v1, {QUERY_REF}"),
                            _inst("move-result-object", "v2"),
                            _inst("invoke-interface", f"v2, {CURSOR_GET_REF}"),
                            _inst("move-result-object", "v3"),
                            _inst("return-object", "v3"),
                        ],
                        registers=5,
                    ),
                    _method(
                        "post",
                        "(Ljava/lang/String;)V",
                        "public",
                        [
                            _inst("invoke-static", f"v1, {HTTP_EXEC_REF}"),
                        ],
                        registers=4,
                    ),
                ],
            )
        ]
    )