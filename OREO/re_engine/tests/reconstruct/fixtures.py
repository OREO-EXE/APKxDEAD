"""Hermetic fixtures for the reconstruct subsystem tests.

Reuses the duck-typed androguard fakes from the triage fixtures so every
reconstruction test runs without androguard.
"""

from __future__ import annotations

from re_engine.models.context import AnalysisContext, Component
from re_engine.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.tests.triage.fixtures import (
    FakeDex,
    FakeDexClass,
    FakeInstruction,
)

INVOKE_OBJECT_INIT = FakeInstruction(
    "invoke-direct", "v0, Ljava/lang/Object;-><init>()V"
)
CALL_SEND = FakeInstruction(
    "invoke-static", "v0, Lcom/evil/Payload;->send(Ljava/lang/String;)Z"
)
GET_BYTES = FakeInstruction(
    "invoke-direct", "v0, Ljava/lang/String;->getBytes()([B)[B"
)
BEACON_STRING = FakeInstruction(
    "const-string",
    'v0, "https://c2.example.com/beacon"',
    string="https://c2.example.com/beacon",
)
NEW_PAYLOAD = FakeInstruction("new-instance", "v0, Lcom/evil/Payload;")
CONST_CLASS = FakeInstruction("const-class", "v0, Lcom/evil/Payload;")
SGET_CRYPT = FakeInstruction(
    "sget-object", "v0, Lcom/evil/Payload;->CRYPT Ljava/lang/String;"
)


def build_dex() -> FakeDex:
    payload = FakeDexClass(
        "Lcom/evil/Payload;",
        "Ljava/lang/Object;",
        [],
        [("KEY", "Ljava/lang/String;")],
        [
            ("<init>", "()V", "public constructor", [INVOKE_OBJECT_INIT]),
            (
                "send",
                "(Ljava/lang/String;)Z",
                "public",
                [GET_BYTES, BEACON_STRING, NEW_PAYLOAD, SGET_CRYPT],
            ),
            (
                "callGraphTest",
                "(I)V",
                "private",
                [CALL_SEND, FakeInstruction("return-void", "")],
            ),
        ],
    )
    main = FakeDexClass(
        "Lcom/evil/Main;",
        "Landroid/app/Activity;",
        ["Landroid/view/View$OnClickListener;"],
        [],
        [
            (
                "onCreate",
                "(Landroid/os/Bundle;)V",
                "protected",
                [CALL_SEND],
            )
        ],
    )
    return FakeDex([payload, main])


class FakeApkAccessor:
    """Minimal accessor surface consumed by the reconstructor (only .dex)."""

    def __init__(self, dex):
        self.dex = [dex]

    def close(self):
        pass


def fake_context(dex: FakeDex | None = None):
    dex = dex or build_dex()
    context = AnalysisContext()
    context.artifacts = FakeApkAccessor(dex)
    context.components = [
        Component(name="com.evil.Main", kind="activity", exported=True)
    ]
    context.add_finding(
        Finding(
            category=FindingCategory.API,
            title="API reach",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            class_name="com.evil.Payload",
            method_name="send",
            analyzer="test",
        )
    )
    return context


def send_mid() -> str:
    return "Lcom/evil/Payload;->send(Ljava/lang/String;)Z"