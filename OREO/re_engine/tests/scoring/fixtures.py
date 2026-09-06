"""Hermetic fixtures for the scoring subsystem (no androguard needed)."""

from __future__ import annotations

from re_engine.models.context import AnalysisContext, Component
from re_engine.tests.triage.fixtures import (
    FakeDex,
    FakeDexClass,
    FakeInstruction,
)

C2_URL = "https://c2.example.com/beacon"
C2_IP = "10.0.0.5"
C2_DOMAIN = "c2.example.com"
SHELL_CMD = "/system/bin/sh -c id"
ENCODED = "aHVza2VkLmJhc2U2NA=="

SMS_SEND = (
    "Landroid/telephony/SmsManager;->sendTextMessage("
    "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
    "Landroid/app/PendingIntent;)V"
)
SMS_GET_DEFAULT = (
    "Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;"
)
SMS_MESSAGE = (
    "Landroid/telephony/SmsMessage;->createFromPdu([B)"
    "Landroid/telephony/SmsMessage;"
)
HTTP_CONNECT = "Ljava/net/HttpURLConnection;->connect()V"
SSL_DEFAULT = "Ljavax/net/ssl/SSLSocketFactory;->getDefault()Ljavax/net/ssl/SSLSocketFactory;"
CIPHER_INSTANCE = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
REFLECT_INVOKE = (
    "Ljava/lang/reflect/Method;->invoke("
    "Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"
)
RUNTIME_EXEC = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
TOAST_MAKE = (
    "Landroid/widget/Toast;->makeText("
    "Landroid/content/Context;Ljava/lang/CharSequence;I)"
    "Landroid/widget/Toast;"
)


def ins(name, out, string=None):
    return FakeInstruction(name, out, string)


STEAL_RECEIVER_CLASS = "Lcom/evil/x7g83/StealReceiver;"
SPY_SERVICE_CLASS = "Lcom/evil/x7g83/SpyService;"
BENIGN_CLASS = "Lcom/example/hello/MainActivity;"

STEAL_RECEIVER_NAME = "com.evil.x7g83.StealReceiver"
SPY_SERVICE_NAME = "com.evil.x7g83.SpyService"
BENIGN_NAME = "com.example.hello.MainActivity"


def build_malicious_dex() -> FakeDex:
    boot = FakeDexClass(
        STEAL_RECEIVER_CLASS,
        "Landroid/content/BroadcastReceiver;",
        [],
        [],
        [
            (
                "onReceive",
                "(Landroid/content/Context;Landroid/content/Intent;)V",
                "public",
                [
                    ins(
                        "invoke-direct",
                        "v0, Lcom/evil/x7g83/StealReceiver;->handleSms()V",
                    ),
                    ins(
                        "const-string",
                        f'v0, "{C2_URL}"',
                        string=C2_URL,
                    ),
                ],
            ),
            (
                "handleSms",
                "()V",
                "private",
                [
                    ins("invoke-static", f"v0, {SMS_GET_DEFAULT}"),
                    ins("invoke-direct", f"v0, {SMS_MESSAGE}"),
                    ins("invoke-static", f"v0, {SMS_SEND}"),
                    ins("const-string", f'v0, "{C2_IP}"', string=C2_IP),
                ],
            ),
        ],
    )
    service = FakeDexClass(
        SPY_SERVICE_CLASS,
        "Landroid/app/Service;",
        [],
        [],
        [
            (
                "doExfil",
                "(Ljava/lang/String;)V",
                "public",
                [
                    ins("invoke-virtual", f"v0, {HTTP_CONNECT}"),
                    ins("invoke-static", f"v0, {SSL_DEFAULT}"),
                    ins("invoke-static", f"v0, {CIPHER_INSTANCE}"),
                    ins("invoke-virtual", f"v0, {REFLECT_INVOKE}"),
                    ins("invoke-static", f"v0, {RUNTIME_EXEC}"),
                    ins(
                        "const-string",
                        'v0, "https://cdn.example.net/p"',
                        string="https://cdn.example.net/p",
                    ),
                ],
            ),
        ],
    )
    benign = FakeDexClass(
        BENIGN_CLASS,
        "Landroid/app/Activity;",
        [],
        [],
        [
            (
                "onCreate",
                "(Landroid/os/Bundle;)V",
                "protected",
                [ins("invoke-static", f"v0, {TOAST_MAKE}")],
            )
        ],
    )
    return FakeDex([boot, service, benign])


def build_benign_dex() -> FakeDex:
    benign = FakeDexClass(
        BENIGN_CLASS,
        "Landroid/app/Activity;",
        [],
        [],
        [
            (
                "onCreate",
                "(Landroid/os/Bundle;)V",
                "protected",
                [ins("invoke-static", f"v0, {TOAST_MAKE}")],
            )
        ],
    )
    return FakeDex([benign])


class FakeApkAccessor:
    def __init__(self, dex):
        self.dex = [dex]

    def close(self):
        pass


def malicious_context() -> AnalysisContext:
    context = AnalysisContext()
    context.artifacts = FakeApkAccessor(build_malicious_dex())
    context.permissions = [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ]
    context.components = [
        Component(name=STEAL_RECEIVER_NAME, kind="receiver", exported=True),
        Component(name=SPY_SERVICE_NAME, kind="service", exported=False),
    ]
    context.boot_receivers = [STEAL_RECEIVER_NAME]
    context.foreground_services = [SPY_SERVICE_NAME]
    context.urls = [C2_URL]
    context.domains = [C2_DOMAIN]
    context.ips = [C2_IP]
    context.encoded_strings = [ENCODED]
    context.shell_commands = [SHELL_CMD]
    return context


def benign_context() -> AnalysisContext:
    context = AnalysisContext()
    context.artifacts = FakeApkAccessor(build_benign_dex())
    context.permissions = ["android.permission.INTERNET"]
    context.components = [
        Component(name=BENIGN_NAME, kind="activity", exported=False)
    ]
    return context


HANDLE_SMS_MID = f"{STEAL_RECEIVER_CLASS}->handleSms()V"
DO_EXFIL_MID = f"{SPY_SERVICE_CLASS}->doExfil(Ljava/lang/String;)V"