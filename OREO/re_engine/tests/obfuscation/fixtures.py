"""Deterministic fixtures for the obfuscation analyzer tests.

Every scenario is built from the shared triage fakes (no androguard) so the
analyzer is unit-testable and the anti-overclaim rules are exercised without
real DEX content.
"""

from __future__ import annotations

from re_engine.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.tests.triage.fixtures import (
    FakeDex,
    FakeDexClass,
    FakeInstruction,
)


class FakeArtifacts:
    """Minimal stand-in exposing the ``dex`` surface the analyzer reads."""

    def __init__(self, dex):
        self.dex = list(dex)


def inst(name, output="", string=None):
    """One FakeInstruction with an optional literal."""
    return FakeInstruction(name, output, string)


def call(target):
    """An invoke instruction targeting ``target`` (raw reference)."""
    return inst("invoke-direct", target)


def const(string_value):
    """A const-string instruction carrying ``string_value``."""
    return inst("const-string", f'"{string_value}"', string=string_value)


def cls(descriptor, methods):
    """A FakeDexClass with ``methods`` as (name, desc, [instructions])."""
    fake_methods = [
        (name, desc, "public", list(instrs))
        for name, desc, instrs in methods
    ]
    return FakeDexClass(
        descriptor, "Ljava/lang/Object;", [], [], fake_methods
    )


def run_analyzer(
    classes,
    strings=None,
    encoded_strings=None,
    urls=None,
):
    """Run the analyzer over synthetic DEX classes and return the context."""
    ctx = AnalysisContext()
    ctx.artifacts = FakeArtifacts([FakeDex(classes)])
    ctx.strings = list(strings or [])
    ctx.encoded_strings = list(encoded_strings or [])
    ctx.urls = list(urls or [])
    ObfuscationAnalyzer().run(ctx)
    return ctx


def finding_of(ctx, find_type):
    """The first finding of ``find_type`` (or None)."""
    for finding in ctx.obfuscation:
        if finding.type.value == find_type:
            return finding
    return None


# ---------------------------------------------------------------------------
# Ready-made scenarios
# ---------------------------------------------------------------------------

REFERENCE_CLASS = "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"
FOR_NAME = "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
BASE64_DECODE = "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B"
RUNTIME_EXEC = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
DEX_CLASS_LOADER = (
    "Ldalvik/system/DexClassLoader;->"
    "<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"
)


def identifier_dex():
    """Ten classes/methods with aggressively short, collapsed names."""
    classes = []
    for letter in "abcdefghij":
        classes.append(
            cls(
                f"Lk/{letter};",
                [
                    (letter, "()V", [inst("return-void", "")]),
                ],
            )
        )
    return classes


def clean_dex():
    """One class with normal, descriptive names (anti-claim control)."""
    return [
        cls(
            "Lcom/example/triage/MainActivity;",
            [
                (
                    "authenticate",
                    "()V",
                    [inst("return-void", "v0")],
                ),
                (
                    "verifySignature",
                    "()Z",
                    [inst("return-object", "v0")],
                ),
            ],
        )
    ]


def string_obfuscation_dex():
    """A method that decodes an encoded literal at runtime."""
    token = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
    return [
        cls(
            "Lcom/example/cfg/Decoder;",
            [
                (
                    "loadPayload",
                    "()Ljava/lang/String;",
                    [
                        const(token),
                        call(BASE64_DECODE),
                        inst("return-object", "v0"),
                    ],
                ),
            ],
        )
    ]


def encoded_literal_heavy_dex():
    """Many literals, well over half encoded-looking (raw scan absent)."""
    methods = []
    for index in range(10):
        methods.append(
            (
                f"step{index}",
                "()Ljava/lang/String;",
                [
                    const("A" * 40 + f"{index}"),
                    const(f"segment{index}"),
                ],
            )
        )
    return [
        cls(
            "Lcom/example/cfg/Segments;",
            methods,
        ),
    ]


def reflection_dex():
    """Two methods, one doing Class.forName + Method.invoke dispatch."""
    return [
        cls(
            "Lcom/example/cfg/Resolver;",
            [
                (
                    "resolve",
                    "()V",
                    [
                        const("com.example.Hidden"),
                        call(FOR_NAME),
                        call(REFERENCE_CLASS),
                        inst("return-void", ""),
                    ],
                ),
                (
                    "normal",
                    "()V",
                    [
                        call("Ljava/lang/String;->length()I"),
                        inst("return-void", ""),
                    ],
                ),
            ],
        )
    ]


def dynamic_loading_dex():
    """DexClassLoader construction plus runtime native-library loading."""
    return [
        cls(
            "Lcom/example/cfg/Loader;",
            [
                (
                    "init",
                    "()V",
                    [
                        call(DEX_CLASS_LOADER),
                        call("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
                        inst("return-void", ""),
                    ],
                ),
            ],
        )
    ]


def runtime_exec_dex():
    """Runtime.exec with a shell command string co-referenced."""
    return [
        cls(
            "Lcom/example/cfg/Spawner;",
            [
                (
                    "spawn",
                    "()V",
                    [
                        const("/system/bin/sh -c id"),
                        call(RUNTIME_EXEC),
                        inst("return-void", ""),
                    ],
                ),
            ],
        )
    ]


def anti_analysis_dex(tokens):
    """A class whose literals carry the given anti-analysis tokens."""
    literals = [const(token) for token in tokens]
    return [
        cls(
            "Lcom/example/cfg/Probe;",
            [
                ("probe", "()V", literals + [inst("return-void", "")]),
            ],
        )
    ]


def control_flow_dex():
    """Ten methods with packed-switch heavy bodies (flattened dispatch)."""
    classes = []
    for index in range(10):
        classes.append(
            cls(
                f"Lcom/example/cfg/Switch{index};",
                [
                    (
                        f"dispatch{index}",
                        "()V",
                        [
                            inst("packed-switch", f".., :label{index}"),
                            inst("packed-switch", f".., :alt{index}"),
                            inst("return-void", ""),
                        ],
                    ),
                ],
            )
        )
    return classes


def mixed_dex():
    """Combines several techniques for determinism/bounds assertions."""
    return identifier_dex() + reflection_dex() + runtime_exec_dex()