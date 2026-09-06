"""Unit tests for the deterministic Smali renderer and reference extraction."""

from re_engine.reconstruct.smali import (
    extract_references,
    render_class_smali,
    render_method_smali,
)
from re_engine.tests.reconstruct.fixtures import build_dex, send_mid
from re_engine.tests.triage.fixtures import FakeInstruction


def send_method():
    dex = build_dex()
    for cls in dex.get_classes():
        if cls.get_name() == "Lcom/evil/Payload;":
            for method in cls.get_methods():
                if method.get_name() == "send":
                    return method
    raise AssertionError("send method not found")


def test_render_method_smali_structure():
    source = render_method_smali(send_method())
    lines = source.splitlines()
    assert lines[0] == ".method public send(Ljava/lang/String;)Z"
    assert any(line.strip() == ".registers 2" for line in lines)
    assert "    invoke-direct v0, Ljava/lang/String;->getBytes()([B)[B" in lines
    assert '    const-string v0, "https://c2.example.com/beacon"' in lines
    assert lines[-1] == ".end method"


def test_render_method_smali_without_registers():
    class Bare:
        def get_access_flags_string(self):
            return "static"

        def get_name(self):
            return "noCode"

        def get_descriptor(self):
            return "()V"

        def get_code(self):
            return None

    source = render_method_smali(Bare())
    assert ".method static noCode()V" in source
    assert ".registers" not in source
    assert ".end method" in source


def test_extract_references_all_categories():
    refs = extract_references(send_method())
    assert "Ljava/lang/String;->getBytes()([B)[B" in refs["calls"]
    assert "Ljava/lang/Object;-><init>" not in refs["calls"]
    assert refs["strings"] == ["https://c2.example.com/beacon"]
    assert "Lcom/evil/Payload;" in refs["classes"]
    assert any("Lcom/evil/Payload;->CRYPT" in field for field in refs["fields"])


def test_extract_references_falls_back_to_output_text():
    from re_engine.tests.triage.fixtures import FakeMethod

    class Odd:
        def get_name(self):
            return "const-string"

        def get_output(self):
            return 'v0, "hardcoded-secret"'

        def get_string(self):
            raise AttributeError("not available")

        def __str__(self):
            return 'const-string v0, "hardcoded-secret"'

    refs = extract_references(FakeMethod("x", "()V", "public", [Odd()]))
    assert refs["strings"] == ["hardcoded-secret"]


def test_render_class_smali():
    dex = build_dex()
    cls = next(c for c in dex.get_classes() if c.get_name() == "Lcom/evil/Main;")
    source = render_class_smali(cls)
    assert ".class Lcom/evil/Main;" in source
    assert ".super Landroid/app/Activity;" in source
    assert ".implements Landroid/view/View$OnClickListener;" in source
    assert ".method protected onCreate(Landroid/os/Bundle;)V" in source
    assert ".field KEY:Ljava/lang/String;" in render_class_smali(
        next(c for c in dex.get_classes() if c.get_name() == "Lcom/evil/Payload;")
    )


def test_capped_references():
    many = [
        FakeInstruction("invoke-direct", f"v0, Lcom/x/C;->m{i}()V")
        for i in range(300)
    ]
    from re_engine.tests.triage.fixtures import FakeMethod

    method = FakeMethod("bulk", "()V", "public", many)
    refs = extract_references(method, ref_cap=50)
    assert len(refs["calls"]) == 50