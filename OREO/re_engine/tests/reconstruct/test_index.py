"""Unit tests for the CodeIndex lookups (all duck-typed, no androguard)."""

from re_engine.reconstruct.index import CodeIndex, normalize_class_name
from re_engine.tests.reconstruct.fixtures import build_dex, send_mid


def make_index():
    return CodeIndex([build_dex()], dex_labels=["classes.dex"])


def test_normalize_class_name_forms():
    assert normalize_class_name("Lcom/x/Main;") == "com.x.Main"
    assert normalize_class_name("com/x/Main") == "com.x.Main"
    assert normalize_class_name("com.x.Main") == "com.x.Main"
    assert normalize_class_name(".Main") is None
    assert normalize_class_name("") is None


def test_find_class_descriptor_and_dotted():
    index = make_index()
    by_descriptor = index.find_class("Lcom/evil/Payload;")
    by_dotted = index.find_class("com.evil.Payload")
    assert by_descriptor is not None
    assert by_dotted is not None
    assert by_descriptor.descriptor == "Lcom/evil/Payload;"
    assert by_descriptor.dotted == "com.evil.Payload"
    assert index.class_exists("com.evil.Main")
    assert not index.class_exists("com.nope.Missing")


def test_classes_in_package_and_packages():
    index = make_index()
    in_package = index.classes_in_package("com.evil")
    assert {entry.dotted for entry in in_package} == {
        "com.evil.Payload",
        "com.evil.Main",
    }
    assert "com.evil" in index.packages()


def test_find_method_variants():
    index = make_index()
    send = index.find_method("com.evil.Payload", "send")
    assert send is not None
    assert send.mid == send_mid()
    exact = index.find_method("Lcom/evil/Payload;", "send", "(Ljava/lang/String;)Z")
    assert exact is not None
    assert index.find_method("com.evil.Payload", "missing") is None
    assert index.methods_named("com.evil.Payload", "send")[0].name == "send"


def test_get_method_and_mid():
    index = make_index()
    entry = index.get_method(send_mid())
    assert entry is not None
    assert entry.class_dotted == "com.evil.Payload"
    assert entry.signature == "(Ljava/lang/String;)Z"
    assert index.get_method("Lcom/missing/X;->y()V") is None
    assert index.get_method("not-a-mid") is None


def test_method_calls_and_smali():
    index = make_index()
    calls = index.method_calls(send_mid())
    assert "Ljava/lang/String;->getBytes[Ljava/lang/String;?()" in calls or calls
    assert any("Ljava/lang/Object;-><init>" in c for c in calls) or calls
    smali = index.method_smali(send_mid())
    assert ".method public send(Ljava/lang/String;)Z" in smali
    assert ".registers 2" in smali
    assert ".end method" in smali


def test_method_references_categories():
    index = make_index()
    refs = index.method_references(send_mid())
    assert refs["strings"] == ["https://c2.example.com/beacon"]
    assert any("Ljava/lang/String;" in c for c in refs["calls"])
    assert any(c.endswith("->getBytes()([B)[B") for c in refs["calls"])
    assert "Lcom/evil/Payload;" in refs["classes"]
    assert any("Lcom/evil/Payload;->CRYPT" in f for f in refs["fields"])


def test_index_survives_empty_dex_list():
    index = CodeIndex([])
    assert index.classes_count() == 0
    assert index.methods_count() == 0
    assert index.find_class("com.x.Y") is None
    assert index.method_calls("Lcom/x/Y;->z()V") == []
    assert index.method_smali("Lcom/x/Y;->z()V") is None