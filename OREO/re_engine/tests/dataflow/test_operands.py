"""Operands: instruction/operand normalization for taint parsing."""

from __future__ import annotations

from re_engine.dataflow.operands import (
    extract_refs,
    instruction_info,
    operand_kind,
    registers_in,
    split_ref,
)
from re_engine.tests.triage.fixtures import FakeInstruction


def _info(output, name="invoke-static", string=None):
    return instruction_info(FakeInstruction(name, output, string=string))


# ---------------------------------------------------------------------------
# Registers first (real androguard output layout)
# ---------------------------------------------------------------------------


def test_invoke_registers_first():
    name, ops = _info("v0, v1, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;", "invoke-virtual")
    assert name == "invoke-virtual"
    assert ops[0] == "v0"
    assert ops[1] == "v1"
    ref = ops[2]
    assert ref.startswith("Landroid/content/ContentResolver;->query")
    assert operand_kind(ops[0]) == "reg"
    assert operand_kind(ref) == "ref"


def test_range_invoke():
    name, ops = _info("v0 ... v5, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;", "invoke-static/range")
    assert name == "invoke-static/range"
    assert registers_in(ops) == ["v0", "v5"]


def test_const_string_output_preferred_over_str():
    ins = FakeInstruction("const-string", 'v2, "_"', "_")
    name, ops = instruction_info(ins)
    assert name == "const-string"
    assert ops == ["v2", '"_"']
    assert operand_kind(ops[1]) == "string"


def test_field_ref_registers_first():
    name, ops = _info("v1, v0, Landroidx/core/app/RemoteActionCompat;->mIcon Landroidx/core/graphics/drawable/IconCompat;", "iput-object")
    assert name == "iput-object"
    assert registers_in(ops) == ["v1", "v0"]
    ref = extract_refs(ops)
    assert len(ref) == 1
    assert ref[0].startswith("Landroidx/core/app/RemoteActionCompat;->mIcon")
    assert operand_kind(ref[0]) == "ref"


# ---------------------------------------------------------------------------
# Reference first (synthetic fixture layout)
# ---------------------------------------------------------------------------


def test_invoke_ref_first():
    name, ops = _info("Lcom/app/Notify;->onNotify()V, v0", "invoke-virtual")
    assert name == "invoke-virtual"
    assert registers_in(ops) == ["v0"]
    assert extract_refs(ops) == ["Lcom/app/Notify;->onNotify()V"]


# ---------------------------------------------------------------------------
# Comma inside descriptor must not split
# ---------------------------------------------------------------------------


def test_descriptor_internal_commas_merge():
    name, ops = _info(
        "v0, Landroid/os/IBinder;->transact(I Landroid/os/Parcel; Landroid/os/Parcel; I)Z"
    )
    assert len(ops) == 2
    ref = ops[1]
    assert ref == "Landroid/os/IBinder;->transact(I Landroid/os/Parcel; Landroid/os/Parcel; I)Z"
    cls, mname, sig = split_ref(ref)
    assert cls == "Landroid/os/IBinder;"
    assert mname == "transact"
    assert sig == "(I Landroid/os/Parcel; Landroid/os/Parcel; I)Z"


# ---------------------------------------------------------------------------
# split_ref
# ---------------------------------------------------------------------------


def test_split_ref_basic():
    assert split_ref("Lcom/app/Main;->onCreate(Landroid/os/Bundle;)V") == (
        "Lcom/app/Main;",
        "onCreate",
        "(Landroid/os/Bundle;)V",
    )


def test_split_ref_field_entry():
    assert split_ref("Lcom/app/Holder;->data Ljava/lang/String;") == (
        "Lcom/app/Holder;",
        "data",
        "Ljava/lang/String;",
    )


def test_split_ref_no_signature():
    assert split_ref("Lcom/app/Main;->onCreate") == ("Lcom/app/Main;", "onCreate", "")


def test_split_ref_non_ref():
    assert split_ref("v3") == ("v3", "", "")


# ---------------------------------------------------------------------------
# Operand classification
# ---------------------------------------------------------------------------


def test_kinds():
    assert operand_kind("v0") == "reg"
    assert operand_kind("p2") == "reg"
    assert operand_kind("v0 ... v5") == "reg"
    assert operand_kind('"content://sms/inbox"') == "string"
    assert operand_kind("42") == "int"
    assert operand_kind("0x1f") == "int"
    assert operand_kind("Lx;->foo()V") == "ref"
    assert operand_kind("junk") == "other"