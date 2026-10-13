"""Tests for the AXML decoder and values-free shape inference."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnirecon import axml  # noqa: E402
from omnirecon.browser_engine import infer_shape  # noqa: E402
from omnirecon import api_intel as AI  # noqa: E402


def _build_axml():
    strs = ["manifest", "package", "com.example.bankapp", "uses-permission",
            "name", "android.permission.INTERNET", "activity", "uses-sdk",
            "minSdkVersion", "android",
            "http://schemas.android.com/apk/res/android"]
    SI = {s: i for i, s in enumerate(strs)}
    AND = SI["http://schemas.android.com/apk/res/android"]

    def enc_u16(s):
        return struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"

    pool_data = b"".join(enc_u16(s) for s in strs)
    offsets, pos = [], 0
    for s in strs:
        offsets.append(pos)
        pos += 2 + len(s.encode("utf-16-le")) + 2
    ss = 8 + 20 + len(strs) * 4
    pool = struct.pack("<HHI", 0x0001, 28, 0)
    pool += struct.pack("<IIIII", len(strs), 0, 0, ss, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + pool_data
    while len(pool) % 4:
        pool += b"\x00"
    pool = pool[:4] + struct.pack("<I", len(pool)) + pool[8:]

    def el_start(name_idx, attrs):
        n = len(attrs)
        h = struct.pack("<HHI", 0x0102, 32, 32 + n * 20)
        h += struct.pack("<III", 1, 0xFFFFFFFF, name_idx)
        h += struct.pack("<HHHHHH", 32, 20, n, 0, 0, 0)
        for (ns, nm, dt, dv) in attrs:
            h += struct.pack("<IIIHBBI", ns, nm, 0xFFFFFFFF, 8, 0, dt, dv)
        return h

    def el_end(ns, name):
        return struct.pack("<HHIII", 0x0103, 16, 16, ns, name)

    chunks = [pool,
              struct.pack("<HHIII", 0x0100, 16, 16, SI["android"], AND),
              el_start(SI["manifest"], [(0xFFFFFFFF, SI["package"], 0x03,
                                         SI["com.example.bankapp"])]),
              el_start(SI["uses-permission"], [(AND, SI["name"], 0x03,
                                                SI["android.permission.INTERNET"])]),
              el_end(0xFFFFFFFF, SI["uses-permission"]),
              el_start(SI["uses-sdk"], [(AND, SI["minSdkVersion"], 0x10, 24)]),
              el_end(0xFFFFFFFF, SI["uses-sdk"]),
              el_start(SI["activity"], [(AND, SI["name"], 0x03,
                                         SI["com.example.bankapp"])]),
              el_end(0xFFFFFFFF, SI["activity"]),
              el_end(0xFFFFFFFF, SI["manifest"])]
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_axml_roundtrip():
    root = axml.parse(_build_axml())
    assert root is not None and root.name == "manifest"
    s = axml.manifest_summary(root)
    assert s["package"] == "com.example.bankapp"
    assert s["permissions"] == ["android.permission.INTERNET"]
    assert s["min_sdk"] == "24"
    assert s["activities"] == ["com.example.bankapp"]


def test_axml_garbage_returns_none():
    assert axml.parse(b"not xml at all") is None
    assert axml.parse(b"") is None


def test_axml_typed_values():
    assert axml._typed_value_to_str(0x12, 1, []) == "true"
    assert axml._typed_value_to_str(0x12, 0, []) == "false"
    assert axml._typed_value_to_str(0x10, 24, []) == "24"
    assert axml._typed_value_to_str(0x03, 0, ["hello"]) == "hello"


def test_infer_shape_values_free():
    shape = infer_shape({"user": {"name": "Alice", "age": 30,
                                  "tags": ["a", "b"]},
                         "active": True, "score": 1.5, "nick": None})
    assert shape["type"] == "object"
    props = shape["properties"]
    assert props["user"]["properties"]["name"] == {"type": "string"}
    assert props["user"]["properties"]["age"] == {"type": "integer"}
    assert props["active"] == {"type": "boolean"}
    assert props["score"] == {"type": "number"}
    assert props["nick"] == {"type": "null"}
    # no example values retained anywhere
    dumped = str(shape)
    assert "Alice" not in dumped and "30" not in dumped


def test_infer_shape_array():
    shape = infer_shape([{"a": 1}, {"a": 2, "b": "x"}])
    assert shape["type"] == "array"
    assert shape["count"] == 2


def test_infer_shape_depth_cap():
    deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
    shape = infer_shape(deep)
    assert shape["type"] == "object"  # must not raise


def test_openapi_with_schemas():
    findings = [
        {"id": "F-1", "type": "endpoint", "title": "t",
         "endpoint": "GET /api/pets", "classification": "OBSERVED",
         "confidence": 0.95, "sources": []},
        {"id": "F-2", "type": "schema", "title": "t",
         "endpoint": "GET /api/pets", "shape_kind": "response",
         "shape": {"type": "object",
                   "properties": {"pets": {"type": "array", "items": [],
                                           "count": 3}},
                   "keys": 1},
         "classification": "OBSERVED", "confidence": 0.9, "sources": []},
    ]
    doc = AI.ledger_to_openapi(findings, title="T")
    op = doc["paths"]["/api/pets"]["get"]
    assert "responses" in op
    schema = op["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["properties"]["pets"]["type"] == "array"
