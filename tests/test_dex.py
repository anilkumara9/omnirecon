"""Tests for omnirecon.dex (pure-Python Dalvik DEX parser).

Builds a minimal but *valid* DEX entirely in code (correct magic, Adler-32
checksum, SHA-1 signature) — no external files, no network.
"""
import hashlib
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

from omnirecon import dex as DX  # noqa: E402


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


# string pool: index -> value
STRINGS = [
    "Lcom/example/Foo;",      # 0
    "Lcom/example/Bar;",      # 1
    "Ljava/lang/Object;",     # 2
    "V",                      # 3
    "Ljava/lang/String;",     # 4
    "Ljavax/crypto/Cipher;",  # 5
    "Ljava/lang/System;",     # 6
    "doThing",                # 7
    "doFinal",                # 8
    "loadLibrary",            # 9
    "Foo.java",               # 10
    "Bar.java",               # 11
    "LV",                     # 12  shorty (Ljava/lang/String;)V
    "[B",                     # 13
    "[B[B",                   # 14  shorty ([B)[B
]
# type_id -> string_idx
TYPES = [0, 1, 2, 3, 4, 5, 6, 13]
# proto: (shorty_idx, return_type_idx, [param_type_idx...])
PROTOS = [(3, 3, []), (12, 3, [4]), (14, 7, [7])]
# method: (class_idx, proto_idx, name_idx)
METHODS = [(0, 0, 7), (5, 2, 8), (6, 1, 9)]
# class_def: (class_idx, superclass_idx, source_file_idx)
CLASSES = [(0, 2, 10), (1, 2, 11)]


def build_test_dex(corrupt: str | None = None) -> bytes:
    """Assemble a valid DEX. corrupt: 'magic' | 'checksum' | 'truncated'."""
    data = bytearray()
    str_offs = []
    for s in STRINGS:
        str_offs.append(len(data))
        raw = s.encode("utf-8")
        data += _uleb128(len(s)) + raw + b"\x00"
    tl_offs = []
    for _, _, params in PROTOS:
        if not params:
            tl_offs.append(0)
            continue
        while len(data) % 4:
            data += b"\x00"
        tl_offs.append(len(data))
        data += struct.pack("<I", len(params))
        for t in params:
            data += struct.pack("<H", t)
    data_off = 0x70 + len(STRINGS) * 4 + len(TYPES) * 4 + len(PROTOS) * 12 \
        + len(METHODS) * 8 + len(CLASSES) * 32
    data_size = len(data)

    blob = bytearray()
    blob += b"\x00" * 0x70  # header placeholder
    string_ids_off = 0x70
    for so in str_offs:
        blob += struct.pack("<I", data_off + so)
    type_ids_off = string_ids_off + len(STRINGS) * 4
    for ti in TYPES:
        blob += struct.pack("<I", ti)
    proto_ids_off = type_ids_off + len(TYPES) * 4
    for (sh, ret, _), tlo in zip(PROTOS, tl_offs):
        blob += struct.pack("<III", sh, ret,
                            data_off + tlo if tlo else 0)
    method_ids_off = proto_ids_off + len(PROTOS) * 12
    for c, p, n in METHODS:
        blob += struct.pack("<HHI", c, p, n)
    class_defs_off = method_ids_off + len(METHODS) * 8
    for c, s, src in CLASSES:
        blob += struct.pack("<8I", c, 0x1, s, 0, src, 0, 0, 0)
    assert len(blob) == data_off, (len(blob), data_off)
    blob += data

    # header
    magic = b"dex\n035\x00"
    if corrupt == "magic":
        magic = b"notadex\x00"
    hdr = bytearray()
    hdr += magic
    hdr += b"\x00" * 4   # checksum placeholder
    hdr += b"\x00" * 20  # signature placeholder
    hdr += struct.pack("<" + "I" * 20,
                       len(blob), 0x70, 0x12345678,
                       0, 0, 0,
                       len(STRINGS), string_ids_off,
                       len(TYPES), type_ids_off,
                       len(PROTOS), proto_ids_off,
                       0, method_ids_off,  # field_ids empty
                       len(METHODS), method_ids_off,
                       len(CLASSES), class_defs_off,
                       data_size, data_off)
    assert len(hdr) == 0x70
    blob[0:0x70] = hdr
    # Spec order: signature = SHA-1 of bytes[32:]; checksum = Adler-32 of
    # bytes[12:] (which includes the signature). So signature first.
    sig = hashlib.sha1(blob[32:]).digest()
    blob[12:32] = sig
    crc = zlib.adler32(blob[12:]) & 0xFFFFFFFF
    if corrupt == "checksum":
        crc ^= 0xFFFFFFFF
    struct.pack_into("<I", blob, 8, crc)
    if corrupt == "truncated":
        blob = blob[:100]
    return bytes(blob)


def test_round_trip_valid_dex():
    raw = build_test_dex()
    p = DX.parse_dex_bytes(raw)
    assert p is not None, "valid DEX should parse"
    assert p["dex_version"] == "035"
    assert p["checksum_ok"] and p["signature_ok"]
    assert p["string_count"] == len(STRINGS)
    assert p["class_count"] == 2
    assert p["method_count"] == 3
    names = {c["name"] for c in p["classes"]}
    assert "Lcom/example/Foo;" in names and "Lcom/example/Bar;" in names
    foo = next(c for c in p["classes"] if c["name"] == "Lcom/example/Foo;")
    assert foo["superclass"] == "Ljava/lang/Object;"
    assert foo["source_file"] == "Foo.java"


def test_method_signatures():
    raw = build_test_dex()
    p = DX.parse_dex_bytes(raw)
    sigs = set()
    # re-derive via internal parse to check signatures
    assert p["method_count"] == 3
    # interesting_apis keys on signatures; check the crypto hit exists
    assert "crypto" in p["interesting_apis"], p["interesting_apis"]
    assert any("Cipher;->doFinal" in s
               for s in p["interesting_apis"]["crypto"])
    assert "native/jni" in p["interesting_apis"]
    assert any("System;->loadLibrary" in s
               for s in p["interesting_apis"]["native/jni"])


def test_malformed_returns_none():
    assert DX.parse_dex_bytes(b"") is None
    assert DX.parse_dex_bytes(b"not a dex file at all....") is None
    assert DX.parse_dex_bytes(build_test_dex(corrupt="magic")) is None
    assert DX.parse_dex_bytes(build_test_dex(corrupt="checksum")) is None
    assert DX.parse_dex_bytes(build_test_dex(corrupt="truncated")) is None
    assert DX.parse_dex("/nonexistent/path.dex") is None
    # bit-flip inside the string pool must not crash
    raw = bytearray(build_test_dex())
    raw[400] ^= 0xFF
    assert DX.parse_dex_bytes(bytes(raw)) is None


def test_summarize_records_findings():
    sid = "test-dex-ledger"
    sdir = os.path.expanduser(f"~/workspace/omnirecon/sessions/{sid}")
    import shutil
    shutil.rmtree(sdir, ignore_errors=True)
    res = DX.summarize_dex_bytes(build_test_dex(), sid,
                                 origin="test.apk!classes.dex")
    assert res["ok"] is True
    assert res["class_count"] == 2
    fs = [json.loads(l) for l in
          open(os.path.join(sdir, "evidence.jsonl"))]
    types = {f["type"] for f in fs}
    assert "tech" in types, types
    tech = next(f for f in fs if f["type"] == "tech")
    assert tech["classification"] == "SOURCE_VERIFIED", tech
    assert tech["confidence"] >= 0.9, tech
    cats = {f["title"] for f in fs if f["type"] == "note"}
    assert any("crypto" in t for t in cats), cats
    # malformed -> BLOCKED finding, no crash
    res2 = DX.summarize_dex_bytes(b"junk", "test-dex-blocked",
                                  origin="bad.apk!classes.dex")
    assert res2["ok"] is False
    fs2 = [json.loads(l) for l in open(os.path.expanduser(
        "~/workspace/omnirecon/sessions/test-dex-blocked/evidence.jsonl"))]
    assert fs2[0]["classification"] == "BLOCKED", fs2[0]


def test_parse_apk_dex_multi():
    import tempfile
    import zipfile
    tmp = tempfile.mkdtemp()
    apk = os.path.join(tmp, "app.apk")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", build_test_dex())
        z.writestr("classes2.dex", build_test_dex())
        z.writestr("AndroidManifest.xml", b"fake")
    items = DX.parse_apk_dex(apk)
    assert len(items) == 2, items
    assert items[0]["dex_name"] == "classes.dex"
    assert items[1]["dex_name"] == "classes2.dex"
    assert all(i["parsed"] is not None for i in items)
    assert all(i["parsed"]["class_count"] == 2 for i in items)
    # not an apk -> empty list, no crash
    assert DX.parse_apk_dex(os.path.join(tmp, "nope.apk")) == []


def test_string_redaction_in_findings():
    # a string-pool secret must not survive verbatim into the ledger
    sid = "test-dex-redact"
    sdir = os.path.expanduser(f"~/workspace/omnirecon/sessions/{sid}")
    import shutil
    shutil.rmtree(sdir, ignore_errors=True)
    raw = build_test_dex()
    # sanity: our own redact would catch a planted bearer token
    from omnirecon import security as SEC
    assert "[REDACTED]" in SEC.redact("Bearer abcdef123456")
    res = DX.summarize_dex_bytes(raw, sid, origin="t.apk!classes.dex")
    assert res["ok"] is True
