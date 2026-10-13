"""Dalvik DEX parser — pure Python, no dependencies.

Production APKs ship their code as classes.dex (sometimes classes2.dex,
classes3.dex, ...). The manifest tells you what the app *declares*; the DEX
tells you what it *does*: every class, every referenced method, every string
constant.

Format reference: dalvik/docs/dex-format.html (AOSP), DexFile.h.
Only the string/type/proto/field/method/class-def tables are parsed —
bytecode disassembly stays REA's job (via the bridge in artifact_intel).

All parsing is defensive: every offset and size is bounds-checked, and any
malformed input returns None (surfaced as a BLOCKED finding), never a crash.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile
import zlib

from omnirecon import security as SEC

_DEX_MAGICS = (b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
               b"dex\n038\x00", b"dex\n039\x00")

_HEADER_SIZE = 0x70
_ENDIAN_TAG = 0x12345678
_NO_INDEX = 0xFFFFFFFF

# sanity caps: a hostile or corrupt DEX must not blow up memory/time
_MAX_STRINGS = 50_000
_MAX_TABLE_ITEMS = 200_000
_MAX_CLASSES_OUT = 100
_MAX_INTERESTING_TOTAL = 200
_MAX_INTERESTING_PER_CAT = 50
_MAX_DEX_PER_APK = 8

# category -> regexes matched against "Lpkg/Cls;->method(params)ret"
_INTERESTING_APIS: list[tuple[str, list[str]]] = [
    ("network", [
        r"HttpURLConnection", r"OkHttp", r"okhttp3", r"Retrofit",
        r"Volley", r"HttpClient", r"URLConnection", r"Socket",
        r"WebSocket", r"java/net/URL",
    ]),
    ("crypto", [
        r"javax/crypto/Cipher", r"MessageDigest", r"javax/crypto/Mac",
        r"KeyGenerator", r"SecretKey", r"KeyStore", r"SecureRandom",
        r"java/security/Signature",
    ]),
    ("reflection", [
        r"Class;->forName", r"getMethod", r"getDeclaredMethod",
        r"Method;->invoke", r"newInstance", r"getDeclaredField",
        r"setAccessible",
    ]),
    ("native/jni", [
        r"System;->loadLibrary", r"System;->load", r"Runtime;->loadLibrary",
    ]),
    ("process-exec", [
        r"Runtime;->exec", r"ProcessBuilder",
    ]),
    ("webview", [
        r"WebView", r"addJavascriptInterface", r"setJavaScriptEnabled",
        r"WebView;->loadUrl",
    ]),
    ("storage", [
        r"SharedPreferences", r"SQLiteDatabase", r"getSharedPreferences",
        r"SQLiteOpenHelper",
    ]),
    ("location", [
        r"LocationManager", r"requestLocationUpdates",
        r"getLastKnownLocation", r"FusedLocationProvider",
    ]),
    ("telephony/sms", [
        r"SmsManager", r"sendTextMessage", r"TelephonyManager",
        r"getDeviceId", r"getSubscriberId", r"getImei",
    ]),
    ("billing", [
        r"BillingClient", r"queryPurchases", r"launchBillingFlow",
    ]),
]


class _DexError(Exception):
    """Internal: any malformed structure raises this; parse_* -> None."""


def _need(data: bytes, off: int, size: int, what: str) -> None:
    if off < 0 or size < 0 or off + size > len(data):
        raise _DexError(
            f"{what} out of bounds (off={off} size={size} len={len(data)})")


def _read_uleb128(data: bytes, off: int) -> tuple[int, int]:
    result, shift = 0, 0
    while True:
        if off >= len(data):
            raise _DexError("uleb128 runs past end of data")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        if shift > 35:
            raise _DexError("uleb128 overflow")
    return result, off


def _decode_mutf8(raw: bytes) -> str:
    # MUTF-8: NUL is 0xC0 0x80; supplementary chars are surrogate pairs
    # (each 3 bytes, decodable as UTF-8). Replace-then-decode is robust.
    return raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")


def _read_string_data(data: bytes, off: int) -> str:
    _need(data, off, 1, "string_data")
    utf16_len, off = _read_uleb128(data, off)
    # MUTF-8 uses at most 3 bytes per UTF-16 code unit, plus NUL
    max_bytes = utf16_len * 3 + 1
    limit = min(off + max_bytes, len(data))
    end = off
    while end < limit and data[end] != 0:
        end += 1
    if end >= len(data) or data[end] != 0:
        raise _DexError("unterminated string_data")
    return _decode_mutf8(data[off:end])


def _read_type_list(data: bytes, off: int) -> list[int]:
    if off == 0:
        return []
    _need(data, off, 4, "type_list header")
    size = struct.unpack_from("<I", data, off)[0]
    if size > 65535:
        raise _DexError(f"type_list absurd size {size}")
    _need(data, off + 4, size * 2, "type_list items")
    return list(struct.unpack_from(f"<{size}H", data, off + 4)) if size else []


def _parse(data: bytes) -> dict:
    if len(data) < _HEADER_SIZE:
        raise _DexError(f"too small for DEX header ({len(data)} bytes)")
    magic = data[0:8]
    if magic not in _DEX_MAGICS:
        raise _DexError(f"bad DEX magic {magic!r}")
    version = magic[4:7].decode("ascii", "replace")

    stored_crc = struct.unpack_from("<I", data, 8)[0]
    if (zlib.adler32(data[12:]) & 0xFFFFFFFF) != stored_crc:
        raise _DexError("DEX checksum mismatch")
    if hashlib.sha1(data[32:]).digest() != data[12:32]:
        raise _DexError("DEX signature mismatch")

    (file_size, header_size, endian_tag, _link_size, _link_off, _map_off,
     string_ids_size, string_ids_off, type_ids_size, type_ids_off,
     proto_ids_size, proto_ids_off, field_ids_size, field_ids_off,
     method_ids_size, method_ids_off, class_defs_size, class_defs_off,
     _data_size, _data_off) = struct.unpack_from("<" + "I" * 20, data, 32)
    if header_size != _HEADER_SIZE:
        raise _DexError(f"bad header_size {header_size:#x}")
    if endian_tag != _ENDIAN_TAG:
        raise _DexError(f"bad endian_tag {endian_tag:#x}")
    if file_size != len(data):
        raise _DexError(f"file_size {file_size} != actual {len(data)}")
    for name, size in (("string_ids", string_ids_size),
                       ("type_ids", type_ids_size),
                       ("proto_ids", proto_ids_size),
                       ("field_ids", field_ids_size),
                       ("method_ids", method_ids_size),
                       ("class_defs", class_defs_size)):
        if size > _MAX_TABLE_ITEMS:
            raise _DexError(f"{name} absurd size {size}")

    # ---- string pool ----
    if string_ids_size > _MAX_STRINGS:
        raise _DexError(f"string_ids absurd size {string_ids_size}")
    _need(data, string_ids_off, string_ids_size * 4, "string_ids")
    strings: list[str] = []
    for i in range(string_ids_size):
        sdo = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
        strings.append(_read_string_data(data, sdo))

    def _str(idx: int) -> str:
        if not 0 <= idx < len(strings):
            raise _DexError(f"string_idx {idx} out of range")
        return strings[idx]

    # ---- type ids ----
    _need(data, type_ids_off, type_ids_size * 4, "type_ids")
    types: list[str] = []
    for i in range(type_ids_size):
        didx = struct.unpack_from("<I", data, type_ids_off + i * 4)[0]
        types.append(_str(didx))

    def _typ(idx: int) -> str:
        if not 0 <= idx < len(types):
            raise _DexError(f"type_idx {idx} out of range")
        return types[idx]

    # ---- proto ids ----
    _need(data, proto_ids_off, proto_ids_size * 12, "proto_ids")
    protos: list[dict] = []
    for i in range(proto_ids_size):
        _sidx, ret_idx, params_off = struct.unpack_from(
            "<III", data, proto_ids_off + i * 12)
        params = [_typ(t) for t in _read_type_list(data, params_off)]
        protos.append({"return_type": _typ(ret_idx), "params": params})

    # ---- field ids ----
    _need(data, field_ids_off, field_ids_size * 8, "field_ids")
    fields: list[dict] = []
    for i in range(field_ids_size):
        class_idx, type_idx, name_idx = struct.unpack_from(
            "<HHI", data, field_ids_off + i * 8)
        fields.append({"class": _typ(class_idx), "type": _typ(type_idx),
                       "name": _str(name_idx)})

    # ---- method ids: the API inventory ----
    _need(data, method_ids_off, method_ids_size * 8, "method_ids")
    methods: list[dict] = []
    for i in range(method_ids_size):
        class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", data, method_ids_off + i * 8)
        if not 0 <= proto_idx < len(protos):
            raise _DexError(f"proto_idx {proto_idx} out of range")
        proto = protos[proto_idx]
        sig = (f"{_typ(class_idx)}->{_str(name_idx)}"
               f"({''.join(proto['params'])}){proto['return_type']}")
        methods.append({"class": _typ(class_idx), "name": _str(name_idx),
                        "proto": proto, "signature": sig})

    # ---- class defs ----
    _need(data, class_defs_off, class_defs_size * 32, "class_defs")
    classes: list[dict] = []
    for i in range(class_defs_size):
        (class_idx, _access, super_idx, _ifaces_off, src_idx, _ann_off,
         _class_data_off, _static_off) = struct.unpack_from(
            "<8I", data, class_defs_off + i * 32)
        classes.append({
            "name": _typ(class_idx),
            "superclass": _typ(super_idx)
            if super_idx != _NO_INDEX else None,
            "source_file": _str(src_idx) if src_idx != _NO_INDEX else "",
        })

    interesting = _interesting_methods([m["signature"] for m in methods])
    return {
        "valid": True,
        "dex_version": version,
        "file_size": file_size,
        "checksum_ok": True,
        "signature_ok": True,
        "string_count": len(strings),
        "type_count": len(types),
        "proto_count": len(protos),
        "field_count": len(fields),
        "method_count": len(methods),
        "class_count": len(classes),
        "classes": classes[:_MAX_CLASSES_OUT],
        "interesting_apis": interesting,
    }


def _interesting_methods(signatures: list[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    total = 0
    for sig in signatures:
        for cat, patterns in _INTERESTING_APIS:
            for pat in patterns:
                if re.search(pat, sig):
                    bucket = hits.setdefault(cat, [])
                    if (len(bucket) < _MAX_INTERESTING_PER_CAT
                            and total < _MAX_INTERESTING_TOTAL):
                        bucket.append(sig)
                        total += 1
                    break
    return hits


def parse_dex_bytes(data: bytes) -> dict | None:
    """Parse DEX bytes. Returns the inventory dict, or None if malformed."""
    try:
        return _parse(bytes(data))
    except Exception:
        return None


def parse_dex(path: str) -> dict | None:
    """Parse a DEX file at path. Returns the inventory dict, or None."""
    try:
        with open(path, "rb") as fh:
            return parse_dex_bytes(fh.read())
    except Exception:
        return None


def parse_apk_dex(apk_path: str) -> list[dict]:
    """Find every classes*.dex in an APK (zip file) or a directory and parse
    each. Returns [{"dex_name", "origin", "parsed": dict|None}]."""
    items: list[tuple[str, str, bytes | None]] = []
    if os.path.isdir(apk_path):
        for name in sorted(os.listdir(apk_path)):
            if re.fullmatch(r"classes\d*\.dex", name):
                p = os.path.join(apk_path, name)
                try:
                    with open(p, "rb") as fh:
                        items.append((name, p, fh.read()))
                except OSError:
                    items.append((name, p, None))
    else:
        try:
            with zipfile.ZipFile(apk_path) as z:
                names = sorted(n for n in z.namelist()
                               if re.fullmatch(r"classes\d*\.dex", n))
                for name in names[:_MAX_DEX_PER_APK]:
                    try:
                        items.append((name, f"{apk_path}!{name}",
                                      z.read(name)))
                    except Exception:
                        items.append((name, f"{apk_path}!{name}", None))
        except Exception:
            return []
    out = []
    for dex_name, origin, raw in items[:_MAX_DEX_PER_APK]:
        out.append({"dex_name": dex_name, "origin": origin,
                    "parsed": parse_dex_bytes(raw) if raw else None})
    return out


# ---------------------------------------------------------------------------
# ledger reporting (same persisted pattern as artifact_intel._record)
# ---------------------------------------------------------------------------

def _session_dir(session_id: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sessions", session_id)


def _record(session_id: str, ftype: str, title: str, detail: str,
            classification: str, confidence: float, why: str,
            sources: list[str], **kw) -> None:
    try:
        from omnirecon import evidence as ev
        sdir = _session_dir(session_id)
        os.makedirs(sdir, exist_ok=True)
        ledger_path = os.path.join(sdir, "evidence.jsonl")
        ledger = ev.EvidenceLedger.load(ledger_path) \
            if os.path.exists(ledger_path) else ev.EvidenceLedger()
        ledger.add({"type": ftype, "title": title, "detail": detail[:2000],
                    "classification": classification, "confidence": confidence,
                    "confidence_why": why, "sources": sources, **kw})
        ledger.save(ledger_path)
    except Exception:
        pass


def summarize_parsed(parsed: dict | None, session_id: str,
                     origin: str = "", dex_name: str = "classes.dex") -> dict:
    """Record DEX findings in the evidence ledger. Never raises."""
    if parsed is None:
        _record(session_id, "note", f"DEX parse failed: {dex_name}",
                f"Could not parse DEX from {origin}: invalid magic, bad "
                f"checksum/signature, or truncated tables. Code treated as "
                f"opaque.",
                "BLOCKED", 1.0, "DEX header/table validation", [origin],
                engine="binary")
        return {"ok": False, "dex": dex_name, "origin": origin}
    interesting = parsed.get("interesting_apis", {})
    total_hits = sum(len(v) for v in interesting.values())
    _record(
        session_id, "tech",
        f"DEX code: {parsed['class_count']} classes, "
        f"{parsed['method_count']} method refs ({dex_name})",
        f"{parsed['class_count']} classes, {parsed['method_count']} "
        f"referenced methods, {parsed['string_count']} strings parsed from "
        f"{dex_name} (DEX v{parsed['dex_version']}). {total_hits} "
        f"references to security/network-relevant APIs.",
        "SOURCE_VERIFIED", 0.95, "DEX string/type/method table parse",
        [origin], engine="binary")
    for cat, sigs in sorted(interesting.items()):
        sample = SEC.redact(", ".join(sigs[:12]))
        more = f" (+{len(sigs) - 12} more)" if len(sigs) > 12 else ""
        _record(
            session_id, "note",
            f"DEX {cat} API refs: {len(sigs)} ({dex_name})",
            f"Method *references* touching {cat} APIs: {sample}{more}. "
            f"References are not confirmed calls — bundled-but-unused SDKs "
            f"(e.g. BillingClient in a free app) appear here. Cross-check "
            f"against the manifest's declared permissions; dynamic "
            f"instrumentation (Frida) is needed to confirm execution.",
            "SOURCE_VERIFIED", 0.8,
            "method-id table matched against API patterns; refs, not calls",
            [origin], engine="binary",
            limitations="Static references only — no call-graph or "
                        "execution confirmation.")
    return {"ok": True, "dex": dex_name, "origin": origin,
            "class_count": parsed["class_count"],
            "method_count": parsed["method_count"],
            "interesting_categories": sorted(interesting)}


def summarize_dex_bytes(data: bytes, session_id: str,
                        origin: str = "") -> dict:
    """Parse DEX bytes and record findings. Never raises."""
    dex_name = origin.split("!")[-1] if "!" in origin else "classes.dex"
    return summarize_parsed(parse_dex_bytes(data), session_id,
                            origin=origin, dex_name=dex_name)


def summarize_dex(path: str, session_id: str, origin: str = "") -> dict:
    """Parse a DEX file at path and record findings. Never raises."""
    return summarize_parsed(parse_dex(path), session_id,
                            origin=origin or path,
                            dex_name=os.path.basename(path))
