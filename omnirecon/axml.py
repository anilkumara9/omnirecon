"""Android Binary XML (AXML) decoder — pure Python, no dependencies.

Production APKs store AndroidManifest.xml, layout XML, and other resources as
binary XML (UTF-16LE or UTF-8 string pools). The old regex-based manifest
parsing silently returned nothing on real APKs; this decoder extracts the
actual element/attribute tree.

Format reference: android/content/res/Chunk.h (AOSP).
"""
from __future__ import annotations

import struct

# chunk types
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESOURCE_MAP = 0x0180
_CHUNK_NS_START = 0x0100
_CHUNK_NS_END = 0x0101
_CHUNK_EL_START = 0x0102
_CHUNK_EL_END = 0x0103

_FLAG_UTF8 = 1 << 8

# typed-value data types (android/util/TypedValue)
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12
_TYPE_FLOAT = 0x04
_TYPE_DIMENSION = 0x05
_TYPE_FRACTION = 0x06


def _u16(s: str) -> str:
    return s


def _decode_string_pool(data: bytes, off: int) -> tuple[list[str], int]:
    """Parse a string-pool chunk at off; return (strings, next_offset)."""
    ctype, hsize, size = struct.unpack_from("<HHI", data, off)
    assert ctype == _CHUNK_STRING_POOL, f"not a string pool: {ctype:#x}"
    (string_count, style_count, flags, strings_start,
     styles_start) = struct.unpack_from("<IIIII", data, off + 8)
    strings: list[str] = []
    is_utf8 = bool(flags & _FLAG_UTF8)
    for i in range(string_count):
        str_off = struct.unpack_from("<I", data, off + 28 + i * 4)[0]
        pos = off + strings_start + str_off
        if is_utf8:
            # utf8: u16 char count, u8 byte count, bytes, 0x00
            clen = data[pos]
            pos += 1
            if clen & 0x80:  # two-byte length
                clen = ((clen & 0x7F) << 8) | data[pos]
                pos += 1
            blen = data[pos]
            pos += 1
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | data[pos]
                pos += 1
            raw = data[pos:pos + blen]
            try:
                strings.append(raw.decode("utf-8"))
            except Exception:
                strings.append(raw.decode("utf-8", "replace"))
        else:
            # utf16: u16 char count, chars, 0x0000
            clen = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            raw = data[pos:pos + clen * 2]
            try:
                strings.append(raw.decode("utf-16-le"))
            except Exception:
                strings.append(raw.decode("utf-16-le", "replace"))
    return strings, off + size


def _typed_value_to_str(dtype: int, data: int, strings: list[str]) -> str:
    if dtype == _TYPE_STRING:
        return strings[data] if 0 <= data < len(strings) else f"@str/{data}"
    if dtype == _TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if dtype == _TYPE_INT_HEX:
        return hex(data)
    if dtype == _TYPE_FLOAT:
        try:
            return str(struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0])
        except Exception:
            return str(data)
    if dtype in (_TYPE_INT_DEC,):
        return str(struct.unpack("<i", struct.pack("<I", data & 0xFFFFFFFF))[0])
    if dtype == _TYPE_DIMENSION or dtype == _TYPE_FRACTION:
        return f"<{dtype:#x}:{data:#x}>"
    return str(data)


class AxmlElement:
    __slots__ = ("name", "attrs", "children")

    def __init__(self, name: str):
        self.name = name
        self.attrs: dict[str, str] = {}
        self.children: list["AxmlElement"] = []

    def to_dict(self) -> dict:
        return {"name": self.name, "attrs": dict(self.attrs),
                "children": [c.to_dict() for c in self.children]}


def parse(data: bytes) -> AxmlElement | None:
    """Parse AXML bytes into an element tree. Returns None on failure."""
    try:
        return _parse(data)
    except Exception:
        return None


def _parse(data: bytes) -> AxmlElement | None:
    if len(data) < 8:
        return None
    ctype, _, _ = struct.unpack_from("<HHI", data, 0)
    if ctype != 0x0003:  # RES_XML_TYPE
        return None
    off = 8
    strings: list[str] = []
    root: AxmlElement | None = None
    stack: list[AxmlElement] = []
    # namespace prefix map: uri idx -> prefix
    ns_map: dict[int, str] = {}

    while off + 8 <= len(data):
        ctype, hsize, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > len(data):
            break
        if ctype == _CHUNK_STRING_POOL:
            strings, _ = _decode_string_pool(data, off)
        elif ctype == _CHUNK_NS_START:
            # ResXMLTree_node header (16 bytes incl. lineNumber+comment),
            # then ResXMLTree_namespaceExt: prefix(int32) + uri(int32).
            prefix_idx, uri_idx = struct.unpack_from("<ii", data, off + 16)
            prefix = strings[prefix_idx] if 0 <= prefix_idx < len(strings) else ""
            if uri_idx >= 0:
                ns_map[uri_idx] = prefix
        elif ctype == _CHUNK_EL_START:
            # ResXMLTree_node: header(8) + lineNumber(4) + comment(4),
            # then ResXMLTree_element: ns(int32) + name(int32),
            # then ResXMLTree_attrExt: 6 x uint16.
            # NOTE: the attrExt's first u16 ("attributeStart") is unreliable
            # across aapt versions (observed 20 on real APKs where attributes
            # actually begin at the fixed header end). Attributes always
            # follow the fixed 36-byte element header; validate by bounds.
            _line_no, _comment, ns_idx, name_idx = struct.unpack_from(
                "<IIii", data, off + 8)
            (_attr_start_raw, attr_size, attr_count,
             _id_idx, _class_idx, _style_idx) = struct.unpack_from(
                "<HHHHHH", data, off + 24)
            attr_base = off + 36
            if not (0 < attr_count < 256 and attr_base + attr_count * attr_size
                    <= off + size):
                # Fall back to the declared start when the fixed layout
                # does not validate (defensive; not observed in the wild).
                alt = off + _attr_start_raw
                if 0 < attr_count < 256 and off < alt < off + size:
                    attr_base = alt
                else:
                    attr_count = 0
            name = strings[name_idx] if 0 <= name_idx < len(strings) else "?"
            el = AxmlElement(name)
            for i in range(attr_count):
                aoff = attr_base + i * attr_size
                if aoff + 20 > len(data):
                    break
                # ResXMLTree_attribute: ns(i) name(i) rawValue(i)
                #   + Res_value: size(H) res0(B) dataType(B) data(I) = 20 bytes
                (a_ns, a_name_idx, _raw, _vsize, _res0,
                 dtype, adata) = struct.unpack_from("<iiiHBBI", data, aoff)
                aname = strings[a_name_idx] \
                    if 0 <= a_name_idx < len(strings) else "?"
                prefix = ns_map.get(a_ns, "") if a_ns >= 0 else ""
                qname = f"{prefix}:{aname}" if prefix else aname
                el.attrs[qname] = _typed_value_to_str(dtype, adata, strings)
            if stack:
                stack[-1].children.append(el)
            else:
                root = el
            stack.append(el)
        elif ctype == _CHUNK_EL_END:
            if stack:
                stack.pop()
        # NS_END, RESOURCE_MAP: skip
        off += size
    return root


def find_all(root: AxmlElement, name: str) -> list[AxmlElement]:
    out: list[AxmlElement] = []

    def _walk(el: AxmlElement):
        if el.name == name:
            out.append(el)
        for c in el.children:
            _walk(c)

    _walk(root)
    return out


def manifest_summary(root: AxmlElement) -> dict:
    """Extract the rebuild-relevant facts from a decoded manifest."""
    uses_sdk = find_all(root, "uses-sdk")
    perms = [e.attrs.get("android:name", "")
             for e in find_all(root, "uses-permission")]
    activities = [e.attrs.get("android:name", "")
                  for e in find_all(root, "activity")]
    services = [e.attrs.get("android:name", "")
                for e in find_all(root, "service")]
    receivers = [e.attrs.get("android:name", "")
                 for e in find_all(root, "receiver")]
    providers = [(e.attrs.get("android:name", ""),
                  e.attrs.get("android:authorities", ""))
                 for e in find_all(root, "provider")]
    deep_links: list[dict] = []
    for intent in find_all(root, "intent-filter"):
        actions = [e.attrs.get("android:name", "")
                   for e in intent.children if e.name == "action"]
        datas = [e.attrs for e in intent.children if e.name == "data"]
        if any("VIEW" in a for a in actions) and datas:
            deep_links.append({"actions": actions, "data": datas})
    app_els = find_all(root, "application")
    app_attrs = app_els[0].attrs if app_els else {}
    return {
        "package": root.attrs.get("package", ""),
        "version_code": root.attrs.get("android:versionCode", ""),
        "version_name": root.attrs.get("android:versionName", ""),
        "min_sdk": uses_sdk[0].attrs.get("android:minSdkVersion", "")
                   if uses_sdk else "",
        "target_sdk": uses_sdk[0].attrs.get("android:targetSdkVersion", "")
                      if uses_sdk else "",
        "permissions": sorted({p for p in perms if p}),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "deep_links": deep_links,
        "debuggable": app_attrs.get("android:debuggable", "false"),
        "network_security_config": app_attrs.get(
            "android:networkSecurityConfig", ""),
        "uses_cleartext": app_attrs.get("android:usesCleartextTraffic", ""),
    }


def layout_blueprint(root: AxmlElement) -> dict:
    """Convert a layout XML tree into a view-hierarchy blueprint
    (the mobile analog of the DOM control inventory)."""
    def _node(el: AxmlElement) -> dict:
        return {
            "widget": el.name,
            "id": el.attrs.get("android:id", ""),
            "text": el.attrs.get("android:text", "")[:80],
            "children": [_node(c) for c in el.children],
        }

    widgets: dict[str, int] = {}

    def _count(el: AxmlElement):
        widgets[el.name] = widgets.get(el.name, 0) + 1
        for c in el.children:
            _count(c)

    _count(root)
    return {"root_widget": root.name, "widget_counts": widgets,
            "tree": _node(root)}
