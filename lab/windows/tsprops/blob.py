"""userParameters blob helpers for the T-1890 capture (tier L: hand-built blobs are allowed here).

units <-> bytes: a DC returns the blob as UTF-16 code units; over LDAP those are UTF-8 octets (spec reports-terminal-services §2).
The blob BYTES are the UTF-16LE of the code units. Reference parser = MS-TSTS userParameters layout; it is the capture's own
sanity check, NOT the product decoder (T-1566).
"""
import struct

RESERVED_LEN = 96


def octets_to_bytes(octets: bytes) -> bytes:
    """LDAP octets (UTF-8 of UTF-16 code units) -> blob bytes. Raises UnicodeDecodeError on invalid UTF-8 / lone surrogate."""
    return octets.decode("utf-8", "strict").encode("utf-16le", "strict")


def bytes_to_octets(blob: bytes) -> bytes:
    if len(blob) % 2:
        raise ValueError("blob has odd length; it cannot be a UTF-16 string")
    return blob.decode("utf-16le", "strict").encode("utf-8", "strict")


def prop(name: str, value_ascii: bytes, ptype: int = 1) -> bytes:
    n = name.encode("utf-16le")
    return struct.pack("<HHH", len(n), len(value_ascii), ptype) + n + value_ascii


def hexval(raw: bytes, upper=False) -> bytes:
    h = raw.hex()
    return (h.upper() if upper else h).encode("ascii")


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def build(props, reserved=None, sig="P"):
    reserved = reserved if reserved is not None else ("CtxCfgPresent".ljust(48)).encode("utf-16le")
    assert len(reserved) == RESERVED_LEN
    return reserved + sig.encode("utf-16le") + struct.pack("<H", len(props)) + b"".join(props)


def parse(blob: bytes):
    """-> dict(sig, count, props=[(name, ptype, value_bytes_raw_ascii)], trailing, reserved_text) ; value_raw = unhexed bytes or None"""
    if len(blob) < 100:
        return {"error": "short", "len": len(blob)}
    out = {"len": len(blob), "sig": blob[96:98].decode("utf-16le", "replace"), "count": struct.unpack("<H", blob[98:100])[0], "props": []}
    o = 100
    for _ in range(out["count"]):
        nl, vl, ty = struct.unpack("<HHH", blob[o:o + 6]); o += 6
        name = blob[o:o + nl].decode("utf-16le", "replace"); o += nl
        v = blob[o:o + vl]; o += vl
        try:
            raw = bytes.fromhex(v.decode("ascii"))
        except ValueError:
            raw = None
        out["props"].append({"name": name, "type": ty, "hex_ascii": v.decode("ascii", "replace"), "value": raw})
    out["trailing"] = len(blob) - o
    return out


def u32_of(p):
    return struct.unpack("<I", p["value"])[0] if p["value"] is not None and len(p["value"]) == 4 else None


def text_of(p):
    """The W (UTF-16LE) variants and ANSI variants as written by Windows: NUL-terminated."""
    raw = p["value"]
    if p["name"].endswith("W"):
        return raw.decode("utf-16le", "replace")
    return raw.decode("latin-1")
