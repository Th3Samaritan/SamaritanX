"""Bounded Android binary XML reader for manifest attributes; resources stay symbolic."""
import struct
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


def parse(data):
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("manifest too large")
    if data.lstrip().startswith(b"<"):
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            raise ValueError("XML entities are not accepted")
        try:
            return SafeET.fromstring(data, forbid_dtd=True)
        except (DefusedXmlException, ET.ParseError) as exc:
            raise ValueError("invalid or unsafe XML") from exc
    try:
        return _binary(data)
    except (IndexError, struct.error, UnicodeError) as exc:
        raise ValueError("malformed Android binary XML") from exc


def _binary(data):
    if len(data) < 8 or struct.unpack_from("<H", data)[0] != 3:
        raise ValueError("not Android binary XML")
    total = struct.unpack_from("<I", data, 4)[0]
    if total != len(data):
        raise ValueError("invalid XML size")
    strings, stack, root = [], [], None
    def string(index):
        if index == 0xffffffff:
            return ""
        if index >= len(strings):
            raise ValueError("invalid string reference")
        return strings[index]
    position = 8
    while position < total:
        kind, header, size = struct.unpack_from("<HHI", data, position)
        if header < 8 or size < header or position + size > total:
            raise ValueError("invalid chunk bounds")
        chunk = data[position:position + size]
        if kind == 1:
            if header < 28:
                raise ValueError("invalid string pool")
            count, styles, flags, start, _ = struct.unpack_from("<IIIII", chunk, 8)
            if count > 100000 or header + count * 4 > size or start < header + (count + styles) * 4:
                raise ValueError("invalid string offsets")
            strings = []
            for index in range(count):
                cursor = start + struct.unpack_from("<I", chunk, header + index * 4)[0]
                if flags & 0x100:
                    def length8(offset):
                        first = chunk[offset]
                        return (((first & 127) << 8) | chunk[offset + 1], offset + 2) if first & 128 else (first, offset + 1)
                    _, cursor = length8(cursor)
                    length, cursor = length8(cursor)
                    if cursor + length >= size:
                        raise ValueError("truncated UTF-8 string")
                    strings.append(chunk[cursor:cursor + length].decode("utf-8"))
                else:
                    length = struct.unpack_from("<H", chunk, cursor)[0]; cursor += 2
                    if length & 0x8000:
                        length = ((length & 0x7fff) << 16) | struct.unpack_from("<H", chunk, cursor)[0]; cursor += 2
                    if cursor + length * 2 + 2 > size:
                        raise ValueError("truncated UTF-16 string")
                    strings.append(chunk[cursor:cursor + length * 2].decode("utf-16-le"))
        elif kind == 0x102:
            if size < 36 or len(stack) > 128:
                raise ValueError("invalid XML element")
            name = struct.unpack_from("<I", chunk, 20)[0]
            start, width, count = struct.unpack_from("<HHH", chunk, 24)
            if start < 20 or width < 20 or 16 + start + count * width > size:
                raise ValueError("invalid attributes")
            node = ET.Element(string(name))
            for index in range(count):
                offset = 16 + start + index * width
                ns, key, raw = struct.unpack_from("<III", chunk, offset)
                typ = chunk[offset + 15]
                value = struct.unpack_from("<I", chunk, offset + 16)[0]
                if raw != 0xffffffff: text = string(raw)
                elif typ == 3: text = string(value)
                elif typ == 0x12: text = "true" if value else "false"
                elif typ == 1: text = f"@0x{value:08x}"
                else: text = str(value)
                node.set(("{" + string(ns) + "}" if ns != 0xffffffff else "") + string(key), text)
            if stack: stack[-1].append(node)
            elif root is not None: raise ValueError("multiple roots")
            else: root = node
            stack.append(node)
        elif kind == 0x103:
            if not stack or size < 24 or stack[-1].tag != string(struct.unpack_from("<I", chunk, 20)[0]):
                raise ValueError("unbalanced XML")
            stack.pop()
        position += size
    if root is None or stack:
        raise ValueError("incomplete XML")
    return root
