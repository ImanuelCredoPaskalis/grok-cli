#!/usr/bin/env python3
"""Minimal protobuf + Connect/gRPC-Web framing helpers."""
from __future__ import annotations

import struct
from typing import Any


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        out.append(bits | (0x80 if value else 0))
        if not value:
            break
    return bytes(out)


def encode_key(field: int, wire_type: int) -> bytes:
    return _encode_varint((field << 3) | wire_type)


def encode_varint_field(field: int, value: int) -> bytes:
    return encode_key(field, 0) + _encode_varint(value)


def encode_string_field(field: int, value: str) -> bytes:
    data = value.encode("utf-8")
    return encode_key(field, 2) + _encode_varint(len(data)) + data


def encode_bytes_field(field: int, value: bytes) -> bytes:
    return encode_key(field, 2) + _encode_varint(len(value)) + value


def encode_message_field(field: int, message: bytes) -> bytes:
    return encode_key(field, 2) + _encode_varint(len(message)) + message


def grpc_web_frame(payload: bytes, compressed: bool = False) -> bytes:
    """5-byte gRPC-Web / Connect binary envelope."""
    flag = 0x01 if compressed else 0x00
    return bytes([flag]) + struct.pack(">I", len(payload)) + payload


def parse_varint(data: bytes, i: int = 0) -> tuple[int, int]:
    result = 0
    shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def parse_fields(data: bytes) -> list[tuple[int, int, Any]]:
    """Return list of (field_number, wire_type, value)."""
    i = 0
    out: list[tuple[int, int, Any]] = []
    while i < len(data):
        key, i = parse_varint(data, i)
        field = key >> 3
        wtype = key & 7
        if wtype == 0:
            val, i = parse_varint(data, i)
            out.append((field, wtype, val))
        elif wtype == 2:
            length, i = parse_varint(data, i)
            val = data[i : i + length]
            i += length
            out.append((field, wtype, val))
        elif wtype == 1:
            val = data[i : i + 8]
            i += 8
            out.append((field, wtype, val))
        elif wtype == 5:
            val = data[i : i + 4]
            i += 4
            out.append((field, wtype, val))
        else:
            break
    return out


def unwrap_grpc_web(body: bytes) -> bytes:
    """Strip gRPC-Web envelopes; return first data frame payload."""
    if not body:
        return b""
    # Some servers return raw protobuf (no frame)
    if len(body) >= 5 and body[0] in (0, 1) and struct.unpack(">I", body[1:5])[0] <= len(body) - 5:
        frames = []
        i = 0
        while i + 5 <= len(body):
            flag = body[i]
            length = struct.unpack(">I", body[i + 1 : i + 5])[0]
            i += 5
            if i + length > len(body):
                break
            payload = body[i : i + length]
            i += length
            frames.append((flag, payload))
        # Prefer non-trailer data frames (flag bit0 = compressed, bit7 often trailer)
        for flag, payload in frames:
            if flag & 0x80:
                continue
            return payload
        return frames[0][1] if frames else body
    return body


def field_str(fields: list[tuple[int, int, Any]], number: int) -> str | None:
    for f, w, v in fields:
        if f == number and w == 2:
            try:
                return v.decode("utf-8")
            except Exception:
                return None
    return None


def field_msg(fields: list[tuple[int, int, Any]], number: int) -> bytes | None:
    for f, w, v in fields:
        if f == number and w == 2 and isinstance(v, (bytes, bytearray)):
            return bytes(v)
    return None


# ---- xAI AuthManagement request builders (from HAR reverse-eng) ----

def build_create_email_validation_code(email: str, castle_token: str) -> bytes:
    # f1=email, f3=castleRequestToken
    msg = encode_string_field(1, email) + encode_string_field(3, castle_token)
    return grpc_web_frame(msg)


def build_verify_email_validation_code(email: str, code: str) -> bytes:
    # f1=email, f2=code
    msg = encode_string_field(1, email) + encode_string_field(2, code)
    return grpc_web_frame(msg)


def build_validate_password(email: str, password: str) -> bytes:
    # f4=email, f5=password (HAR entry 132)
    msg = encode_string_field(4, email) + encode_string_field(5, password)
    return grpc_web_frame(msg)