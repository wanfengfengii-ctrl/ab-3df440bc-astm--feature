"""ASTM 复核引擎与 API 的测试。"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.protocol import (
    ACK,
    CR,
    ENQ,
    EOT,
    ETB,
    ETX,
    LF,
    NAK,
    STX,
    ProtocolViolation,
    audit,
    parse_request,
)

client = TestClient(app)


def make_frame(fn: int, payload: bytes, terminator: int = ETB) -> bytes:
    """按线路格式构造一帧。"""
    body = bytes([ord(str(fn))]) + payload
    checksum = (sum(body) + terminator) & 0xFF
    return bytes([STX]) + body + bytes([terminator]) + f"{checksum:02X}".encode() + bytes([CR, LF])


def chunks_for(events, piece: int):
    """把 [(direction, bytes), ...] 按固定小块再切分（同方向段内部切）。"""
    out = []
    for direction, data in events:
        for i in range(0, len(data), piece):
            out.append((direction, data[i : i + piece]))
    return out


def valid_events():
    """ENQ/ACK -> 帧1 -> NAK -> 原样重传帧1 -> ACK -> 帧2(ETX) -> ACK -> EOT。"""
    f1 = make_frame(1, b"H|\\^&|||analyzer^1.0")
    f2 = make_frame(2, b"O|1||^^^ASTM^M|||", terminator=ETX)
    return [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
        ("sender", f2),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]


EXPECTED_PAYLOAD = b"H|\\^&|||analyzer^1.0" + b"O|1||^^^ASTM^M|||"


def test_valid_session_with_retransmission():
    result = audit("analyzer-A", valid_events())
    assert result["ok"] is True
    assert result["frame_count"] == 2
    assert result["retransmissions"] == 1
    assert result["payload_bytes"] == len(EXPECTED_PAYLOAD)
    assert result["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


@pytest.mark.parametrize("piece", [1, 2, 3, 5, 7, 13, 64, 4096])
def test_chunking_invariance(piece):
    result = audit("x", chunks_for(valid_events(), piece))
    assert result["frame_count"] == 2
    assert result["retransmissions"] == 1
    assert result["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


def test_frame_number_cycles_1_to_7_then_0():
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    payloads = []
    for fn in [1, 2, 3, 4, 5, 6, 7, 0, 1]:
        data = f"P{fn}".encode()
        payloads.append(data)
        events += [
            ("sender", make_frame(fn, data)),
            ("receiver", bytes([ACK])),
        ]
    events.append(("sender", bytes([EOT])))
    result = audit("x", events)
    assert result["frame_count"] == 9
    assert result["sha256"] == hashlib.sha256(b"".join(payloads)).hexdigest()


def expect_violation(events, code):
    with pytest.raises(ProtocolViolation) as exc:
        audit("x", events)
    assert exc.value.code == code
    return exc.value


def test_must_start_with_enq():
    events = list(valid_events())
    events[0] = ("sender", bytes([ACK]))
    expect_violation(events, "STAGE_ORDER")


def test_first_byte_direction_must_be_sender():
    events = list(valid_events())
    events[0] = ("receiver", bytes([ENQ]))
    expect_violation(events, "DIRECTION_VIOLATION")


def test_enq_requires_ack():
    events = list(valid_events())
    events[1] = ("receiver", bytes([NAK]))
    expect_violation(events, "STAGE_ORDER")


def test_frame_number_skip_rejected():
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    events += [("sender", make_frame(2, b"x")), ("receiver", bytes([ACK]))]
    events.append(("sender", bytes([EOT])))
    expect_violation(events, "FRAME_NUMBER_SKIP")


def test_frame_number_skip_after_wrap_rejected():
    # 0 之后必须是 1，发 2 即跳变
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    for fn in [1, 2, 3, 4, 5, 6, 7, 0]:
        events += [("sender", make_frame(fn, b"x")), ("receiver", bytes([ACK]))]
    events += [("sender", make_frame(2, b"y")), ("receiver", bytes([ACK]))]
    events.append(("sender", bytes([EOT])))
    expect_violation(events, "FRAME_NUMBER_SKIP")


def test_bad_checksum_rejected_and_position_points_into_block():
    good = make_frame(1, b"abc")
    bad = bytearray(good)
    bad[-3] = ord("0")  # 第 2 个校验和十六进制位改错
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bytes(bad)),
    ]
    exc = expect_violation(events, "CHECKSUM_FAILED")
    assert exc.block_index == 2
    assert exc.position == len(bad) - 3  # 0 基位置，指向出错的校验和字节


def test_lowercase_checksum_rejected():
    good = make_frame(1, b"abc")  # 校验和为 6E
    bad = good[:-3] + good[-3:].replace(b"E", b"e")
    assert bad != good
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bad),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    expect_violation(events, "CHECKSUM_FAILED")


def test_missing_crlf_rejected():
    good = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", good[:-2] + bytes([CR, CR])),
    ]
    expect_violation(events, "INVALID_TERMINATOR")


def test_non_identical_retransmission_rejected():
    f1 = make_frame(1, b"abc")
    f1_alt = make_frame(1, b"abd")  # 仅正文最后一个字节不同
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1_alt),
    ]
    exc = expect_violation(events, "NON_IDENTICAL_RETRANSMISSION")
    # f1_alt 布局：STX '1' a b [d] ETX cs cs CR LF，差异字节下标为 4
    assert exc.position == 4


def test_nak_must_be_followed_by_retransmission_not_eot():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", bytes([EOT])),
    ]
    expect_violation(events, "STAGE_ORDER")


def test_more_than_two_retransmissions_rejected():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),  # 第 3 个 NAK
    ]
    expect_violation(events, "RETRANSMISSION_LIMIT")


def test_two_retransmissions_then_ack_ok():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    result = audit("x", events)
    assert result["frame_count"] == 1
    assert result["retransmissions"] == 2


def test_receiver_may_only_ack_or_nak():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([ENQ])),
    ]
    expect_violation(events, "UNEXPECTED_REPLY")


def test_direction_violation_frame_from_receiver():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("receiver", f1),
    ]
    expect_violation(events, "DIRECTION_VIOLATION")


def test_incomplete_without_eot():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
    ]
    expect_violation(events, "INCOMPLETE_SESSION")


def test_truncated_mid_frame_rejected():
    # 最后一个块在帧内部截断 —— 不能被当作完整结果
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1[:4]),
    ]
    expect_violation(events, "INCOMPLETE_SESSION")


def test_trailing_data_after_eot_rejected():
    events = valid_events() + [("receiver", bytes([ACK]))]
    expect_violation(events, "TRAILING_DATA")


def test_payload_length_bounds():
    # 0 字节正文不合法
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"")),
    ]
    expect_violation(events, "INVALID_FRAME")

    # 241 字节正文不合法
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"A" * 241)),
    ]
    expect_violation(events, "FRAME_TOO_LONG")


def test_control_byte_in_payload_rejected():
    f = make_frame(1, b"ab\x01cd")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f),
    ]
    expect_violation(events, "INVALID_BODY")


def test_cr_allowed_inside_payload():
    payload = b"line1\rline2"
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, payload, terminator=ETX)),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    result = audit("x", events)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()


# ---- 请求解析与 HTTP 层 ----------------------------------------------------

def _post(events, piece=None, sender="analyzer-A"):
    decoded = chunks_for(events, piece) if piece else events
    body = {
        "sender": sender,
        "chunks": [
            {"direction": d, "data": base64.b64encode(raw).decode()}
            for d, raw in decoded
        ],
    }
    return client.post("/api/astm/sessions/audit", json=body)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_valid_cross_chunk_with_retransmission():
    resp = _post(valid_events(), piece=1)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["frame_count"] == 2
    assert data["retransmissions"] == 1
    assert data["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


def test_api_violation_reports_block_and_position():
    # 逐字节分块，块下标即出错字节所在块，position 恒为 0
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bytes([STX, ord("2"), ord("x"), ETX])),
    ]
    resp = _post(events, piece=1)
    assert resp.status_code == 422
    err = resp.json()
    assert err["ok"] is False
    assert err["code"] == "FRAME_NUMBER_SKIP"
    assert err["block_index"] == 3  # ENQ,ACK,STX 之后是帧号字节
    assert err["position"] == 0
    assert "global_offset" in err


def test_api_bad_base64_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": [{"direction": "sender", "data": "@@@@"}]},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "BAD_BASE64"


def test_api_bad_direction_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": [{"direction": "bus", "data": ""}]},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_DIRECTION"


def test_api_empty_chunks_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": []},
    )
    assert resp.status_code == 400


def test_parse_request_size_limit():
    big = base64.b64encode(b"\x00" * (1024 * 1024 + 1)).decode()
    with pytest.raises(Exception):
        parse_request({"sender": "x", "chunks": [{"direction": "sender", "data": big}]})


def test_parse_request_size_limit_code():
    big = base64.b64encode(b"\x00" * (1024 * 1024 + 1)).decode()
    from app.protocol import RequestError

    with pytest.raises(RequestError) as exc:
        parse_request({"sender": "x", "chunks": [{"direction": "sender", "data": big}]})
    assert exc.value.code == "SIZE_EXCEEDED"


def test_too_many_chunks_rejected():
    from app.protocol import MAX_CHUNKS, RequestError

    body = {
        "sender": "x",
        "chunks": [
            {"direction": "sender", "data": ""} for _ in range(MAX_CHUNKS + 1)
        ],
    }
    with pytest.raises(RequestError) as exc:
        parse_request(body)
    assert exc.value.code == "INVALID_REQUEST"


def test_max_size_valid_session_accepted():
    # 每帧 240 字节正文，拼到恰好接近 1 MiB 且合法
    target = 1024 * 1024 - 100
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    payloads = []
    remaining = target
    fn = 1
    while remaining > 0:
        size = min(240, remaining)
        data = bytes(0x41 + (i % 26) for i in range(size))
        payloads.append(data)
        events += [
            ("sender", make_frame(fn, data, terminator=ETB if remaining > 240 else ETX)),
            ("receiver", bytes([ACK])),
        ]
        fn = 1 if fn == 0 else (fn + 1 if fn < 7 else 0)
        remaining -= size
    events.append(("sender", bytes([EOT])))
    result = audit("x", events)
    assert result["payload_bytes"] == target
    assert result["sha256"] == hashlib.sha256(b"".join(payloads)).hexdigest()

