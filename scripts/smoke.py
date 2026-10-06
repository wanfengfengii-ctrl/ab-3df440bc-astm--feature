"""针对运行中的服务执行 API 冒烟。

用法::

    python scripts/smoke.py [BASE_URL]

覆盖：健康检查、跨块（每块 1 字节）合法会话且含 NAK 重传、校验失败、
方向越权、非原样重传、坏 Base64，以及 evidence=byte_provenance 下的
跨块与重传来源映射（每个输出正文字节恰好映射到一个获接纳的捕获位置）。
全部通过则以退出码 0 结束。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

STX, ETX, EOT, ENQ, ACK, NAK, CR, LF = 0x02, 0x03, 0x04, 0x05, 0x06, 0x15, 0x0D, 0x0A
ETB = 0x17


def make_frame(fn: int, payload: bytes, terminator: int = ETB) -> bytes:
    body = bytes([ord(str(fn))]) + payload
    checksum = (sum(body) + terminator) & 0xFF
    return bytes([STX]) + body + bytes([terminator]) + f"{checksum:02X}".encode() + bytes([CR, LF])


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, body = request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return
        except OSError as exc:  # 服务尚未就绪
            last_error = exc
        time.sleep(0.5)
    raise SystemExit(f"健康检查在 {timeout}s 内未通过：{last_error}")


def to_chunks(events, piece: int = 1) -> list[dict]:
    chunks: list[dict] = []
    for direction, raw in events:
        for i in range(0, len(raw), piece):
            chunks.append(
                {
                    "direction": direction,
                    "data": base64.b64encode(raw[i : i + piece]).decode(),
                }
            )
    return chunks


def read_slice(chunks: list[dict], seg: dict) -> bytes:
    """按来源段定位从提交块中读回字节。"""
    raw = base64.b64decode(chunks[seg["chunkIndex"]]["data"])
    return raw[seg["offset"] : seg["offset"] + seg["length"]]


def provenance_ok(body: dict, chunks: list[dict], expected_payload: bytes) -> bool:
    """校验 byte_provenance 证据的来源映射不变量。

    每个输出正文字节恰好映射到一个获接纳（ACK）的捕获位置；每次发送尝试
    的分段拼出完整线路帧；仅最后一试为 ACK；重传后来源指向获接纳的副本。
    """
    evidence = body.get("evidence")
    if not isinstance(evidence, dict):
        return False
    frames = evidence.get("frames")
    if not isinstance(frames, list) or len(frames) != body.get("frame_count"):
        return False
    pos = 0
    retrans = 0
    covered: set[tuple[int, int]] = set()
    for frame in frames:
        rng = frame.get("payloadRange") or {}
        if rng.get("start") != pos or not isinstance(rng.get("end"), int):
            return False
        attempts = frame.get("attempts") or []
        if not attempts or attempts[-1].get("result") != "ACK":
            return False
        if any(a.get("result") != "NAK" for a in attempts[:-1]):
            return False
        retrans += len(attempts) - 1
        ack_chunks = set()
        nak_chunks = set()
        for att in attempts:
            segments = att.get("segments") or []
            if not segments:
                return False
            wire = b"".join(read_slice(chunks, s) for s in segments)
            if not (wire.startswith(bytes([STX])) and wire.endswith(bytes([CR, LF]))):
                return False
            chunk_ids = {s["chunkIndex"] for s in segments}
            if att is attempts[-1]:
                ack_chunks = chunk_ids
            else:
                nak_chunks |= chunk_ids
        # 重传后来源必须指向获接纳的副本，而非被 NAK 的首次发送
        if nak_chunks & ack_chunks:
            return False
        slices = frame.get("payloadSlices") or []
        if any(s["chunkIndex"] not in ack_chunks for s in slices):
            return False
        data = b"".join(read_slice(chunks, s) for s in slices)
        if data != expected_payload[rng["start"] : rng["end"]]:
            return False
        for s in slices:
            for i in range(s["offset"], s["offset"] + s["length"]):
                key = (s["chunkIndex"], i)
                if key in covered:
                    return False
                covered.add(key)
        pos = rng["end"]
    return (
        pos == len(expected_payload) == body.get("payload_bytes")
        and retrans == body.get("retransmissions")
    )


RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))


def main() -> int:
    wait_for_health()
    check("健康检查 GET /health", True)

    f1 = make_frame(1, b"H|\\^&|||analyzer^1.0")
    f2 = make_frame(2, b"O|1||^^^ASTM^M|||", terminator=ETX)
    expected_payload = b"H|\\^&|||analyzer^1.0" + b"O|1||^^^ASTM^M|||"
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),  # 原样重传
        ("receiver", bytes([ACK])),
        ("sender", f2),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]

    # 1) 合法会话：跨块（1 字节/块）+ 重传
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(events, piece=1)},
    )
    ok = (
        status == 200
        and body.get("frame_count") == 2
        and body.get("retransmissions") == 1
        and body.get("sha256") == hashlib.sha256(expected_payload).hexdigest()
        and body.get("payload_bytes") == len(expected_payload)
        and "evidence" not in body  # 省略 evidence 时响应语义不变
    )
    check("跨块合法会话（含 1 次重传）返回重组结果", ok, f"status={status}, body={body}")

    # 2) 校验失败：破坏 f2 的校验和，且跨块提交
    bad_f2 = bytearray(f2)
    bad_f2[-3] = ord("0") if bad_f2[-3] != ord("0") else ord("1")
    bad_events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"abc")),
        ("receiver", bytes([ACK])),
        ("sender", bytes(bad_f2)),
    ]
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(bad_events, piece=3)},
    )
    ok = (
        status == 422
        and body.get("code") == "CHECKSUM_FAILED"
        and isinstance(body.get("block_index"), int)
        and isinstance(body.get("position"), int)
    )
    check("校验失败被拒绝并定位首个出错块位置", ok, f"status={status}, body={body}")

    # 3) 方向越权：会话由 receiver 发起
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "chunks": to_chunks(
                [("receiver", bytes([ENQ]))],
                piece=1,
            ),
        },
    )
    check(
        "方向越权被拒绝（DIRECTION_VIOLATION）",
        status == 422 and body.get("code") == "DIRECTION_VIOLATION",
        f"status={status}, body={body}",
    )

    # 4) 非原样重传：NAK 后帧内容被改动
    f_good = make_frame(1, b"abc")
    f_changed = make_frame(1, b"abd")
    rt_events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f_good),
        ("receiver", bytes([NAK])),
        ("sender", f_changed),
    ]
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(rt_events, piece=2)},
    )
    check(
        "非原样重传被拒绝（NON_IDENTICAL_RETRANSMISSION）",
        status == 422 and body.get("code") == "NON_IDENTICAL_RETRANSMISSION",
        f"status={status}, body={body}",
    )

    # 5) 坏 Base64 → 400
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": [{"direction": "sender", "data": "@@@"}]},
    )
    check(
        "坏 Base64 返回 400（BAD_BASE64）",
        status == 400 and body.get("code") == "BAD_BASE64",
        f"status={status}, body={body}",
    )

    # 6) 字节来源映射：evidence=byte_provenance，跨块（3 字节/块）+ NAK 重传
    prov_chunks = to_chunks(events, piece=3)
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "evidence": "byte_provenance",
            "chunks": prov_chunks,
        },
    )
    ok = status == 200 and provenance_ok(body, prov_chunks, expected_payload)
    check(
        "字节来源映射：跨块 + 重传会话可追溯到获接纳位置",
        ok,
        f"status={status}, body={body}",
    )

    # 7) 非法 evidence 取值 → 400
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "evidence": "full",
            "chunks": to_chunks(events, piece=1),
        },
    )
    check(
        "非法 evidence 取值返回 400（INVALID_REQUEST）",
        status == 400 and body.get("code") == "INVALID_REQUEST",
        f"status={status}, body={body}",
    )

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n冒烟结果：{len(RESULTS) - len(failed)}/{len(RESULTS)} 通过")
    if failed:
        print("失败项：" + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
