"""针对运行中的服务执行 API 冒烟。

用法::

    python scripts/smoke.py [BASE_URL]

覆盖：健康检查、跨块（每块 1 字节）合法会话且含 NAK 重传、校验失败、
方向越权、非原样重传、坏 Base64。全部通过则以退出码 0 结束。
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


def _read_slices(slices: list[dict], raws: list[bytes]) -> bytes:
    """按 [{chunkIndex, offset, length}] 半开区间重组字节。"""
    out = bytearray()
    for s in slices:
        ci, off, ln = s["chunkIndex"], s["offset"], s["length"]
        if not isinstance(ln, int) or ln < 1:
            raise ValueError("length 必须为正整数")
        if not (0 <= off and off + ln <= len(raws[ci])):
            raise ValueError("区间越界")
        out += raws[ci][off : off + ln]
    return bytes(out)


def check_provenance(body: dict, chunks: list[dict], expected_wire: list[bytes]) -> bool:
    """校验 byte_provenance 证据。

    * 每个逻辑帧返回 frameNumber、半开 payloadRange、每次发送尝试（ACK/NAK）；
    * 每次尝试的 chunks 区间重组出该次完整帧线路字节；
    * payloadSlices 只来自最终 ACK 尝试，重组出全部正文；
    * 每个输出正文字节恰好映射到一个获接纳捕获位置（无重复、NAK 位置不贡献）。

    ``expected_wire`` 为每个逻辑帧的线路字节（重传内容相同）。
    """
    try:
        evidence = body.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("type") != "byte_provenance":
            return False
        frames = evidence.get("frames")
        raws = [base64.b64decode(c["data"]) for c in chunks]
        dirs = [c["direction"] for c in chunks]
        if not isinstance(frames, list) or len(frames) != body.get("frame_count"):
            return False

        cursor = 0
        reassembled = b""
        accepted: set[tuple[int, int]] = set()
        for fi, fr in enumerate(frames):
            if fr.get("frameNumber") != fi + 1:
                return False
            attempts = fr.get("attempts")
            if not isinstance(attempts, list) or not attempts:
                return False
            results = [a.get("result") for a in attempts]
            if results[-1] != "ACK" or any(r != "NAK" for r in results[:-1]):
                return False

            nak_positions: set[tuple[int, int]] = set()
            for ai, att in enumerate(attempts):
                if _read_slices(att.get("chunks"), raws) != expected_wire[fi]:
                    return False  # 该次尝试必须覆盖完整帧
                for s in att["chunks"]:
                    if dirs[s["chunkIndex"]] != "sender":
                        return False
                    for j in range(s["offset"], s["offset"] + s["length"]):
                        if results[ai] == "NAK":
                            nak_positions.add((s["chunkIndex"], j))
                # 同块连续来源必须已合并：相邻区间不得可再合并
                prev = None
                for s in att["chunks"]:
                    if prev is not None:
                        pci, p = prev
                        if s["chunkIndex"] == pci and s["offset"] == p["offset"] + p["length"]:
                            return False
                    prev = (s["chunkIndex"], s)

            slices = fr.get("payloadSlices")
            payload_wire = expected_wire[fi][2:-5]  # 去 STX FN 与 TERM cs cs CR LF
            if _read_slices(slices, raws) != payload_wire:
                return False

            rng = fr.get("payloadRange")
            if rng != [cursor, cursor + len(payload_wire)]:
                return False

            for s in slices:
                if dirs[s["chunkIndex"]] != "sender":
                    return False
                for j in range(s["offset"], s["offset"] + s["length"]):
                    pos = (s["chunkIndex"], j)
                    if pos in accepted or pos in nak_positions:
                        return False  # 每字节恰好一个获接纳位置，且不来自 NAK 尝试
                    accepted.add(pos)
            reassembled += payload_wire
            cursor += len(payload_wire)

        if body.get("payload_bytes") != cursor:
            return False
        return reassembled == b"".join(expected_wire[i][2:-5] for i in range(len(frames)))
    except (KeyError, TypeError, ValueError, IndexError, AssertionError):
        return False


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
    )
    check("跨块合法会话（含 1 次重传）返回重组结果", ok, f"status={status}, body={body}")

    # 1b) 启用 byte_provenance：跨块 + NAK 重传来源映射
    submit_chunks = to_chunks(events, piece=1)
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "evidence": "byte_provenance",
            "chunks": submit_chunks,
        },
    )
    ok = status == 200 and check_provenance(body, submit_chunks, [f1, f2])
    check(
        "byte_provenance：每字节唯一映射到获 ACK 位置，NAK 尝试不贡献正文",
        ok,
        f"status={status}, body={body}",
    )

    # 1b-2) 较大块切分（7 字节/块）：同块连续来源必须合并
    submit_chunks7 = to_chunks(events, piece=7)
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "evidence": "byte_provenance",
            "chunks": submit_chunks7,
        },
    )

    def has_merged_slice(b: dict) -> bool:
        try:
            for fr in b["evidence"]["frames"]:
                if any(s["length"] > 1 for s in fr["payloadSlices"]):
                    return True
                for att in fr["attempts"]:
                    if any(s["length"] > 1 for s in att["chunks"]):
                        return True
        except (KeyError, TypeError):
            return False
        return False

    ok = (
        status == 200
        and check_provenance(body, submit_chunks7, [f1, f2])
        and has_merged_slice(body)
    )
    check("byte_provenance：同块连续来源合并为半开区间", ok, f"status={status}, body={body}")

    # 1c) 省略 evidence 时响应不含证据字段（语义不变）
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(events, piece=1)},
    )
    check(
        "省略 evidence 时响应不包含证据字段",
        status == 200 and "evidence" not in body,
        f"status={status}, body={body}",
    )

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

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n冒烟结果：{len(RESULTS) - len(failed)}/{len(RESULTS)} 通过")
    if failed:
        print("失败项：" + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
