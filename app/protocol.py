"""ASTM E1381 风格会话复核引擎。

线路帧格式::

    STX FN PAYLOAD (ETB|ETX) HEX HEX CR LF

* ``FN``  为单字节帧号，取值 ``'1'``..``'7'``、``'0'``，按 1..7,0 循环；
* ``PAYLOAD`` 为 1..240 个允许的 ASTM 文本字节（0x20..0x7E，以及记录分隔 CR）；
* 两位大写十六进制校验和 = STX 之后一个字节起、到结束符（含）逐字节求和模 256；
* 校验和之后必须紧跟 CRLF。

会话次序（sender / receiver 为相对于请求 ``sender`` 的方向）::

    sender: ENQ
    receiver: ACK
    sender: frame [receiver: ACK | NAK -> sender 原样重传 ...]
    ...
    sender: EOT

NAK 后只允许原样重传当前帧，且重传至多两次（即同一帧最多收到 2 个 NAK）。

引擎在 *解码后的字节流* 上逐字节工作，调用方可以把捕获内容切成任意块——
块边界可以落在 STX/ETX/CRLF 等控制序列或帧内部中间，解析结果与切分方式无关。
所有协议错误都携带稳定错误码以及“首个出错块内”的 0 基字节位置。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import List, Tuple

# ---- 线路控制字符 -----------------------------------------------------------
STX = 0x02
ETX = 0x03
EOT = 0x04
ENQ = 0x05
ACK = 0x06
LF = 0x0A
CR = 0x0D
NAK = 0x15
ETB = 0x17

MAX_CHUNKS = 2000
MAX_TOTAL_BYTES = 1024 * 1024  # 1 MiB
MAX_PAYLOAD = 240

DIRECTION_SENDER = "sender"
DIRECTION_RECEIVER = "receiver"
DIRECTIONS = (DIRECTION_SENDER, DIRECTION_RECEIVER)

# 帧号循环：1,2,...,7,0,1,...
_FRAME_CYCLE = (1, 2, 3, 4, 5, 6, 7, 0)


class RequestError(ValueError):
    """请求本身格式不合格（400），与 ASTM 会话内容无关。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ProtocolViolation(Exception):
    """捕获到的字节流不满足合法 ASTM 会话要求（422）。"""

    def __init__(
        self,
        code: str,
        message: str,
        block_index: int,
        position: int,
        global_offset: int,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.block_index = block_index
        self.position = position
        self.global_offset = global_offset

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "block_index": self.block_index,
            "position": self.position,
            "global_offset": self.global_offset,
        }


def _is_allowed_text(b: int) -> bool:
    return 0x20 <= b <= 0x7E or b == CR


def parse_request(body: object) -> Tuple[str, List[Tuple[str, bytes]]]:
    """校验并解码 HTTP 请求体，返回 ``(sender, [(direction, bytes), ...])``。"""
    if not isinstance(body, dict):
        raise RequestError("INVALID_REQUEST", "请求体必须为 JSON 对象")

    sender = body.get("sender")
    if not isinstance(sender, str) or not sender.strip() or len(sender) > 128:
        raise RequestError("INVALID_REQUEST", "sender 必须为 1..128 字符的非空字符串")
    sender = sender.strip()

    chunks = body.get("chunks")
    if not isinstance(chunks, list) or not (1 <= len(chunks) <= MAX_CHUNKS):
        raise RequestError(
            "INVALID_REQUEST",
            f"chunks 必须为 1..{MAX_CHUNKS} 个元素的数组",
        )

    decoded: List[Tuple[str, bytes]] = []
    total = 0
    for i, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            raise RequestError("INVALID_REQUEST", f"块 {i} 必须为对象")
        direction = chunk.get("direction")
        if direction not in DIRECTIONS:
            raise RequestError(
                "INVALID_DIRECTION",
                f"块 {i} 的 direction 只能是 'sender' 或 'receiver'",
            )
        data = chunk.get("data")
        if not isinstance(data, str):
            raise RequestError("INVALID_REQUEST", f"块 {i} 的 data 必须为 Base64 字符串")
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raise RequestError("BAD_BASE64", f"块 {i} 不是合法 Base64")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise RequestError(
                "SIZE_EXCEEDED",
                f"解码后总字节数超过 {MAX_TOTAL_BYTES} 字节（1 MiB）",
            )
        decoded.append((direction, raw))

    return sender, decoded


# 会话阶段
_S_ENQ = "enq"                # 等待 sender 的 ENQ
_S_ENQ_ACK = "enq_ack"        # 等待 receiver 对 ENQ 的 ACK
_S_IDLE = "idle"              # 等待 sender 开始新帧（STX）或 EOT
_S_BODY = "body"              # 帧正文（含帧号）
_S_CKSUM1 = "cksum1"          # 校验和第 1 个十六进制字符
_S_CKSUM2 = "cksum2"          # 校验和第 2 个十六进制字符
_S_CR = "cr"                  # 结束后的 CR
_S_LF = "lf"                  # 结束后的 LF
_S_REPLY = "reply"            # 等待 receiver 的 ACK/NAK
_S_DONE = "done"              # EOT 之后，会话结束


class _Session:
    def __init__(self) -> None:
        self.state = _S_ENQ
        self.frame_count = 0
        self.retransmissions = 0

        self.fn_index = 0           # 下一个 *新* 帧在 _FRAME_CYCLE 中的下标
        self.payload = bytearray()    # 重组正文（不含帧号/控制符）
        self.pending: bytes = b""     # 最近一次已通过校验的帧（整帧线路字节）
        self.nak_count = 0            # 当前帧已收到的 NAK 数
        self.retrans = False          # 当前正在收的是否为重传帧
        self.rt_pos = 0               # 重传逐字节比对位置

        self.body = bytearray()
        self.terminator = 0
        self.cksum = bytearray()

        # 位置追踪
        self.global_offset = 0
        self.block_index = 0
        self.block_len = 0

    def fail(self, code: str, message: str, pos: int) -> None:
        raise ProtocolViolation(
            code, message, self.block_index, pos, self.global_offset
        )

    def rt_match(self, b: int, pos: int) -> None:
        """重传帧必须与上一帧线路字节完全一致。"""
        if not self.retrans:
            return
        if self.rt_pos >= len(self.pending) or b != self.pending[self.rt_pos]:
            self.fail(
                "NON_IDENTICAL_RETRANSMISSION",
                "NAK 后必须原样重传当前帧",
                pos,
            )
        self.rt_pos += 1

    def feed(self, direction: str, raw: bytes, block_index: int, block_len: int) -> None:
        self.block_index = block_index
        self.block_len = block_len
        for pos, b in enumerate(raw):
            self._byte(direction, b, pos)
            self.global_offset += 1

    def _byte(self, direction: str, b: int, pos: int) -> None:
        st = self.state

        if st == _S_ENQ:
            if direction != DIRECTION_SENDER:
                self.fail("DIRECTION_VIOLATION", "会话必须由 sender 以 ENQ 开始", pos)
            if b != ENQ:
                self.fail("STAGE_ORDER", "会话必须以 ENQ 开始", pos)
            self.state = _S_ENQ_ACK
            return

        if st == _S_ENQ_ACK:
            if direction != DIRECTION_RECEIVER:
                self.fail("DIRECTION_VIOLATION", "ENQ 之后必须由 receiver 应答", pos)
            if b != ACK:
                # 本阶段的 NAK 会要求重新建立链路，不属于允许的帧重传流程。
                self.fail("STAGE_ORDER", "ENQ 之后只接受 ACK", pos)
            self.state = _S_IDLE
            return

        if st == _S_DONE:
            self.fail("TRAILING_DATA", "EOT 之后不允许再有任何字节", pos)

        if st == _S_REPLY:
            if direction != DIRECTION_RECEIVER:
                self.fail("DIRECTION_VIOLATION", "帧结束后必须由 receiver 应答 ACK/NAK", pos)
            if b == ACK:
                self.nak_count = 0
                self.state = _S_IDLE
                return
            if b == NAK:
                if self.nak_count >= 2:
                    self.fail(
                        "RETRANSMISSION_LIMIT",
                        "同一帧最多重传两次（NAK 至多 2 个）",
                        pos,
                    )
                self.nak_count += 1
                self.state = _S_IDLE  # sender 必须立刻重传
                return
            self.fail("UNEXPECTED_REPLY", "receiver 只能回复 ACK 或 NAK", pos)

        # ---- 以下状态均属于 sender 发帧阶段 ----
        if direction != DIRECTION_SENDER:
            self.fail("DIRECTION_VIOLATION", "当前阶段只允许 sender 发送", pos)

        if st == _S_IDLE:
            if self.nak_count > 0:
                # NAK 之后只能立刻原样重传当前帧，不允许 EOT、不允许发新帧。
                if b != STX:
                    self.fail(
                        "STAGE_ORDER",
                        "NAK 之后只能原样重传当前帧",
                        pos,
                    )
            elif b == EOT:
                self.state = _S_DONE
                return
            elif b != STX:
                self.fail("STAGE_ORDER", "此处只允许 STX 开始新帧或 EOT 结束会话", pos)
            self.body = bytearray()
            self.cksum = bytearray()
            self.retrans = self.nak_count > 0
            self.rt_pos = 0
            if self.retrans:
                # pending 第一字节必为 STX
                self.rt_match(b, pos)
            self.state = _S_BODY
            return

        if st == _S_BODY:
            if b in (ETB, ETX):
                if len(self.body) < 2 or len(self.body) - 1 > MAX_PAYLOAD:
                    self.fail(
                        "INVALID_FRAME",
                        f"帧正文（不含帧号）长度必须为 1..{MAX_PAYLOAD} 字节",
                        pos,
                    )
                self.terminator = b
                self.rt_match(b, pos)
                self.state = _S_CKSUM1
                return
            # 首字节是帧号
            if not self.body:
                if not self.retrans:
                    expected_fn = _FRAME_CYCLE[self.fn_index]
                    if b != ord(str(expected_fn)):
                        self.fail(
                            "FRAME_NUMBER_SKIP",
                            f"帧号必须为 {expected_fn}，且按 1..7,0 循环",
                            pos,
                        )
                # 重传帧的帧号由 rt_match 逐字节原样比对保证。
            if not _is_allowed_text(b):
                self.fail("INVALID_BODY", "正文包含不允许的 ASTM 文本字节", pos)
            if len(self.body) >= 1 + MAX_PAYLOAD:
                self.fail(
                    "FRAME_TOO_LONG",
                    f"帧正文超过 {MAX_PAYLOAD} 字节",
                    pos,
                )
            self.rt_match(b, pos)
            self.body.append(b)
            return

        if st == _S_CKSUM1:
            if b not in b"0123456789ABCDEF":
                self.fail("CHECKSUM_FAILED", "校验和必须为两位大写十六进制字符", pos)
            self.rt_match(b, pos)
            self.cksum.append(b)
            self.state = _S_CKSUM2
            return

        if st == _S_CKSUM2:
            if b not in b"0123456789ABCDEF":
                self.fail("CHECKSUM_FAILED", "校验和必须为两位大写十六进制字符", pos)
            self.rt_match(b, pos)
            self.cksum.append(b)
            expected = (sum(self.body) + self.terminator) & 0xFF
            if int(self.cksum, 16) != expected:
                self.fail(
                    "CHECKSUM_FAILED",
                    f"校验和错误：收到 {self.cksum.decode()}，"
                    f"应为 {expected:02X}",
                    pos,
                )
            self.state = _S_CR
            return

        if st == _S_CR:
            self.rt_match(b, pos)
            if b != CR:
                self.fail("INVALID_TERMINATOR", "校验和之后必须为 CRLF", pos)
            self.state = _S_LF
            return

        if st == _S_LF:
            self.rt_match(b, pos)
            if b != LF:
                self.fail("INVALID_TERMINATOR", "校验和之后必须为 CRLF", pos)
            self._frame_complete()
            return

    def _frame_complete(self) -> None:
        wire = bytes([STX]) + bytes(self.body) + bytes(
            [self.terminator]
        ) + bytes(self.cksum) + bytes([CR, LF])

        if self.retrans:
            # 逐字节比对已保证一致；这里防御性兜底长度。
            if self.rt_pos != len(self.pending):
                # 位置信息在逐字节比对阶段已给出，正常不会走到这里。
                raise ProtocolViolation(
                    "NON_IDENTICAL_RETRANSMISSION",
                    "NAK 后必须原样重传当前帧",
                    self.block_index,
                    self.block_len - 1,
                    self.global_offset,
                )
            self.retransmissions += 1
        else:
            self.frame_count += 1
            self.payload.extend(self.body[1:])  # 去掉帧号
            self.fn_index = (self.fn_index + 1) % 8
        self.pending = wire
        self.state = _S_REPLY

    def finish(self, last_block_index: int, last_block_len: int) -> dict:
        if self.state != _S_DONE:
            raise ProtocolViolation(
                "INCOMPLETE_SESSION",
                "会话不完整：sender 必须依次完成 ENQ、逐帧发送并以 EOT 结束",
                last_block_index,
                last_block_len,
                self.global_offset,
            )
        payload_bytes = bytes(self.payload)
        return {
            "ok": True,
            "payload": payload_bytes.decode("latin-1"),
            "payload_bytes": len(payload_bytes),
            "frame_count": self.frame_count,
            "retransmissions": self.retransmissions,
            "sha256": hashlib.sha256(payload_bytes).hexdigest(),
        }


def audit(sender: str, decoded: List[Tuple[str, bytes]]) -> dict:
    """复核整段捕获；decoded 为 ``(direction, raw_bytes)`` 列表。"""
    session = _Session()
    last_index = 0
    last_len = 0
    for index, (direction, raw) in enumerate(decoded):
        if raw:
            last_index = index
            last_len = len(raw)
        session.feed(direction, raw, index, len(raw))
    result = session.finish(last_index, last_len)
    result["sender"] = sender
    # 重新排一下字段顺序，便于阅读
    return {
        "ok": True,
        "sender": sender,
        "payload": result["payload"],
        "payload_bytes": result["payload_bytes"],
        "frame_count": result["frame_count"],
        "retransmissions": result["retransmissions"],
        "sha256": result["sha256"],
    }
