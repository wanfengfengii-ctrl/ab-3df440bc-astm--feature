# ASTM 会话复核服务

复核检验分析仪与主机之间按块捕获的 ASTM（E1381 风格）文本传输，避免采集分块或重传掩盖不完整结果。

## 协议规则

发送方（`sender`）必须依次完成：

1. `ENQ`（0x05）建链，接收方（`receiver`）只能回 `ACK`（0x06）；
2. 逐帧发送，每帧后接收方只能回 `ACK` 或 `NAK`（0x15）；
3. 以 `EOT`（0x04）结束。

帧格式：

```
STX FN PAYLOAD (ETB|ETX) HEX HEX CR LF
```

- `FN`：单字节帧号，按 `1..7, 0` 循环；
- `PAYLOAD`：1..240 个允许的 ASTM 文本字节（`0x20..0x7E` 及记录分隔 `CR`）；
- 校验和：`STX` 后一个字节起、到 `ETB/ETX`（含）逐字节求和模 256，两位**大写**十六进制；
- 校验和后必须紧跟 `CRLF`。

重传：收到 `NAK` 后只能**原样**重传当前帧，同一帧至多重传两次（至多 2 个 `NAK`）。

请求按捕获顺序提交 1..2000 个块，每块带方向（`sender`/`receiver`）和 Base64 数据，块边界可落在任意控制字节或数据帧内部（服务逐字节重组，结果与切分方式无关）；解码总量不超过 1 MiB。

## 接口

### `POST /api/astm/sessions/audit`

```json
{
  "sender": "analyzer-A",
  "chunks": [
    {"direction": "sender", "data": "BQ=="},
    {"direction": "receiver", "data": "Bg=="}
  ]
}
```

合法会话返回 `200`：

```json
{
  "ok": true,
  "sender": "analyzer-A",
  "payload": "H|\\^&|||analyzer^1.0O|1||^^^ASTM^M|||",
  "payload_bytes": 38,
  "frame_count": 2,
  "retransmissions": 1,
  "sha256": "…"
}
```

协议违例返回 `422`，错误码稳定，并给出**首个出错块内**的 0 基位置 `position` 及全局偏移 `global_offset`：

```json
{
  "ok": false,
  "code": "CHECKSUM_FAILED",
  "message": "校验和错误：收到 00，应为 6E",
  "block_index": 6,
  "position": 7,
  "global_offset": 41
}
```

错误码：

| 代码 | 含义 |
| --- | --- |
| `DIRECTION_VIOLATION` | 任何方向越权（阶段由另一方向发起） |
| `STAGE_ORDER` | 阶段失序（未以 ENQ 开始、NAK 后未立即重传等） |
| `FRAME_NUMBER_SKIP` | 帧号未按 1..7,0 循环（跳变） |
| `NON_IDENTICAL_RETRANSMISSION` | NAK 后未原样重传当前帧 |
| `RETRANSMISSION_LIMIT` | 同一帧重传超过两次 |
| `CHECKSUM_FAILED` | 校验和错误或非两位大写十六进制 |
| `INVALID_TERMINATOR` | 校验和后不是 CRLF |
| `INVALID_BODY` / `FRAME_TOO_LONG` / `INVALID_FRAME` | 正文字节非法或长度越界 |
| `UNEXPECTED_REPLY` | receiver 回复了 ACK/NAK 以外的字节 |
| `INCOMPLETE_SESSION` | 捕获在帧/应答中间结束，未到 EOT |
| `TRAILING_DATA` | EOT 之后还有字节 |

请求本身格式问题返回 `400`：`INVALID_REQUEST`、`INVALID_DIRECTION`、`BAD_BASE64`、`SIZE_EXCEEDED`。

### `GET /health`

返回 `{"status": "ok"}`，供容器健康检查使用。

## 运行（Docker Compose）

```bash
# 宿主机端口可通过环境变量配置
ASTM_HOST_PORT=8080 docker compose up --build
```

- `api`：常驻 API 服务，带健康检查；
- `verify`：一次性服务，等 `api` 健康后依次执行
  单元测试（pytest）、构建检查（字节码编译 + 应用导入）、
  含跨块切分与 NAK 重传的 API 冒烟，以退出码报告结果后自行退出：

```bash
docker compose up --build verify
# 退出码 0 即全部通过
docker compose ps   # verify 已退出，api 继续运行
```

## 本地开发

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                      # 代码测试
uvicorn app.main:app --port 8000 &
python scripts/smoke.py                  # API 冒烟
```
