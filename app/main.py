"""FastAPI 入口：ASTM 会话复核接口与健康检查。"""

from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .protocol import ProtocolViolation, RequestError, audit, parse_request

app = FastAPI(
    title="ASTM 会话复核服务",
    description="复核分析仪与主机之间按块捕获的 ASTM 文本传输。",
    version="1.0.0",
)


@app.exception_handler(RequestError)
async def _request_error_handler(_request: Request, exc: RequestError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"ok": False, "code": exc.code, "message": exc.message},
    )


@app.exception_handler(ProtocolViolation)
async def _violation_handler(_request: Request, exc: ProtocolViolation) -> JSONResponse:
    return JSONResponse(status_code=422, content={"ok": False, **exc.to_dict()})


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/astm/sessions/audit")
async def audit_session(request: Request) -> dict:
    raw = await request.body()
    try:
        body = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RequestError("INVALID_REQUEST", "请求体必须为合法 UTF-8 JSON")
    sender, decoded = parse_request(body)
    return audit(sender, decoded)
