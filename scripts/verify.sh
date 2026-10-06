#!/bin/sh
# 一次性校验：等 API 健康后执行单元测试、构建检查与 API 冒烟，
# 全部通过以 0 退出，任一失败即以非零码退出。
set -eu

BASE_URL="${API_BASE_URL:-http://api:8000}"

echo "==> 等待 API 健康检查通过：${BASE_URL}/health"
python - <<'PY'
import os, sys, time, urllib.request
base = os.environ.get("API_BASE_URL", "http://api:8000")
deadline = time.time() + 30
last = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/health", timeout=3) as resp:
            if resp.status == 200:
                print("API 已就绪")
                sys.exit(0)
    except OSError as exc:
        last = exc
    time.sleep(0.5)
print(f"API 健康检查超时：{last}", file=sys.stderr)
sys.exit(1)
PY

echo "==> 1/3 代码测试（pytest）"
python -m pytest -q tests

echo "==> 2/3 构建检查（字节码编译 + 应用导入）"
python -m compileall -q app scripts
python -c "from app.main import app; print('应用导入成功：', app.title)"

echo "==> 3/3 API 冒烟（跨块切分 + NAK 重传）"
python scripts/smoke.py "${BASE_URL}"

echo "==> 全部校验通过"
