#!/usr/bin/env bash
# Lop vo mong goi vao client Python. MOT ban cai dat duy nhat cho ca host lan
# container: hai ban song song se troi khoi nhau, dung loai loi da xay ra voi
# ingestion/normalizer.py va ingestion/zap_normalizer.py.
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
report_path="${1:-$project_root/artifacts/raw/zap.json}"
gateway_log="${2:-$project_root/artifacts/dast/gateway-access.log}"

python="${SENTINEL_PYTHON:-$project_root/.venv/bin/python3}"
if [ ! -x "$python" ]; then python=python3; fi

exec "$python" -m project_sentinel.dast.zap_client "$report_path" "$gateway_log"
