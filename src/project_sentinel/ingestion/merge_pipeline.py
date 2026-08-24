"""Trộn finding SAST và DAST thành một file duy nhất.

Chuỗi này từng chỉ sống trong `orchestrator/steps/ingest.py`, nên đường chạy thủ
công không với tới được: `make normalize` cho ra 23 finding chỉ có SAST, trong khi
cùng cái tên đó ở luồng run có 37. Hệ quả không chỉ là hiểu nhầm — `cli.py` đặt
mặc định `analyze --input` chính là file đó, nên `make analyze` chưa bao giờ nhìn
thấy một finding DAST nào.

Đưa vào đây để hai đường gọi cùng một hàm và không thể lệch nhau lần nữa.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any


from project_sentinel.analysis.correlation import correlate, parse_gateway_access_log
from project_sentinel.ingestion.merge_findings import merge_files
from project_sentinel.ingestion.zap_normalizer import run_normalize


def normalise_finding_fields(findings: list[dict[str, Any]]) -> None:
    """Ép cwe/owasp về list cho mọi finding, sửa tại chỗ.

    zap_normalizer cho list, normalizer.py của OpenGrep cho giá trị vô hướng. Để
    cả hai hình dạng vào findings.json thì mọi thứ đọc nó về sau — prompt,
    validator, report — đều phải xử lý hai trường hợp.
    """
    for item in findings:
        for field in ("cwe", "owasp"):
            value = item.get(field)
            if value is None or value == "":
                item[field] = []
            elif not isinstance(value, list):
                item[field] = [str(value)]


def merge_normalized(
    *,
    sast_findings: Path,
    zap_alerts: Path | None,
    gateway_log: Path | None,
    output: Path,
    project_root: Path,
) -> dict[str, int]:
    """Trộn SAST + DAST vào `output`.

    Không có alert ZAP thì trả về SAST-only và KHÔNG báo lỗi: máy không chạy
    Docker vẫn phải normalize được.

    `correlate` chỉ chạy khi có DAST, đúng như hành vi cũ của `step_normalize`.
    Không có traffic thật thì không có gì để đối chiếu, và gắn một khối
    `runtime_evidence` rỗng vào mọi finding tĩnh chỉ làm nhiễu file.
    """
    payload = json.loads(sast_findings.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError(f"File SAST chuẩn hoá không có mảng findings: {sast_findings}")

    zap_added = 0
    correlated = 0

    if zap_alerts is not None and zap_alerts.is_file():
        # Dữ liệu từ container ZAP là dữ liệu KHÔNG đáng tin chảy thẳng vào prompt
        # LLM. Thu hồi quyền ghi của group/other trước khi đọc.
        with contextlib.suppress(OSError):
            # Tệp do container tạo; UID host khác UID container thì không chmod
            # được. Không làm sập lần chạy vì chuyện này.
            zap_alerts.chmod(0o600)

        output.parent.mkdir(parents=True, exist_ok=True)
        zap_normalized = output.parent / "zap-findings.json"
        zap_added = len(run_normalize(zap_alerts, zap_normalized))

        # Ghi ra file thứ ba rồi đọc lại, KHÔNG merge_files([target, x], target):
        # đọc và ghi cùng một đường dẫn chỉ chạy được nhờ merge_files tình cờ đọc
        # hết trước khi ghi. Dựa vào một chi tiết nội tại như vậy là mong manh.
        combined = output.parent / ".findings.merged.json"
        merge_files([sast_findings, zap_normalized], combined)
        payload = json.loads(combined.read_text(encoding="utf-8"))
        combined.unlink()

        normalise_finding_fields(payload["findings"])
        payload["findings"] = correlate(
            payload["findings"],
            parse_gateway_access_log(gateway_log) if gateway_log else {"endpoints": []},
            project_root=project_root,
        )
        correlated = sum(
            1
            for f in payload["findings"]
            if (f.get("runtime_evidence") or {}).get("strength", "no_route") != "no_route"
        )

    payload["count"] = len(payload["findings"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    return {
        "findings": len(payload["findings"]),
        "zap_findings": zap_added,
        "correlated": correlated,
    }


DEFAULT_SAST = Path("artifacts/normalized/sast-findings.json")
DEFAULT_ZAP_ALERTS = Path("artifacts/raw/zap.json")
DEFAULT_GATEWAY_LOG = Path("artifacts/dast/gateway-access.log")
DEFAULT_OUTPUT = Path("artifacts/normalized/findings.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Tron finding SAST va DAST thanh mot file chuan hoa duy nhat."
    )
    parser.add_argument("--sast", type=Path, default=DEFAULT_SAST)
    parser.add_argument("--zap-alerts", type=Path, default=DEFAULT_ZAP_ALERTS)
    parser.add_argument("--gateway-log", type=Path, default=DEFAULT_GATEWAY_LOG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    try:
        counts = merge_normalized(
            sast_findings=args.sast,
            zap_alerts=args.zap_alerts,
            gateway_log=args.gateway_log,
            output=args.output,
            project_root=args.project_root,
        )
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Merged {counts['findings']} findings "
        f"({counts['zap_findings']} from ZAP) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

