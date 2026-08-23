"""Điều khiển ZAP daemon qua API nội bộ.

Container `web` KHÔNG có Docker CLI và KHÔNG có docker socket — đây là có ý, xem
`docs/superpowers/specs/2026-08-23-dast-daemon-api-design.md` §1.1. Nên nó không thể
`docker compose run zap` như script cũ, cũng không thể `docker compose logs gateway-dast`
để lấy bằng chứng. Thay vào đó nó nói chuyện với một daemon ZAP chạy sẵn trên mạng nội
bộ, và đọc log của lane DAST từ một volume dùng chung.

Hai hàm `_assert_*` ở cuối file là bản sao ngữ nghĩa của hai kiểm tra trong
`scripts/scan-zap.sh`: bằng chứng traffic thật sự đi qua lane DAST, và khoá DAST không
rò rỉ ra artifact. Mất một trong hai là mất lý do tồn tại của Gateway đứng trước WebGoat.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_PLAN = "/zap/plans/scan-plan.yaml"
DEFAULT_GATEWAY_LOG = Path("/var/log/sentinel/dast-access.log")


class DastError(RuntimeError):
    """DAST không hoàn thành. `step_scan` bắt lỗi này và ghi `skipped`."""


@dataclass(frozen=True)
class ZapConfig:
    base_url: str
    api_key: str
    dast_key: str
    dast_header: str = "X-Sentinel-DAST-Key"
    plan_path: str = DEFAULT_PLAN
    gateway_log_path: Path = DEFAULT_GATEWAY_LOG
    ready_timeout_s: float = 120.0
    plan_timeout_s: float = 600.0
    poll_interval_s: float = 2.0

    @classmethod
    def from_env(cls) -> ZapConfig:
        dast_key = os.getenv("SENTINEL_DAST_API_KEY", "")
        api_key = os.getenv("SENTINEL_ZAP_API_KEY", "")
        if not dast_key or not api_key:
            raise DastError(
                "Thieu SENTINEL_DAST_API_KEY hoac SENTINEL_ZAP_API_KEY trong moi truong"
            )
        return cls(
            base_url=os.getenv("SENTINEL_ZAP_URL", "http://zap:8090"),
            api_key=api_key,
            dast_key=dast_key,
            gateway_log_path=Path(
                os.getenv("SENTINEL_DAST_LOG", str(DEFAULT_GATEWAY_LOG))
            ),
        )


def _http_call(config: ZapConfig) -> Callable[[str, dict[str, str]], dict]:
    def call(path: str, params: dict[str, str]) -> dict:
        query = urllib.parse.urlencode({**params, "apikey": config.api_key})
        url = f"{config.base_url}/JSON/{path}/?{query}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            # KHONG bao gio dua `url` vao thong diep: query string cua no chua apikey.
            raise DastError(
                f"Goi ZAP API '{path}' that bai: {type(exc).__name__}"
            ) from exc

    return call


def _wait_until_ready(
    call: Callable[[str, dict[str, str]], dict],
    config: ZapConfig,
    sleep: Callable[[float], None],
) -> None:
    deadline = time.monotonic() + config.ready_timeout_s
    last = "chua goi duoc lan nao"
    while time.monotonic() < deadline:
        try:
            version = call("core/view/version", {}).get("version")
        except DastError as exc:
            last = str(exc)
        else:
            if version:
                return
            last = "ZAP tra ve phan hoi khong co truong version"
        sleep(config.poll_interval_s)
    raise DastError(
        f"ZAP daemon khong san sang trong {config.ready_timeout_s}s: {last}"
    )


def _add_dast_key_header(
    call: Callable[[str, dict[str, str]], dict], config: ZapConfig
) -> None:
    """Tiem header xac thuc cua lane DAST vao moi request ZAP gui đi.

    Khong co no thi Gateway tu choi het va ZAP khong cham duoc WebGoat.
    """
    call(
        "replacer/action/addRule",
        {
            "description": "sentinel-dast-key",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": config.dast_header,
            "matchRegex": "false",
            "replacement": config.dast_key,
        },
    )


def _run_plan(
    call: Callable[[str, dict[str, str]], dict],
    config: ZapConfig,
    sleep: Callable[[float], None],
) -> None:
    started = call("automation/action/runPlan", {"filePath": config.plan_path})
    plan_id = str(started.get("planId") or "")
    if not plan_id:
        raise DastError("ZAP khong tra ve planId khi chay plan")

    deadline = time.monotonic() + config.plan_timeout_s
    while time.monotonic() < deadline:
        progress = call("automation/view/planProgress", {"planId": plan_id})
        errors = progress.get("error") or []
        if errors:
            raise DastError(f"Plan ZAP loi: {errors}")
        if progress.get("finished"):
            return
        sleep(config.poll_interval_s)
    raise DastError(f"Plan ZAP khong xong trong {config.plan_timeout_s}s")


def _write_report(report_path: Path, alerts: list[dict[str, Any]]) -> None:
    # Giu nguyen hinh dang {"site": [{"alerts": [...]}]} ma zap_normalizer dang doc,
    # de khong phai sua tang chuan hoa.
    payload = {"site": [{"@name": "sentinel-dast", "alerts": alerts}]}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    report_path.chmod(0o600)


def _assert_traffic_went_through_gateway(log_path: Path) -> None:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "channel=dast" not in text:
        raise DastError(
            "ZAP sinh ra bao cao nhung log Gateway DAST khong co dong nao — "
            "khong chung minh duoc traffic di qua lane"
        )


def _assert_key_did_not_leak(
    report_path: Path, log_path: Path, dast_key: str
) -> None:
    for path in (report_path, log_path):
        if dast_key in path.read_text(encoding="utf-8", errors="replace"):
            raise DastError(f"Khoa DAST ro ri vao {path.name}")


def run_dast(
    report_path: Path,
    log_path: Path,
    *,
    config: ZapConfig,
    call: Callable[[str, dict[str, str]], dict] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Chạy một lần DAST đầy đủ. Ném `DastError` nếu bất kỳ bước nào thất bại."""
    api = call or _http_call(config)

    _wait_until_ready(api, config, sleep)
    _add_dast_key_header(api, config)

    # Ghi lai vi tri cuoi file log TRUOC khi chay plan. Script cu dung
    # `docker compose logs --since "$scan_started_at"`, tuc bang chung cua DUNG lan
    # quet nay. File log thi tich luy qua nhieu lan chay, nen copy ca file se khien
    # traffic cu cua lan truoc thoa man kiem tra — bang chung gia.
    offset = (
        config.gateway_log_path.stat().st_size
        if config.gateway_log_path.is_file()
        else 0
    )

    _run_plan(api, config, sleep)

    alerts = api("core/view/alerts", {}).get("alerts") or []
    _write_report(report_path, list(alerts))

    if not config.gateway_log_path.is_file():
        raise DastError(f"Khong thay log Gateway DAST tai {config.gateway_log_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with config.gateway_log_path.open("rb") as source:
        source.seek(offset)
        log_path.write_bytes(source.read())
    log_path.chmod(0o600)

    _assert_traffic_went_through_gateway(log_path)
    _assert_key_did_not_leak(report_path, log_path, config.dast_key)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Chay mot lan DAST qua ZAP daemon.")
    parser.add_argument("report", type=Path)
    parser.add_argument("log", type=Path)
    args = parser.parse_args(argv)
    try:
        run_dast(args.report, args.log, config=ZapConfig.from_env())
    except DastError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ZAP report: {args.report}")
    print(f"DAST Gateway evidence: {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
