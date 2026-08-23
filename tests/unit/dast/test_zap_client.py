"""Client dieu khien ZAP daemon. Moi test dung transport gia — khong cham mang."""

import json
from pathlib import Path

import pytest

from project_sentinel.dast.zap_client import DastError, ZapConfig, run_dast

GATEWAY_LOG = "channel=dast method=GET path=/WebGoat/login status=200\n"


def _config(tmp_path: Path, **overrides) -> ZapConfig:
    log = tmp_path / "dast-access.log"
    if not log.exists():
        # File log TON TAI san nhung RONG: gateway ghi vao no trong luc plan chay.
        # Neu fixture ghi san noi dung thi test se khong bat duoc loi lay nham
        # bang chung cua lan quet truoc.
        log.write_text("", encoding="utf-8")
    base = {
        "base_url": "http://zap:8090",
        "api_key": "zapkey",
        "dast_key": "dastkey",
        "gateway_log_path": log,
        "ready_timeout_s": 5.0,
        "plan_timeout_s": 5.0,
        "poll_interval_s": 0.0,
    }
    base.update(overrides)
    return ZapConfig(**base)


def _fake_call(alerts=None, progress=None, gateway_log=None):
    """Transport gia: tra ve phan hoi theo path duoc goi."""
    calls: list[str] = []

    def call(path: str, params: dict) -> dict:
        calls.append(path)
        if path == "core/view/version":
            return {"version": "2.17.0"}
        if path == "replacer/action/addRule":
            return {"Result": "OK"}
        if path == "automation/action/runPlan":
            # Gateway ghi bang chung TRONG LUC plan chay, khong phai truoc do.
            if gateway_log is not None:
                with gateway_log.open("a", encoding="utf-8") as handle:
                    handle.write(GATEWAY_LOG)
            return {"planId": "7"}
        if path == "automation/view/planProgress":
            return progress or {"planId": "7", "finished": "2026-08-23", "error": []}
        if path == "core/view/alerts":
            return {"alerts": alerts if alerts is not None else []}
        raise AssertionError(f"path khong mong doi: {path}")

    call.calls = calls  # type: ignore[attr-defined]
    return call


def test_duong_thuan_loi_ghi_ra_bao_cao_va_log(tmp_path):
    report = tmp_path / "zap-alerts.json"
    out_log = tmp_path / "out.log"
    call = _fake_call(alerts=[{"pluginId": "10038", "alert": "CSP Header Not Set"}],
                      gateway_log=tmp_path / "dast-access.log")

    run_dast(report, out_log, config=_config(tmp_path), call=call, sleep=lambda _: None)

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload["site"], list)
    assert payload["site"][0]["alerts"][0]["pluginId"] == "10038"
    assert out_log.read_text(encoding="utf-8") == GATEWAY_LOG


def test_header_dast_duoc_tiem_truoc_khi_chay_plan(tmp_path):
    """Khong tiem header thi ZAP khong qua noi gateway-dast."""
    call = _fake_call(gateway_log=tmp_path / "dast-access.log")
    run_dast(
        tmp_path / "r.json", tmp_path / "l.log",
        config=_config(tmp_path), call=call, sleep=lambda _: None,
    )
    assert call.calls.index("replacer/action/addRule") < call.calls.index(
        "automation/action/runPlan"
    )


def test_daemon_khong_san_sang_thi_bao_loi_chu_khong_treo(tmp_path):
    def call(path, params):
        raise DastError("connection refused")

    with pytest.raises(DastError, match="khong san sang"):
        run_dast(
            tmp_path / "r.json", tmp_path / "l.log",
            config=_config(tmp_path), call=call, sleep=lambda _: None,
        )


def test_plan_loi_thi_bao_loi_kem_thong_diep_cua_zap(tmp_path):
    call = _fake_call(progress={"planId": "7", "error": ["job spider failed"]})
    with pytest.raises(DastError, match="spider failed"):
        run_dast(
            tmp_path / "r.json", tmp_path / "l.log",
            config=_config(tmp_path), call=call, sleep=lambda _: None,
        )


def test_log_gateway_khong_co_dong_dast_nao_thi_bao_loi(tmp_path):
    """Bao cao co the sinh ra ma traffic chua tung di qua lane. Do la bang chung rong."""
    log = tmp_path / "dast-access.log"
    log.write_text("channel=probe method=GET path=/x\n", encoding="utf-8")
    with pytest.raises(DastError, match="lane"):
        run_dast(
            tmp_path / "r.json", tmp_path / "l.log",
            config=_config(tmp_path, gateway_log_path=log),
            call=_fake_call(), sleep=lambda _: None,
        )


def test_khoa_dast_ro_ri_vao_bao_cao_thi_bao_loi(tmp_path):
    call = _fake_call(alerts=[{"pluginId": "1", "other": "dastkey"}],
                      gateway_log=tmp_path / "dast-access.log")
    with pytest.raises(DastError, match="ro ri"):
        run_dast(
            tmp_path / "r.json", tmp_path / "l.log",
            config=_config(tmp_path), call=call, sleep=lambda _: None,
        )


def test_thong_diep_loi_khong_bao_gio_chua_apikey(tmp_path):
    """URL cua ZAP mang apikey trong query string. No khong duoc vao thong diep loi."""
    from project_sentinel.dast.zap_client import _http_call

    config = _config(tmp_path, base_url="http://127.0.0.1:1")
    with pytest.raises(DastError) as caught:
        _http_call(config)("core/view/version", {})
    assert "zapkey" not in str(caught.value)


def test_thieu_bien_moi_truong_thi_bao_loi_ro_rang(monkeypatch):
    monkeypatch.delenv("SENTINEL_DAST_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_ZAP_API_KEY", raising=False)
    with pytest.raises(DastError, match="SENTINEL_"):
        ZapConfig.from_env()


def test_bang_chung_cu_cua_lan_quet_truoc_khong_duoc_tinh(tmp_path):
    """File log tich luy qua nhieu lan chay. Neu copy ca file thi traffic cu se
    thoa man kiem tra du lan quet nay chua he cham toi Gateway — bang chung gia.

    Script cu tranh duoc bang `docker compose logs --since "$scan_started_at"`.
    """
    log = tmp_path / "dast-access.log"
    log.write_text(GATEWAY_LOG, encoding="utf-8")  # bang chung cua LAN TRUOC

    with pytest.raises(DastError, match="lane"):
        run_dast(
            tmp_path / "r.json", tmp_path / "l.log",
            config=_config(tmp_path, gateway_log_path=log),
            call=_fake_call(),  # khong ghi them gi trong luc plan chay
            sleep=lambda _: None,
        )
