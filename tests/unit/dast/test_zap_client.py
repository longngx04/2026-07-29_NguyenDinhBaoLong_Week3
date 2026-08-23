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
        "report_dir_in_zap": str(tmp_path / "zapout"),
        "report_dir_local": tmp_path / "zapout",
    }
    base.update(overrides)
    return ZapConfig(**base)


def _fake_call(alerts=None, progress=None, gateway_log=None, record=None, leak=None):
    """Transport gia: tra ve phan hoi theo path duoc goi."""
    calls: list[str] = record if record is not None else []

    def call(path: str, params: dict) -> dict:
        calls.append(path)
        if path == "core/action/newSession":
            return {"Result": "OK"}
        if path == "reports/action/generate":
            target = Path(params["reportDir"]) / params["reportFileName"]
            target.parent.mkdir(parents=True, exist_ok=True)
            body = {"site": [{"@name": "x", "alerts": [
                {"pluginid": "10038", "alert": "CSP Header Not Set",
                 "other": leak or "",
                 "instances": [{"uri": "http://gateway-dast:8081/WebGoat/login",
                                "method": "GET", "param": ""}]}
            ]}]}
            target.write_text(json.dumps(body), encoding="utf-8")
            return {"generate": str(target)}
        if path == "core/view/version":
            return {"version": "2.17.0"}
        if path in ("replacer/action/removeRule", "replacer/action/addRule"):
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
    call = _fake_call(gateway_log=tmp_path / "dast-access.log")

    run_dast(report, out_log, config=_config(tmp_path), call=call, sleep=lambda _: None)

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload["site"], list)
    # `pluginid` chu thuong: dung truong ma ingestion/zap_normalizer doc.
    assert payload["site"][0]["alerts"][0]["pluginid"] == "10038"
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
    call = _fake_call(gateway_log=tmp_path / "dast-access.log", leak="dastkey")
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


def test_chay_lan_thu_hai_khong_hong_vi_rule_da_ton_tai(tmp_path):
    """Daemon song lau, nen rule replacer con lai tu lan quet truoc. ZAP tra
    `already_exists` neu them trung description. Script cu tao container ZAP moi
    moi lan nen khong gap; thiet ke nay thi gap tu lan thu hai tro di."""
    seen: list[str] = []

    def call(path: str, params: dict) -> dict:
        seen.append(path)
        if path == "core/view/version":
            return {"version": "2.17.0"}
        if path in ("replacer/action/removeRule", "replacer/action/addRule"):
            return {"Result": "OK"}
        if path == "core/action/newSession":
            return {"Result": "OK"}
        if path == "reports/action/generate":
            target = Path(params["reportDir"]) / params["reportFileName"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps({"site": [{"@name": "x", "alerts": [{"pluginid": "1"}]}]}),
                encoding="utf-8",
            )
            return {"generate": str(target)}
        if path == "automation/action/runPlan":
            (tmp_path / "dast-access.log").write_text(GATEWAY_LOG, encoding="utf-8")
            return {"planId": "7"}
        if path == "automation/view/planProgress":
            return {"planId": "7", "finished": "x", "error": []}
        raise AssertionError(path)

    run_dast(
        tmp_path / "r.json", tmp_path / "l.log",
        config=_config(tmp_path), call=call, sleep=lambda _: None,
    )
    assert seen.index("replacer/action/removeRule") < seen.index(
        "replacer/action/addRule"
    ), "Phai xoa rule cu TRUOC khi them, neu khong lan thu hai se hong"


def test_xoa_rule_that_bai_khong_lam_hong_ca_lan_quet(tmp_path):
    """Lan dau chay thi chua co rule nao de xoa. Do khong phai loi."""
    def call(path: str, params: dict) -> dict:
        if path == "replacer/action/removeRule":
            raise DastError("does_not_exist")
        if path == "core/view/version":
            return {"version": "2.17.0"}
        if path == "replacer/action/addRule":
            return {"Result": "OK"}
        if path == "core/action/newSession":
            return {"Result": "OK"}
        if path == "reports/action/generate":
            target = Path(params["reportDir"]) / params["reportFileName"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps({"site": [{"@name": "x", "alerts": [{"pluginid": "1"}]}]}),
                encoding="utf-8",
            )
            return {"generate": str(target)}
        if path == "automation/action/runPlan":
            (tmp_path / "dast-access.log").write_text(GATEWAY_LOG, encoding="utf-8")
            return {"planId": "7"}
        if path == "automation/view/planProgress":
            return {"planId": "7", "finished": "x", "error": []}
        raise AssertionError(path)

    run_dast(
        tmp_path / "r.json", tmp_path / "l.log",
        config=_config(tmp_path), call=call, sleep=lambda _: None,
    )


def test_thong_diep_loi_neu_ma_loi_cua_zap_de_chan_doan_duoc(tmp_path):
    """`HTTPError` tran khong du de go loi. Phai co ma loi cua ZAP, nhung van
    KHONG duoc co apikey."""
    import io
    import urllib.error
    from project_sentinel.dast.zap_client import _http_call

    body = io.BytesIO(b'{"code":"already_exists","message":"Already Exists"}')
    err = urllib.error.HTTPError("http://zap/x", 400, "Bad Request", {}, body)

    def fake_urlopen(*args, **kwargs):
        raise err

    import project_sentinel.dast.zap_client as mod

    original = mod.urllib.request.urlopen
    mod.urllib.request.urlopen = fake_urlopen
    try:
        with pytest.raises(DastError) as caught:
            _http_call(_config(tmp_path))("replacer/action/addRule", {})
    finally:
        mod.urllib.request.urlopen = original

    message = str(caught.value)
    assert "already_exists" in message, f"thieu ma loi cua ZAP: {message}"
    assert "zapkey" not in message


def test_moi_lan_quet_bat_dau_bang_mot_phien_moi(tmp_path):
    """Daemon song lau nen alert tich luy qua cac lan quet. Do duoc: mot lan chay
    tra 172 alert trong khi thuc te chi ~10 loai — phan con lai la cua lan truoc."""
    seen: list[str] = []
    call = _fake_call(gateway_log=tmp_path / "dast-access.log", record=seen)
    run_dast(
        tmp_path / "r.json", tmp_path / "l.log",
        config=_config(tmp_path), call=call, sleep=lambda _: None,
    )
    assert "core/action/newSession" in seen
    assert seen.index("core/action/newSession") < seen.index(
        "automation/action/runPlan"
    ), "Phai xoa phien TRUOC khi quet, khong thi bao cao gom ca alert cu"


def test_bao_cao_do_chinh_zap_sinh_ra_de_dung_dinh_dang_normalizer_doc(tmp_path):
    """`core/view/alerts` tra pluginId camelCase va alert phang; normalizer doc
    `pluginid` chu thuong va mang `instances`. Do duoc: tu nan hinh dang cho ra
    0 finding. Dung bo sinh bao cao cua ZAP thi khong phai nan tay."""
    seen: list[str] = []
    call = _fake_call(gateway_log=tmp_path / "dast-access.log", record=seen)
    report = tmp_path / "r.json"
    run_dast(
        report, tmp_path / "l.log",
        config=_config(tmp_path), call=call, sleep=lambda _: None,
    )
    assert "reports/action/generate" in seen
    assert "pluginid" in report.read_text(encoding="utf-8"), (
        "Bao cao phai giu truong `pluginid` chu thuong ma normalizer doc"
    )
