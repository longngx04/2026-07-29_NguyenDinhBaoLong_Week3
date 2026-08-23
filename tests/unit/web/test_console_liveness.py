"""Bảng điều khiển một trang, và cách nó phân biệt "đang chạy" với "đã treo".

Hiệu ứng chạy trên màn hình là một lời khẳng định: có thứ gì đó vẫn đang tiến
triển. Các test ở đây canh đúng một điều — lời khẳng định đó phải đúng, kể cả
trong những trường hợp dễ nói dối nhất: bước LLM im lặng hàng phút, và cổng phê
duyệt đứng yên vô hạn vì đang đợi người.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from project_sentinel.orchestrator.context import RunContext
from project_sentinel.orchestrator.run_log import LOG_FILENAME, append_log
from project_sentinel.orchestrator.state import RunState, new_run, save_run
from project_sentinel.web import main as web_main


@pytest.fixture
def client(tmp_path):
    ctx = RunContext.default().replace(runs_dir=tmp_path / "runs")
    web_main.app.dependency_overrides[web_main.get_context] = lambda: ctx
    yield TestClient(web_main.app), ctx
    web_main.app.dependency_overrides.clear()


def _run_stuck_at(ctx, step_name, idle_seconds, state=RunState.ANALYZING):
    """Lần chạy đang ở `step_name` và đã im lặng đúng `idle_seconds` giây."""
    record = new_run(ctx.runs_dir)
    record.state = state
    record.mark_step(step_name, "running")
    save_run(record)
    append_log(record.root, step=step_name, level="info", message="bắt đầu")

    stale = (datetime.now(timezone.utc) - timedelta(seconds=idle_seconds)).isoformat()
    state_file = record.root / "state.json"
    payload = json.loads(state_file.read_text(encoding="utf-8"))
    payload["updated_at"] = stale
    state_file.write_text(json.dumps(payload), encoding="utf-8")

    old = time.time() - idle_seconds
    os.utime(record.root / LOG_FILENAME, (old, old))
    return record


def _status(http, run_id):
    return http.get(f"/api/runs/{run_id}").json()


# --- Ngân sách theo từng bước ------------------------------------------------


def test_analyze_im_lang_bon_phut_van_khong_bi_coi_la_treo(client):
    """Đo được thật: một lần chạy có `analyze` im lặng 251 giây liền.

    Nếu ngưỡng là một hằng chung vài chục giây thì mỗi lần chạy thật đều bị báo
    treo giữa chừng, và cảnh báo treo lập tức thành thứ người xem học cách bỏ qua.
    """
    http, ctx = client
    record = _run_stuck_at(ctx, "analyze", idle_seconds=200)

    data = _status(http, record.run_id)
    assert data["stalled"] is False
    assert data["running_step"] == "analyze"
    assert data["stall_budget_s"] == 360


def test_analyze_vuot_ngan_sach_thi_bi_bao_treo(client):
    http, ctx = client
    record = _run_stuck_at(ctx, "analyze", idle_seconds=400)

    data = _status(http, record.run_id)
    assert data["stalled"] is True
    assert data["idle_seconds"] > 360


def test_moi_buoc_co_ngan_sach_rieng(client):
    """`normalize` xong trong phần mười giây; nó không được xài ngưỡng của LLM."""
    http, ctx = client
    record = _run_stuck_at(ctx, "normalize", idle_seconds=40, state=RunState.NORMALIZING)

    data = _status(http, record.run_id)
    assert data["stall_budget_s"] == 30
    assert data["stalled"] is True


# --- Những thứ KHÔNG được coi là treo ----------------------------------------


def test_cho_nguoi_phe_duyet_khong_bao_gio_la_treo(client):
    """Dừng ở cổng phê duyệt là đúng thiết kế, không phải hỏng hóc.

    Không có ngưỡng nào đúng cho việc một người rời bàn đi pha cà phê.
    """
    http, ctx = client
    record = _run_stuck_at(
        ctx, "approval", idle_seconds=99999, state=RunState.AWAITING_APPROVAL
    )

    data = _status(http, record.run_id)
    assert data["stalled"] is False
    assert data["waiting_for_human"] is True


def test_lan_chay_da_ket_thuc_khong_bao_gio_la_treo(client):
    http, ctx = client
    record = _run_stuck_at(ctx, "finalize", idle_seconds=99999, state=RunState.DONE)

    data = _status(http, record.run_id)
    assert data["terminal"] is True
    assert data["stalled"] is False


def test_ghi_them_mot_dong_nhat_ky_lam_moi_dong_ho_im_lang(client):
    """Một bước dài vẫn ghi log giữa chừng mà chưa đổi trạng thái.

    Chỉ nhìn `updated_at` thì bước đó bị kết luận treo trong khi nó đang chạy
    và đang nói ra điều đó ở từng dòng log.
    """
    http, ctx = client
    record = _run_stuck_at(ctx, "analyze", idle_seconds=1300)
    assert _status(http, record.run_id)["stalled"] is True

    append_log(record.root, step="analyze", level="info", message="còn sống")

    data = _status(http, record.run_id)
    assert data["stalled"] is False
    assert data["idle_seconds"] < 5


# --- Bảng điều khiển gom mọi thứ về một trang --------------------------------


def test_bang_dieu_khien_hien_ca_chin_buoc_va_nhat_ky(client):
    http, ctx = client
    record = _run_stuck_at(ctx, "analyze", idle_seconds=1)

    body = http.get("/").text
    for name in ("scan", "normalize", "analyze", "propose", "approval",
                 "probe", "scrub", "report", "finalize"):
        assert f'data-step="{name}"' in body, f"Thiếu trạm {name} trên đường ray"
    assert 'id="terminal-body"' in body, "Thiếu nhật ký ngay dưới đường ray"
    assert record.run_id in body


def test_bang_dieu_khien_danh_dau_san_trang_thai_treo_ngay_tu_may_chu(client):
    """Người xem mở trang lúc lần chạy đã treo sẵn cũng phải thấy ngay.

    Nếu chỉ phát hiện trong vòng lặp poll thì trang vừa mở sẽ chạy hiệu ứng một
    nhịp trước khi tự sửa, tức là nói dối một nhịp.
    """
    http, ctx = client
    _run_stuck_at(ctx, "analyze", idle_seconds=400)

    assert 'data-stalled="true"' in http.get("/").text


def test_the_phe_duyet_nam_ngay_tren_bang_dieu_khien(client):
    """Người duyệt không phải rời trang: đọc tiến trình và bấm ở cùng một chỗ."""
    http, ctx = client
    record = new_run(ctx.runs_dir)
    record.state = RunState.AWAITING_APPROVAL
    record.mark_step("approval", "running")
    (record.root / "approval-request.json").write_text(
        json.dumps({
            "method": "POST",
            "endpoint": "/WebGoat/attack",
            "payload": "value=AAAA",
            "purpose": "Kiem tra gioi han do dai",
            "risk_reason": "Request POST co the doi trang thai",
            "request_fingerprint": "abc",
        }),
        encoding="utf-8",
    )
    save_run(record)

    body = http.get("/").text
    assert "/WebGoat/attack" in body
    assert "Kiem tra gioi han do dai" in body
    assert f'action="/approvals/{record.run_id}"' in body


def test_state_json_hong_o_lan_chay_moi_nhat_khong_lam_trang_bang_dieu_khien(client):
    """Bảng điều khiển giờ là trang chủ, nên lỗi ở đây là lỗi ở lối vào duy nhất."""
    http, ctx = client
    good = new_run(ctx.runs_dir)
    good.state = RunState.DONE
    save_run(good)

    broken = new_run(ctx.runs_dir)
    save_run(broken)
    (broken.root / "state.json").write_text("{ khong phai json", encoding="utf-8")

    response = http.get("/")
    assert response.status_code == 200
    assert good.run_id in response.text


# --- Trang lịch sử tách riêng ------------------------------------------------


def test_lich_su_la_mot_trang_rieng(client):
    http, ctx = client
    record = new_run(ctx.runs_dir)
    record.state = RunState.DONE
    save_run(record)

    body = http.get("/history").text
    assert record.run_id in body
    assert f'href="/runs/{record.run_id}"' in body


def test_lich_su_cong_don_ca_so_lan_tu_choi_va_so_loi(client):
    """Hai ô này từng luôn hiện 0 vì không bao giờ được cộng vào."""
    http, ctx = client
    record = new_run(ctx.runs_dir)
    record.state = RunState.REJECTED
    (record.root / "events.jsonl").write_text(
        json.dumps({
            "ts": "2026-08-23T00:00:00+00:00",
            "kind": "approval",
            "detail": {"approved": False, "decided_by": "web-operator"},
        }) + "\n",
        encoding="utf-8",
    )
    save_run(record)
    append_log(record.root, step="analyze", level="error", message="LLM tra ve rac")

    data = web_main.views.history_data(ctx)
    assert data["totals"]["rejected"] == 1
    assert data["totals"]["errors"] == 1
