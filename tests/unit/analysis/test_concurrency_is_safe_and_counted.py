"""Chạy song song chỉ được đổi thời gian, không được đổi kết quả.

Bước `analyze` mất 344-415 giây trên 37 finding vì nó chạy 4 nhóm một lượt.
Đo được: nâng lên 37 luồng còn 108 giây, không gặp một lỗi 429 nào. Nhưng con
số song song chỉ an toàn khi hai điều dưới đây đúng, nên chúng được canh ở đây
chứ không nằm trong một comment.
"""

from __future__ import annotations

import threading
import time

from project_sentinel.analysis.pipeline import _GroupOutcome, _analyze_groups
from project_sentinel.config import AppConfig
from project_sentinel.llm.base import LLMResult


class _Group:
    def __init__(self, key: str) -> None:
        self.group_key = key


# --- Bất biến 1: thứ tự đầu ra bám theo thứ tự đầu vào ----------------------


def test_ket_qua_giu_dung_thu_tu_dau_vao_du_hoan_thanh_lung_tung(monkeypatch):
    """Nhóm xong trước không được chen lên trước trong `analysis.jsonl`.

    Nhóm đầu cố tình chậm nhất. Nếu kết quả được xếp theo thứ tự HOÀN THÀNH thì
    nó rơi xuống cuối, và mọi artifact lịch sử so theo thứ tự sẽ lệch.
    """
    groups = [_Group(f"group-{i}") for i in range(8)]
    delays = {"group-0": 0.05}

    def fake_analyze_one(group, config, provider, allowlist=None):
        time.sleep(delays.get(group.group_key, 0.0))
        return _GroupOutcome(record={"g": group.group_key}, prompt_sha256="", group_key=group.group_key)

    monkeypatch.setattr(
        "project_sentinel.analysis.pipeline._analyze_one_group", fake_analyze_one
    )
    config = AppConfig.from_env()
    config.llm_concurrency = 8

    outcomes = _analyze_groups(groups, config, provider=object(), allowlist=None)

    assert [o.group_key for o in outcomes] == [g.group_key for g in groups]


def test_so_luong_luong_khong_vuot_qua_so_nhom(monkeypatch):
    """Ba nhóm thì không dựng bốn mươi luồng."""
    groups = [_Group(f"group-{i}") for i in range(3)]
    seen: set[int] = set()
    lock = threading.Lock()

    def fake_analyze_one(group, config, provider, allowlist=None):
        with lock:
            seen.add(threading.get_ident())
        time.sleep(0.02)
        return _GroupOutcome(record=None, prompt_sha256="", group_key=group.group_key)

    monkeypatch.setattr(
        "project_sentinel.analysis.pipeline._analyze_one_group", fake_analyze_one
    )
    config = AppConfig.from_env()
    config.llm_concurrency = 40

    _analyze_groups(groups, config, provider=object(), allowlist=None)

    assert len(seen) <= len(groups)


# --- Bất biến 2: sức ép rate-limit phải đếm được ----------------------------


def test_so_lan_bi_gioi_han_toc_do_duoc_cong_qua_moi_lan_goi():
    """Kể cả lần thử lại.

    Đây là số liệu duy nhất nói được mức song song đã chạm trần hay chưa. Không
    có nó thì lần chỉnh sau lại phải đoán, đúng như lần này.
    """
    outcome = _GroupOutcome(record=None, prompt_sha256="")

    outcome.add_tokens(LLMResult(raw_response="", rate_limited_attempts=2))
    outcome.add_tokens(LLMResult(raw_response="", rate_limited_attempts=1))

    assert outcome.rate_limited_attempts == 3


def test_duong_chay_binh_thuong_khong_bao_bi_gioi_han():
    outcome = _GroupOutcome(record=None, prompt_sha256="")
    outcome.add_tokens(LLMResult(raw_response="", prompt_tokens=10))
    assert outcome.rate_limited_attempts == 0
