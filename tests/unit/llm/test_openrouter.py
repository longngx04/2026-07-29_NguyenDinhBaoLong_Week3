import io
import json
import os
import time
import urllib.error
import urllib.request

import pytest

from project_sentinel.config import AppConfig
from project_sentinel.llm.base import AnalysisPacket
from project_sentinel.llm.factory import build_llm
from project_sentinel.llm.openrouter import (
    OpenRouterClient,
    _read_response_bytes,
    _sanitize_error,
    _unwrap_json_envelope,
)


def test_read_response_bytes_returns_bounded_content():
    content = b'{"status":"ok"}'

    assert _read_response_bytes(io.BytesIO(content), deadline=time.monotonic() + 1) == content


def test_read_response_bytes_rejects_oversized_content():
    with pytest.raises(ValueError, match="exceeds the configured byte limit"):
        _read_response_bytes(io.BytesIO(b"12345"), deadline=time.monotonic() + 1, max_response_bytes=4)


def test_read_response_bytes_enforces_absolute_deadline():
    with pytest.raises(TimeoutError, match="total request deadline"):
        _read_response_bytes(io.BytesIO(b"{}"), deadline=time.monotonic() - 1)


def test_unwrap_json_envelope_with_type():
    record = {"schema_version": "1.0", "title": "SQL injection"}

    assert _unwrap_json_envelope({"type": "json_object", "data": record}) is record


def test_unwrap_json_envelope_with_data_only():
    proposal = {
        "objective_id": "objective-1",
        "proposal_id": "proposal-1",
        "endpoint_id": "health",
        "reason": "Confirm the endpoint is reachable.",
    }

    assert _unwrap_json_envelope({"data": proposal}) is proposal


def test_unwrap_json_envelope_preserves_flat_analysis_record():
    record = {
        "schema_version": "1.0",
        "analysis_id": "analysis-1234abcd",
        "group_key": "group-1",
        "source_finding_ids": ["finding-1"],
        "title": "SQL injection",
        "severity": "high",
        "scanner_severities": ["ERROR"],
        "confidence": "high",
        "confidence_rationale": "The scanner evidence shows string concatenation.",
        "locations": [{"file": "Example.java", "line": 10}],
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "evidence": [
            {
                "type": "scanner",
                "finding_id": "finding-1",
                "content": "Untrusted input reaches a SQL query.",
            }
        ],
        "explanation": "Untrusted input is concatenated into a SQL query.",
        "preconditions": ["The input is attacker-controlled."],
        "verification_steps": ["Review the query construction."],
        "remediation": ["Use parameterized queries."],
        "knowledge_refs": [],
        "limitations": [],
    }

    assert _unwrap_json_envelope(record) is record


def test_unwrap_json_envelope_preserves_flat_probe_proposal():
    proposal = {
        "objective_id": "objective-1",
        "proposal_id": "proposal-1",
        "endpoint_id": "health",
        "reason": "Confirm the endpoint is reachable.",
    }

    assert _unwrap_json_envelope(proposal) is proposal


def test_unwrap_json_envelope_preserves_data_dict_with_extra_key():
    parsed = {
        "type": "json_object",
        "data": {"title": "SQL injection"},
        "metadata": {"provider": "openrouter"},
    }

    assert _unwrap_json_envelope(parsed) is parsed


@pytest.mark.parametrize("data", ["record", ["record"], None])
def test_unwrap_json_envelope_preserves_non_dict_data(data):
    parsed = {"type": "json_object", "data": data}

    assert _unwrap_json_envelope(parsed) is parsed


def test_missing_api_key_does_not_call_network():
    client = OpenRouterClient(
        api_key="",
        base_url="https://openrouter.ai/api/v1",
        model="deepseek/deepseek-v4-flash-0731",
        timeout_seconds=5.0,
        max_retries=1
    )
    with pytest.raises(ValueError, match="LLM_API_KEY is required"):
        client.analyze(AnalysisPacket(group_key="g1"), system_prompt="SYS")
    with pytest.raises(ValueError, match="LLM_API_KEY is required"):
        client.generate(system_prompt="SYS", user_prompt="Return JSON")


def test_provider_factory_openrouter(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-secret")
    config = AppConfig.from_env()
    llm = build_llm(config)
    assert isinstance(llm.inner, OpenRouterClient)


def test_provider_factory_rejects_unsupported(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "unsupported_provider")
    config = AppConfig.from_env()
    with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
        build_llm(config)


def test_sanitize_error_redacts_api_key():
    key = "sk-openrouter-secret-key"
    msg = f"Failed connecting with Auth Bearer {key} to server"
    sanitized = _sanitize_error(msg, key)
    assert key not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized


@pytest.mark.llm
def test_real_openrouter_live_call(llm_ready):
    api_key = llm_ready
    client = OpenRouterClient(
        api_key=api_key,
        base_url=os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1"),
        model=os.getenv("LLM_MODEL", "deepseek/deepseek-v4-flash-0731"),
        timeout_seconds=30.0,
        max_retries=1,
    )
    packet = AnalysisPacket(
        group_key="grp-live-test",
        finding_group={
            "source_finding_ids": ["f-live-1"],
            "locations": [{"file": "Test.java", "line": 10}],
            "rule_id": "java.lang.security.audit.sql-injection",
        },
        knowledge_hits=[],
    )
    result = client.analyze(packet, system_prompt="You are a security analyzer. Respond in JSON.")
    assert result.error is None
    assert result.parsed_response is not None


# --- Chịu được giới hạn tốc độ ----------------------------------------------
#
# Bốn mươi luồng bắn vào cùng một endpoint thì 429 là chuyện sẽ xảy ra, không
# phải chuyện có thể xảy ra. Cơ chế cũ — ngủ đúng 1 giây, thử lại đúng một lần —
# biến 429 thành finding bị mất. Các test dưới đây canh phần thay thế.


class _FakeHTTPError(urllib.error.HTTPError):
    """HTTPError dựng tay, có headers để thử nhánh Retry-After."""

    def __init__(self, code, headers=None):
        super().__init__(
            url="https://openrouter.ai/api/v1/chat/completions",
            code=code,
            msg="rate limited" if code == 429 else "server error",
            hdrs=headers or {},
            fp=io.BytesIO(b""),
        )


def _ok_body():
    return json.dumps({
        "model": "test-model",
        "id": "req-1",
        "choices": [{"message": {"content": '{"ok": true}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }).encode("utf-8")


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def read(self, amt=None):
        return super().read(amt)


def _client(**overrides):
    kwargs = {
        "api_key": "sk-test",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "test-model",
        "timeout_seconds": 5.0,
        "max_retries": 1,
    }
    kwargs.update(overrides)
    return OpenRouterClient(**kwargs)


def _patch_calls(monkeypatch, outcomes, slept):
    """Cho urlopen trả lần lượt các `outcomes`, và ghi lại mọi lần ngủ."""
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        index = calls["n"]
        calls["n"] += 1
        outcome = outcomes[min(index, len(outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return _FakeResponse(outcome)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    return calls


def test_bi_gioi_han_toc_do_hai_lan_roi_thanh_cong(monkeypatch):
    """429 phải được thử lại đủ nhiều để không mất finding."""
    slept = []
    calls = _patch_calls(
        monkeypatch,
        [_FakeHTTPError(429), _FakeHTTPError(429), _ok_body()],
        slept,
    )

    result = _client(rate_limit_max_retries=4).generate(
        system_prompt="SYS", user_prompt="Return JSON"
    )

    assert result.error is None, result.error
    assert result.parsed_response == {"ok": True}
    assert calls["n"] == 3
    assert result.rate_limited_attempts == 2


def test_429_khong_tieu_ngan_sach_thu_lai_cua_loi_5xx(monkeypatch):
    """Hết giờ mạng và bị giới hạn tốc độ là hai chuyện khác nhau.

    `max_retries=1` là ngân sách cho lỗi tạm thời của máy chủ. Nếu 429 cũng ăn
    vào đó thì chỉ một lần bị giới hạn là hết lượt, đúng lúc cần nhất.
    """
    slept = []
    calls = _patch_calls(
        monkeypatch,
        [_FakeHTTPError(429)] * 3 + [_ok_body()],
        slept,
    )

    result = _client(max_retries=1, rate_limit_max_retries=4).generate(
        system_prompt="SYS", user_prompt="Return JSON"
    )

    assert result.error is None, result.error
    assert calls["n"] == 4


def test_ton_trong_header_retry_after(monkeypatch):
    """Máy chủ đã nói phải đợi bao lâu thì đừng đoán."""
    slept = []
    _patch_calls(
        monkeypatch,
        [_FakeHTTPError(429, {"Retry-After": "7"}), _ok_body()],
        slept,
    )

    _client(rate_limit_max_retries=4).generate(
        system_prompt="SYS", user_prompt="Return JSON"
    )

    assert slept == [7.0]


def test_backoff_co_jitter_va_tang_dan(monkeypatch):
    """Bốn mươi luồng cùng bị 429 mà ngủ y hệt nhau thì chúng va lại đúng nhịp.

    Jitter tồn tại chính vì lý do đó, nên nó phải có thật chứ không phải một
    hằng số cố định.
    """
    slept = []
    _patch_calls(monkeypatch, [_FakeHTTPError(429)] * 3 + [_ok_body()], slept)

    _client(rate_limit_max_retries=4).generate(
        system_prompt="SYS", user_prompt="Return JSON"
    )

    assert len(slept) == 3
    assert all(0 < s <= 30.0 for s in slept), slept
    # Không được là ba con số y hệt nhau, và phải có xu hướng giãn ra.
    assert slept[-1] > slept[0]


def test_het_luot_thi_bao_loi_chu_khong_treo(monkeypatch):
    slept = []
    calls = _patch_calls(monkeypatch, [_FakeHTTPError(429)] * 10, slept)

    result = _client(rate_limit_max_retries=2).generate(
        system_prompt="SYS", user_prompt="Return JSON"
    )

    assert result.error is not None
    assert "429" in result.error
    assert calls["n"] == 3
    assert result.rate_limited_attempts == 2


def test_phan_hoi_200_nhung_json_hong_lien_tuc_van_phai_dung(monkeypatch):
    """Vòng lặp gọi phải thoát, kể cả khi máy chủ trả 200 với rác mãi mãi.

    Ba nhánh "HTTP 200 nhưng nội dung không dùng được" cũng `continue`. Khi ngân
    sách thử lại được tách làm hai bộ đếm, ba nhánh đó không còn bộ đếm nào tự
    tăng — quên tăng là treo cả bước analyze thay vì báo lỗi.
    """
    slept = []
    garbage = json.dumps({
        "model": "test-model",
        "choices": [{"message": {"content": "khong-phai-json"}}],
    }).encode("utf-8")
    calls = _patch_calls(monkeypatch, [garbage] * 50, slept)

    result = _client(max_retries=2).generate(system_prompt="SYS", user_prompt="X")

    assert result.error is not None
    assert "Malformed" in result.error
    assert calls["n"] == 3, "phải dừng sau 1 lần đầu + 2 lần thử lại"


def test_noi_dung_rong_lien_tuc_cung_phai_dung(monkeypatch):
    slept = []
    empty = json.dumps({
        "model": "test-model",
        "choices": [{"message": {"content": ""}}],
    }).encode("utf-8")
    calls = _patch_calls(monkeypatch, [empty] * 50, slept)

    result = _client(max_retries=1).generate(system_prompt="SYS", user_prompt="X")

    assert result.error is not None
    assert calls["n"] == 2
