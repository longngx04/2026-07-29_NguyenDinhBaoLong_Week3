# tests/unit/triage/test_rules.py
from pathlib import Path

import pytest

from project_sentinel.analysis.validators import validate_record_schema

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA = REPO_ROOT / "schemas" / "verify-verdict.schema.json"
PROMPT = REPO_ROOT / "configs" / "prompts" / "verify-finding-system.md"


def _verdict(**overrides) -> dict:
    base = {
        "schema_version": "1.0",
        "finding_id": "opengrep-001",
        "verdict": "true_positive",
        "confidence": "high",
        "rationale": "Runtime.exec nhan gia tri tu tham so request.",
        "evidence_seen": "source",
    }
    base.update(overrides)
    return base


def test_verdict_hop_le_qua_schema():
    ok, error = validate_record_schema(_verdict(), SCHEMA)
    assert ok, error


@pytest.mark.parametrize(
    "field", ["schema_version", "finding_id", "verdict", "confidence", "rationale", "evidence_seen"]
)
def test_thieu_bat_ky_truong_nao_deu_bi_tu_choi(field):
    payload = _verdict()
    del payload[field]
    ok, _ = validate_record_schema(payload, SCHEMA)
    assert not ok


@pytest.mark.parametrize("value", ["confirmed", "likely", "needs_review", ""])
def test_verdict_ngoai_ba_gia_tri_bi_tu_choi(value):
    """Ba gia tri nay la cua `disposition` o buoc analyze, khong phai cua verify."""
    ok, _ = validate_record_schema(_verdict(verdict=value), SCHEMA)
    assert not ok


def test_truong_la_bi_tu_choi():
    ok, _ = validate_record_schema(_verdict(severity="high"), SCHEMA)
    assert not ok


def test_rationale_qua_dai_bi_tu_choi():
    ok, _ = validate_record_schema(_verdict(rationale="x" * 301), SCHEMA)
    assert not ok


def test_prompt_ton_tai_va_khong_hoi_muc_nghiem_trong():
    """Ranh gioi voi analyze: verify khong duoc cham severity."""
    text = PROMPT.read_text(encoding="utf-8")
    assert "uncertain" in text
    assert "true_positive" in text and "false_positive" in text
    assert "severity" not in text.lower()
