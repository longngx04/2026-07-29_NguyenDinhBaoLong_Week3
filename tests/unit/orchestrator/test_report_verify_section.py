# tests/unit/orchestrator/test_report_verify_section.py
from __future__ import annotations

import json

from project_sentinel.orchestrator.report import build_report
from project_sentinel.orchestrator.state import RunState, new_run


def _setup(tmp_path, *, summary: dict | None, verdicts: list[dict], kept: list[str]):
    record = new_run(tmp_path)
    record.state = RunState.DONE
    (record.root / "findings.json").write_text(
        json.dumps(
            {
                "source": "merged",
                "count": 2,
                "findings": [
                    {"id": "opengrep-001", "title": "Potential command injection"},
                    {"id": "zap-10009-abc", "title": "Banner leak"},
                ],
            }
        ),
        encoding="utf-8",
    )
    if summary is not None:
        (record.root / "verify-summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )
        (record.root / "verify.jsonl").write_text(
            "".join(json.dumps(v) + "\n" for v in verdicts), encoding="utf-8"
        )
        (record.root / "findings.verified.json").write_text(
            json.dumps(
                {"source": "verified", "count": len(kept), "findings": [{"id": i} for i in kept]}
            ),
            encoding="utf-8",
        )
    return record


def test_liet_ke_finding_bi_loai_kem_ly_do(tmp_path):
    record = _setup(
        tmp_path,
        summary={"total": 2, "kept": 1, "dropped": 1, "uncertain": 0,
                 "llm_errors": 0, "degraded_reasons": []},
        verdicts=[
            {"schema_version": "1.0", "finding_id": "opengrep-001",
             "verdict": "false_positive", "confidence": "high",
             "rationale": "Vi tri nam trong ma kiem thu.", "evidence_seen": "source"}
        ],
        kept=["zap-10009-abc"],
    )

    markdown, data = build_report(record)

    assert data["findings_total"] == 2
    assert data["findings_verified"] == 1
    assert data["findings_dropped"] == 1
    assert "Đã loại ở bước verify" in markdown
    assert "opengrep-001" in markdown
    assert "Vi tri nam trong ma kiem thu." in markdown


def test_khong_co_verify_thi_khong_co_muc_do(tmp_path):
    record = _setup(tmp_path, summary=None, verdicts=[], kept=[])

    markdown, data = build_report(record)

    assert "Đã loại ở bước verify" not in markdown
    assert data["findings_dropped"] == 0
    assert data["findings_total"] == 2


def test_verify_suy_giam_duoc_noi_ro_thay_vi_hien_dropped_0(tmp_path):
    """`dropped: 0` vi buoc hong khac `dropped: 0` vi moi finding deu that."""
    record = _setup(
        tmp_path,
        summary={"total": 2, "kept": 2, "dropped": 0, "uncertain": 0,
                 "llm_errors": 2, "degraded_reasons": ["opengrep-001: mang hong"]},
        verdicts=[],
        kept=["opengrep-001", "zap-10009-abc"],
    )

    markdown, data = build_report(record)

    assert data["verify_degraded"] is True
    assert "mang hong" in markdown
