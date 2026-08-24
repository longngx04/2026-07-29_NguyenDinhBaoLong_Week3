# tests/unit/orchestrator/test_step_analyze_input.py
from __future__ import annotations

import json

from project_sentinel.orchestrator.state import new_run
from project_sentinel.orchestrator.steps.ingest import _analysis_input


def _write(path, ids):
    path.write_text(
        json.dumps(
            {
                "source": "x",
                "count": len(ids),
                "findings": [{"id": i} for i in ids],
            }
        ),
        encoding="utf-8",
    )


def test_dung_findings_verified_khi_co(tmp_path):
    record = new_run(tmp_path)
    _write(record.root / "findings.json", ["a", "b"])
    _write(record.root / "findings.verified.json", ["a"])

    assert _analysis_input(record.root).name == "findings.verified.json"


def test_quay_ve_findings_json_khi_verify_bi_bo_qua(tmp_path):
    record = new_run(tmp_path)
    _write(record.root / "findings.json", ["a", "b"])

    assert _analysis_input(record.root).name == "findings.json"
