# tests/unit/orchestrator/test_step_verify.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_sentinel.orchestrator.context import RunContext
from project_sentinel.orchestrator.state import RunState, new_run
from project_sentinel.orchestrator.steps import step_verify


@pytest.fixture
def ctx(tmp_path):
    real_root = Path(__file__).resolve().parents[3]
    return RunContext.default(repo_root=real_root).replace(runs_dir=tmp_path / "runs")


FINDINGS = {
    "source": "merged",
    "count": 1,
    "findings": [
        {
            "id": "opengrep-001",
            "tool": "opengrep",
            "severity": "high",
            "file_or_url": "src/app/Handler.java",
            "line": 10,
            "title": "Potential command injection",
            "rule_id": "java-command-execution",
            "cwe": ["CWE-78"],
            "owasp": [],
            "message": "Runtime.exec receives a command value.",
        }
    ],
}


def _record_with_findings(ctx):
    record = new_run(ctx.runs_dir)
    (record.root / "findings.json").write_text(
        json.dumps(FINDINGS), encoding="utf-8"
    )
    return record


def test_thieu_findings_json_thi_bo_qua_chu_khong_fail(ctx):
    record = new_run(ctx.runs_dir)

    record = step_verify(record, ctx)

    assert record.step("verify").status == "skipped"
    assert record.state is not RunState.FAILED


def test_loi_ngoai_du_kien_khong_keo_run_sang_failed(ctx, monkeypatch):
    """Mot buoc lam sach hong khong duoc phep giet mot lan quet da chay xong."""
    from project_sentinel.orchestrator.steps import verify as verify_module

    record = _record_with_findings(ctx)

    def no_ra_loi(*args, **kwargs):
        raise RuntimeError("provider chet")

    monkeypatch.setattr(verify_module, "verify_findings", no_ra_loi)

    record = step_verify(record, ctx)

    assert record.step("verify").status == "skipped"
    assert record.state is not RunState.FAILED
    assert not (record.root / "findings.verified.json").exists()


def test_verify_nam_trong_phase_one_truoc_analyze():
    from project_sentinel.orchestrator.runner import PHASE_ONE

    names = [name for name, _ in PHASE_ONE]
    assert names.index("verify") == names.index("normalize") + 1
    assert names.index("verify") == names.index("analyze") - 1
