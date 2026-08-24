# tests/unit/orchestrator/test_state_verify_step.py
import json

from project_sentinel.orchestrator.state import (
    STEP_BUDGET_S,
    STEP_NAMES,
    RunRecord,
    RunState,
    new_run,
)


def test_verify_nam_giua_normalize_va_analyze():
    assert STEP_NAMES.index("verify") == STEP_NAMES.index("normalize") + 1
    assert STEP_NAMES.index("verify") == STEP_NAMES.index("analyze") - 1
    assert len(STEP_NAMES) == 10


def test_ngan_sach_verify_bang_analyze():
    """Buoc nay goi LLM nen im lang hang phut; 30 giay se bao treo gia."""
    assert STEP_BUDGET_S["verify"] == STEP_BUDGET_S["analyze"]


def test_co_trang_thai_verifying():
    assert RunState.VERIFYING.value == "VERIFYING"
    assert not RunState.VERIFYING.is_terminal()


def test_run_moi_co_du_muoi_buoc(tmp_path):
    record = new_run(tmp_path)
    assert [s.name for s in record.steps] == list(STEP_NAMES)
    assert [s.index for s in record.steps] == list(range(1, 11))


def test_run_cu_chin_buoc_van_doc_duoc(tmp_path):
    """state.json da co tren dia khong co `verify`; doc no khong duoc no KeyError."""
    root = tmp_path / "20260101T000000Z"
    root.mkdir()
    old_steps = [
        "scan", "normalize", "analyze", "propose",
        "approval", "probe", "scrub", "report", "finalize",
    ]
    (root / "state.json").write_text(
        json.dumps(
            {
                "run_id": "20260101T000000Z",
                "state": "DONE",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "steps": [
                    {"index": i, "name": name, "status": "done"}
                    for i, name in enumerate(old_steps, 1)
                ],
            }
        ),
        encoding="utf-8",
    )

    record = RunRecord.from_dict(
        json.loads((root / "state.json").read_text(encoding="utf-8")), root
    )

    assert [s.name for s in record.steps] == list(STEP_NAMES)
    assert record.step("verify").status == "skipped"
    assert record.step("analyze").status == "done"
    assert [s.index for s in record.steps] == list(range(1, 11))
