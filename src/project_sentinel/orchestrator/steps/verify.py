"""Bước 3 — hỏi LLM xem từng cảnh báo thô có thật không, trước khi phân tích.

Bước này KHÔNG BAO GIỜ được kéo một lần chạy sang FAILED. Nó chỉ làm sạch đầu
vào cho bước sau, và `step_scan` đã có tiền lệ cho nguyên tắc đó với DAST: một
bước phụ hỏng không được phép giết một lần quét đã chạy xong. Khi bước này bỏ
qua, `findings.verified.json` vắng mặt và `step_analyze` tự dùng lại
`findings.json` — luồng chạy đúng như trước khi có tính năng này.
"""

from __future__ import annotations

import json

from project_sentinel.config import AppConfig
from project_sentinel.llm.factory import build_llm
from project_sentinel.orchestrator.context import RunContext
from project_sentinel.orchestrator.run_log import append_log
from project_sentinel.orchestrator.state import RunRecord, RunState
from project_sentinel.triage.verifier import verify_findings

PROMPT_RELATIVE = ("configs", "prompts", "verify-finding-system.md")
SCHEMA_RELATIVE = ("schemas", "verify-verdict.schema.json")


def _skip(record: RunRecord, reason: str) -> RunRecord:
    """Bỏ qua bước và đi tiếp. Luôn ghi lý do — `dropped: 0` vì bước hỏng và
    `dropped: 0` vì mọi finding đều thật là hai điều khác nhau."""
    append_log(record.root, step="verify", level="warn", message=f"Bỏ qua verify: {reason}")
    record.mark_step("verify", "skipped", detail={"reason": reason})
    return record


def step_verify(record: RunRecord, ctx: RunContext) -> RunRecord:
    source = record.root / "findings.json"
    if not source.exists():
        return _skip(record, "không có findings.json")

    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        findings = payload["findings"]
        if not isinstance(findings, list):
            raise ValueError("findings không phải mảng")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as exc:
        return _skip(record, f"không đọc được findings.json: {exc}")

    record.state = RunState.VERIFYING
    record.mark_step("verify", "running")
    append_log(
        record.root,
        step="verify",
        level="info",
        message=f"Bắt đầu kiểm lại {len(findings)} cảnh báo",
    )

    try:
        config = AppConfig.from_env()
        outcome = verify_findings(
            findings,
            config=config,
            provider=build_llm(config),
            prompt_path=ctx.repo_root.joinpath(*PROMPT_RELATIVE),
            schema_path=ctx.repo_root.joinpath(*SCHEMA_RELATIVE),
            output_dir=record.root,
        )
    except Exception as exc:
        # Bat rong co chu y: khong co loi nao o day duoc phep lam sap lan chay.
        return _skip(record, f"{type(exc).__name__}: {exc}")

    for reason in outcome.summary.get("degraded_reasons", []):
        append_log(record.root, step="verify", level="warn", message=reason)

    record.mark_step("verify", "done", detail=outcome.summary)
    append_log(
        record.root,
        step="verify",
        level="info",
        message="Kiểm lại xong",
        kept=outcome.summary["kept"],
        dropped=outcome.summary["dropped"],
    )
    return record
