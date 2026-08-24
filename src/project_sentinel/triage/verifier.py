"""Vòng hỏi LLM "cảnh báo này có thật không" cho từng finding thô.

Đây là bước DUY NHẤT trong luồng được phép vứt dữ liệu đi, nên mọi nhánh hỏng ở
đây đều nghiêng về giữ finding lại: LLM lỗi, JSON hỏng, sai schema, verdict trỏ
tới một finding không có thật — tất cả đều kết thúc bằng "finding này đi tiếp".

Bước này cố ý KHÔNG nạp knowledge base và KHÔNG chấm mức nghiêm trọng. Nếu nó cần
những thứ đó thì nó chính là `analysis/pipeline.py` và không có lý do tồn tại.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from project_sentinel.analysis.evidence import SourceEvidence, evidence_for_finding
from project_sentinel.analysis.validators import validate_record_schema
from project_sentinel.config import AppConfig
from project_sentinel.llm.base import LLMProvider
from project_sentinel.triage.rules import should_drop


@dataclass
class VerifyOutcome:
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    kept: list[dict[str, Any]] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def build_user_prompt(finding: dict[str, Any], evidence: SourceEvidence) -> str:
    """Gói một finding và bằng chứng của nó thành prompt người dùng.

    Bằng chứng đi vào giữa hai thẻ đánh dấu rõ ràng: nội dung bên trong do scanner
    và ứng dụng đích sinh ra, và ứng dụng đích chính là thứ đang bị kiểm tra.
    """
    packet = {
        "id": finding.get("id"),
        "tool": finding.get("tool"),
        "rule_id": finding.get("rule_id"),
        "title": finding.get("title"),
        "message": finding.get("message"),
        "file_or_url": finding.get("file_or_url"),
        "line": finding.get("line"),
        "cwe": finding.get("cwe"),
        "owasp": finding.get("owasp"),
        "scanner_severity": finding.get("severity"),
    }
    body = json.dumps(packet, ensure_ascii=False, indent=2)
    snippet = evidence.content if not evidence.error else "(không đọc được mã nguồn)"
    return (
        "<untrusted_finding>\n"
        f"{body}\n"
        "</untrusted_finding>\n\n"
        "<untrusted_evidence>\n"
        f"{snippet}\n"
        "</untrusted_evidence>\n\n"
        f"Trả về verdict cho finding_id = {finding.get('id')!r}."
    )


def _evidence_seen(finding: dict[str, Any], evidence: SourceEvidence) -> str:
    if str(finding.get("tool")) == "zap" or evidence.error:
        return "metadata_only"
    return "source"


def _verify_one(
    finding: dict[str, Any],
    *,
    config: AppConfig,
    provider: LLMProvider,
    system_prompt: str,
    schema_path: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Trả (verdict hợp lệ, lỗi). Đúng một trong hai luôn là None."""
    finding_id = finding.get("id")
    try:
        evidence = evidence_for_finding(
            finding,
            project_root=config.project_root,
            target_root=config.target_root,
            radius=config.source_radius,
        )
        result = provider.generate(
            system_prompt=system_prompt,
            user_prompt=build_user_prompt(finding, evidence),
        )
    except Exception as exc:
        return None, f"{finding_id}: {type(exc).__name__}: {exc}"

    if result.error:
        return None, f"{finding_id}: provider báo lỗi: {result.error}"

    payload = result.parsed_response
    if payload is None:
        try:
            payload = json.loads(result.raw_response)
        except (json.JSONDecodeError, TypeError) as exc:
            return None, f"{finding_id}: phản hồi không phải JSON: {exc}"

    if not isinstance(payload, dict):
        return None, f"{finding_id}: phản hồi không phải JSON object"

    ok, error = validate_record_schema(payload, schema_path)
    if not ok:
        return None, f"{finding_id}: {error}"

    # Provenance: một verdict chỉ được nói về đúng finding nó được hỏi. Không có
    # lớp này thì một verdict lạc chỗ có thể loại mất một finding khác.
    if payload.get("finding_id") != finding_id:
        return None, (
            f"{finding_id}: verdict trỏ tới finding_id khác "
            f"({payload.get('finding_id')!r})"
        )

    return payload, None


def verify_findings(
    findings: list[dict[str, Any]],
    *,
    config: AppConfig,
    provider: LLMProvider,
    prompt_path: Path,
    schema_path: Path,
    output_dir: Path,
) -> VerifyOutcome:
    """Chấm từng finding, ghi ba artifact, trả về kết quả đã phân loại.

    Ném FileNotFoundError nếu thiếu prompt hoặc schema — và trong trường hợp đó
    KHÔNG ghi `findings.verified.json`, để bước gọi biết mà dùng lại findings gốc.
    """
    if not prompt_path.is_file():
        raise FileNotFoundError(f"Không có prompt verify: {prompt_path}")
    if not schema_path.is_file():
        raise FileNotFoundError(f"Không có schema verify: {schema_path}")

    system_prompt = prompt_path.read_text(encoding="utf-8")
    outcome = VerifyOutcome()
    errors: list[str] = []

    if findings:
        with ThreadPoolExecutor(max_workers=config.llm_concurrency) as executor:
            results = list(
                executor.map(
                    lambda finding: _verify_one(
                        finding,
                        config=config,
                        provider=provider,
                        system_prompt=system_prompt,
                        schema_path=schema_path,
                    ),
                    findings,
                )
            )
    else:
        results = []

    uncertain = 0
    for finding, (verdict, error) in zip(findings, results, strict=True):
        if error is not None:
            errors.append(error)
            outcome.kept.append(finding)
            continue

        assert verdict is not None
        outcome.verdicts.append(verdict)
        if verdict.get("verdict") == "uncertain":
            uncertain += 1

        if should_drop(verdict):
            outcome.dropped.append(finding)
        else:
            outcome.kept.append(finding)

    outcome.summary = {
        "total": len(findings),
        "kept": len(outcome.kept),
        "dropped": len(outcome.dropped),
        "uncertain": uncertain,
        "llm_errors": len(errors),
        "degraded_reasons": errors[:20],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "verify.jsonl").write_text(
        "".join(
            json.dumps(item, ensure_ascii=False) + "\n" for item in outcome.verdicts
        ),
        encoding="utf-8",
    )
    (output_dir / "verify-summary.json").write_text(
        json.dumps(outcome.summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    # Ghi CUOI CUNG, va chi khi moi finding da co ket luan. Su vang mat cua file
    # nay la tin hieu suy giam duy nhat ma step_analyze doc.
    _write_verified(output_dir / "findings.verified.json", outcome.kept)

    return outcome


def _write_verified(path: Path, findings: list[dict[str, Any]]) -> None:
    """Ghi nguyên tử qua đổi tên: file dở dang không bao giờ được đọc thấy."""
    payload = {"source": "verified", "count": len(findings), "findings": findings}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)
