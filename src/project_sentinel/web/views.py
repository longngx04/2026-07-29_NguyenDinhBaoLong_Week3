"""Đọc artifact của các lần chạy và dựng dữ liệu cho template.

Module này CHỈ ĐỌC. Không thay đổi trạng thái, không gọi mạng, không chạy bước
nào. Mọi thay đổi đều thuộc về orchestrator.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from project_sentinel.guardrails.events import read_events
from project_sentinel.orchestrator.context import RunContext
from project_sentinel.orchestrator.metrics import collect_metrics
from project_sentinel.orchestrator.run_log import read_log
from project_sentinel.orchestrator.state import RunRecord, list_runs, load_run
from project_sentinel.retrieval.kb_schema import parse_tier2
import yaml

MAX_RUNS_ON_OVERVIEW = 20


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(default, dict) and not isinstance(data, dict):
            return default
        if isinstance(default, list) and not isinstance(data, list):
            return default
        return data
    except Exception:
        return default


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    results = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    results.append(parsed)
            except Exception:
                continue
    except Exception:
        return []
    return results


def overview_data(ctx: RunContext) -> dict:
    """Số liệu tổng hợp và danh sách các lần chạy gần đây."""
    rows = []
    totals = {"runs": 0, "findings": 0, "requests": 0, "approved": 0, "rejected": 0, "errors": 0}

    for run_id in list_runs(ctx.runs_dir)[:MAX_RUNS_ON_OVERVIEW]:
        try:
            record = load_run(ctx.runs_dir, run_id)
            metrics = collect_metrics(record)
        except Exception:
            continue
        rows.append({
            "run_id": run_id,
            "state": record.state.value,
            "created_at": record.created_at,
            "findings": metrics["findings_total"],
            "requests": metrics["requests_total"],
            "elapsed_ms": metrics["total_elapsed_ms"],
        })
        totals["runs"] += 1
        totals["findings"] += metrics["findings_total"]
        totals["requests"] += metrics["requests_total"]
        totals["approved"] += metrics["approvals"]["approved"]
    has_active = any(
        row["state"] not in {"DONE", "FAILED", "REJECTED"}
        for row in rows
    )

    return {
        "runs": rows,
        "totals": totals,
        "demo_run": os.getenv("SENTINEL_DEMO_RUN") or None,
        "has_active": has_active,
    }



def _strength_distribution(findings: list) -> dict[str, int]:
    """Đếm `runtime_evidence.strength`, CHỈ trên finding tĩnh.

    Finding động đã LÀ bằng chứng runtime nên `correlate` cố ý không gắn khối
    này cho chúng; đếm cả hai sẽ trộn hai thứ khác nghĩa vào một biểu đồ.

    Trả dict rỗng khi lần chạy không có DAST. Hiện một khối toàn số 0 làm
    người đọc tưởng đã quét mà không tìm ra gì.
    """
    counts: dict[str, int] = {}
    for item in findings:
        if not isinstance(item, dict) or item.get("tool") == "zap":
            continue
        strength = (item.get("runtime_evidence") or {}).get("strength")
        if strength:
            counts[str(strength)] = counts.get(str(strength), 0) + 1
    return counts


def _load_findings(record) -> list:
    raw = _read_json(record.root / "findings.json", {})
    findings = raw.get("findings", []) if isinstance(raw, dict) else []
    return findings if isinstance(findings, list) else []


def run_data(ctx: RunContext, run_id: str) -> dict:
    """Tiến trình chín bước của một lần chạy."""
    record = load_run(ctx.runs_dir, run_id)
    return {
        "run": record,
        "steps": [
            {
                "index": step.index,
                "name": step.name,
                "status": step.status,
                "elapsed_ms": step.elapsed_ms,
                "detail": step.detail,
            }
            for step in record.steps
        ],
        "metrics": collect_metrics(record),
        # `completeness: PARTIAL` nghĩa là vài nhóm biến mất khỏi báo cáo.
        # report.md nói điều đó ngay dòng đầu; màn hình này trước đây im lặng.
        "analysis_summary": _read_json(record.root / "analysis-summary.json", {}),
        "strengths": _strength_distribution(_load_findings(record)),
        "log": read_log(record.root)[-50:],
    }


def findings_data(ctx: RunContext, run_id: str) -> dict:
    record = load_run(ctx.runs_dir, run_id)
    findings = _load_findings(record)
    severities: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        key = str(item.get("severity", "unknown"))
        severities[key] = severities.get(key, 0) + 1
        tool = str(item.get("tool") or "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1
    return {
        "run": record,
        "findings": findings,
        "severities": severities,
        # Một finding ZAP gộp theo loại alert, một finding OpenGrep là một vị
        # trí trong mã. Gộp chúng vào một con số là trộn hai loại hạt.
        "by_tool": by_tool,
        "strengths": _strength_distribution(findings),
    }


def _split_yaml_frontmatter(text: str) -> tuple[str, str]:
    """Tách frontmatter YAML và phần thân markdown.

    Dùng cho các tài liệu tri thức (Tier 1 hoặc tài liệu tự do) khi cần đọc nhanh metadata
    mà không ràng buộc chặt chẽ theo schema Tier 2.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return "", text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i]), "\n".join(lines[i + 1:]).strip()
    return "", text


def _load_knowledge_details(ctx: RunContext, refs: list) -> list[dict[str, Any]]:
    """Trích xuất thông tin chi tiết (references, safe alternative, safe boundaries) từ tài liệu KB.

    Duyệt qua danh sách `knowledge_refs` của finding analysis để tải tài liệu tri thức
    tương ứng từ data/knowledge-base. Dữ liệu trích xuất bao gồm link tham chiếu chính thống,
    giải pháp an toàn và điều kiện an toàn (not_exploitable_when) để hiển thị trên Web UI.
    """
    details: list[dict[str, Any]] = []
    if not isinstance(refs, list):
        return details

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        path_str = str(ref.get("path") or "").strip()
        if not path_str:
            continue
        score = ref.get("score")

        doc_path = Path(path_str)
        if not doc_path.is_absolute():
            candidate = ctx.repo_root / doc_path
            if candidate.exists():
                doc_path = candidate
            elif not doc_path.exists():
                # Nếu không tìm thấy file, vẫn giữ record tối thiểu để không mất dữ liệu
                details.append({
                    "path": path_str,
                    "score": score,
                    "title": path_str,
                    "references": [],
                    "safe_alternative": "",
                    "not_exploitable_when": "",
                })
                continue

        # Thử đọc qua parser Tier 2 trước vì Tier 2 có cấu trúc chuẩn đầy đủ nhất
        try:
            tier2 = parse_tier2(doc_path)
            title = ""
            for line in tier2.body.splitlines():
                stripped = line.strip()
                if stripped.startswith("# "):
                    title = stripped.lstrip("# ").strip()
                    break
            if not title:
                title = f"{tier2.canonical_category} ({tier2.id})"

            details.append({
                "path": path_str,
                "score": score,
                "id": tier2.id,
                "title": title,
                "canonical_category": tier2.canonical_category,
                "cwe": list(tier2.cwe),
                "safe_alternative": tier2.safe_alternative,
                "not_exploitable_when": tier2.not_exploitable_when,
                "exploitable_when": tier2.exploitable_when,
                "references": list(tier2.references),
            })
            continue
        except Exception:
            pass

        # Nếu không phải Tier 2 (ví dụ Tier 1 hoặc markdown tuỳ biến), đọc frontmatter tổng quát
        try:
            text = doc_path.read_text(encoding="utf-8")
            raw_meta, body = _split_yaml_frontmatter(text)
            meta = yaml.safe_load(raw_meta) if raw_meta else {}
            if isinstance(meta, dict):
                title = str(meta.get("title") or "").strip()
                if not title:
                    for line in body.splitlines():
                        if line.strip().startswith("# "):
                            title = line.strip().lstrip("# ").strip()
                            break
                refs_list = meta.get("references") or []
                if isinstance(refs_list, str):
                    refs_list = [refs_list]
                elif not isinstance(refs_list, list):
                    refs_list = []

                details.append({
                    "path": path_str,
                    "score": score,
                    "id": str(meta.get("id") or doc_path.stem),
                    "title": title or doc_path.stem,
                    "safe_alternative": str(meta.get("safe_alternative") or ""),
                    "not_exploitable_when": str(meta.get("not_exploitable_when") or ""),
                    "exploitable_when": str(meta.get("exploitable_when") or ""),
                    "references": [str(r) for r in refs_list if str(r).startswith("http")],
                })
        except Exception:
            details.append({
                "path": path_str,
                "score": score,
                "title": path_str,
                "references": [],
                "safe_alternative": "",
                "not_exploitable_when": "",
            })

    return details


def analysis_data(ctx: RunContext, run_id: str) -> dict:
    record = load_run(ctx.runs_dir, run_id)
    records = _read_jsonl(record.root / "analysis.jsonl")
    for item in records:
        if isinstance(item, dict):
            k_refs = item.get("knowledge_refs") or []
            item["knowledge_details"] = _load_knowledge_details(ctx, k_refs)
    return {
        "run": record,
        "records": records,
        "proposal": _read_json(record.root / "proposal.json", {}),
    }


def events_data(ctx: RunContext, run_id: str) -> dict:
    record = load_run(ctx.runs_dir, run_id)
    return {
        "run": record,
        "events": read_events(record.root / "events.jsonl"),
        "scrubbed": _read_json(record.root / "scrubbed.json", {}),
        "proposal": _read_json(record.root / "proposal.json", {}),
    }


def requests_data(ctx: RunContext, run_id: str) -> dict:
    record = load_run(ctx.runs_dir, run_id)
    return {
        "run": record,
        "requests": _read_jsonl(record.root / "gateway-requests.jsonl"),
        "probe_result": _read_json(record.root / "probe-result.json", {}),
    }


def approvals_data(ctx: RunContext) -> dict:
    """Các lần chạy đang chờ người duyệt."""
    pending = []
    for run_id in list_runs(ctx.runs_dir):
        try:
            record = load_run(ctx.runs_dir, run_id)
        except Exception:
            continue
        if record.state.value != "AWAITING_APPROVAL":
            continue
        request = _read_json(record.root / "approval-request.json", None)
        if isinstance(request, dict):
            pending.append({"run_id": run_id, "request": request})
    return {"pending": pending}


def run_status(ctx: RunContext, run_id: str) -> dict:
    """Dữ liệu thời gian thực phục vụ polling / live updates."""
    record: RunRecord = load_run(ctx.runs_dir, run_id)
    logs = read_log(record.root)[-100:]
    log_text = "\n".join(
        f"[{entry.get('level', 'info').upper()}] {entry.get('step', 'system')}: {entry.get('message', '')}"
        for entry in logs
    )
    metrics = collect_metrics(record)
    return {
        "run_id": record.run_id,
        "state": record.state.value,
        "error": record.error,
        "terminal": record.state.is_terminal(),
        "awaiting_approval": record.state.value == "AWAITING_APPROVAL",
        "steps": [
            {"index": s.index, "name": s.name, "status": s.status, "elapsed_ms": s.elapsed_ms}
            for s in record.steps
        ],
        "log": log_text,
        "metrics": {
            "findings_total": metrics["findings_total"],
            "requests_total": metrics["requests_total"],
            "approvals_approved": metrics["approvals"]["approved"],
            "approvals_rejected": metrics["approvals"]["rejected"],
            "total_elapsed_ms": metrics["total_elapsed_ms"],
        },
    }
