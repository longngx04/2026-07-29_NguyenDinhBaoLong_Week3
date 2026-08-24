# tests/integration/test_verify_step.py
"""Kiem chung buoc verify tren luong that.

Test danh dau `llm` goi LLM THAT theo AGENTS.md §2.2 — khong co mock, khong co
che do offline gia lap. Chung chay bang `make llm-test`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_sentinel.config import AppConfig
from project_sentinel.llm.factory import build_llm
from project_sentinel.triage.verifier import verify_findings

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = REPO_ROOT / "schemas" / "verify-verdict.schema.json"
PROMPT = REPO_ROOT / "configs" / "prompts" / "verify-finding-system.md"


def _finding(finding_id: str, path: str, line: int, title: str, message: str) -> dict:
    return {
        "id": finding_id,
        "tool": "opengrep",
        "severity": "high",
        "file_or_url": path,
        "line": line,
        "title": title,
        "rule_id": "java-sql-injection",
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "message": message,
    }


@pytest.mark.llm
def test_verify_khong_bao_gio_loai_nhieu_hon_so_finding_dau_vao(tmp_path):
    findings = [
        _finding(
            "opengrep-001",
            "benchmarks/targets/webgoat/src/main/java/org/owasp/webgoat/lessons/"
            "sqlinjection/introduction/SqlInjectionLesson5a.java",
            50,
            "SQL Injection",
            "Statement.executeQuery receives a concatenated string.",
        ),
    ]
    config = AppConfig.from_env()

    outcome = verify_findings(
        findings,
        config=config,
        provider=build_llm(config),
        prompt_path=PROMPT,
        schema_path=SCHEMA,
        output_dir=tmp_path,
    )

    assert len(outcome.kept) + len(outcome.dropped) == len(findings)
    verified = json.loads(
        (tmp_path / "findings.verified.json").read_text(encoding="utf-8")
    )
    input_ids = {f["id"] for f in findings}
    assert {f["id"] for f in verified["findings"]} <= input_ids


@pytest.mark.llm
def test_verdict_luon_hop_le_theo_schema(tmp_path):
    from project_sentinel.analysis.validators import validate_record_schema

    findings = [
        _finding(
            "opengrep-002",
            "benchmarks/targets/webgoat/src/main/java/org/owasp/webgoat/lessons/"
            "sqlinjection/introduction/SqlInjectionLesson5a.java",
            50,
            "SQL Injection",
            "Statement.executeQuery receives a concatenated string.",
        ),
    ]
    config = AppConfig.from_env()

    outcome = verify_findings(
        findings,
        config=config,
        provider=build_llm(config),
        prompt_path=PROMPT,
        schema_path=SCHEMA,
        output_dir=tmp_path,
    )

    for verdict in outcome.verdicts:
        ok, error = validate_record_schema(verdict, SCHEMA)
        assert ok, error
        assert verdict["finding_id"] in {f["id"] for f in findings}


@pytest.mark.llm
def test_rationale_khong_chua_payload_khai_thac(tmp_path):
    forbidden = ["' or '1'='1", "union select", "drop table", "rm -rf", "<script>"]
    findings = [
        _finding(
            "opengrep-003",
            "benchmarks/targets/webgoat/src/main/java/org/owasp/webgoat/lessons/"
            "sqlinjection/introduction/SqlInjectionLesson5a.java",
            50,
            "SQL Injection",
            "Statement.executeQuery receives a concatenated string.",
        ),
    ]
    config = AppConfig.from_env()

    outcome = verify_findings(
        findings,
        config=config,
        provider=build_llm(config),
        prompt_path=PROMPT,
        schema_path=SCHEMA,
        output_dir=tmp_path,
    )

    for verdict in outcome.verdicts:
        lowered = verdict["rationale"].lower()
        for payload in forbidden:
            assert payload not in lowered
