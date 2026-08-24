"""Test cho vong verify.

KHONG mock LLM provider theo nghia stub-de-qua-test: cac lop provider o day la
provider THAT theo giao thuc `LLMProvider`, chi khac o cho chung tra ve mot cau
tra loi da biet thay vi goi mang. Dieu duoc kiem la logic fail-open cua chinh
`verify_findings`, va logic do phai kiem duoc ma khong dot token.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from project_sentinel.config import AppConfig
from project_sentinel.llm.base import LLMResult
from project_sentinel.triage.verifier import verify_findings

if TYPE_CHECKING:
    from project_sentinel.triage.verifier import VerifyOutcome

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA = REPO_ROOT / "schemas" / "verify-verdict.schema.json"
PROMPT = REPO_ROOT / "configs" / "prompts" / "verify-finding-system.md"

FINDINGS = [
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
    },
    {
        "id": "zap-10009-abc",
        "tool": "zap",
        "severity": "low",
        "file_or_url": "http://gateway-dast:8081/WebGoat/logout",
        "line": 0,
        "title": "In Page Banner Information Leak",
        "rule_id": "10009",
        "cwe": ["CWE-497"],
        "owasp": [],
        "message": "The server returned a version banner string.",
    },
]


class ScriptedProvider:
    """Provider tra loi theo kich ban da dinh, khong goi mang."""

    def __init__(self, by_finding: dict[str, dict | Exception]):
        self.by_finding = by_finding
        self.calls = 0

    def analyze(self, packet, system_prompt=None):  # pragma: no cover - khong dung
        raise NotImplementedError

    def generate(self, *, system_prompt: str, user_prompt: str) -> LLMResult:
        self.calls += 1
        for finding_id, answer in self.by_finding.items():
            if finding_id in user_prompt:
                if isinstance(answer, Exception):
                    raise answer
                return LLMResult(
                    raw_response=json.dumps(answer), parsed_response=answer
                )
        raise AssertionError("prompt khong chua finding_id nao da biet")


def _verdict(finding_id: str, verdict: str, confidence: str, seen: str) -> dict:
    return {
        "schema_version": "1.0",
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": confidence,
        "rationale": "Ly do ngan gon.",
        "evidence_seen": seen,
    }


def _run(provider: ScriptedProvider, tmp_path: Path) -> VerifyOutcome:
    return verify_findings(
        FINDINGS,
        config=AppConfig.from_env(),
        provider=provider,
        prompt_path=PROMPT,
        schema_path=SCHEMA,
        output_dir=tmp_path,
    )


def test_loai_dung_finding_bi_cham_fp_confidence_cao(tmp_path: Path) -> None:
    provider = ScriptedProvider(
        {
            "opengrep-001": _verdict("opengrep-001", "false_positive", "high", "source"),
            "zap-10009-abc": _verdict("zap-10009-abc", "true_positive", "high", "metadata_only"),
        }
    )

    outcome = _run(provider, tmp_path)

    assert [f["id"] for f in outcome.kept] == ["zap-10009-abc"]
    assert [f["id"] for f in outcome.dropped] == ["opengrep-001"]
    assert outcome.summary["total"] == 2
    assert outcome.summary["kept"] == 1
    assert outcome.summary["dropped"] == 1


def test_llm_loi_thi_finding_van_di_tiep(tmp_path: Path) -> None:
    """Fail-open: khong ket luan duoc thi giu."""
    provider = ScriptedProvider(
        {
            "opengrep-001": RuntimeError("mang hong"),
            "zap-10009-abc": _verdict("zap-10009-abc", "false_positive", "high", "metadata_only"),
        }
    )

    outcome = _run(provider, tmp_path)

    assert "opengrep-001" in [f["id"] for f in outcome.kept]
    assert outcome.summary["llm_errors"] == 1


def test_verdict_sai_schema_thi_finding_van_di_tiep(tmp_path: Path) -> None:
    provider = ScriptedProvider(
        {
            "opengrep-001": {"verdict": "false_positive"},  # thieu truong bat buoc
            "zap-10009-abc": _verdict("zap-10009-abc", "uncertain", "low", "metadata_only"),
        }
    )

    outcome = _run(provider, tmp_path)

    assert sorted(f["id"] for f in outcome.kept) == ["opengrep-001", "zap-10009-abc"]
    assert outcome.summary["dropped"] == 0
    assert outcome.summary["llm_errors"] == 1


def test_verdict_tro_toi_finding_khong_co_that_bi_bo(tmp_path: Path) -> None:
    """Provenance: khong duoc phep loai mot finding bang verdict cua finding khac."""
    provider = ScriptedProvider(
        {
            "opengrep-001": _verdict("khong-ton-tai", "false_positive", "high", "source"),
            "zap-10009-abc": _verdict("zap-10009-abc", "uncertain", "low", "metadata_only"),
        }
    )

    outcome = _run(provider, tmp_path)

    assert sorted(f["id"] for f in outcome.kept) == ["opengrep-001", "zap-10009-abc"]
    assert outcome.summary["llm_errors"] == 1


def test_uncertain_luon_duoc_giu(tmp_path: Path) -> None:
    provider = ScriptedProvider(
        {
            "opengrep-001": _verdict("opengrep-001", "uncertain", "high", "source"),
            "zap-10009-abc": _verdict("zap-10009-abc", "uncertain", "high", "metadata_only"),
        }
    )

    outcome = _run(provider, tmp_path)

    assert len(outcome.kept) == 2
    assert outcome.summary["uncertain"] == 2


def test_ghi_du_ba_artifact(tmp_path: Path) -> None:
    provider = ScriptedProvider(
        {
            "opengrep-001": _verdict("opengrep-001", "false_positive", "high", "source"),
            "zap-10009-abc": _verdict("zap-10009-abc", "true_positive", "high", "metadata_only"),
        }
    )

    _run(provider, tmp_path)

    verified = json.loads((tmp_path / "findings.verified.json").read_text(encoding="utf-8"))
    assert [f["id"] for f in verified["findings"]] == ["zap-10009-abc"]
    assert verified["count"] == 1

    lines = (tmp_path / "verify.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    summary = json.loads((tmp_path / "verify-summary.json").read_text(encoding="utf-8"))
    assert summary["dropped"] == 1


def test_danh_sach_findings_rong(tmp_path: Path) -> None:
    provider = ScriptedProvider({})

    outcome = verify_findings(
        [],
        config=AppConfig.from_env(),
        provider=provider,
        prompt_path=PROMPT,
        schema_path=SCHEMA,
        output_dir=tmp_path,
    )

    assert outcome.kept == []
    assert outcome.summary["total"] == 0
    assert provider.calls == 0


def test_thieu_prompt_thi_bao_loi_chu_khong_loai_gi(tmp_path: Path) -> None:
    provider = ScriptedProvider({})

    with pytest.raises(FileNotFoundError):
        verify_findings(
            FINDINGS,
            config=AppConfig.from_env(),
            provider=provider,
            prompt_path=tmp_path / "khong-co-prompt.md",
            schema_path=SCHEMA,
            output_dir=tmp_path,
        )

    assert not (tmp_path / "findings.verified.json").exists()


def test_prompt_nguoi_dung_chua_id_va_bang_chung(tmp_path: Path) -> None:
    """Prompt phai mang du du lieu de LLM tra loi duoc, va phai co finding_id."""
    from project_sentinel.analysis.evidence import evidence_for_finding
    from project_sentinel.triage.verifier import build_user_prompt

    config = AppConfig.from_env()
    evidence = evidence_for_finding(
        FINDINGS[1],
        project_root=config.project_root,
        target_root=config.target_root,
        radius=config.source_radius,
    )
    prompt = build_user_prompt(FINDINGS[1], evidence)

    assert "zap-10009-abc" in prompt
    assert "In Page Banner Information Leak" in prompt
