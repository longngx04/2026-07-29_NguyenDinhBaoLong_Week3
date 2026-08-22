"""Frontmatter cua Tier 2 la hop dong. Doc sai mot truong la hong ca chuoi tra cuu."""

from pathlib import Path

import pytest

from project_sentinel.retrieval.kb_schema import (
    KbSchemaError,
    load_tier2,
    parse_tier2,
)

VALID = """---
tier: 2
id: java-sql-statement-execute
canonical_category: SQL Injection
cwe: [CWE-89]
tier1_parent: sql-injection
language: java
sink_signatures:
  - java.sql.Statement.execute
  - java.sql.Statement.executeQuery
matches_rule_ids:
  - java-sql-statement-execution
safe_alternative: PreparedStatement voi placeholder `?`
exploitable_when: chuoi truy van duoc noi tu du lieu caller kiem soat
not_exploitable_when: >
  truy van la hang bien dich, hoac moi gia tri noi suy deu tu allowlist
  co dinh trong ma
---

# SQL Injection qua Statement

Than tai lieu.
"""


def _write(tmp_path: Path, text: str, name: str = "entry.md") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_entry_hop_le_doc_ra_du_moi_truong(tmp_path: Path) -> None:
    entry = parse_tier2(_write(tmp_path, VALID))
    assert entry.id == "java-sql-statement-execute"
    assert entry.canonical_category == "SQL Injection"
    assert entry.cwe == ("CWE-89",)
    assert entry.tier1_parent == "sql-injection"
    assert entry.sink_signatures == (
        "java.sql.Statement.execute",
        "java.sql.Statement.executeQuery",
    )
    assert entry.matches_rule_ids == ("java-sql-statement-execution",)
    assert entry.no_rule_yet is False
    assert "Than tai lieu" in entry.body


def test_scalar_gap_duoc_gop_thanh_mot_dong(tmp_path: Path) -> None:
    """`not_exploitable_when: >` la YAML folded scalar; parser viet tay khong doc duoc."""
    entry = parse_tier2(_write(tmp_path, VALID))
    assert "allowlist" in entry.not_exploitable_when
    assert "\n" not in entry.not_exploitable_when.strip()


def test_thieu_truong_bat_buoc_bi_tu_choi_va_neu_ten_truong(tmp_path: Path) -> None:
    text = VALID.replace("tier1_parent: sql-injection\n", "")
    with pytest.raises(KbSchemaError, match="tier1_parent"):
        parse_tier2(_write(tmp_path, text))


def test_category_ngoai_tap_dong_bi_tu_choi(tmp_path: Path) -> None:
    """Tap dong la thu giu cho luat 11 doi chieu duoc; go bo la mat cho dua."""
    text = VALID.replace("canonical_category: SQL Injection", "canonical_category: SQLi")
    with pytest.raises(KbSchemaError, match="SQLi"):
        parse_tier2(_write(tmp_path, text))


def test_tier_sai_bi_tu_choi(tmp_path: Path) -> None:
    text = VALID.replace("tier: 2", "tier: 1")
    with pytest.raises(KbSchemaError, match="tier"):
        parse_tier2(_write(tmp_path, text))


def test_sink_signatures_rong_bi_tu_choi(tmp_path: Path) -> None:
    text = VALID.replace(
        "sink_signatures:\n  - java.sql.Statement.execute\n"
        "  - java.sql.Statement.executeQuery\n",
        "sink_signatures: []\n",
    )
    with pytest.raises(KbSchemaError, match="sink_signatures"):
        parse_tier2(_write(tmp_path, text))


def test_entry_chua_co_rule_khong_can_matches_rule_ids(tmp_path: Path) -> None:
    text = VALID.replace(
        "matches_rule_ids:\n  - java-sql-statement-execution\n",
        "no_rule_yet: true\n",
    )
    entry = parse_tier2(_write(tmp_path, text))
    assert entry.no_rule_yet is True
    assert entry.matches_rule_ids == ()


def test_load_tier2_tra_ve_rong_khi_thu_muc_khong_ton_tai(tmp_path: Path) -> None:
    assert load_tier2(tmp_path / "khong-co") == []
