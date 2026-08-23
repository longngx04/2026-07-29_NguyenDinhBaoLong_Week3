"""Luat 10 va 11: KB phai la rang buoc, khong phai ngu canh thu dong."""

from project_sentinel.analysis.validators import validate_provenance

TIER2_HIT = {
    "path": "data/knowledge-base/tier2/java-sql-statement-execute.md",
    "score": 100.0,
    "tier": 2,
    "match_kind": "rule_id",
    "canonical_category": "SQL Injection",
}
CWE_HIT = {**TIER2_HIT, "match_kind": "cwe"}


def _record(**overrides):
    base = {
        "source_finding_ids": ["f1"],
        "locations": [{"file": "src/Login.java", "line": 42}],
        "title": "SQL Injection",
        "knowledge_refs": [
            {"path": TIER2_HIT["path"], "score": 100.0}
        ],
    }
    base.update(overrides)
    return base


def _check(record, hits):
    return validate_provenance(
        record_dict=record,
        input_group_finding_ids=["f1"],
        input_locations=[{"file": "src/Login.java", "line": 42}],
        input_knowledge_paths=[hit["path"] for hit in hits],
        input_knowledge_hits=hits,
    )


def test_bo_qua_hit_rule_id_la_loi_va_thong_diep_neu_dung_path():
    ok, errors = _check(_record(knowledge_refs=[]), [TIER2_HIT])
    assert not ok
    assert any(TIER2_HIT["path"] in err for err in errors), errors


def test_trich_dan_dung_thi_khong_loi():
    ok, errors = _check(_record(), [TIER2_HIT])
    assert ok, errors


def test_hit_theo_cwe_khong_bat_buoc_trich_dan():
    """CWE la khop gan dung: mot CWE bao nhieu sink, entry co the khong dung sink nay."""
    ok, errors = _check(_record(knowledge_refs=[]), [CWE_HIT])
    assert ok, errors


def test_title_lech_canonical_category_la_loi_va_neu_ten_dung():
    ok, errors = _check(_record(title="Command Injection"), [TIER2_HIT])
    assert not ok
    assert any("SQL Injection" in err for err in errors), errors


def test_title_khac_hoa_thuong_va_khoang_trang_van_duoc_chap_nhan():
    ok, errors = _check(_record(title="  sql injection  "), [TIER2_HIT])
    assert ok, errors


def test_khong_co_hit_tier2_thi_khong_rang_buoc_gi_them():
    tier1_hit = {
        "path": "data/knowledge-base/tier1/xss.md",
        "score": 12.5,
        "tier": 1,
        "match_kind": "keyword",
    }
    ok, errors = _check(
        _record(title="Bat cu ten gi", knowledge_refs=[]), [tier1_hit]
    )
    assert ok, errors


def test_trich_path_tier2_khong_co_trong_packet_van_bi_luat_3_chan():
    """Luat 10 khong duoc lam yeu luat 3: bia ra path van phai bi bat."""
    bia = _record(knowledge_refs=[
        {"path": "data/knowledge-base/tier2/khong-ton-tai.md", "score": 100.0}
    ])
    ok, errors = _check(bia, [TIER2_HIT])
    assert not ok
    assert any("khong-ton-tai" in err for err in errors), errors
