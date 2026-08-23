"""Thác nước ba mức: rule_id -> cwe -> keyword. Hai mức đầu phải tất định.

Tất định là điều kiện tiên quyết để kết quả phân tích có thể tái lập và
luật provenance có thể kiểm tra chéo được điểm số và nguồn trích dẫn.
"""

from pathlib import Path

from project_sentinel.retrieval.knowledge_retriever import retrieve_knowledge
from project_sentinel.retrieval.tier_lookup import lookup_tier2

REPO_ROOT = Path(__file__).resolve().parents[3]
TIER1 = REPO_ROOT / "data" / "knowledge-base" / "tier1"
TIER2 = REPO_ROOT / "data" / "knowledge-base" / "tier2"


def test_rule_id_tra_dung_entry_va_ghi_dung_match_kind():
    entry, kind = lookup_tier2("java-sql-statement-execution", None, TIER2)
    assert entry is not None
    assert entry.id == "java-sql-statement-execute"
    assert kind == "rule_id"


def test_cwe_chi_chay_khi_rule_id_truot():
    entry, kind = lookup_tier2("rule-khong-ai-biet", ["CWE-89"], TIER2)
    assert entry is not None
    assert entry.id == "java-sql-statement-execute"
    assert kind == "cwe"


def test_rule_id_thang_cwe_khi_ca_hai_deu_khop():
    """Rule_id chính xác hơn CWE, nên nó phải được ưu tiên."""
    entry, kind = lookup_tier2("java-command-execution", ["CWE-89"], TIER2)
    assert entry is not None
    assert entry.id == "java-runtime-exec"
    assert kind == "rule_id"


def test_khong_khop_gi_thi_tra_ve_rong_chu_khong_nem_loi():
    assert lookup_tier2("khong-co", ["CWE-99999"], TIER2) == (None, None)


def test_thu_muc_khong_ton_tai_thi_tra_ve_rong():
    assert lookup_tier2("java-command-execution", None, Path("/khong/co")) == (None, None)


def test_hit_tier2_luon_keo_theo_doc_cha():
    hits = retrieve_knowledge(
        title="SQL Injection",
        rule_id="java-sql-statement-execution",
        cwe=["CWE-89"],
        knowledge_dir=TIER1,
    )
    kinds = {h.match_kind for h in hits}
    assert "rule_id" in kinds, "Thiếu hit Tier 2"
    assert "parent" in kinds, "Hit Tier 2 phải kéo theo tier1_parent"
    parent = next(h for h in hits if h.match_kind == "parent")
    assert parent.path.endswith("tier1/sql-injection.md")
    assert parent.tier == 1


def test_moi_hit_deu_mang_tier_va_match_kind_trong_to_dict():
    hits = retrieve_knowledge(
        title="SQL Injection",
        rule_id="java-sql-statement-execution",
        cwe=["CWE-89"],
        knowledge_dir=TIER1,
    )
    for hit in hits:
        payload = hit.to_dict()
        assert payload["tier"] in (1, 2)
        assert payload["match_kind"] in {"rule_id", "cwe", "parent", "keyword"}


def test_co_hit_tier2_thi_khong_con_hit_keyword():
    hits = retrieve_knowledge(
        title="SQL query built by string concatenation",
        rule_id="java-sql-statement-execution",
        cwe=["CWE-89"],
        knowledge_dir=TIER1,
    )
    assert any(h.tier == 2 for h in hits)
    assert not any(h.match_kind == "keyword" for h in hits), (
        "Doc Tier 1 dung da nam o kenh parent; keyword chi con hang 2-3 sai ho"
    )


def test_khong_co_hit_tier2_thi_keyword_van_phai_chay():
    """Duong nay phuc vu finding DAST — khong duoc lam mat."""
    hits = retrieve_knowledge(
        title="Weak hash function",
        rule_id="khong-co",
        cwe=["CWE-327"],
        knowledge_dir=TIER1,
    )
    assert hits
    assert all(h.match_kind == "keyword" for h in hits)


def test_keyword_search_khong_bao_gio_tra_ve_doc_tier2():
    """Để keyword chạm tier2/ là để khớp chữ cạnh tranh với tra cứu tất định."""
    hits = retrieve_knowledge(
        title="SQL Injection",
        rule_id="khong-co",
        cwe=[],
        knowledge_dir=TIER1,
    )
    for hit in hits:
        if hit.match_kind == "keyword":
            assert "/tier2/" not in hit.path


def test_hit_tier2_mang_theo_dieu_kien_khong_khai_thac_duoc():
    """Prompt dan agent dung `not_exploitable_when`; no phai co that trong packet."""
    h = [
        x
        for x in retrieve_knowledge(
            title="Potential SQL injection",
            rule_id="java-sql-statement-execution",
            cwe=["CWE-89"],
            knowledge_dir=TIER1,
        )
        if x.tier == 2
    ][0]
    payload = h.to_dict()
    assert payload["not_exploitable_when"], "Truong nay bi cat thi prompt dan hut"
    assert payload["exploitable_when"]
    assert payload["safe_alternative"]


def test_than_tai_lieu_tier2_toi_duoc_muc_khac_phuc():
    """Chi gui muc 1 la chi gui nua THUC DAY ket luan co lo hong."""
    h = [
        x
        for x in retrieve_knowledge(
            title="Potential SQL injection",
            rule_id="java-sql-statement-execution",
            cwe=["CWE-89"],
            knowledge_dir=TIER1,
        )
        if x.tier == 2
    ][0]
    assert "## 3. Biện pháp khắc phục" in h.snippet

