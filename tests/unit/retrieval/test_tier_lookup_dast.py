"""Kiểm tra tra cứu tri thức Tier 2 và fallback cho các rule/finding DAST."""

from pathlib import Path

from project_sentinel.retrieval.knowledge_retriever import retrieve_knowledge
from project_sentinel.retrieval.tier_lookup import lookup_tier2

REPO_ROOT = Path(__file__).resolve().parents[3]
TIER1 = REPO_ROOT / "data" / "knowledge-base" / "tier1"
TIER2 = REPO_ROOT / "data" / "knowledge-base" / "tier2"


def test_dast_rule_id_10021_tra_ve_tier2_match_kind_rule_id():
    """Rule DAST 10021 (X-Content-Type-Options) khớp chính xác Tier 2."""
    entry, kind = lookup_tier2("10021", None, TIER2)
    assert entry is not None
    assert entry.id == "http-missing-xcto-header"
    assert kind == "rule_id"


def test_dast_rule_id_10038_keo_theo_parent_security_headers():
    """Rule DAST 10038 (CSP) trúng Tier 2 và tự động kéo theo doc cha Tier 1 security-headers.md.

    Hợp đồng 4: Tuyệt đối không còn hit keyword khi đã có hit Tier 2.
    """
    hits = retrieve_knowledge(
        title="Content Security Policy (CSP) Header Not Set",
        rule_id="10038",
        cwe=["CWE-693"],
        knowledge_dir=TIER1,
    )
    kinds = {h.match_kind for h in hits}
    assert "rule_id" in kinds, "Thiếu hit Tier 2 bằng rule_id"
    assert "parent" in kinds, "Hit Tier 2 phải kéo theo tier1_parent"

    tier2_hit = next(h for h in hits if h.match_kind == "rule_id")
    assert tier2_hit.tier == 2
    assert tier2_hit.path.endswith("tier2/http-missing-csp-header.md")

    parent_hit = next(h for h in hits if h.match_kind == "parent")
    assert parent_hit.tier == 1
    assert parent_hit.path.endswith("tier1/security-headers.md")

    # HỢP ĐỒNG 4: KHÔNG assert có keyword khi đã có hit Tier 2!
    assert not any(h.match_kind == "keyword" for h in hits), (
        "Đã có hit Tier 2 tất định thì không được lẫn hit keyword"
    )


def test_unknown_dast_rule_fallback_to_keyword_on_cwe524():
    """Rule_id không tồn tại (99999) và CWE-524 (Insecure Caching Policy):
    Không có hit Tier 2, rơi xuống keyword search trên Tier 1 và tìm thấy caching-policy.md mà không ném lỗi.
    """
    hits = retrieve_knowledge(
        title="Insecure Caching Policy",
        rule_id="99999",
        cwe=["CWE-524"],
        knowledge_dir=TIER1,
    )
    assert hits, "Phải tìm thấy ít nhất 1 hit qua fallback keyword"
    assert all(h.match_kind == "keyword" for h in hits)
    assert all(h.tier == 1 for h in hits)
    assert any("caching-policy.md" in h.path for h in hits)


def test_moi_header_co_tai_lieu_rieng_khong_dung_chung_doc_csp():
    """CWE-693 co nhieu entry; tra nham doc se cho loi khuyen khac phuc sai header."""
    for rule_id, expect in (
        ("10038", "http-missing-csp-header"),
        ("10021", "http-missing-xcto-header"),
        ("10063", "http-missing-permissions-policy"),
        ("90004", "http-missing-coep-header"),
    ):
        entry, kind = lookup_tier2(rule_id, ["CWE-693"], TIER2)
        assert entry is not None and entry.id == expect, (
            f"{rule_id} -> {entry.id if entry else None}"
        )
        assert kind == "rule_id"

