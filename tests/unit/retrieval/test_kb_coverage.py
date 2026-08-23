"""Bao cao do phu noi KB dung o dau so voi lo hong co that."""

from pathlib import Path

from project_sentinel.retrieval.kb_coverage import build_report

REPO_ROOT = Path(__file__).resolve().parents[3]
TIER2 = REPO_ROOT / "data" / "knowledge-base" / "tier2"
RULES = REPO_ROOT / "configs" / "opengrep" / "java-security.yml"
TRUTH = (
    REPO_ROOT / "eval" / "ground-truth" / "recall"
    / "webgoat-vulnerabilities.applicable.json"
)


def test_dem_dung_so_entry_va_so_entry_co_rule():
    report = build_report(TIER2, RULES, TRUTH)
    assert report["entries"] == 17
    assert report["with_sast"] == 3
    assert report["with_dast"] == 6
    assert report["without_rule"] == 8
    assert report["with_rule"] == 9


def test_moi_khoang_trong_kem_so_lo_hong_that_cua_cwe_do():
    report = build_report(TIER2, RULES, TRUTH)
    by_cwe = {gap["cwe"]: gap for gap in report["gaps"]}
    assert by_cwe["CWE-79"]["truth_count"] == 6
    assert by_cwe["CWE-22"]["truth_count"] == 5
    assert by_cwe["CWE-352"]["truth_count"] == 5


def test_khoang_trong_xep_giam_dan_theo_so_lo_hong_that():
    """Nguoi doc phai thay ngay nen viet rule nao truoc."""
    counts = [gap["truth_count"] for gap in build_report(TIER2, RULES, TRUTH)["gaps"]]
    assert counts == sorted(counts, reverse=True)


def test_bao_cao_neu_ca_tran_lan_so_do_duoc():
    """Chi in tran ma khong in so do that se bi doc thanh cam ket."""
    report = build_report(TIER2, RULES, TRUTH)
    assert report["truth_total"] == 75
    assert report["cwe_reach"] == 42
