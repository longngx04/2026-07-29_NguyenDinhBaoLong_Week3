"""KB thật phải đúng cấu trúc. Test này chạy trên data/ thật, không phải fixture."""

from pathlib import Path

import yaml

from project_sentinel.retrieval.kb_schema import load_tier2

REPO_ROOT = Path(__file__).resolve().parents[3]
KB = REPO_ROOT / "data" / "knowledge-base"
TIER1 = KB / "tier1"
TIER2 = KB / "tier2"
RULES_FILE = REPO_ROOT / "configs" / "opengrep" / "java-security.yml"

EXPECTED_TIER1_IDS = {
    "sql-injection", "xss", "command-injection", "csrf", "idor",
    "path-traversal", "insecure-deserialization", "jwt-weak-verification",
    "broken-auth", "ssrf", "xxe", "html-tampering",
    "security-misconfiguration", "vulnerable-components",
}


def _frontmatter(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines and lines[0].strip() == "---", f"{path.name}: thieu frontmatter"
    end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    return yaml.safe_load("\n".join(lines[1:end])) or {}


def _rule_ids() -> set[str]:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return {str(rule["id"]) for rule in data["rules"]}


def test_thu_muc_vulnerabilities_cu_da_bien_mat():
    assert not (KB / "vulnerabilities").exists(), (
        "Con thu muc cu thi keyword search se quet ca hai noi va dem trung"
    )


def test_tier1_co_dung_muoi_bon_doc_va_dung_id():
    ids = {_frontmatter(p)["id"] for p in TIER1.glob("*.md")}
    assert ids == EXPECTED_TIER1_IDS


def test_moi_doc_tier1_khai_dung_tier():
    for path in TIER1.glob("*.md"):
        assert _frontmatter(path)["tier"] == 1, f"{path.name}"


def test_co_dung_muoi_mot_entry_tier2():
    assert len(load_tier2(TIER2)) == 11


def test_moi_tier1_parent_tro_toi_doc_co_that():
    """Parent tro sai la loi im lang: hit Tier 2 se khong keo duoc ngu canh lop."""
    for entry in load_tier2(TIER2):
        assert (TIER1 / f"{entry.tier1_parent}.md").exists(), (
            f"{entry.id}: tier1_parent '{entry.tier1_parent}' khong ton tai"
        )


def test_moi_rule_id_duoc_khai_deu_ton_tai_that():
    known = _rule_ids()
    for entry in load_tier2(TIER2):
        for rule_id in entry.matches_rule_ids:
            assert rule_id in known, f"{entry.id}: rule '{rule_id}' khong co that"


def test_entry_khong_co_rule_phai_danh_dau_no_rule_yet():
    for entry in load_tier2(TIER2):
        if not entry.matches_rule_ids:
            assert entry.no_rule_yet, (
                f"{entry.id}: khong khai rule nao ma cung khong danh dau no_rule_yet"
            )


def test_khong_sink_nao_xuat_hien_o_hai_entry():
    """Sink trung nghia la tra cuu nhap nhang: hai entry cung nhan mot finding."""
    seen: dict[str, str] = {}
    for entry in load_tier2(TIER2):
        for sink in entry.sink_signatures:
            assert sink not in seen, f"sink '{sink}' co ca o {seen[sink]} va {entry.id}"
            seen[sink] = entry.id


def test_khong_rule_id_nao_xuat_hien_o_hai_entry():
    seen: dict[str, str] = {}
    for entry in load_tier2(TIER2):
        for rule_id in entry.matches_rule_ids:
            assert rule_id not in seen, (
                f"rule '{rule_id}' duoc ca {seen[rule_id]} va {entry.id} nhan"
            )
            seen[rule_id] = entry.id


def test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc():
    """Day la truong nham vao over-claim rate 40%. Bo trong la mat muc dich."""
    for entry in load_tier2(TIER2):
        assert len(entry.not_exploitable_when) >= 30, (
            f"{entry.id}: not_exploitable_when qua ngan de co ich"
        )

