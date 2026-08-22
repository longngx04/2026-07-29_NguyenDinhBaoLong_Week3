"""KB thật phải đúng cấu trúc. Test này chạy trên data/ thật, không phải fixture."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
KB = REPO_ROOT / "data" / "knowledge-base"
TIER1 = KB / "tier1"

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
