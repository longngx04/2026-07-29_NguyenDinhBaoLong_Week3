import json
from pathlib import Path

import yaml

from project_sentinel.retrieval.kb_schema import load_tier2

REPO_ROOT = Path(__file__).resolve().parents[3]
KB = REPO_ROOT / "data" / "knowledge-base"
TIER1 = KB / "tier1"
TIER2 = KB / "tier2"
RULES_FILE = REPO_ROOT / "configs" / "opengrep" / "java-security.yml"
ZAP_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "dast" / "zap-alerts-authenticated.json"

EXPECTED_TIER1_IDS = {
    "sql-injection", "xss", "command-injection", "csrf", "idor",
    "path-traversal", "insecure-deserialization", "jwt-weak-verification",
    "broken-auth", "ssrf", "xxe", "html-tampering",
    "security-misconfiguration", "vulnerable-components",
    "security-headers", "information-disclosure", "caching-policy",
}


def _frontmatter(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines and lines[0].strip() == "---", f"{path.name}: thieu frontmatter"
    end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    return yaml.safe_load("\n".join(lines[1:end])) or {}


def _rule_ids() -> set[str]:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return {str(rule["id"]) for rule in data["rules"]}


def _zap_plugin_ids() -> set[str]:
    """Plugin id ZAP co that, lay tu ket qua quet da commit.

    Khong dung isdigit(): no chap nhan moi chuoi so, nen mot id go nham van qua
    test roi im lang khong khop gi — dung cai loi im lang ma test nay sinh ra de chan.
    """
    ids: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("pluginid", "pluginId") and value:
                    ids.add(str(value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json.loads(ZAP_FIXTURE.read_text(encoding="utf-8")))
    return ids


def test_thu_muc_vulnerabilities_cu_da_bien_mat():
    assert not (KB / "vulnerabilities").exists(), (
        "Con thu muc cu thi keyword search se quet ca hai noi va dem trung"
    )


def test_tier1_co_dung_muoi_bay_doc_va_dung_id():
    ids = {_frontmatter(p)["id"] for p in TIER1.glob("*.md")}
    assert ids == EXPECTED_TIER1_IDS


def test_moi_doc_tier1_khai_dung_tier():
    for path in TIER1.glob("*.md"):
        assert _frontmatter(path)["tier"] == 1, f"{path.name}"


def test_co_dung_muoi_bay_entry_tier2():
    assert len(load_tier2(TIER2)) == 17


def test_moi_tier1_parent_tro_toi_doc_co_that():
    """Parent tro sai la loi im lang: hit Tier 2 se khong keo duoc ngu canh lop."""
    for entry in load_tier2(TIER2):
        assert (TIER1 / f"{entry.tier1_parent}.md").exists(), (
            f"{entry.id}: tier1_parent '{entry.tier1_parent}' khong ton tai"
        )


def test_moi_rule_id_duoc_khai_deu_ton_tai_that():
    known = _rule_ids() | _zap_plugin_ids()
    for entry in load_tier2(TIER2):
        for rule_id in entry.matches_rule_ids:
            assert rule_id in known, (
                f"{entry.id}: rule '{rule_id}' khong ton tai trong "
                f"configs/opengrep/*.yml lan fixture ZAP"
            )


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


def test_moi_entry_tier2_co_du_bon_de_muc_chuan():
    """Kiem tra 100% 15 file Tier 2 deu co du 4 de muc chuan:
    1. Co che rui ro
    2. Ma nguon minh hoa
    3. Bien phap khac phuc chuan
    4. Tai lieu tham khao

    Bat buoc de dam bao cau truc tri thuc dong nhat, phuc vu viec parse hien thi
    Web Dashboard va cung cap ngu canh chi tiet khi phan tich lo hong.
    """
    required_headings = [
        "## 1. Cơ chế rủi ro",
        "## 2. Mã nguồn minh họa",
        "## 3. Biện pháp khắc phục chuẩn",
        "## 4. Tài liệu tham khảo",
    ]
    tier2_files = list(TIER2.glob("*.md"))
    assert len(tier2_files) == 17, f"Ky vong 17 file Tier 2 nhung tim thay {len(tier2_files)}"
    for path in tier2_files:
        content = path.read_text(encoding="utf-8")
        for heading in required_headings:
            assert heading in content, f"{path.name}: thieu de muc bat buoc '{heading}'"


def test_moi_entry_tier2_co_code_block_vulnerable_va_remediated():
    """Kiem tra 100% 17 file Tier 2 deu co:
    - ### ❌ Không an toàn
    - ### ✅ Đã khắc phục an toàn
    - Chua it nhat mot code block ```java, ```html, hoac ```http

    Bat buoc de Web UI va ky su bao mat co ma doi chung truc quan, khong phong doan.
    """
    tier2_files = list(TIER2.glob("*.md"))
    assert len(tier2_files) == 17, f"Ky vong 17 file Tier 2 nhung tim thay {len(tier2_files)}"
    for path in tier2_files:
        content = path.read_text(encoding="utf-8")
        assert "### ❌ Không an toàn" in content, (
            f"{path.name}: thieu de muc mau khong an toan '### ❌ Không an toàn'"
        )
        assert "### ✅ Đã khắc phục an toàn" in content, (
            f"{path.name}: thieu de muc mau khac phuc '### ✅ Đã khắc phục an toàn'"
        )
        assert "```java" in content or "```html" in content or "```http" in content, (
            f"{path.name}: phai chua it nhat mot khoi code ```java, ```html, hoac ```http"
        )


def test_moi_entry_tier2_khai_references_url_hop_le():
    """Kiem tra 100% 17 file Tier 2 deu co references (danh sach >= 1 URL)
    va moi URL deu bat dau bang http:// hoac https://.

    Bat buoc de chong troi lien ket tham quyen (OWASP, CWE, Oracle docs),
    phuc vu tao badge lien ket tren Web UI.
    """
    tier2_files = list(TIER2.glob("*.md"))
    assert len(tier2_files) == 17, f"Ky vong 17 file Tier 2 nhung tim thay {len(tier2_files)}"
    for path in tier2_files:
        fm = _frontmatter(path)
        refs = fm.get("references")
        assert isinstance(refs, list) and len(refs) >= 1, (
            f"{path.name}: 'references' phai la danh sach co it nhat 1 URL tham chieu"
        )
        for url in refs:
            assert isinstance(url, str) and (
                url.startswith("http://") or url.startswith("https://")
            ), f"{path.name}: URL tham chieu '{url}' khong hop le (phai bat dau bang http:// hoac https://)"


def test_moi_doc_tier1_co_du_bon_de_muc_chuan():
    """Kiem tra 100% 17 file Tier 1 deu co du 4 de muc chuan:
    1. Khai niem & Moi de doa
    2. Cac bien the pho bien
    3. Nguyen tac phong thu da lop
    4. Tai lieu tham khao tham quyen

    Giup duy tri cau truc tai lieu phan loai lo hong dong bo cho toan bo 17 lop CWE/OWASP.
    """
    required_headings = [
        "## 1. Khái niệm & Mối đe dọa",
        "## 2. Các biến thể phổ biến",
        "## 3. Nguyên tắc phòng thủ đa lớp",
        "## 4. Tài liệu tham khảo thẩm quyền",
    ]
    tier1_files = list(TIER1.glob("*.md"))
    assert len(tier1_files) == 17, f"Ky vong 17 file Tier 1 nhung tim thay {len(tier1_files)}"
    for path in tier1_files:
        content = path.read_text(encoding="utf-8")
        for heading in required_headings:
            assert heading in content, f"{path.name}: thieu de muc bat buoc '{heading}'"


def test_moi_doc_tier1_khai_references_url_hop_le():
    """Kiem tra 100% 17 file Tier 1 deu co truong references trong frontmatter
    va moi URL deu hop le (bat dau bang http:// hoac https://).

    Giup lien ket truc tiep toi OWASP Top 10 va CWE Definitions.
    """
    tier1_files = list(TIER1.glob("*.md"))
    assert len(tier1_files) == 17, f"Ky vong 17 file Tier 1 nhung tim thay {len(tier1_files)}"
    for path in tier1_files:
        fm = _frontmatter(path)
        refs = fm.get("references")
        assert isinstance(refs, list) and len(refs) >= 1, (
            f"{path.name}: 'references' phai la danh sach co it nhat 1 URL tham chieu"
        )
        for url in refs:
            assert isinstance(url, str) and (
                url.startswith("http://") or url.startswith("https://")
            ), f"{path.name}: URL tham chieu '{url}' khong hop le (phai bat dau bang http:// hoac https://)"


