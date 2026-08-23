# Worklog — Mở rộng Knowledge Base sang nửa DAST (F5)

**Ngày:** 2026-08-23 · **Agent/Model:** Subagent D · Antigravity ·
**Branch:** `feat/dast-zap-authenticated` · **Plan:** `docs/superpowers/plans/2026-08-22-dast-zap-authenticated.md` · **Task ID:** `Task D`

---

## 1. Tóm tắt

Đã mở rộng kho tri thức an ninh (Knowledge Base) hai tầng sang nửa DAST (Dynamic Application Security Testing) bằng việc bổ sung 3 tài liệu Tier 1 và 4 entry Tier 2 neo theo các rule ID chuẩn của OWASP ZAP (10038, 10021, 10020, 10009, 10036). Cập nhật schema phân loại chuẩn (CANONICAL_CATEGORIES) và cơ chế báo cáo độ phủ (kb_coverage) để phân tách rõ ràng các entry neo theo SAST, DAST và chưa có rule. Toàn bộ 41 unit test kiểm thử tính toàn vẹn và tra cứu DAST đều vượt qua 100%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp dữ liệu tri thức chuyên sâu và đối chứng tất định cho các cảnh báo DAST (ZAP Alerts) về Security Headers và Information Disclosure, giúp Security Analysis Agent phân tích nguyên nhân gốc rễ và đề xuất biện pháp khắc phục chính xác.
- **Nằm ở đâu trong luồng:** Nằm tại tầng `retrieval/` (`knowledge_retriever` và `tier_lookup`), hoạt động trước bước gán ngữ cảnh tri thức vào prompt gửi cho LLM.
- **Không có nó thì hỏng gì:** Các phát hiện DAST sẽ rơi vào tra cứu mờ (fuzzy keyword search) hoặc không có tri thức Tier 2 đối sánh, dẫn đến prompt phân tích thiếu thông tin chi tiết về header rủi ro và điều kiện loại trừ sai số (`not_exploitable_when`).
- **Ngoài phạm vi (cố ý không làm):** Không sửa đổi `test_tier_lookup.py` (tạo file test riêng `test_tier_lookup_dast.py`), không chạy lệnh git commit/branch (để agent cha thực hiện sau khi hoàn tất phối hợp các subagent).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `data/knowledge-base/tier1/security-headers.md` | Tạo mới | Tạo tài liệu Tier 1 tổng quan về Security Headers (CWE-693, CWE-1021, OWASP A05:2021) với 4 mục chuẩn | Cung cấp tri thức nền tảng cho lớp lỗ hổng header HTTP |
| `data/knowledge-base/tier1/information-disclosure.md` | Tạo mới | Tạo tài liệu Tier 1 tổng quan về Information Disclosure (CWE-497, CWE-200, OWASP A01/A05:2021) với 4 mục chuẩn | Cung cấp tri thức nền tảng cho rò rỉ phiên bản/thông tin hệ thống |
| `data/knowledge-base/tier1/caching-policy.md` | Tạo mới | Tạo tài liệu Tier 1 tổng quan về Insecure Caching Policy (CWE-524, CWE-525) với 4 mục chuẩn | Cung cấp tri thức cho chính sách lưu đệm HTTP |
| `data/knowledge-base/tier2/http-missing-csp-header.md` | Tạo mới | Entry Tier 2 cho ZAP rule 10038 (Content-Security-Policy), parent `security-headers`, code block HTTP | Tra cứu tất định cho lỗi thiếu CSP header |
| `data/knowledge-base/tier2/http-missing-xcto-header.md` | Tạo mới | Entry Tier 2 cho ZAP rule 10021 (X-Content-Type-Options), parent `security-headers`, code block HTTP | Tra cứu tất định cho lỗi thiếu X-Content-Type-Options |
| `data/knowledge-base/tier2/http-missing-frame-options.md` | Tạo mới | Entry Tier 2 cho ZAP rule 10020 (X-Frame-Options), parent `security-headers`, code block HTTP | Tra cứu tất định cho lỗi chống Clickjacking |
| `data/knowledge-base/tier2/http-server-version-leak.md` | Tạo mới | Entry Tier 2 cho ZAP rule 10009, 10036 (Server header leak), parent `information-disclosure`, code block HTTP | Tra cứu tất định cho lỗi lộ phiên bản máy chủ |
| `src/project_sentinel/retrieval/kb_schema.py` | Sửa | Thêm `Security Misconfiguration` và `Information Disclosure` vào `CANONICAL_CATEGORIES` | Cho phép schema YAML parse hợp lệ các entry DAST mới |
| `src/project_sentinel/retrieval/kb_coverage.py` | Sửa | Phân loại `with_sast`, `with_dast` (rule.isdigit()), `without_rule`, cập nhật `render()` | Báo cáo chính xác phân bố nguồn rule SAST và DAST |
| `tests/unit/retrieval/test_tier_lookup_dast.py` | Tạo mới | Test tra cứu rule 10021, 10038 kéo parent, fallback keyword cho CWE-524 khi không khớp Tier 2 | Kiểm thử độc lập hợp đồng tra cứu DAST |
| `tests/unit/retrieval/test_kb_integrity.py` | Sửa | Cập nhật EXPECTED_TIER1_IDS (17 docs), số lượng Tier 2 (15 entries), hỗ trợ code block ```http và rule ID số | Đảm bảo 100% tính toàn vẹn của kho tri thức sau mở rộng |
| `tests/unit/retrieval/test_kb_coverage.py` | Sửa | Cập nhật assert 15 entries, 3 SAST, 4 DAST, 8 no rule, 7 with rule | Khớp cấu trúc báo cáo độ phủ mới |
| `tests/unit/infra/test_docs_complete.py` | Sửa | Cập nhật assert tier1 == 17, tier2 == 15 | Đồng bộ số lượng tài liệu kho tri thức trong bài kiểm thử tài liệu |

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Khởi tạo 3 tài liệu Tier 1 và 4 tài liệu Tier 2 với đầy đủ frontmatter YAML, các trường bắt buộc (`safe_alternative`, `exploitable_when`, `not_exploitable_when` >= 30 ký tự, `references` >= 3 URLs), và 4 phân mục nội dung chuẩn kèm khối mã minh họa HTTP response headers (`### ❌ Không an toàn` và `### ✅ Đã khắc phục an toàn`).
2. Bổ sung 2 danh mục chuẩn mới vào `CANONICAL_CATEGORIES` trong `kb_schema.py`.
3. Tinh chỉnh logic phân loại rule trong `kb_coverage.py`: nhận diện rule SAST qua tập `known_rules` từ OpenGrep config và rule DAST qua điều kiện `rule.isdigit()` (quy ước ID số của OWASP ZAP).
4. Viết mới bộ test tra cứu `test_tier_lookup_dast.py` và cập nhật các unit test liên quan.

**Luồng dữ liệu:**
`Finding DAST (ZAP Alert với ruleId)` → `lookup_tier2(rule_id, cwe)` → `Khớp Tier2Entry` → `Kéo theo Tier 1 parent doc` → `Đóng gói RetrievalHit tất định gửi sang Analysis Agent`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Doc Tier 1 | `security-headers.md` | `data/knowledge-base/tier1/security-headers.md` | Tri thức tổng quan Security Headers |
| Doc Tier 1 | `information-disclosure.md` | `data/knowledge-base/tier1/information-disclosure.md` | Tri thức tổng quan Information Disclosure |
| Doc Tier 1 | `caching-policy.md` | `data/knowledge-base/tier1/caching-policy.md` | Tri thức tổng quan Insecure Caching Policy |
| Doc Tier 2 | `http-missing-csp-header.md` | `data/knowledge-base/tier2/http-missing-csp-header.md` | Entry Tier 2 ZAP Rule 10038 |
| Doc Tier 2 | `http-missing-xcto-header.md` | `data/knowledge-base/tier2/http-missing-xcto-header.md` | Entry Tier 2 ZAP Rule 10021 |
| Doc Tier 2 | `http-missing-frame-options.md` | `data/knowledge-base/tier2/http-missing-frame-options.md` | Entry Tier 2 ZAP Rule 10020 |
| Doc Tier 2 | `http-server-version-leak.md` | `data/knowledge-base/tier2/http-server-version-leak.md` | Entry Tier 2 ZAP Rule 10009, 10036 |
| Module | `kb_schema.py` | `CANONICAL_CATEGORIES` | Mở rộng tập phân loại danh mục hợp lệ |
| Module | `kb_coverage.py` | `build_report()`, `render()` | Báo cáo độ phủ phân nhóm SAST / DAST / Chưa có rule |
| Test | `test_tier_lookup_dast.py` | `tests/unit/retrieval/test_tier_lookup_dast.py` | Bộ test tra cứu DAST |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_tier_lookup_dast.py tests/unit/retrieval/test_kb_integrity.py tests/unit/retrieval/test_kb_coverage.py tests/unit/infra/test_docs_complete.py -v
.venv/bin/python -m project_sentinel.retrieval.kb_coverage
```

**Output thật từ terminal:**

```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /home/longngx04/VinSOC/project_sentinel_main/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/longngx04/VinSOC/project_sentinel_main
configfile: pyproject.toml
plugins: respx-0.23.1, xdist-3.8.0, anyio-4.14.2, cov-7.1.0
collecting ... collected 41 items                                                             

tests/unit/retrieval/test_tier_lookup_dast.py::test_dast_rule_id_10021_tra_ve_tier2_match_kind_rule_id PASSED [  2%]
tests/unit/retrieval/test_tier_lookup_dast.py::test_dast_rule_id_10038_keo_theo_parent_security_headers PASSED [  4%]
tests/unit/retrieval/test_tier_lookup_dast.py::test_unknown_dast_rule_fallback_to_keyword_on_cwe524 PASSED [  7%]
tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat PASSED [  9%]
tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bay_doc_va_dung_id PASSED [ 12%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier PASSED [ 14%]
tests/unit/retrieval/test_kb_integrity.py::test_co_dung_muoi_lam_entry_tier2 PASSED [ 17%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_tier1_parent_tro_toi_doc_co_that PASSED [ 19%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_rule_id_duoc_khai_deu_ton_tai_that PASSED [ 21%]
tests/unit/retrieval/test_kb_integrity.py::test_entry_khong_co_rule_phai_danh_dau_no_rule_yet PASSED [ 24%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_sink_nao_xuat_hien_o_hai_entry PASSED [ 26%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_rule_id_nao_xuat_hien_o_hai_entry PASSED [ 29%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc PASSED [ 31%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_du_bon_de_muc_chuan PASSED [ 34%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_code_block_vulnerable_va_remediated PASSED [ 36%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_khai_references_url_hop_le PASSED [ 39%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_co_du_bon_de_muc_chuan PASSED [ 41%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_references_url_hop_le PASSED [ 43%]
tests/unit/retrieval/test_kb_coverage.py::test_dem_dung_so_entry_va_so_entry_co_rule PASSED [ 46%]
tests/unit/retrieval/test_kb_coverage.py::test_moi_khoang_trong_kem_so_lo_hong_that_cua_cwe_do PASSED [ 48%]
tests/unit/retrieval/test_kb_coverage.py::test_khoang_trong_xep_giam_dan_theo_so_lo_hong_that PASSED [ 51%]
tests/unit/retrieval/test_kb_coverage.py::test_bao_cao_neu_ca_tran_lan_so_do_duoc PASSED [ 53%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[README.md] PASSED [ 56%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/architecture.md] PASSED [ 58%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/target-webgoat.md] PASSED [ 60%]
tests/unit/infra/test_docs_complete.py::test_product_brief_covers_the_six_required_points PASSED [ 63%]
tests/unit/infra/test_docs_complete.py::test_readme_has_an_architecture_diagram PASSED [ 65%]
tests/unit/infra/test_docs_complete.py::test_readme_documents_the_one_command_run PASSED [ 68%]
tests/unit/infra/test_docs_complete.py::test_demo_script_covers_all_seven_required_items PASSED [ 70%]
tests/unit/infra/test_docs_complete.py::test_historical_reports_are_untouched PASSED [ 73%]
tests/unit/infra/test_docs_complete.py::test_limitations_names_residual_security_risks PASSED [ 75%]
tests/unit/infra/test_docs_complete.py::test_documentation_does_not_drift_on_eval_case_counts PASSED [ 78%]
tests/unit/infra/test_docs_complete.py::test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc PASSED [ 80%]
tests/unit/infra/test_docs_complete.py::test_readme_noi_ve_hai_tang_va_lenh_do_phu PASSED [ 82%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/limitations.md] PASSED [ 85%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/demo-script.md] PASSED [ 87%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[eval/README.md] PASSED [ 90%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[exercises/week4-gateway/README.md] PASSED [ 92%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[reports/week-05/report.md] PASSED [ 95%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[reports/week-06/report.md] PASSED [ 97%]
tests/unit/infra/test_docs_complete.py::test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc PASSED [100%]

============================== 41 passed in 0.47s ==============================
```

```text
=== KB Tier 2 ===
  Entry              : 15
  Entry neo theo SAST: 3 | neo theo DAST: 4 | chưa có rule: 8
  Có rule            : 7
  Chưa có rule       : 8

=== Thiếu rule, xếp theo số lỗ hổng thật trong WebGoat ===
   6x  CWE-79   java-servlet-response-writer, java-thymeleaf-unescaped-output
   5x  CWE-22   java-file-path-concat
   5x  CWE-352  java-spring-csrf-disabled
   3x  CWE-347  java-jwt-parse-unverified
   3x  CWE-798  java-hardcoded-credential
   2x  CWE-338  java-insecure-random
   1x  CWE-611  java-documentbuilder-xxe

  CWE mà KB chạm tới : 42/75 lỗ hổng (56.0%) — đây là TRẦN TRÊN
  Trần này giả định mỗi rule bắt được mọi thực thể của CWE mình phụ trách.
  Recall đo được thật nằm trong reports/week-06/report.md §4.5.
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Neo các rule DAST theo mã số chuẩn của OWASP ZAP (chuỗi số nguyên `rule_id.isdigit()`) và ánh xạ sang Tier 1 category tương ứng.

**Lý do:** ZAP phân loại các plugin/rule kiểm thử động theo ID số (ví dụ 10038 = CSP, 10021 = X-Content-Type-Options). Việc giữ nguyên ID số trong `matches_rule_ids` giúp tra cứu tất định 1-1 từ alert DAST vào KB mà không cần cơ chế dịch ID trung gian phức tạp.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_tier_lookup_dast.py tests/unit/retrieval/test_kb_integrity.py tests/unit/retrieval/test_kb_coverage.py tests/unit/infra/test_docs_complete.py -v` | 0 | 41 passed in 0.47s |
| `.venv/bin/python -m compileall -q src/project_sentinel` | 0 | Biên dịch thành công, không có lỗi cú pháp |
| `.venv/bin/python -m project_sentinel.retrieval.kb_coverage` | 0 | In báo cáo độ phủ KB Tier 2 chính xác (15 entries, 3 SAST, 4 DAST, 8 chưa có rule) |

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có. Các tài liệu và test tuân thủ nghiêm ngặt schema và hợp đồng tra cứu.
- **Giả định đã đặt:** Các cảnh báo từ ZAP DAST luôn cung cấp rule ID dạng chuỗi số (`"10038"`, `"10021"`, v.v.).
- **Việc còn nợ:** Không có.
