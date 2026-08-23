# Worklog — Năm sửa đổi nâng cao độ chính xác và mở rộng DAST cho Kho tri thức

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · inherit ·
**Branch:** `feat/enhance-kb` · **Plan:** N/A (Direct 4-Subagent Parallel Remediation) · **Task ID:** `F1, F2, F3, F4, F5`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã giải quyết đồng thời 5 vấn đề cốt lõi trong hệ thống Kho tri thức (KB) thông qua 4 subagent song song:
1. **F1 (Subagent C):** Bỏ triệt để keyword search khi đã có tri thức tất định Tier 2, loại bỏ 100% (46/46) hit keyword rác/sai họ lỗ hổng trên các finding SAST.
2. **F2, F3 (Subagent A):** Sửa các URL trả 404 (Path Traversal, JWT) và xây dựng công cụ kiểm tra sống liên kết tự động `scripts/check-kb-links.sh` tích hợp vào `make kb-links`. Toàn bộ 66/66 URL trong KB đạt HTTP 200 OK.
3. **F4 (Subagent B):** Cập nhật System Prompt cảnh báo rõ ràng `match_kind == "keyword"` là khớp mờ, cấm mô hình thay đổi `title` hoặc `cwe` dựa trên keyword.
4. **F5 (Subagent D):** Mở rộng KB sang nửa DAST với 3 tài liệu Tier 1 mới (`security-headers`, `information-disclosure`, `caching-policy`) và 4 entry Tier 2 mới neo theo ZAP plugin ID (`10038`, `10021`, `10020`, `10009`, `10036`). Cập nhật `kb_schema.py` và báo cáo phân loại nguồn trong `kb_coverage.py`.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Tăng độ chính xác của tri thức đưa vào prompt LLM (loại bỏ nhiễu), đảm bảo tính toàn vẹn và khả năng truy cập của các tài liệu tham chiếu, và mở rộng độ bao phủ tri thức tất định cho các cảnh báo DAST từ OWASP ZAP.
- **Nằm ở đâu trong luồng:**
  - `src/project_sentinel/retrieval/knowledge_retriever.py`: Bước truy xuất tri thức trước khi phân tích.
  - `configs/prompts/security-analysis-system.md`: System prompt điều khiển agent LLM.
  - `data/knowledge-base/`: Dữ liệu tri thức 2 tầng.
  - `scripts/check-kb-links.sh` & `Makefile`: Công cụ kiểm thử chất lượng liên kết mạng.
- **Không có nó thì hỏng gì:**
  - 46/46 hit keyword sai họ gây loãng và làm xao nhãng LLM trong phân tích SAST.
  - DAST chỉ có 1/14 finding được gán tri thức chuẩn, 13/14 phải dựa vào keyword search không chính xác.
  - 2 liên kết 404 gây lỗi cho người dùng khi tra cứu tài liệu từ Web UI.
- **Ngoài phạm vi (cố ý không làm):** Không đưa `make kb-links` vào `make quality` vì cần kết nối Internet (tránh làm fail CI offline).

---

## 3. Đã làm gì

| Subagent | File | Thao tác | Nội dung |
|---|---|---|---|
| **A** | `data/knowledge-base/tier2/java-file-path-concat.md` | Sửa | Sửa URL 404 sang `https://owasp.org/www-community/attacks/Path_Traversal` |
| **A** | `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Sửa | Sửa URL 404 sang `https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html` |
| **A** | `data/knowledge-base/tier1/jwt-weak-verification.md` | Sửa | Sửa URL 404 JWT |
| **A** | `data/knowledge-base/tier1/path-traversal.md` | Sửa | Sửa URL 404 Path Traversal |
| **A** | `scripts/check-kb-links.sh` | Tạo mới | Script kiểm tra HTTP status code của mọi URL trong KB |
| **A** | `Makefile` | Sửa | Thêm target `kb-links` |
| **A** | `README.md` | Sửa | Thêm hướng dẫn `make kb-links` |
| **B** | `configs/prompts/security-analysis-system.md` | Sửa | Bổ sung quy tắc hard rule về `match_kind == "keyword"` là khớp mờ |
| **B** | `tests/unit/guardrails/test_system_prompt_rules.py` | Sửa | Thêm test kiểm tra quy tắc khớp mờ trong prompt |
| **C** | `src/project_sentinel/retrieval/knowledge_retriever.py` | Sửa | Bỏ keyword search khi đã có hit Tier 2 |
| **C** | `tests/unit/retrieval/test_tier_lookup.py` | Sửa | Thêm test kiểm tra bỏ keyword search khi có Tier 2 |
| **C** | `docs/superpowers/specs/2026-08-23-knowledge-base-two-tier-design.md` | Sửa | Cập nhật mục §5.1 theo đúng hành vi mới |
| **D** | `data/knowledge-base/tier1/*.md` (3 files) | Tạo mới | Thêm `security-headers.md`, `information-disclosure.md`, `caching-policy.md` |
| **D** | `data/knowledge-base/tier2/*.md` (4 files) | Tạo mới | Thêm 4 entry neo theo ZAP (`10038`, `10021`, `10020`, `10009/10036`) |
| **D** | `src/project_sentinel/retrieval/kb_schema.py` | Sửa | Thêm `Security Misconfiguration` & `Information Disclosure` |
| **D** | `src/project_sentinel/retrieval/kb_coverage.py` | Sửa | Phân loại nguồn SAST/DAST và in dòng nguồn |
| **D** | `tests/unit/retrieval/test_tier_lookup_dast.py` | Tạo mới | Test tra cứu tất định cho finding DAST |
| **D** | `tests/unit/retrieval/test_kb_integrity.py` | Sửa | Cập nhật kiểm tra 17 Tier 1 docs và 15 Tier 2 entries |
| **D** | `tests/unit/retrieval/test_kb_coverage.py` | Sửa | Cập nhật kiểm tra 15 entries với phân loại mới |
| **D** | `tests/unit/infra/test_docs_complete.py` | Sửa | Cập nhật chống trôi số lượng doc KB (17/15) |

---

## 4. Làm như thế nào

- **Subagent A:** Dùng curl với cờ `-L` và timeout 15s để kiểm tra toàn bộ URL trích xuất từ YAML frontmatter.
- **Subagent B:** Thêm chỉ thị tường minh vào system prompt giúp model không bị dẫn dắt bởi các tài liệu nền khớp mờ.
- **Subagent C:** Đặt điều kiện `if not any(h.tier == 2 for h in hits):` bọc quanh vòng lặp keyword search trong `retrieve_knowledge`.
- **Subagent D:** Khai báo `language: http`, `sink_signatures: ["Content-Security-Policy"]...` và `matches_rule_ids: ["10038"]...` cho các entry DAST, giữ vững cơ chế so khớp chuỗi tất định không cần sửa đổi mã tra cứu.

---

## 5. Output là gì

**Kết quả đo đạc thực tế trên run `20260822T205249Z` (37 findings = 23 SAST + 14 DAST):**

```text
Evaluating run: artifacts/runs/20260822T205249Z/findings.json (37 findings)
opengrep: 23/23 co hit Tier 2 | {'rule_id': 23, 'parent': 23}
zap: 8/14 co hit Tier 2 | {'rule_id': 5, 'parent': 8, 'keyword': 18, 'cwe': 3}
```

**Bảng so sánh Trước / Sau:**

| Chỉ số | Trước (Tuần 6) | Sau (Năm sửa đổi F1–F5) | Thay đổi / Ý nghĩa |
|---|---:|---:|---|
| **SAST có hit Tier 2** | **23/23 (100%)** | **23/23 (100%)** | Duy trì tuyệt đối |
| **Hit keyword rác trên SAST** | **46** | **0** | **-100%** — Triệt tiêu hoàn toàn nhiễu sai họ lỗ hổng |
| **DAST có hit Tier 2** | **1/14 (7.1%)** | **8/14 (57.1%)** | **+50.0%** — Mở rộng tri thức tất định cho DAST |
| **Tỷ lệ URL sống trong KB** | 97.0% (64/66) | **100.0% (66/66)** | 100% URL trả về HTTP 200 OK |
| **Số tài liệu KB** | 14 Tier 1 / 11 Tier 2 | **17 Tier 1 / 15 Tier 2** | Mở rộng bảo hiểm cho Security Headers & Info Leak |

**Output `make kb-coverage`:**

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

**Output `make quality`:**

```text
All checks passed!
Success: no issues found in 81 source files
........................................................................ [  7%]
........................................................................ [ 14%]
........................................................................ [ 21%]
........................................................................ [ 28%]
........................................................................ [ 35%]
........................................................................ [ 42%]
........................................................................ [ 49%]
........................................................................ [ 56%]
........................................................................ [ 63%]
........................................................................ [ 70%]
........................................................................ [ 77%]
........................................................................ [ 84%]
........................................................................ [ 91%]
........................................................................ [ 98%]
.................                                                        [100%]
================================ tests coverage ================================
Required test coverage of 78.0% reached. Total coverage: 83.81%
1025 passed, 41 deselected, 1 warning in 25.10s
No known vulnerabilities found
```

---

## 6. Vì sao chọn cách implement này

- Bỏ keyword search khi đã có Tier 2 là cách tiếp cận sạch nhất, loại bỏ hoàn toàn hiện tượng "bổ sung tài liệu hạng 2-3 lạc đề" mà không làm thay đổi logic tra cứu của các finding chỉ có keyword.
- Neo DAST theo ZAP Plugin ID trực tiếp qua cơ chế `matches_rule_ids` tận dụng được 100% hạ tầng tra cứu tất định hiện có mà không phải viết thêm logic branching phức tạp.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `./scripts/check-kb-links.sh` | 0 | 66/66 URL sống (HTTP 200 OK) |
| `make kb-coverage` | 0 | 15 entries, in đúng 3 SAST, 4 DAST, 8 chưa có rule |
| `pytest tests/unit/retrieval/ -v` | 0 | 87 passed |
| `pytest tests/unit/guardrails/test_system_prompt_rules.py -v` | 0 | 17 passed |
| `make quality` | 0 | 1025 passed, coverage 83.81% |

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có.
- **Giả định đã đặt:** `make kb-links` phụ thuộc mạng bên ngoài nên chạy độc lập, không chạy trong CI khép kín.
- **Việc còn nợ:** Không có.
- **Câu hỏi cho người dùng:** Không có.
