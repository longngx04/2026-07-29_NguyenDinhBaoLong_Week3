# Enriched Knowledge Base Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mở rộng và chuẩn hóa toàn bộ 25 tài liệu trong Kho tri thức (14 Tier 1 và 11 Tier 2) với các phần đối chứng mã nguồn (Vulnerable vs. Remediated Pattern), điều kiện an toàn chuyên sâu, liên kết thẩm quyền OWASP/CWE/Spring và tích hợp hiển thị trên Web UI.

**Architecture:** Chuẩn hóa cấu trúc Markdown 5 phần, bổ sung trường `references` trong frontmatter YAML được kiểm tra bởi `kb_schema.py` và `test_kb_integrity.py`. Tách bạch dữ liệu prompt LLM (ngắn gọn) với hiển thị đầy đủ trên Web Dashboard.

**Tech Stack:** Python 3.12, PyYAML, pytest, FastAPI/Jinja2.

## Global Constraints

- Ngôn ngữ chú thích và tài liệu: tiếng Việt, giải thích **vì sao**, theo đúng phong cách repo.
- **Không** đổi `schemas/security-analysis-record.schema.json`.
- **Không** thêm dependency mới (sử dụng PyYAML và thư viện sẵn có).
- **Không** gọi live API bên ngoài trong runtime; toàn bộ tri thức nằm trong repository.
- `make quality` phải xanh sau **mỗi** commit (ruff + mypy + coverage ≥ 78% + pip-audit).

---

## File Structure

**Tạo mới / Sửa đổi**

| File | Trách nhiệm |
| :--- | :--- |
| `src/project_sentinel/retrieval/kb_schema.py` | Cập nhật `Tier2Entry` hỗ trợ `references` và kiểm tra URL hợp lệ. |
| `tests/unit/retrieval/test_kb_schema.py` | Test xác thực trường `references` và URL formatting. |
| `data/knowledge-base/tier2/*.md` (11 file) | Bổ sung 5 phần chuẩn: Risk Mechanism, Code Examples (Vulnerable/Remediated), Remediation Guide, References. |
| `data/knowledge-base/tier1/*.md` (14 file) | Bổ sung 4 phần chuẩn: Overview & Impact, Attack Variants, Defense Strategy, References. |
| `tests/unit/retrieval/test_kb_integrity.py` | Kiểm tra tính toàn vẹn của cấu trúc 5 phần, code snippets và reference links. |
| `src/project_sentinel/web/views.py` & templates | Tải và hiển thị Knowledge & Remediation chi tiết trên Web UI. |
| `tests/unit/web/test_views.py` | Kiểm thử endpoint Web UI hiển thị thông tin tri thức. |

---

## Task 1: Nâng cấp `kb_schema.py` hỗ trợ `references` & URL validation

**Files:**
- Modify: `src/project_sentinel/retrieval/kb_schema.py`
- Modify: `tests/unit/retrieval/test_kb_schema.py`

**Interfaces:**
- Produces: `Tier2Entry.references: tuple[str, ...]`.
- Validates: Mọi phần tử trong `references` phải là chuỗi URL bắt đầu bằng `http://` hoặc `https://`.

- [ ] **Step 1: Viết test đỏ cho trường `references`**

Thêm vào `tests/unit/retrieval/test_kb_schema.py`:

```python
def test_entry_co_references_doc_ra_danh_sach_url(tmp_path):
    text = VALID.replace(
        "matches_rule_ids:\n  - java-sql-statement-execution\n",
        "matches_rule_ids:\n  - java-sql-statement-execution\n"
        "references:\n"
        "  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n"
        "  - https://cwe.mitre.org/data/definitions/89.html\n",
    )
    entry = parse_tier2(_write(tmp_path, text))
    assert len(entry.references) == 2
    assert entry.references[0].startswith("https://")


def test_references_chua_url_khong_hop_le_bi_tu_choi(tmp_path):
    text = VALID.replace(
        "matches_rule_ids:\n  - java-sql-statement-execution\n",
        "matches_rule_ids:\n  - java-sql-statement-execution\n"
        "references:\n  - khong-phai-url-hop-le\n",
    )
    with pytest.raises(KbSchemaError, match="URL"):
        parse_tier2(_write(tmp_path, text))
```

- [ ] **Step 2: Chạy test, xác nhận đỏ**

Run: `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -k references -v`
Expected: FAIL

- [ ] **Step 3: Cập nhật `kb_schema.py`**

Trong `src/project_sentinel/retrieval/kb_schema.py`:
1. Thêm `references: tuple[str, ...] = ()` vào `Tier2Entry`.
2. Trong `parse_tier2`:
```python
    references_raw = meta.get("references")
    references = ()
    if references_raw is not None:
        refs_tuple = _as_str_tuple(references_raw, "references", path)
        for ref in refs_tuple:
            if not (ref.startswith("http://") or ref.startswith("https://")):
                raise KbSchemaError(f"{path}: reference '{ref}' khong phai URL hop le (phai bat dau bang http/https)")
        references = refs_tuple
```

- [ ] **Step 4: Chạy test, xác nhận xanh**

Run: `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -v`
Expected: PASS

- [ ] **Step 5: Kiểm tra chất lượng và commit**

```bash
make quality
git add src/project_sentinel/retrieval/kb_schema.py tests/unit/retrieval/test_kb_schema.py
git commit -m "feat(kb): add references field and URL validation to Tier2Entry schema"
```

---

## Task 2: Chuẩn hóa 3 tài liệu Tier 2 có rule với 5 phần & Mã nguồn đối chứng

**Files:**
- Modify: `data/knowledge-base/tier2/java-sql-statement-execute.md`
- Modify: `data/knowledge-base/tier2/java-runtime-exec.md`
- Modify: `data/knowledge-base/tier2/java-objectinputstream-readobject.md`
- Test: `tests/unit/retrieval/test_kb_integrity.py`

**Interfaces:**
- Cả 3 file đều có frontmatter `references`, 5 mục Markdown: `## 1. Cơ chế rủi ro`, `## 2. Mã nguồn minh họa` (có `### ❌ Không an toàn` và `### ✅ Đã khắc phục an toàn`), `## 3. Biện pháp khắc phục chuẩn`, `## 4. Tài liệu tham khảo`.

- [ ] **Step 1: Cập nhật `java-sql-statement-execute.md`**
Bổ sung `references`, code blocks `Statement.executeQuery` (vulnerable) vs `PreparedStatement` (safe), remediation 3 lớp, links OWASP/CWE/Oracle Java.

- [ ] **Step 2: Cập nhật `java-runtime-exec.md`**
Bổ sung `references`, code blocks `Runtime.getRuntime().exec(cmd)` (vulnerable) vs `ProcessBuilder(argsList)` (safe), remediation tách rời arguments, links OWASP/CWE/Java ProcessBuilder.

- [ ] **Step 3: Cập nhật `java-objectinputstream-readobject.md`**
Bổ sung `references`, code blocks `ObjectInputStream.readObject()` (vulnerable) vs Jackson `ObjectMapper` / `ObjectInputFilter` (safe), links OWASP Deserialization Cheat Sheet / CWE-502.

- [ ] **Step 4: Chạy test kiểm tra tính toàn vẹn**

Run: `.venv/bin/python -m pytest tests/unit/retrieval/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
make quality
git add data/knowledge-base/tier2/
git commit -m "feat(kb): enrich Tier 2 entries with rules (SQLi, Command Exec, Deserialization)"
```

---

## Task 3: Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm A: XSS, Path Traversal, CSRF)

**Files:**
- Modify: `data/knowledge-base/tier2/java-servlet-response-writer.md`
- Modify: `data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md`
- Modify: `data/knowledge-base/tier2/java-file-path-concat.md`
- Modify: `data/knowledge-base/tier2/java-spring-csrf-disabled.md`

- [ ] **Step 1: Cập nhật `java-servlet-response-writer.md`**
Bổ sung `references` (OWASP XSS Cheat Sheet, CWE-79), code blocks `response.getWriter().println(input)` vs `HtmlUtils.htmlEscape(input)`.

- [ ] **Step 2: Cập nhật `java-thymeleaf-unescaped-output.md`**
Bổ sung `references`, code blocks `th:utext="${untrusted}"` vs `th:text="${untrusted}"`.

- [ ] **Step 3: Cập nhật `java-file-path-concat.md`**
Bổ sung `references` (CWE-22), code blocks `new File(base, filename)` vs canonical path normalization validation (`getCanonicalPath().startsWith(baseCanonical)`).

- [ ] **Step 4: Cập nhật `java-spring-csrf-disabled.md`**
Bổ sung `references` (OWASP CSRF Cheat Sheet, Spring Security CSRF docs), code blocks `http.csrf().disable()` vs `http.csrf(Customizer.withDefaults())` kèm `CookieCsrfTokenRepository`.

- [ ] **Step 5: Chạy test và commit**

```bash
make quality
git add data/knowledge-base/tier2/
git commit -m "feat(kb): enrich Tier 2 entries for XSS, Path Traversal, and CSRF"
```

---

## Task 4: Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm B: JWT, Credentials, Random, XXE)

**Files:**
- Modify: `data/knowledge-base/tier2/java-jwt-parse-unverified.md`
- Modify: `data/knowledge-base/tier2/java-hardcoded-credential.md`
- Modify: `data/knowledge-base/tier2/java-insecure-random.md`
- Modify: `data/knowledge-base/tier2/java-documentbuilder-xxe.md`

- [ ] **Step 1: Cập nhật `java-jwt-parse-unverified.md`**
Bổ sung `references` (CWE-347, JJWT docs), code blocks `parseClaimsJwt(token)` vs `setSigningKey(key).parseClaimsJws(token)`.

- [ ] **Step 2: Cập nhật `java-hardcoded-credential.md`**
Bổ sung `references` (CWE-798), code blocks hardcoded string password vs `@Value("${DB_PASSWORD}")` / Environment variables / Vault.

- [ ] **Step 3: Cập nhật `java-insecure-random.md`**
Bổ sung `references` (CWE-338), code blocks `new Random()` vs `new SecureRandom()`.

- [ ] **Step 4: Cập nhật `java-documentbuilder-xxe.md`**
Bổ sung `references` (OWASP XXE Prevention Cheat Sheet, CWE-611), code blocks `DocumentBuilderFactory.newInstance()` vs disallow-doctype-decl feature activation.

- [ ] **Step 5: Chạy test và commit**

```bash
make quality
git add data/knowledge-base/tier2/
git commit -m "feat(kb): enrich Tier 2 entries for JWT, Credentials, Randomness, and XXE"
```

---

## Task 5: Chuẩn hóa 14 tài liệu Tier 1 với 4 phần & Liên kết tham chiếu chuẩn

**Files:**
- Modify: `data/knowledge-base/tier1/*.md` (14 files)

- [ ] **Step 1: Cập nhật 14 file Tier 1**
Bổ sung trường `references` trong frontmatter và cấu trúc 4 phần chuẩn:
1. `## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)`
2. `## 2. Các biến thể phổ biến (Common Attack Variants)`
3. `## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)`
4. `## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)`

- [ ] **Step 2: Chạy test toàn vẹn và kiểm tra chất lượng**

Run: `.venv/bin/python -m pytest tests/unit/retrieval/ -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
make quality
git add data/knowledge-base/tier1/
git commit -m "feat(kb): enrich 14 Tier 1 vulnerability class documents with standard sections and references"
```

---

## Task 6: Bổ sung bộ test toàn vẹn cấu trúc và chống trôi (5-Section & Reference Integrity)

**Files:**
- Modify: `tests/unit/retrieval/test_kb_integrity.py`

- [ ] **Step 1: Viết test kiểm tra cấu trúc 5 phần và code snippet của mọi file Tier 2**
- [ ] **Step 2: Viết test kiểm tra cấu trúc 4 phần và references của mọi file Tier 1**
- [ ] **Step 3: Viết test kiểm tra tính hợp lệ của mọi link trong `references`**
- [ ] **Step 4: Chạy test xác nhận xanh và commit**

```bash
make quality
git add tests/unit/retrieval/test_kb_integrity.py
git commit -m "test(kb): add structural integrity and reference anti-drift tests"
```

---

## Task 7: Hiển thị Tri thức & Remediation trên Web UI

**Files:**
- Modify: `src/project_sentinel/web/views.py`
- Modify: `src/project_sentinel/web/templates/run_overview.html` hoặc `finding_detail.html`
- Test: `tests/unit/web/test_views.py`

- [ ] **Step 1: Viết test đỏ cho endpoint chi tiết finding có nạp thông tin KB remediation**
- [ ] **Step 2: Cập nhật Web views để đọc file Tier 2 và trích xuất Code Snippets & References**
- [ ] **Step 3: Cập nhật Web template hiển thị Tab/Card "Knowledge & Remediation"**
- [ ] **Step 4: Chạy test xác nhận xanh và commit**

```bash
make quality
git add src/project_sentinel/web/ tests/unit/web/
git commit -m "feat(web): display rich remediation code and reference badges in finding details"
```

---

## Task 8: Nghiệm thu toàn diện & Báo cáo tổng kết

**Files:**
- Create/Update: `worklog/2026-08-23-enriched-kb-complete.md`

- [ ] **Step 1: Chạy toàn bộ test offline**
`.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests`
- [ ] **Step 2: Chạy kiểm tra chất lượng**
`make quality`
- [ ] **Step 3: Chạy báo cáo độ phủ**
`make kb-coverage`
- [ ] **Step 4: Chạy đánh giá agent**
`make eval`
- [ ] **Step 5: Viết worklog và commit tổng kết**

```bash
git add worklog/2026-08-23-enriched-kb-complete.md
git commit -m "docs(worklog): complete enriched knowledge base implementation and quality verification"
```

---

## Kiểm tra cuối (Final Acceptance Checklist)

- [ ] `make quality` 100% xanh.
- [ ] 14 file Tier 1 và 11 file Tier 2 có đầy đủ các mục chuẩn hóa và link tham chiếu.
- [ ] 11 file Tier 2 đều có ít nhất 1 block Vulnerable Code và 1 block Remediated Code Java.
- [ ] `make kb-coverage` chạy chính xác.
- [ ] `make search Q='SQL Injection'` trả kết quả chuẩn.
- [ ] `make eval` đạt điểm chuẩn.
