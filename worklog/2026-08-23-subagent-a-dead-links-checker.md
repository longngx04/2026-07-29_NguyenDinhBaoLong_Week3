# Worklog — Sửa URL chết và tạo bộ kiểm tra liên kết KB (Subagent A)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Gemini 3.6 Flash ·
**Branch:** `feat/kb-two-tier` · **Plan:** `docs/superpowers/specs/2026-08-23-knowledge-base-two-tier-design.md` · **Task ID:** `Subagent A (F2, F3)`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã sửa 2 URL 404 trong 3 tài liệu Knowledge Base (`java-file-path-concat.md`, `java-jwt-parse-unverified.md`, `jwt-weak-verification.md`) sang các URL chính thức còn sống của OWASP. Tạo script `scripts/check-kb-links.sh` để kiểm tra HTTP status 200 cho 100% URL tham chiếu trong KB và tích hợp target `kb-links` vào `Makefile` cùng tài liệu hướng dẫn trong `README.md`. Quá trình quét thực tế phát hiện 66/67 URL trả về HTTP 200 OK và phát hiện thêm 1 URL 404 nằm ngoài phạm vi file của Subagent A (`tier1/path-traversal.md`).

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Đảm bảo toàn bộ tài liệu an toàn trong cơ sở tri thức (KB Tier 1 và Tier 2) có liên kết tham chiếu thẩm quyền hợp lệ và còn sống (HTTP 200), ngăn chặn việc model/agent trích dẫn hoặc hiển thị các URL chết lên Web UI / Báo cáo phân tích.
- **Nằm ở đâu trong luồng:** Nằm ở tầng dữ liệu tri thức (`data/knowledge-base/`), hỗ trợ module retrieval (`project_sentinel.retrieval`) và các đường dẫn tra cứu thông tin tham chiếu bảo mật.
- **Không có nó thì hỏng gì:** Các liên kết tài liệu tham khảo (OWASP Cheat Sheet, CWE, Oracle Docs) bị 404 khiến chuyên viên bảo mật hoặc LLM khi tra cứu không đọc được tài liệu gốc, giảm độ tin cậy của phân tích.
- **Ngoài phạm vi (cố ý không làm):**
  - Không sửa các file ngoài danh mục được phân quyền của Subagent A (đặc biệt không tự ý sửa `data/knowledge-base/tier1/path-traversal.md` dù phát hiện link 404).
  - Không đưa `kb-links` vào `make quality` vì script yêu cầu kết nối Internet, tránh làm gãy CI offline.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `data/knowledge-base/tier2/java-file-path-concat.md` | Sửa | Đổi `File_Path_Traversal_Cheat_Sheet.html` (404) thành `https://owasp.org/www-community/attacks/Path_Traversal` ở frontmatter và mục 4 | URL cũ của OWASP Cheat Sheet bị 404 |
| `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Sửa | Đổi `JSON_Web_Token_for_Java_Cheat_Sheet.html` (404) thành `https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html` ở frontmatter và mục 4 | OWASP đã gộp cheat sheet Java vào cheat sheet JWT chung |
| `data/knowledge-base/tier1/jwt-weak-verification.md` | Sửa | Đổi `JSON_Web_Token_for_Java_Cheat_Sheet.html` (404) thành `https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html` ở frontmatter và mục 4 | Đồng bộ URL tham chiếu JWT còn sống |
| `scripts/check-kb-links.sh` | Tạo | Tạo script bash trích xuất URL frontmatter `references:` từ `tier1/` và `tier2/`, dùng `curl` kiểm tra mã trạng thái HTTP 200 | Cung cấp công cụ kiểm tra tính sống của toàn bộ URL trong KB |
| `Makefile` | Sửa | Thêm `kb-links` vào `.PHONY` và khai báo target `kb-links: @./scripts/check-kb-links.sh` | Cho phép chạy kiểm tra URL qua lệnh make chuẩn |
| `README.md` | Sửa | Thêm dòng `make kb-links # kiểm URL trích dẫn trong KB còn sống không (cần mạng)` trong mục "Kiểm tra chất lượng mã" | Cập nhật tài liệu hướng dẫn cho lập trình viên/operator |

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Rà soát và cập nhật chính xác 2 URL 404 đã chỉ định trên 3 file markdown, sửa cả trường `references:` trong frontmatter YAML và khối Markdown liên kết trong mục `## 4. Tài liệu tham khảo`.
2. Viết script `scripts/check-kb-links.sh` bằng Bash kết hợp đoạn Python ngắn trích xuất chính xác cấu trúc YAML frontmatter `references:` từ các file `data/knowledge-base/tier1/*.md` và `tier2/*.md`.
3. Với mỗi URL duy nhất, script chạy `curl -sS -o /dev/null -w '%{http_code}' -L --max-time 15 "$url"`.
4. Nếu có bất kỳ mã trạng thái nào khác `200`, in chi tiết lỗi và thoát với exit code `1`. Nếu toàn bộ 200, in tổng kết và exit code `0`.
5. Tích hợp `make kb-links` vào `Makefile` và cập nhật `README.md`.

**Luồng dữ liệu:**
`data/knowledge-base/tier{1,2}/*.md` → `Python YAML Parser (Frontmatter references)` → `Unique URLs List` → `curl HTTP GET (max-time 15s, follow redirects)` → `HTTP Status Evaluation (200 == OK)` → `Exit Code (0/1)`

**Các quyết định kỹ thuật:**
- Dùng Python YAML parser bên trong bash script để trích xuất `references:` thay vì regex thô, tránh parse nhầm các URL trong phần thân markdown hoặc comment.
- Sử dụng cờ `-L` (follow redirects) và `--max-time 15` cho `curl` để tránh treo kết nối khi gặp server phản hồi chậm.

**Xử lý lỗi / trường hợp biên:**
- File không có frontmatter hoặc không có trường `references:` được bỏ qua an toàn mà không gây crash.
- URL không kết nối được hoặc timeout trả về HTTP code `000` và được đánh dấu FAIL.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Script | `check-kb-links.sh` | `scripts/check-kb-links.sh` | Script kiểm tra HTTP 200 cho tất cả URL references trong KB |
| Makefile Target | `kb-links` | `make kb-links` | Target Makefile gọi `scripts/check-kb-links.sh` |
| Markdown KB | Tier 1 & Tier 2 docs | `data/knowledge-base/tier*/*.md` | Các file KB đã được cập nhật URL hợp lệ |

**Cách chạy:**

```bash
make kb-links
# hoặc
./scripts/check-kb-links.sh
```

**Output thật (đã che secret):**

```text
======================================================================
Project Sentinel — Kiem tra URL tham chieu trong Knowledge Base
======================================================================
Tim thay 67 URL duy nhat trong Tier 1 va Tier 2.
----------------------------------------------------------------------
[ 1/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[ 2/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
[ 3/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
[ 4/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
[ 5/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
[ 6/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
[ 7/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
[ 8/67] OK (200): https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
[ 9/67] FAIL (404): https://cheatsheetseries.owasp.org/cheatsheets/File_Inclusion_Cheat_Sheet.html
...
[65/67] OK (200): https://owasp.org/www-community/attacks/Path_Traversal
[66/67] OK (200): https://owasp.org/www-project-secure-headers/
[67/67] OK (200): https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#unescaped-text
======================================================================
Ket qua kiem tra: 66 URL song (200), 1 URL that bai / tong 67 URL.
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
- Dùng `curl` với `--max-time 15` và `-L` để kiểm tra trực tiếp qua mạng bên ngoài `make quality`.
- Sửa URL trỏ thẳng về trang chính thức đang hoạt động của OWASP Community Attack (`Path_Traversal`) và OWASP Cheat Sheet (`JSON_Web_Token_Cheat_Sheet.html`).

**Lý do:**
- Thỏa mãn nguyên tắc cô lập test: CI offline không phụ thuộc vào trạng thái mạng ngoài, nhưng operator/dev có công cụ kiểm tra khi cần.
- Giữ vững tính bất biến về schema và validation của KB retrieval pipeline.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Nhúng kiểm tra HTTP vào `test_kb_integrity.py` (chạy trong `make quality`) | Tự động chạy trong mọi lần test | Vi phạm nguyên tắc CI: CI sẽ gãy khi mất mạng hoặc khi server bên ngoài bảo trì |
| Dùng `grep` regex thuần trong bash để lấy URL | Không cần Python | Dễ lấy nhầm URL trong code block hoặc comment markdown |

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests/unit/retrieval/` | 0 | 87 passed in 1.76s |
| `./scripts/check-kb-links.sh` | 1 | 66/67 URL OK (200); 1 URL ngoài phạm vi phân quyền (`path-traversal.md`) bị 404 |

**Bất biến đã giữ:**
- Không sửa file ngoài 6 file được phân quyền cho Subagent A.
- Không commit tự động.
- Không sửa `reports/week-XX/`.

**Còn fail / chưa chạy được:**
- URL `https://cheatsheetseries.owasp.org/cheatsheets/File_Inclusion_Cheat_Sheet.html` trong `data/knowledge-base/tier1/path-traversal.md` trả về 404 (cần Agent cha hoặc subagent phụ trách sửa sang `https://owasp.org/www-community/attacks/Path_Traversal`).

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `data/knowledge-base/tier1/path-traversal.md` chứa `File_Inclusion_Cheat_Sheet.html` bị 404 nhưng không nằm trong danh sách 6 file của Subagent A.
- **Giả định đã đặt:** Giả định Agent cha sẽ cập nhật `path-traversal.md` hoặc cho phép Subagent A cập nhật để `./scripts/check-kb-links.sh` đạt 67/67 URL OK (exit code 0).
- **Việc còn nợ:** Cập nhật `path-traversal.md` khi có phê duyệt.
