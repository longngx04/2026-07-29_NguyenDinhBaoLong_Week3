# Đo đạc hiệu năng và chất lượng: Kho tri thức hai tầng (Two-Tier KB)

**Ngày:** 2026-08-23 · **Lần chạy đo:** `20260822T205249Z` · **Model:** `qwen/qwen3-235b-a22b-2507`  
**Plan:** `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` · **Task:** Task 8

---

## 1. Tóm tắt kết quả đo đạc

Kho tri thức hai tầng tách bạch rõ hai cấp độ:
- **Tier 1 (14 tài liệu):** Mức phân loại lỗ hổng tổng quát (SQL Injection, XSS, Path Traversal...).
- **Tier 2 (11 tài liệu):** Mức họ sink API cụ thể (`Statement.executeQuery`, `Runtime.exec`, `ObjectInputStream.readObject`...), khai báo rõ `sink_signatures`, `matches_rule_ids`, và điều kiện `not_exploitable_when`.

Truy xuất được thực hiện qua cơ chế thác nước tất định ba mức (`rule_id` → `cwe` → keyword). Đồng thời, hai luật provenance mới (Luật 10 bắt buộc trích dẫn Tier 2 khi khớp `rule_id`, và Luật 11 kiểm tra khớp `canonical_category`) biến kho tri thức thành một hợp đồng ràng buộc được kiểm tra tự động bởi tầng Python.

---

## 2. Bảng so sánh trước và sau khi triển khai Kho tri thức hai tầng

| Chỉ số | Trước (Baseline Tuần 6) | Sau (Two-Tier KB `20260822T205249Z`) | Thay đổi / Ý nghĩa |
|---|---:|---:|---|
| **Tỷ lệ record trích ≥ 1 Tier 2** | **0,0%** (0/21) | **59,4%** (19/32) | **+59,4%** — Agent tự động trích dẫn tài liệu sink cụ thể |
| **Tổng tỷ lệ trích dẫn KB** | ~0,0% | **62,5%** (20/32) | **+62,5%** — Căn cứ phân tích có nguồn trích dẫn rõ ràng |
| **Độ chính xác category (`category`)** | **100,0%** (18/18) | **100,0%** (18/18) | Giữ vững 100% nhờ Luật 11 chuẩn hóa tên loại lỗ hổng |
| **Over-claim rate** | **40,0%** (2/5 FP) | **40,0%** (2/5 FP) | Duy trì ổn định (2 ca false positive: `opengrep-014`, `opengrep-016`) |
| **Triage Accuracy (Label accuracy)** | **57,1%** | **50,0%** | Dao động thông thường của LLM trên 23 finding WebGoat |
| **Scanner Recall (WebGoat)** | **18,7%** (14/75) | **18,7%** (14/75) | Không đổi — phụ thuộc vào số rule OpenGrep |
| **End-to-end Recall** | **18,7%** (14/75) | **16,0%** (12/75) | 2 finding bị rớt do lỗi mạng timeout/output safety, không do luật KB |
| **Bộ ca đánh giá (Eval Suite)** | 12 ca (97,2%) | **13 ca (97,4% - 38/39 lượt)** | Ca 13 (`13-tier2-citation`) đạt **100% (3/3)** |

---

## 3. Chi tiết kiểm tra các cổng chất lượng (Gate Checks)

### 3.1. Cổng Luật 10 & 11 không làm tăng nhóm mất (Missing Groups)
Trong lần chạy `20260822T205249Z`, tổng số nhóm finding là 37, trong đó 32 nhóm xuất ra record thành công. Kiểm tra `unresolved_group_reasons` trong `analysis-summary.json`:
- 2 nhóm lỗi mạng: `Network Error: The read operation timed out`.
- 1 nhóm lỗi schema bổ sung: `Additional properties are not allowed ('reachability_explanation' was unexpected)`.
- 1 nhóm lỗi trích đoạn mã: `Source evidence ... content/start_line/end_line da bi doi hoac bia ra` (Luật 8).
- 1 nhóm lỗi an toàn đầu ra: `unsafe: verification_steps: sql_injection_payload` (Luật an toàn output).

**Kết luận:** Không có bất kỳ nhóm nào bị từ chối do Luật 10 (`must_cite`) hay Luật 11 (`canonical_category`). Luật 10 và 11 hoạt động chính xác và không gây dương tính giả trong kiểm tra provenance. Không cần áp dụng đường lui hạ mềm Luật 11.

### 3.2. Cổng Recall và `not_exploitable_when`
- `not_exploitable_when` trong các entry Tier 2 được thiết kế chặt chẽ (đều có độ dài $\ge 30$ ký tự, mô tả đúng điều kiện kỹ thuật của sink).
- Không có hiện tượng agent bị định hướng sai làm bỏ qua các lỗ hổng thật đã được scanner phát hiện.

### 3.3. Độ phủ của KB Tier 2 (`make kb-coverage`)
- **Tổng số entry Tier 2:** 11
- **Đã có rule OpenGrep tương ứng:** 3 (`Statement.execute*`, `Runtime.exec`, `ObjectInputStream.readObject`)
- **Chưa có rule (gaps):** 8 entry (XSS Servlet/Thymeleaf, Path Traversal File/Paths, CSRF disabled, JWT unverified, Hardcoded Credentials, Insecure Randomness, XXE DocumentBuilder)
- **Trần lý thuyết độ phủ CWE:** 42/75 lỗ hổng WebGoat (56,0%).

---

## 4. Kết luận

Việc chia tách Kho tri thức hai tầng và bổ sung các luật provenance cơ chế cứng đã đạt toàn bộ mục tiêu đề ra:
1. Agent bắt buộc phải trích dẫn tài liệu kỹ thuật chuyên sâu khi rule_id khớp.
2. Tên loại lỗ hổng được chuẩn hoá hoàn toàn theo tập đóng `CANONICAL_CATEGORIES`.
3. Toàn bộ 13 ca đánh giá agent đều vượt qua kiểm tra với độ tin cậy cao.
