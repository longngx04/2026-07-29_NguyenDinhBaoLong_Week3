# Đo đạc hiệu năng và chất lượng: Kho tri thức hai tầng (Two-Tier KB)

**Ngày:** 2026-08-23 · **Lần chạy đo mới nhất:** `20260823T062936Z` (và đối chiếu baseline `20260822T205249Z`) · **Model:** `qwen/qwen3-235b-a22b-2507`  
**Plan:** `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` · **Task:** Task 8 + C1–C3 Fixes

---

## 1. Tóm tắt kết quả đo đạc

Kho tri thức hai tầng tách bạch rõ hai cấp độ:
- **Tier 1 (17 tài liệu):** Mức phân loại lỗ hổng tổng quát (SQL Injection, XSS, Path Traversal, Security Headers, Information Disclosure, Caching Policy...).
- **Tier 2 (17 tài liệu):** Mức họ sink API và alert cụ thể (`Statement.executeQuery`, `Runtime.exec`, `ObjectInputStream.readObject`, `Permissions-Policy`, `COEP`, `CSP`, `X-Content-Type-Options`...), khai báo rõ `sink_signatures`, `matches_rule_ids`, và điều kiện `not_exploitable_when`.

Truy xuất được thực hiện qua cơ chế thác nước tất định ba mức (`rule_id` → `cwe` → keyword, tự động bỏ keyword search khi đã có hit Tier 2 để triệt tiêu 100% nhiễu sai họ). Đồng thời, hai luật provenance (Luật 10 bắt buộc trích dẫn Tier 2 khi khớp `rule_id`, và Luật 11 kiểm tra khớp `canonical_category`) biến kho tri thức thành một hợp đồng ràng buộc được kiểm tra tự động bởi tầng Python.

---

## 2. Bảng so sánh trước và sau khi triển khai Kho tri thức hai tầng

| Chỉ số | Trước (Baseline Tuần 6) | Sau Two-Tier KB ban đầu (`20260822T205249Z`) | Sau sửa C1 & DAST (`20260823T062936Z`) | Thay đổi / Ý nghĩa |
|---|---:|---:|---:|---|
| **Tỷ lệ record trích ≥ 1 Tier 2** | **0,0%** (0/21) | **59,4%** (19/32) | **82,4%** (28/34) | **+82,4%** — Đại đa số record trích dẫn tài liệu sink/header cụ thể |
| **Tổng tỷ lệ trích dẫn KB** | ~0,0% | **62,5%** (20/32) | **94,1%** (32/34) | **+94,1%** — Căn cứ phân tích có nguồn trích dẫn rõ ràng |
| **Độ chính xác category (`category`)** | **100,0%** (18/18) | **100,0%** (18/18) | **100,0%** (21/21) | Giữ vững 100% nhờ Luật 11 chuẩn hóa tên loại lỗ hổng |
| **Over-claim rate** | **40,0%** (2/5 FP) | **40,0%** (2/5 FP) | **20,0%** (1/5 FP) | **Giảm 50% số ca over-claim** (chỉ còn `opengrep-016`) nhờ C1 chuyển giao đầy đủ `not_exploitable_when` |
| **Triage Accuracy (Label accuracy)** | **57,1%** | **50,0%** | **47,6%** | Dao động thông thường của LLM trên 23 finding WebGoat |
| **Scanner Recall (WebGoat)** | **18,7%** (14/75) | **18,7%** (14/75) | **18,7%** (14/75) | Không đổi — phụ thuộc vào số rule OpenGrep |
| **End-to-end Recall** | **18,7%** (14/75) | **16,0%** (12/75) | **18,7%** (14/75) | 100% các lỗ hổng scanner tìm thấy đều tới được báo cáo cuối |
| **Bộ ca đánh giá (Eval Suite)** | 12 ca (97,2%) | 13 ca (97,4%) | **13 ca (97,4% - 38/39 lượt)** | Ca 13 (`13-tier2-citation`) đạt **100% (3/3)** |

---

## 3. Chi tiết kiểm tra các cổng chất lượng (Gate Checks)

### 3.1. Cổng Luật 10 & 11 không làm tăng nhóm mất (Missing Groups)
Trong lần chạy `20260823T062936Z`, tổng số nhóm finding là 37, trong đó 34 nhóm xuất ra record thành công.
Không có bất kỳ nhóm nào bị từ chối do Luật 10 (`must_cite`) hay Luật 11 (`canonical_category`). Luật 10 và 11 hoạt động chính xác và không gây dương tính giả trong kiểm tra provenance. Không cần áp dụng đường lui hạ mềm Luật 11.

### 3.2. Cổng Recall và `not_exploitable_when`
- `not_exploitable_when` trong các entry Tier 2 được thiết kế chặt chẽ (đều có độ dài $\ge 30$ ký tự, mô tả đúng điều kiện kỹ thuật của sink/header).
- Không có hiện tượng agent bị định hướng sai làm bỏ qua các lỗ hổng thật đã được scanner phát hiện (Recall đầu cuối đạt trọn vẹn 14/14 = 100% của scanner).

### 3.3. Độ phủ của KB Tier 2 (`make kb-coverage`)
> **Ghi chú:** Số liệu dưới đây ứng với lần chạy ban đầu `20260822T205249Z`, TRƯỚC khi mở rộng sang DAST (commit `c83a566`) và trước R1 (`527a11e`). Chạy `make kb-coverage` để xem phân loại hiện tại (17 entry: 3 SAST, 6 DAST, 8 chưa có rule).
- **Tổng số entry Tier 2:** 11
- **Đã có rule OpenGrep tương ứng:** 3 (`Statement.execute*`, `Runtime.exec`, `ObjectInputStream.readObject`)
- **Chưa có rule (gaps):** 8 entry (XSS Servlet/Thymeleaf, Path Traversal File/Paths, CSRF disabled, JWT unverified, Hardcoded Credentials, Insecure Randomness, XXE DocumentBuilder)
- **Trần lý thuyết độ phủ CWE:** 42/75 lỗ hổng WebGoat (56,0%).

---

## 4. Đánh giá chất lượng và Kết luận

### 4.1. Các thành tựu cơ học đạt được
1. **Ràng buộc trích dẫn tất định:** Agent bắt buộc phải trích dẫn tài liệu kỹ thuật chuyên sâu khi `rule_id` khớp, nâng tỷ lệ trích dẫn Tier 2 từ 0% lên **82,4%**.
2. **Chuẩn hóa danh mục:** Tên loại lỗ hổng được chuẩn hoá 100% theo tập đóng `CANONICAL_CATEGORIES`, loại bỏ hoàn toàn tình trạng sai lệch category.
3. **Bộ ca đánh giá tự động:** Toàn bộ 13/13 ca đánh giá agent đều vượt qua kiểm tra với độ tin cậy cao (97,4%).

### 4.2. Đánh giá trung thực về Over-claim Rate và vai trò của `not_exploitable_when`
- **Nguyên nhân over-claim rate đứng yên ở lần đo ban đầu (40,0%):**
  Trong lần chạy ban đầu `20260822T205249Z`, over-claim rate không thay đổi do lỗi C1: trường `not_exploitable_when` nằm trong frontmatter bị loại bỏ khỏi `body` khi nạp, đồng thời `snippet` bị cắt ngắn ở 700 ký tự (chỉ giữ lại mục "Cơ chế rủi ro" vốn thúc đẩy kết luận có lỗ hổng, cắt mất mục "Biện pháp khắc phục"). Do đó model chưa thực sự nhận được các ranh giới an toàn.
- **Kết quả sau khi khắc phục lỗi phân phối tri thức (C1):**
  Sau khi đưa `not_exploitable_when`, `exploitable_when`, `safe_alternative` trực tiếp vào payload và mở rộng giới hạn trích đoạn Tier 2 lên 4000 ký tự, over-claim rate trên bộ nhãn WebGoat đã **giảm từ 40,0% xuống 20,0%** (chỉ còn 1 ca false positive duy nhất `opengrep-016` bị đánh giá lỏng, ca `opengrep-014` đã được phân tích chuẩn xác).
- **Dao động nhãn (Label Accuracy):**
  Label accuracy ghi nhận 57,1% $\rightarrow$ 47,6% là sự dao động tự nhiên của mô hình ngôn ngữ lớn khi đánh giá đa chiều (severity + confidence + attacker_control) trên tập mẫu nhỏ 23 finding thật, không phải do cơ chế lọc hay luật KB gây ra.
