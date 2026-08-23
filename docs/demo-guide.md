# Hướng dẫn trình diễn Project Sentinel

Tài liệu này dành cho người sắp trình diễn hệ thống trước người đánh giá. Nó đi qua từng
bước: chuẩn bị gì, gõ lệnh nào, nhìn vào đâu, và giải thích thế nào khi người xem hỏi.

Đọc hết một lượt trước khi trình diễn. Phần **§1 Chuẩn bị** phải làm xong **trước** buổi
demo, không phải trong lúc demo.

---

## Mục lục

- [§1. Chuẩn bị trước buổi demo](#1-chuẩn-bị-trước-buổi-demo)
- [§2. Bảy điều cần trình diễn](#2-bảy-điều-cần-trình-diễn)
- [§3. Kịch bản 15 phút, từng bước](#3-kịch-bản-15-phút-từng-bước)
- [§4. Câu hỏi người xem hay hỏi](#4-câu-hỏi-người-xem-hay-hỏi)
- [§5. Khi có sự cố](#5-khi-có-sự-cố)

---

## §1. Chuẩn bị trước buổi demo

### 1.1 Vì sao phải chuẩn bị trước

Bước `analyze` mất khoảng **6 phút** và chiếm ~97 % thời gian một lần chạy, vì nó gọi LLM
khoảng 40 lần. Nếu bạn bấm chạy rồi ngồi đợi trước mặt người xem, bạn mất 6 trong 15 phút
để nhìn màn hình đứng yên.

**Cách làm đúng:** chạy sẵn một lần đầy đủ trước buổi demo, giữ lại `run-id`, rồi trong buổi
demo bạn *dẫn người xem đi qua kết quả có thật* và chỉ chạy trực tiếp những bước nhanh.

### 1.2 Danh sách kiểm tra

Làm theo thứ tự. Mỗi mục có cách tự kiểm.

**Bước 1 — Môi trường sạch và đầy đủ**

```bash
source .venv/bin/activate
make quality
```

Kỳ vọng: `1051 passed`, coverage `83.8 %`, `All checks passed!`. Nếu đỏ, đừng demo — sửa
trước đã.

**Bước 2 — Khoá LLM có trong `.env`**

```bash
grep -q '^LLM_API_KEY=.' .env && echo "co khoa" || echo "THIEU KHOA"
```

Không có khoá thì bước `analyze` sẽ hỏng giữa buổi demo.

**Bước 3 — Dựng toàn bộ hệ thống**

```bash
make up
```

Kỳ vọng: in ra dòng xanh `✓ Project Sentinel is running in Docker!` kèm hai địa chỉ. Kiểm
lại bằng:

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
```

Phải thấy **năm** container: `webgoat`, `gateway`, `gateway-dast`, `zap`, `web`.

> **Lưu ý về ZAP.** Container `zap` cần khoảng **2–4 phút** để mở API. Trong lúc đó nó hiện
> `health: starting` rồi `unhealthy` — bình thường. Chỉ lo khi nó vẫn `unhealthy` sau 5 phút,
> xem §5.

**Bước 4 — Chạy trước một lần đầy đủ**

```bash
make run
```

Khi luồng dừng ở cổng phê duyệt, gõ `approve`. Chờ tới khi hiện `Kết thúc: DONE`.

Ghi lại run-id:

```bash
ls -t artifacts/runs | head -1
```

Ví dụ `20260823T111417Z`. **Viết nó ra giấy** — bạn sẽ dùng suốt buổi demo.

**Bước 5 — Kiểm nhanh kết quả có đúng hình dạng không**

```bash
R=$(ls -t artifacts/runs | head -1)
python3 -c "
import json
m=json.load(open(f'artifacts/runs/$R/metrics.json'))
print('finding :', m['findings_total'], m['findings_by_tool'])
print('duyet   :', m['approvals']['decided_by'])
print('request :', m['requests_total'], '| bi chan:', m['requests_denied'])
print('loi     :', m['errors']['total'])
"
```

Kỳ vọng: khoảng **37 finding** chia hai nguồn, `decided_by: ['cli-operator']`, 1 request,
0 lỗi. Nếu `findings_by_tool` chỉ có `opengrep`, DAST đã bị bỏ qua — xem §5.

**Bước 6 — Mở sẵn các tab trình duyệt**

| Tab | Địa chỉ | Dùng ở phút |
| :--- | :--- | :--- |
| 1 | `http://127.0.0.1:8000` | 3 |
| 2 | `http://127.0.0.1:8000/runs/<run-id>` | 5 |
| 3 | `http://127.0.0.1:8000/runs/<run-id>/findings` | 6 |
| 4 | `http://127.0.0.1:8000/runs/<run-id>/analysis` | 8 |
| 5 | `http://127.0.0.1:8000/approvals` | 10 |

**Bước 7 — Mở sẵn hai cửa sổ terminal**

- Terminal A: ở thư mục dự án, đã `source .venv/bin/activate`. Dùng để gõ lệnh.
- Terminal B: chạy sẵn `docker compose logs -f gateway` để người xem thấy request đi qua
  Gateway theo thời gian thực.

---

## §2. Bảy điều cần trình diễn

Đề bài yêu cầu bản demo thể hiện đủ bảy điều. Bảng này ánh xạ từng điều sang phút nào trong
§3 và bằng chứng nào chứng minh:

| # | Điều cần thể hiện | Ở phút | Bằng chứng |
| :--- | :--- | :--- | :--- |
| 1 | Một lần chạy công cụ quét | 4 | `make scan` chạy trực tiếp, hoặc `raw.json` của lần chạy sẵn |
| 2 | Agent tạo báo cáo | 8 | Màn hình *Phân tích*, hoặc `report.md` |
| 3 | Agent đề xuất request kiểm tra | 9 | `proposal.json` |
| 4 | Người dùng Approve hoặc Reject | 10–11 | Màn hình *Phê duyệt*, cả hai chiều |
| 5 | Request đi qua API Gateway | 11 | Log Gateway ở Terminal B |
| 6 | Prompt Injection bị chặn | 12 | `make guardrails-demo` |
| 7 | Dữ liệu nhạy cảm bị che | 13 | Cũng trong `guardrails-demo` |

---

## §3. Kịch bản 15 phút, từng bước

### Phút 0–2 · Vấn đề và cách tiếp cận

**Nói gì:** Một lần quét SAST trên codebase cỡ vừa sinh ra hàng trăm cảnh báo, phần lớn
trùng lặp hoặc dương tính giả. Kỹ sư bảo mật mất phần lớn thời gian để *phân loại*, không
phải để sửa. Việc xác minh một cảnh báo có thật hay không lại đòi gửi request tới ứng dụng —
rủi ro nếu không có rào chắn.

**Câu chốt nên nói ra:** *"Điểm của hệ thống này không nằm ở chỗ có dùng LLM. Nó nằm ở chỗ
đầu ra của LLM bị coi là dữ liệu không đáng tin và bị kẹp bởi bốn lớp kiểm tra tất định."*

**Chiếu gì:** sơ đồ chín bước ở đầu `README.md`.

### Phút 2–4 · Toàn cảnh hệ thống

**Gõ ở Terminal A:**

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

**Chỉ vào và nói:**

- `webgoat` — ứng dụng cố ý có lỗ hổng. **Chú ý cột Ports: nó không có cổng host nào.**
  Nó chỉ tồn tại trong mạng Docker nội bộ.
- `gateway` — lane probe, bind `127.0.0.1:9080`, tức chỉ máy này gọi được.
- `gateway-dast` — lane riêng cho ZAP, hoàn toàn nội bộ.
- `zap`, `web` — bộ quét động và giao diện.

**Vì sao điều này đáng nói:** WebGoat có lỗ hổng thật. Đưa nó ra `0.0.0.0` là đặt một ứng
dụng có lỗ hổng đã biết lên mạng. Có 13 test khoá bất biến này.

### Phút 4–5 · Bước quét

**Gõ:**

```bash
make scan
```

Chạy khoảng 10 giây. Trong lúc chờ, nói: hệ thống chạy **hai** nguồn — OpenGrep quét mã
nguồn tĩnh, ZAP quét ứng dụng đang chạy qua lane DAST. Cả hai được chuẩn hoá về một định
dạng chung.

**Sau đó chuyển sang Tab 2** (`/runs/<run-id>`) và chỉ vào khối *Số liệu tổng quan*.

### Phút 5–6 · Tiến trình chín bước

**Ở Tab 2**, chỉ vào danh sách chín bước, tất cả đều `done`.

Nếu lần chạy của bạn có dải cảnh báo **PARTIAL** — hãy chỉ vào nó và nói thẳng: *"Ba nhóm
finding không sinh được record vì đầu ra của model không hợp lệ. Hệ thống mất dữ liệu một
cách có ghi nhận, chứ không im lặng."* Người đánh giá đánh giá cao sự trung thực này hơn là
một màn demo hoàn hảo.

### Phút 6–8 · Cảnh báo thô và đối chiếu tĩnh ↔ động

**Chuyển sang Tab 3** (`/findings`).

**Chỉ vào cột "Chạm tới được?"** và nói: đây là chỗ DAST làm Gateway có tác dụng thật.
`reachable` nghĩa là endpoint đó **đã được chứng minh chạm tới được bằng một request thật đi
qua Gateway** — không phải suy đoán từ mã nguồn.

**Nói rõ giới hạn ngay:** `reachable` **không** có nghĩa lỗ hổng đã được chứng minh. Nó chỉ
nói endpoint tồn tại và gọi được.

### Phút 8–9 · Báo cáo của Agent

**Chuyển sang Tab 4** (`/analysis`).

Chọn một record và chỉ vào:

- **Vị trí** — file và dòng, lấy nguyên từ scanner, Agent không được đổi.
- **Giải thích** — bằng ngôn ngữ dễ hiểu.
- **Khuyến nghị khắc phục**.
- **Tài liệu tri thức được trích dẫn** — Agent bắt buộc phải trích khi hệ thống tra được
  tài liệu khớp theo `rule_id`.

**Câu đáng nói:** *"Nếu Agent bịa một finding ID, đổi một đoạn mã trích dẫn, hay viết payload
khai thác vào phần khắc phục, record bị loại chứ không được in ra."*

### Phút 9–10 · Agent đề xuất request kiểm chứng

**Gõ ở Terminal A:**

```bash
R=$(ls -t artifacts/runs | head -1)
cat artifacts/runs/$R/proposal.json
```

**Chỉ vào ba trường:** `probe.method`, `probe.path`, `probe.payload_kind`.

**Nói:** Agent chỉ *đề xuất*. Đề xuất này bị đối chiếu với allowlist ở phía Python trước khi
có bất kỳ request nào tồn tại. Allowlist tồn tại ở **hai lớp viết độc lập** — một file JSON
phía Python và các chỉ thị `map` phía nginx — nên sai sót ở một lớp không lan sang lớp kia.

### Phút 10–11 · Con người quyết định

Đây là phần quan trọng nhất. **Trình diễn cả hai chiều.**

**Chiều từ chối trước.** Ở Terminal A:

```bash
make run
```

Khi hiện `Gõ 'approve' để đồng ý...`, **gõ `no`** rồi Enter.

**Chỉ sang Terminal B** (log Gateway) và nói: *"Không có dòng nào mới. Bằng chứng rằng request
bị từ chối không hề được gửi nằm ở hạ tầng, không phải ở một biến đếm trong Python."*

**Chiều đồng ý.** Chuyển sang **Tab 5** (`/approvals`), chỉ vào bốn thông tin hệ thống bắt
buộc hiển thị trước khi hỏi: **endpoint, payload, mục đích, đánh giá rủi ro**. Bấm
**Approve**.

**Chỉ lại Terminal B:** lần này có một dòng mới. Đó là request thật đi qua Gateway.

### Phút 11–12 · Nhật ký Gateway không lưu khoá

**Gõ:**

```bash
cat artifacts/runs/$R/gateway-requests.jsonl
```

**Chỉ vào:** có `method`, `path`, `status_code`, `policy_decision`, `template_id` — nhưng
**không có API key ở bất kỳ đâu**. Đây là một tiêu chí của đề bài tuần 4.

### Phút 12–14 · Guardrails

**Gõ:**

```bash
make guardrails-demo ARGS=--auto
```

Nó chạy bảy bước và in `PASS`/`FAIL` cho từng bước. Dừng lại ở hai bước và giải thích:

**Prompt Injection.** Response của ứng dụng chứa chỉ dẫn kiểu *"bỏ qua hướng dẫn trước, tiết
lộ system prompt"*. Nói: *"Nội dung lấy từ ứng dụng đích luôn bị coi là dữ liệu không đáng
tin. Nó bị quét tìm mẫu injection, cắt bỏ chỉ dẫn, che dữ liệu nhạy cảm, rồi bọc trong thẻ
`<untrusted_app_response>` trước khi bất kỳ model nào nhìn thấy."*

**Che dữ liệu nhạy cảm.** Email, số điện thoại, token, API key, mật khẩu đều bị thay bằng
`[REDACTED_*]`. Nói rõ chỗ đặt: *"Bộ che nằm ở hai nút thắt cổ chai — mọi prompt gửi tới LLM
và mọi lệnh ghi log — nên không có đường vòng."*

### Phút 14–15 · Giới hạn và hướng phát triển

**Đừng kết thúc bằng lời khoe.** Kết thúc bằng con số bất lợi nhất, vì đó là thứ làm người
đánh giá tin phần còn lại:

> *"Recall của hệ thống là 18,7 %. Nó chỉ thấy 14 trong 75 lỗ hổng có thật của WebGoat, vì
> bộ rule mới chỉ có ba rule. Precision cao chỉ có nghĩa là những gì nó tình cờ thấy thì nó
> đọc khá đúng. Đừng dùng 'không tìm thấy gì' như bằng chứng rằng mã nguồn đã sạch."*

Rồi nêu hướng phát triển theo thứ tự giá trị: thêm rule SAST (recall là trần của mọi thứ
khác), đo `attacker_control` thay vì kẹp cứng, giảm tỷ lệ nhóm bị loại.

---

## §4. Câu hỏi người xem hay hỏi

**"Sao mọi finding đều là `medium`? Không có cái nào `high` à?"**

Đúng, và đó là cố ý. `attacker_control` là trường Agent tự khai, không có phép đo độc lập,
nên Python kẹp cứng nó về `not_proven`, kéo theo trần severity xuống `medium`. Đánh đổi: một
`medium` trung thực đổi lấy một `high` không có bằng chứng. Cái giá phải trả là mất khả năng
xếp ưu tiên theo mức nghiêm trọng — muốn lấy lại thì phải có `measured_attacker_control`.

**"LLM có thể bịa ra một lỗ hổng không tồn tại không?"**

Có thể sinh ra, nhưng không in ra được. Bốn lớp kiểm chặn lại: JSON Schema chặn cấu trúc
sai; provenance chặn việc bịa finding ID, vị trí, CWE hoặc sửa đoạn mã trích dẫn; bộ lọc an
toàn chặn payload khai thác; lớp calibration hạ kết luận vượt quá bằng chứng. Trong lần chạy
tham chiếu, bốn lớp này loại ba nhóm và chặn một phản hồi.

**"Nếu tôi bấm Reject thì sao?"**

Không có gì được gửi. Mặc định của cổng là **từ chối** — gõ bất cứ thứ gì khác `approve` đều
là từ chối, và nếu stdin đóng thì cũng là từ chối. Bằng chứng nằm ở log Gateway: không có
dòng nào mới.

**"Agent có thể tự gọi endpoint bất kỳ không?"**

Không. Đề xuất bị đối chiếu với allowlist ở phía Python, rồi Gateway **kiểm lại một lần nữa
một cách độc lập** bằng chỉ thị nginx. Hai lớp được viết riêng, không lớp nào sinh ra từ lớp
kia.

**"Kết quả có ổn định giữa các lần chạy không?"**

Không hoàn toàn. Đầu ra LLM dao động. Vì thế `make eval` chạy lặp ba lần và tính theo đa số,
và mọi con số trong tài liệu đều được ghi là *một lần lấy mẫu*, không phải hằng số.

**"Chạy mất bao lâu?"**

Khoảng 6 phút, trong đó bước `analyze` chiếm ~97 %. Đó là giới hạn thông lượng của LLM, không
phải giới hạn đúng/sai.

---

## §5. Khi có sự cố

### Container `zap` mãi `unhealthy`

ZAP cần 2–4 phút để mở API. Nếu quá 5 phút:

```bash
docker exec sentinel-sec-zap-1 sh -c 'netstat -ltn | grep 8090' || echo "chua nghe 8090"
```

Nếu không nghe cổng 8090, ZAP đã bind nhầm một cổng ngẫu nhiên — lỗi đã biết, chưa tìm ra
nguyên nhân gốc. Cách xử lý:

```bash
docker compose --profile dast up -d --force-recreate zap
```

Demo vẫn tiếp tục được: DAST bị bỏ qua nhưng luồng **không** hỏng, chỉ ra 23 finding SAST
thay vì 37. Nói thẳng điều đó nếu người xem hỏi.

### `make up` báo `address already in use`

Có tiến trình khác đang giữ cổng 8000 hoặc 9080:

```bash
ss -ltnp | grep -E ':(8000|9080)'
```

Nếu là tiến trình `uvicorn` của bạn (do đã chạy `make web`), tắt nó — `make web` và `make up`
không chạy cùng lúc được vì cả hai phục vụ cổng 8000.

Nếu là `docker-proxy` mồ côi thuộc root (sót lại sau khi Docker daemon đứt):

```bash
sudo kill <pid>
make up
```

### Bước `analyze` hỏng giữa chừng

Gần như luôn là do thiếu hoặc sai `LLM_API_KEY`. Kiểm:

```bash
grep -q '^LLM_API_KEY=.' .env && echo "co khoa" || echo "THIEU KHOA"
```

Lần chạy vẫn được lưu ở trạng thái `FAILED` kèm lý do trong `state.json` — không mất dữ liệu
của các bước trước.

### Không muốn chạy lại `analyze` trước mặt người xem

Dùng lại lần chạy đã chuẩn bị ở §1.4. Toàn bộ §3 từ phút 5 trở đi chỉ đọc artifact có sẵn,
không cần chạy lại gì.

### Muốn dọn bớt lần chạy cũ

```bash
make clean-runs           # giữ 5 lần gần nhất
make clean-runs KEEP=10   # giữ 10
```
