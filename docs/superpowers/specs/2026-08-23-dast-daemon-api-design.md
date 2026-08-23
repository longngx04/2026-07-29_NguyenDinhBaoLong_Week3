# DAST chạy được từ giao diện — ZAP daemon và API nội bộ

**Ngày:** 2026-08-23
**Trạng thái:** đã chốt hướng, chờ viết plan
**Động cơ:** bấm quét từ giao diện chỉ ra 23 finding SAST; DAST luôn bị bỏ qua

---

## 1. Vấn đề

Bấm quét từ giao diện web, mỗi lần đều chỉ ra 23 finding SAST. Nhật ký của lần chạy
`20260823T084826Z` nói thẳng lý do:

```text
[info] Bắt đầu quét mã nguồn
[info] OpenGrep report: /app/artifacts/runs/20260823T084826Z/raw.json
[warn] Bo qua DAST: Bước scan thất bại (mã 127): Docker is required to run the real ZAP Baseline scan.
[info] Quét xong
```

Mã 127 là "command not found". Nguyên nhân có **hai tầng**, và sửa một tầng không đủ.

**Tầng 1 — container `web` không có Docker.** `infra/docker/web/Dockerfile` cài thẳng
binary `opengrep` vào `/usr/local/bin/`, nên SAST chạy native trong container. Nhưng
`scripts/scan-zap.sh` vẫn phải gọi `docker compose` để dựng ZAP, mà container không có
Docker CLI lẫn `/var/run/docker.sock`. Bất đối xứng: SAST đã được làm cho chạy được
trong container, DAST thì chưa.

**Tầng 2 — `make up` không bật lane DAST.** Nó chạy `--profile target --profile app`,
trong khi `gateway-dast` và `zap` đều ở profile `dast`. Kể cả gỡ được tầng 1, hai
container mà DAST cần vẫn không tồn tại.

### 1.1 Vì sao không mount docker socket

Cách nhanh nhất là mount `/var/run/docker.sock` vào container `web`. Spec này **từ chối**
hướng đó. Một container có socket của daemon có thể tạo container đặc quyền, mount hệ
thống file của host, và trở thành tương đương root trên máy. Toàn bộ dự án được xây
quanh nguyên tắc ngược lại: WebGoat không bao giờ publish, gateway chỉ bind loopback,
allowlist hai lớp suy ra độc lập, 13 test khoá bất biến mạng. Trao quyền daemon cho đúng
container đang mở cổng HTTP là gỡ bỏ chính điều đó — và cổng `POST /runs` của giao diện
sẽ trở thành đường chạy container tuỳ ý.

---

## 2. Những gì luồng DAST hiện tại đang làm

`scripts/scan-zap.sh` làm nhiều hơn "chạy một lần quét". Bất kỳ thiết kế mới nào cũng
phải giữ đủ:

1. Sinh `SENTINEL_DAST_API_KEY` tạm thời.
2. Dựng `gateway-dast` và `webgoat`.
3. `zap-baseline.py` nhắm `http://gateway-dast:8081/WebGoat/login` — spider và passive scan.
4. Một lần gọi ZAP **thứ hai** chạy `infra/docker/zap/requestor-plan.yaml`, kèm `-config
   replacer.*` để tiêm header `X-Sentinel-DAST-Key`. Đây là phần chứng minh reachability
   cho các endpoint `@PostMapping`.
5. `jq` kiểm hình dạng báo cáo.
6. `docker compose logs gateway-dast` → `gateway-access.log`.
7. **Hai kiểm tra an toàn:** có bằng chứng ZAP thật sự đi qua lane DAST, và khoá DAST
   **không** rò vào báo cáo hay log.
8. Chuyển hai artifact vào chỗ bằng `mv` nguyên tử.

Bước 6 cũng cần Docker. Nên chỉ thay cách gọi ZAP là không đủ.

---

## 3. Spike — đã kiểm, không phải giả định

Chạy đúng image đã pin (`ghcr.io/zaproxy/zaproxy@sha256:8d387b1a…`) ở chế độ daemon và
gọi thử từng endpoint. ZAP báo `2.17.0`. Kết quả:

| Endpoint | Kết quả | Dùng để |
| :--- | :--- | :--- |
| `core/view/version` | `{"version":"2.17.0"}` | kiểm daemon sẵn sàng |
| `automation/action/runPlan` | `missing_parameter` — **endpoint tồn tại** | chạy plan, tái dùng `requestor-plan.yaml` |
| `automation/view/planProgress` | `missing_parameter` — tồn tại | chờ plan xong |
| `core/view/alerts` | `{"alerts":[]}` | lấy alert ra |
| `replacer/action/addRule` | `missing_parameter` — tồn tại | tiêm header `X-Sentinel-DAST-Key` |
| `replacer/view/rules` | trả danh sách rule | kiểm rule đã được thêm |

`missing_parameter` là câu trả lời **tốt**: nó chứng minh endpoint có thật và chỉ thiếu
tham số. Mọi cơ chế thiết kế này cần đều đã được xác nhận trên đúng image sẽ dùng.

---

## 4. Thiết kế

### 4.1 ZAP thành service chạy nền

`zap` đổi từ container dùng-một-lần thành daemon chạy suốt vòng đời stack:

```yaml
zap:
  profiles: ["dast"]        # giữ nguyên; make up bật profile này, xem §4.5
  image: ghcr.io/zaproxy/zaproxy@sha256:8d387b1a…   # giữ nguyên, đã pin
  command: >
    zap.sh -daemon -host 0.0.0.0 -port 8090
    -config api.key=${SENTINEL_ZAP_API_KEY}
    -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
  expose: ["8090"]          # KHÔNG ports: — API không bao giờ ra host
  volumes:
    - ./artifacts:/zap/wrk:rw
  networks: [sentinel-net]
```

`expose` chứ không `ports` là bất biến phải khoá bằng test: API của ZAP điều khiển được
một trình duyệt tấn công, nó không được xuất hiện trên bất kỳ giao diện host nào.

### 4.2 Một plan thay hai lần gọi

Automation Framework làm được cả spider lẫn passive scan, nên hai lần `docker run` gộp
thành một plan duy nhất. `infra/docker/zap/scan-plan.yaml`:

```yaml
env:
  contexts:
    - name: sentinel-dast
      urls: ["http://gateway-dast:8081/WebGoat/"]
  parameters:
    failOnError: true
    progressToStdout: true

jobs:
  - type: spider
    parameters: { context: sentinel-dast, url: "http://gateway-dast:8081/WebGoat/login", maxDuration: 1 }
  - type: requestor
    parameters: { user: "" }
    requests: [ … giữ nguyên toàn bộ danh sách từ requestor-plan.yaml … ]
  - type: passiveScan-wait
    parameters: { maxDuration: 5 }
```

**Thứ tự đổi có chủ ý.** Hiện tại baseline chạy trước (spider + passive), requestor chạy
sau ở một tiến trình ZAP khác — nên phản hồi của các request POST **không** được passive
scan. Đưa `requestor` vào trước `passiveScan-wait` khiến chúng được quét. Đây là thay đổi
hành vi: số alert có thể tăng. Task đo phải ghi lại con số trước/sau chứ không được coi
là như nhau.

### 4.3 Log gateway thành file

`gateway-dast` hiện ghi `access_log /dev/stdout sentinel_dast_access;`, nên phải dùng
`docker compose logs` để đọc — lại cần Docker. Sửa: ghi ra **cả hai** nơi.

```nginx
access_log /dev/stdout sentinel_dast_access;
access_log /var/log/sentinel/dast-access.log sentinel_dast_access;
```

và mount một volume dùng chung giữa `gateway-dast` và `web`:

```yaml
volumes:
  sentinel-dast-log:

gateway-dast:
  volumes: [ "sentinel-dast-log:/var/log/sentinel" ]
web:
  volumes:
    - ./artifacts:/app/artifacts
    - "sentinel-dast-log:/var/log/sentinel:ro"    # chỉ đọc
```

`:ro` phía `web` là có chủ ý: đây là **bằng chứng**, và tiến trình đang đọc nó không được
sửa nó.

Giữ dòng `/dev/stdout` để `docker compose logs` vẫn dùng được khi gỡ lỗi trên host.

### 4.4 Một bản cài đặt, dùng chung cho host và container

Viết `src/project_sentinel/dast/zap_client.py`, và `scripts/scan-zap.sh` trở thành lớp
vỏ mỏng gọi vào nó. Hai bản cài đặt song song sẽ trôi khỏi nhau — đúng loại lỗi đã xảy ra
với `normalizer` và `zap_normalizer`.

Client làm đúng trình tự cũ:

```python
def run_dast(report_path: Path, log_path: Path, *, config: ZapConfig) -> None:
    wait_until_ready(config)                  # core/view/version, có hạn giờ
    add_dast_key_header(config)               # replacer/action/addRule
    plan_id = run_plan(config, PLAN_PATH)     # automation/action/runPlan
    wait_for_plan(config, plan_id)            # automation/view/planProgress
    alerts = fetch_alerts(config)             # core/view/alerts
    _write_report(report_path, alerts)
    _copy_gateway_log(log_path)               # từ volume dùng chung
    _assert_traffic_went_through_gateway(log_path)
    _assert_key_did_not_leak(report_path, log_path, config.dast_key)
```

Hai hàm `_assert_*` cuối là hai kiểm tra an toàn ở bước 7 mục §2, giữ nguyên ngữ nghĩa.
Chúng ném `DastError`, và `step_scan` bắt như hiện nay — DAST vẫn **không bao giờ** làm
sập một lần chạy.

### 4.5 `make up` bật lane DAST

`make up` chuyển sang `--profile target --profile app --profile dast`, nên `webgoat`,
`gateway`, `gateway-dast`, `zap`, `web` cùng lên. Đây chính là điều người dùng cần: bấm
quét từ giao diện thì WebGoat có chạy thật, và Gateway đứng trước nó có tác dụng.

Thêm hai khoá vào phần sinh credential của `make up`: `SENTINEL_DAST_API_KEY` và
`SENTINEL_ZAP_API_KEY`, sinh bằng `openssl rand -hex 32` như khoá Gateway đang làm.

---

## 5. Đánh đổi phải ghi vào tài liệu

**Khoá DAST không còn theo từng lần quét.** Compose truyền `SENTINEL_DAST_API_KEY` vào
`gateway-dast` **lúc tạo container**, nên không thể sinh khoá mới cho mỗi lần quét mà
không dựng lại container. Khoá trở thành tồn tại theo vòng đời stack.

Đây là nới lỏng thật so với hiện tại và phải nói ra. Giảm nhẹ: khoá vẫn sinh ngẫu nhiên
mỗi lần `make up`, không bao giờ vào Git, không bao giờ ra host, và kiểm tra chống rò rỉ
ở §4.4 giữ nguyên. Ghi vào `docs/limitations.md`.

**Bề mặt tấn công thêm một service.** ZAP daemon là một tiến trình chạy suốt với API
điều khiển được. Nó bị chặn bởi: `expose` chứ không `ports`, API key bắt buộc, và nó chỉ
nằm trên mạng nội bộ `sentinel-net`. Có test khoá cả ba.

---

## 6. Kiểm thử

**Bất biến compose** (thêm vào `tests/unit/infra/test_compose_invariants.py`):

- `zap` **không** khai `ports` — API không bao giờ chạm host.
- `zap` chạy với `api.key` lấy từ biến môi trường, không phải hằng trong file.
- `zap` vẫn nhắm `gateway-dast`, không bao giờ `webgoat` (test hiện có, phải còn xanh).
- `web` mount volume log ở chế độ `:ro`.
- Ảnh ZAP vẫn pin theo digest (test hiện có).

**Client** (`tests/unit/dast/test_zap_client.py`, dùng transport giả, không cần mạng):

- Daemon không sẵn sàng trong hạn giờ → `DastError`, không treo.
- Plan chạy lỗi → `DastError` kèm thông điệp của ZAP.
- Log gateway không có dòng nào của lane DAST → `DastError` (bằng chứng đi qua gateway).
- Khoá DAST xuất hiện trong báo cáo hoặc log → `DastError` (chống rò rỉ).
- Đường đi thuận lợi → ghi ra báo cáo đúng hình dạng `{"site": [...]}`.

**Tích hợp** (đánh dấu `integration`, cần Docker):

- `make up` rồi gọi client → sinh ra `zap-alerts.json` và `gateway-access.log`.
- `step_scan` chạy trong container `web` → `dast_status == "done"`.

---

## 7. Tiêu chí đạt

Đo trên một lần chạy bấm từ giao diện, sau khi `make up`:

| Chỉ số | Trước | Yêu cầu |
| :--- | ---: | :--- |
| Finding từ giao diện | 23 (chỉ SAST) | **37** (23 SAST + 14 DAST) |
| `dast_status` trong `state.json` | `skipped` | `done` |
| Docker CLI trong container `web` | không có | **vẫn không có** |
| `/var/run/docker.sock` trong `web` | không có | **vẫn không có** |
| Cổng host của ZAP | — | **không có** |
| `make quality` | xanh | xanh |

Ba dòng giữa là điều kiện phủ định và quan trọng ngang các dòng còn lại: nếu DAST chạy
được nhờ trao quyền Docker cho container web thì task này thất bại, kể cả khi con số
finding đúng.

---

## 8. Ngoài phạm vi

- **Active scan.** Vẫn chỉ spider và passive scan. Đây là quyết định cũ, không đổi ở đây.
- **Sinh rule OpenGrep từ KB.** Không liên quan.
- **Bỏ `zap-baseline.py`.** `make dast` trên host vẫn dùng đường cũ cho tới khi client
  chứng minh ổn định qua một lần bàn giao; sau đó mới xoá script, để không mất đường lui.
