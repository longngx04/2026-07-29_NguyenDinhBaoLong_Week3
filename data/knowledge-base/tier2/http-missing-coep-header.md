---
tier: 2
id: http-missing-coep-header
canonical_category: Security Misconfiguration
cwe: [CWE-693]
tier1_parent: security-headers
language: http
sink_signatures:
  - Cross-Origin-Embedder-Policy
matches_rule_ids:
  - "90004"
safe_alternative: "Khai báo tiêu đề Cross-Origin-Embedder-Policy: require-corp hoặc credentialless để bảo vệ tài nguyên chống tấn công rò rỉ dữ liệu cross-origin (Spectre / XS-Leaks)"
exploitable_when: >
  ứng dụng nạp tài nguyên từ các nguồn cross-origin khác mà không kiểm soát
  chính sách chia sẻ tài nguyên hoặc cần kích hoạt tính năng cô lập cross-origin cho SharedArrayBuffer.
not_exploitable_when: >
  mọi tài nguyên của trang đều là same-origin và ứng dụng không sử dụng các API
  cần cô lập cross-origin như SharedArrayBuffer hay performance.measureUserAgentSpecificMemory.
references:
  - https://owasp.org/www-project-secure-headers/
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
  - https://cwe.mitre.org/data/definitions/693.html
---

# `Cross-Origin-Embedder-Policy` — Missing Cross-Origin Embedder Policy Header

## 1. Cơ chế rủi ro (Risk Mechanism)

Tiêu đề HTTP `Cross-Origin-Embedder-Policy` (COEP) ngăn chặn tài nguyên của trang web (ảnh, video, iframe, script) nạp bất kỳ tài nguyên cross-origin nào không cấp phép rõ ràng thông qua CORS hoặc CORP (Cross-Origin Resource Policy).

Khi máy chủ không gửi tiêu đề COEP:
- Kẻ tấn công có thể lợi dụng các kỹ thuật tấn công kênh kề (Side-Channel Attacks / Spectre / Meltdown) hoặc Cross-Site Leaks (XS-Leaks) để suy đoán hoặc trích xuất dữ liệu nhạy cảm lưu trong bộ nhớ trình duyệt.
- Trình duyệt sẽ vô hiệu hóa các API hiệu năng cao như `SharedArrayBuffer` nhằm tự vệ.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP từ máy chủ không chứa tiêu đề `Cross-Origin-Embedder-Policy`:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 512

<!DOCTYPE html>
<html>
  <head><title>COEP Vulnerable App</title></head>
  <body><img src="https://external-bank.example.com/balance-chart.png"></body>
</html>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Máy chủ phản hồi với tiêu đề `Cross-Origin-Embedder-Policy: require-corp`:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Content-Length: 512

<!DOCTYPE html>
<html>
  <head><title>COEP Protected App</title></head>
  <body><img src="/static/chart.png"></body>
</html>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

1. **Lớp 1 — Khai báo tiêu đề COEP kết hợp COOP:**
   Để kích hoạt chế độ Cross-Origin Isolation hoàn chỉnh:
   ```http
   Cross-Origin-Embedder-Policy: require-corp
   Cross-Origin-Opener-Policy: same-origin
   ```
2. **Lớp 2 — Sử dụng `credentialless` cho tài nguyên bên ngoài:**
   Nếu trang web cần nạp tài nguyên từ các bên thứ ba không hỗ trợ CORP, có thể dùng `Cross-Origin-Embedder-Policy: credentialless`.
3. **Lớp 3 — Cấu hình tập trung tại Reverse Proxy / Web Server:**
   - Trên Nginx: `add_header Cross-Origin-Embedder-Policy "require-corp" always;`
   - Trong Spring Security: Sử dụng `http.headers(headers -> headers.crossOriginEmbedderPolicy(coep -> coep.policy(CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP)))`.

## 4. Tài liệu tham khảo (References)

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
