---
tier: 1
id: xss
title: Cross-Site Scripting
cwe: [CWE-79]
owasp: [A03:2021]
tags: [example, xss, cross-site-scripting, cwe-79]
---

# Cross-Site Scripting

Kẻ tấn công chèn mã JavaScript độc hại vào ứng dụng web, mã này được thực thi trong trình duyệt của nạn nhân để đánh cắp phiên làm việc, mạo danh người dùng hoặc thao túng DOM.

## Biến thể: Reflected

Ứng dụng phản chiếu input (search, error message) vào HTML mà không encode. Payload ví dụ: `<script>alert(1)</script>`.

Cross Site Scripting (XSS) cho phép đánh cắp session cookie hoặc giả mạo hành động. Mitigation: encode output theo context (HTML/attr/JS), Content-Security-Policy.

## Biến thể: Stored

Payload XSS được lưu (comment, profile) rồi phục vụ cho mọi người xem. Nguy hiểm hơn reflected vì lan rộng.

Tìm kiếm “XSS” hoặc “cross site scripting” nên trỏ tới tài liệu này. Fix: sanitize/encode khi lưu và khi render; dùng thư viện templating tự escape.

## Biến thể: DOM

JavaScript phía client lấy dữ liệu từ `location.hash` / `innerHTML` mà không kiểm soát. Không cần phản hồi server chứa script.

Mitigation: tránh `innerHTML` với dữ liệu không tin cậy; dùng `textContent`; validate URL fragment.

## Khắc phục chung

Encode dữ liệu đầu ra theo đúng ngữ cảnh hiển thị (HTML body, attribute, JavaScript context), áp dụng Content-Security-Policy (CSP) chặt chẽ, và hạn chế dùng các API nguy hiểm như `innerHTML` phía client.
