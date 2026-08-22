---
tier: 2
id: java-spring-csrf-disabled
canonical_category: CSRF
cwe: [CWE-352]
tier1_parent: csrf
language: java
sink_signatures:
  - org.springframework.security.config.annotation.web.builders.HttpSecurity.csrf().disable
no_rule_yet: true
safe_alternative: "Giữ bảo vệ CSRF bật mặc định của Spring Security hoặc dùng Token-based CSRF filter"
exploitable_when: >
  ứng dụng web dùng xác thực dựa trên Cookie phiên duyệt (Session Cookie) cho các thao tác
  thay đổi trạng thái (POST/PUT/DELETE) nhưng tắt bảo vệ CSRF
not_exploitable_when: >
  ứng dụng là API hoàn toàn stateless sử dụng Bearer Token trong header Authorization
  hoặc mọi cookie đều cấu hình SameSite=Strict
---

# `HttpSecurity.csrf().disable` — Disabled CSRF Protection

Tắt tính năng bảo vệ CSRF trong Spring Security khiến các endpoint nhạy cảm bị tổn thương
khi người dùng đăng nhập bằng cookie phiên trình duyệt và truy cập trang web độc hại của kẻ tấn công.

Nên duy trì cơ chế bảo vệ CSRF mặc định cho các ứng dụng web truyền thống có trạng thái session.

## Vì sao `not_exploitable_when` quan trọng ở đây

Trong kiến trúc REST API thuần tuý (Stateless) xác thực qua header `Authorization: Bearer <token>`,
trình duyệt không tự động gửi token qua các cross-origin requests, do đó không bị ảnh hưởng bởi CSRF.

## Nguồn

- Spring Security Reference: Cross Site Request Forgery (CSRF) Protection
- CWE-352: Cross-Site Request Forgery (CSRF)
