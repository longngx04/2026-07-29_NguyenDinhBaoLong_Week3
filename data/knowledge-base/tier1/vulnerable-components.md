---
tier: 1
id: vulnerable-components
title: Vulnerable and Outdated Components
cwe: [CWE-1395, CWE-1035]
owasp: [A06:2021]
tags: [example, components, cve, a06, dependencies, cwe-1395, supply-chain, sca]
references:
  - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
  - https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/1395.html
---

# Vulnerable and Outdated Components

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Vulnerable and Outdated Components (Sử dụng các thành phần phần mềm có lỗ hổng hoặc lỗi thời - OWASP A06:2021 / CWE-1395) là rủi ro an ninh xảy ra khi ứng dụng tích hợp các thư viện bên thứ ba, framework mã nguồn mở, module hoặc hệ điều hành chứa các lỗ hổng bảo mật đã được công bố công khai (CVE).

Trong các ứng dụng hiện đại, mã nguồn của bên thứ ba thường chiếm từ 70% đến 90% tổng dung lượng codebase. Khi một lỗ hổng trong thư viện được công bố, các mã khai thác tự động (Exploit PoC) thường nhanh chóng xuất hiện trên Internet.

Tác động của việc sử dụng thành phần có lỗ hổng:
- **Thực thi mã từ xa (RCE) trên diện rộng:** Điển hình như các lỗ hổng thảm họa Log4Shell (CVE-2021-44228 trong Apache Log4j2) hay Spring4Shell (CVE-2022-22965 trong Spring Framework).
- **Rò rỉ dữ liệu và chiếm đoạt máy chủ:** Kẻ tấn công khai thác trực tiếp từ các hàm thư viện mà không cần tìm lỗi trong mã nghiệp vụ tự viết.
- **Tấn công chuỗi cung ứng phần mềm (Supply Chain Attack):** Mã độc được cấy vào các bản cập nhật thư viện bị thỏa hiệp hoặc qua hình thức nhầm lẫn tên gói (Dependency Confusion).

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Thư viện chứa lỗ hổng công bố (Known CVE Exploitation)

Ứng dụng sử dụng các phiên bản thư viện cũ có CVE đã công bố (như log4j, Jackson Databind, cũ Spring, commons-fileupload). Các công cụ quét SCA/tool dependency giúp phát hiện; tuy nhiên phân tích SAST pattern đơn thuần không thay thế được việc cập nhật bản vá (patch).

### 2.2. Lỗ hổng trong Phụ thuộc Gián tiếp (Transitive Dependencies)

Ứng dụng không trực tiếp khai báo thư viện lỗi thời trong `pom.xml` hoặc `requirements.txt`, nhưng một thư viện trung gian lại kéo theo thư viện con chứa lỗ hổng nghiêm trọng mà đội ngũ phát triển không hay biết.

### 2.3. Thư viện không còn được duy trì (Unmaintained / Abandoned Libraries)

Dự án sử dụng các gói thư viện mã nguồn mở đã bị tác giả ngừng phát triển từ nhiều năm. Khi xuất hiện lỗ hổng bảo mật mới, thư viện không có bản vá chính thức và buộc phải thay thế toàn bộ giải pháp.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống rủi ro từ thành phần bên thứ ba:

1. **Lớp 1 — Tích hợp Công cụ Phân tích Thành phần Phần mềm (SCA Tooling in CI/CD):**
   Tự động hóa kiểm tra phụ thuộc trong pipeline xây dựng mã nguồn bằng các công cụ SCA tiêu chuẩn (như `pip-audit`, OWASP Dependency-Check, Snyk, GitHub Dependabot) để chặn build ngay khi phát hiện CVE có mức độ High/Critical.
2. **Lớp 2 — Quản lý Bản vá & Nâng cấp Định kỳ (Patch Management):**
   Thiết lập quy trình cập nhật thường xuyên các dependency và base image của container; theo dõi các thông báo an ninh (Security Advisories) từ nhà phát triển framework.
3. **Lớp 3 — Xây dựng Danh mục Thành phần Phần mềm (Software Bill of Materials - SBOM):**
   Tự động xuất file SBOM (chuẩn CycloneDX hoặc SPDX) cho mỗi bản phát hành sản phẩm để nắm bắt đầy đủ toàn bộ cây phụ thuộc trực tiếp và gián tiếp.
4. **Lớp 4 — Kiểm soát Nguồn cung cấp Gói (Private Package Repository):**
   Chỉ tải và cài đặt các gói thư viện từ kho lưu trữ nội bộ (Nexus/Artifactory) đã qua kiểm duyệt bảo mật; cấu hình namespace rõ ràng để phòng chống tấn công Dependency Confusion.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A06: Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [OWASP Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
- [CWE-1395: Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
