---
tier: 1
id: path-traversal
title: Path Traversal
tags: [example, path-traversal, lfi, cwe-22]
---

# Path Traversal

Input kiểu `../../etc/passwd` đọc file ngoài thư mục cho phép. Thường gặp ở download/upload.

Mitigation: resolve path rồi kiểm tra nằm trong base directory; reject `..`; dùng ID thay vì tên file thô.
