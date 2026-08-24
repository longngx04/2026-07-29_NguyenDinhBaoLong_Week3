"""Luật quyết định một finding có bị loại khỏi đầu vào của analyze hay không.

Quyết định vứt dữ liệu đi là quyết định có hậu quả, nên nó KHÔNG được giao cho
LLM. Repo đã có tiền lệ cho nguyên tắc này ở `analysis/calibration.py`: LLM đề
xuất, Python quyết.

Bảng 3x3 (verdict × confidence) có đúng MỘT ô dẫn tới việc loại bỏ. Mọi ô còn
lại, cùng mọi hình dạng dữ liệu hỏng, đều giữ finding lại — vì sai theo hướng
giữ chỉ tốn thêm một lượt phân tích, còn sai theo hướng loại thì mất hẳn một lỗ
hổng thật.
"""

from __future__ import annotations

from typing import Any

DROP_VERDICT = "false_positive"
DROP_CONFIDENCE = "high"


def should_drop(verdict: Any) -> bool:
    """True chỉ khi verdict là false_positive VÀ confidence là high."""
    if not isinstance(verdict, dict):
        return False
    return (
        verdict.get("verdict") == DROP_VERDICT
        and verdict.get("confidence") == DROP_CONFIDENCE
    )
