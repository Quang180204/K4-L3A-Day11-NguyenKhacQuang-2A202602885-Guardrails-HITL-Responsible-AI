# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T08:59:05.463286+00:00`
- Framework: `google-adk`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/6`
- Attack queries blocked: `8/8`
- Edge cases blocked: `2/4`
- Rate limit blocked/sent: `3/8`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `3/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
============================== warnings summary ===============================
.venv\Lib\site-packages\_pytest\cacheprovider.py:469
  C:\Users\PC\K4-L3A-Day11-NguyenKhacQuang-2A202602885-Guardrails-HITL-Responsible-AI\.venv\Lib\site-packages\_pytest\cacheprovider.py:469: PytestCacheWarning: cache could not write path C:\Users\PC\K4-L3A-Day11-NguyenKhacQuang-2A202602885-Guardrails-HITL-Responsible-AI\.pytest_cache\v\cache\nodeids: [Errno 13] Permission denied: 'C:\\Users\\PC\\K4-L3A-Day11-NguyenKhacQuang-2A202602885-Guardrails-HITL-Responsible-AI\\.pytest_cache\\v\\cache\\nodeids'
    config.cache.set("cache/nodeids", sorted(self.cached_nodeids))

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
10 passed, 1 warning in 0.88s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
