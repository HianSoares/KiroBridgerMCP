# Implementation Plan

- [x] 1. Agent responsibilities and tool lists
  - case-investigator (case writes), threat-hunter (read + case reads), report-writer (case reads), response-advisor unchanged
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [x] 2. Common case workflow steering; product/evidence/tech steering corrected; skills updated
  - `.kiro/steering/case-workflow.md`, `product.md`, `evidence-and-limits.md`, `tech.md`; offense-investigation, incident-report, hypothesis-hunting
  - _Requirements: 2.1, 2.2, 2.3_
- [x] 3. Consistency tests for pack, docs, specs and tool count
  - `tests/test_pack_consistency.py`
  - _Requirements: 3.1, 3.2, 3.4_
- [x] 4. CI on Windows and Linux, Python 3.11-3.13, suite + schemas + coverage matrix
  - `.github/workflows/ci.yml`
  - _Requirements: 3.3_
