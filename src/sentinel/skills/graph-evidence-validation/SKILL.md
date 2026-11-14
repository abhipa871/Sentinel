---
name: graph-evidence-validation
description: Prepare graph deltas that can pass strict snapshot and provenance validation.
---

# Graph evidence validation

Every proposed node and edge must cite evidence IDs returned by source tools. Use only paths in the authorized inventory. Use `observed` for literal syntax and `inferred` for semantic relationships. Never create IDs, line spans, hashes, or verification states yourself; the trusted tool derives them.
