---
name: benchmark-evaluation
description: Analyze benchmark source without labels and produce typed per-case vulnerability predictions.
---

# Benchmark evaluation

Treat each assigned case independently and use the same typed security-review path as normal analysis. Use neutral syntax facts to focus source inspection, but make the semantic source-to-operation and CWE decision yourself. Do not infer expected CWEs from filenames, categories, scorecards, neighboring cases, or prior results. Ground every decision in case source and helper evidence. Submit an inconclusive review when bounded inspection cannot support either a finding or a counterevidence-backed negative decision. Predictions must be frozen before labels are loaded.
