# SENTINEL Module 1 Skills

Deep Agents loads the canonical skills from `src/sentinel/skills`. Each directory contains a standard `SKILL.md` file.

| Skill | Primary specialist | Responsibility |
| --- | --- | --- |
| `source-ingestion` | source-intake-specialist | Select bounded source context from an authorized snapshot |
| `file-dependency-graph` | file-dependency-specialist | Infer evidence-backed relationships within one file |
| `repository-dependency-graph` | repository-dependency-specialist | Link modules, services, routes, tools, identities, and data across files |
| `graph-evidence-validation` | graph specialists | Submit graph deltas that cite existing source evidence |
| `vulnerability-analysis` | security-finding-specialist | Propose typed CWE findings without claiming runtime verification |
| `outcome-mapping` | outcome-mapping-specialist | Map accepted generic findings to an authorized organizational outcome |
| `attack-graph-reasoning` | attack-path-specialist | Propose outcome-focused AND/OR/NOT prerequisites and counterevidence |
| `hypothetical-compromise-evaluation` | hypothetical-compromise-specialist | Analyze isolated compromise assumptions |
| `jit-verification-planning` | verification-planner | Submit typed questions to the deterministic compiler |
| `scenario-reporting` | scenario-reporting-specialist | Synthesize the seven-field evidence report |
| `benchmark-evaluation` | benchmark-analysis-specialist | Analyze cases without labels and freeze predictions before scoring |
