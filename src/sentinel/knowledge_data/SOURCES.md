# Predefined G_V sources

`gv_predefined.json.gz` is generated, not hand-authored. It contains normalized records from:

- MITRE CWE comprehensive XML, version 5.0
- MITRE CAPEC comprehensive XML, version 3.9
- MITRE ATLAS YAML, content version 2026.10 / format version 6.1.0
- MITRE D3FEND JSON-LD, ontology version 1.6.0
- OWASP API Security Top 10, 2023 edition, from github.com/OWASP/API-Security at commit
  `33cea37b2ffde3e2e62f6b5d79a029a22a846633` (`editions/2023/en/0xa1`–`0xaa`)

Each source URL and SHA-256 is embedded in the snapshot's `source_manifest`. Every node and edge
retains source system/version and assertion origin. Regenerate with
`python scripts/build_vulnerability_graph.py`. CVEs are intentionally not bulk-bundled: the
technical plan requires product/package-targeted CVE and advisory overlays.

## OWASP API Security Top 10 attribution

The `OWASP_API_RISK` records (names, the "Is the API Vulnerable?" descriptions, threat
ratings) and their `REFERENCES_WEAKNESS` edges are adapted from the OWASP API Security Top 10
2023 by the OWASP Foundation, licensed under the Creative Commons Attribution-ShareAlike 4.0
International License (https://creativecommons.org/licenses/by-sa/4.0/). Text is reproduced
with whitespace normalized; edges are only the CWE references OWASP lists for each risk.
Those adapted records remain under CC BY-SA 4.0.
