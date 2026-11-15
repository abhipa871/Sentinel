# Predefined G_V sources

`gv_predefined.json.gz` is generated, not hand-authored. It contains normalized records from:

- MITRE CWE comprehensive XML, version 5.0
- MITRE CAPEC comprehensive XML, version 3.9
- MITRE ATLAS YAML, content version 2026.10 / format version 6.1.0
- MITRE D3FEND JSON-LD, ontology version 1.6.0

Each source URL and SHA-256 is embedded in the snapshot's `source_manifest`. Every node and edge
retains source system/version and assertion origin. Regenerate with
`python scripts/build_vulnerability_graph.py`. CVEs are intentionally not bulk-bundled: the
technical plan requires product/package-targeted CVE and advisory overlays.
