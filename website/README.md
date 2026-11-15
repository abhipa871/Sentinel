# Sentinel hackathon demo

Open `index.html` in a browser, keeping `assets-data.js` beside it, or serve this directory with
`python -m http.server 8080`.

The page replays a saved static scan of OWASP crAPI. "Run demo scan" replays the saved results; it
does not call a model or scan anything. ChatOverflow creates a defensive lesson draft for manual
sharing.

`assets-data.js` is generated from a scan bundle and is not edited by hand:

```powershell
python scripts/build_website_data.py artifacts\crapi-full-v7.json
```

What the page shows, all copied from the bundle unchanged:

- Every Module I candidate with its Module II verdict exactly as recorded (strongly supported,
  inconclusive, refuted, or not analyzed). Nothing is relabeled.
- The hash-verified source lines each review cites, linked to the pinned commit on GitHub.
- The Module III fix proposed for a finding, where one exists. Fixes are proposals; none has
  been applied or verified.
- Footer counts computed from the data, including how many of crAPI's 18 documented challenges
  have a strongly supported finding of the matching weakness type in the right service. That
  match is by weakness type and service, not by exact endpoint.

This is static review. No finding was exploited or run against a live system, and the positive
findings have not been manually verified.
