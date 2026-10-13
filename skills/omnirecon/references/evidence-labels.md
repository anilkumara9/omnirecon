# Evidence labels — examples

## OBSERVED
- "GET /api/products?page=2 → 200, JSON array of 20 items" — the request was
  actually issued by the page in the owned browser (`recon_capture_network`).
- "Route /pricing exists, title 'Pricing', 3 forms" — page fetched and parsed
  during `recon_discover_routes`.
- "Clicking 'Load more' appended 20 product cards; 1 XHR to /api/products"
  — state transition recorded by `recon_trace_workflow`.

## SOURCE_VERIFIED
- "Framework: Next.js 14" — `next` in package.json dependencies.
- "Route /api/checkout (POST)" — `@app.post("/api/checkout")` in
  `backend/orders.py:42`.

## INFERRED
- "Framework: likely React SPA" — `<div id="root">` + react bundle markers,
  but no manifest or source available.
- "Entity: Product {id, name, price}" — inferred from repeated JSON shapes in
  `/api/products` responses; the real DB schema is unknown.

## UNVERIFIED
- "The /admin route probably requires auth" — route discovered in JS bundle,
  never fetched (would need credentials we don't have).

## BLOCKED
- "Checkout workflow" — blocked at login wall; no authorized test account
  provided.

## Confidence guidance
- 0.9–1.0: direct capture or manifest-backed fact.
- 0.7–0.89: strong heuristic with corroborating signals.
- 0.4–0.69: single weak signal.
- < 0.4: guess — keep it out of the spec's requirements sections.
