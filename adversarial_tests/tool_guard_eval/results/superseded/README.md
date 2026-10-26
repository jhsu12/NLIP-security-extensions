# Superseded results

Dev-split runs of `catalog_only_d3` and `hybrid_d3_catalog` from before two fixes:

- `catalog_only_d3` used `judge = "stub"`, so the catalog check ran with rules only (no d3).
  Fixed by the separate `catalog_judge` option.
- A catalog finding tainted the session and raised the judge threshold, blocking legitimate
  calls even though the poisoned text had already been stripped. Catalog findings now only
  record planted addresses/URLs (`GuardSession.taint(..., exposed=False)`).

Kept for transparency; not used for any reported number.
