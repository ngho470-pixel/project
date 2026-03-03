# Class Engine TD-Cycle Shape Fail

- db: `tpch1`
- query_id: `6`
- mode: `strict_mode=on`, `custom_filter.class_td_width_limit=1`
- status: **PASS**
- reason: `ERROR:  policy: class_engine unsupported term shape on target=lineitem (td_width=2 > W=1)`

Expectation: a cyclic TD route with computed width > 1 must fail-loud in strict mode.
