# Class Engine `!=` Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`

## Cases
- F_NEQ_K3: PASS :: cross-table != with separator key arity > 2 must fail-loud :: error=`ERROR:  policy: class_engine unsupported term shape on target=supplier HINT:  strict experimental mode allows only class_engine supported shapes`

- overall: PASS
