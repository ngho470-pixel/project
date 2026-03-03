# Class Engine Witness-Witness Comparator Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`

## Cases
- F_WW_NONADJ: PASS :: non-adjacent witness-witness comparator must fail-loud :: error=`ERROR:  policy: class_engine unsupported term shape on target=lineitem HINT:  strict experimental mode allows only class_engine supported shapes`

- overall: PASS
