# Policy Pool Key Arity Static

- db: `tpch1`
- policies: `1..30`
- max_cmp_key_arity: 2
- max_hub_key_arity: 1
- max_td_width: 0

## Rows
- policy=1 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=single_hub:2
- policy=2 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1
- policy=3 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=single_hub:2
- policy=4 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1
- policy=5 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=single_hub:3
- policy=6 target=customer cmp_key=0 hub_key=0 td_width=0 notes=q=13
- policy=7 target=customer cmp_key=0 hub_key=0 td_width=0 notes=q=13; route=single_hub:2
- policy=8 target=customer cmp_key=0 hub_key=0 td_width=0 notes=q=13
- policy=9 target=customer cmp_key=0 hub_key=0 td_width=0 notes=q=13; route=single_hub:2
- policy=10 target=customer cmp_key=0 hub_key=0 td_width=0 notes=q=13
- policy=11 target=orders cmp_key=0 hub_key=1 td_width=0 notes=q=3; route=single_hub:2
- policy=12 target=orders cmp_key=0 hub_key=0 td_width=0 notes=q=3
- policy=13 target=orders cmp_key=0 hub_key=1 td_width=0 notes=q=3; route=two_hop:4
- policy=14 target=orders cmp_key=0 hub_key=0 td_width=0 notes=q=3
- policy=15 target=lineitem cmp_key=0 hub_key=1 td_width=0 notes=q=1; route=tree:18
- policy=16 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1
- policy=17 target=lineitem cmp_key=0 hub_key=1 td_width=0 notes=q=1; route=tree:6
- policy=18 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1
- policy=19 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=reject:1; err=ERROR:  policy: class_engine unsupported term shape on target=lineitem HINT:  strict experimental mode allows only class_engine supported shapes
- policy=20 target=partsupp cmp_key=0 hub_key=0 td_width=0 notes=q=11
- policy=21 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=single_hub:1
- policy=22 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1
- policy=23 target=lineitem cmp_key=0 hub_key=0 td_width=0 notes=q=1; route=single_hub:1
- policy=24 target=partsupp cmp_key=0 hub_key=0 td_width=0 notes=q=11
- policy=25 target=supplier cmp_key=0 hub_key=0 td_width=0 notes=q=5; route=single_hub:1
- policy=26 target=orders cmp_key=0 hub_key=0 td_width=0 notes=q=3
- policy=27 target=lineitem cmp_key=1 hub_key=1 td_width=0 notes=q=1; route=tree:1
- policy=28 target=partsupp cmp_key=0 hub_key=0 td_width=0 notes=q=11
- policy=29 target=lineitem cmp_key=2 hub_key=1 td_width=0 notes=q=1; route=cycle_rect:1
- policy=30 target=supplier cmp_key=0 hub_key=0 td_width=0 notes=q=5
