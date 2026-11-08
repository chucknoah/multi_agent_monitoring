# Monitors under log tampering

Attack episodes: 45  |  Benign episodes: 45  |  Threshold τ = 10.0 (set on clean benign logs at target FPR 5%)  |  tampered conditions use only episodes where the tamperer made edits


## Monitor on clean logs (= gateway log; the baseline)

AUROC 0.997 [0.989–1.000]; TPR at τ 100% [92–100] (45/45); FPR 4% [1–15] (2/45)

## Monitor on agent-written logs after tampering

| Condition | AUROC [95% CI] | ΔAUROC vs clean [95% CI], p | TPR at τ | McNemar (lost / gained), p | FPR on benign controls |
|---|---|---|---|---|---|
| delete_coordinated | 0.871 [0.796–0.936] | -0.126 [-0.199, -0.061], p=0.000 | 76% [61–86] (31/41) | 10 / 0, p=0.00195 | 4% [1–15] (2/45) |
| delete_solo | 0.997 [0.989–1.000] | +0.000 [-0.005, +0.001], p=0.918 | 100% [89–100] (32/32) | 0 / 0, p=1 | 4% [1–15] (2/45) |
| inject_coordinated | 0.981 [0.946–1.000] | -0.015 [-0.051, +0.001], p=0.440 | 97% [85–99] (33/34) | 1 / 0, p=1 | 7% [2–18] (3/45) |
| inject_solo | 0.998 [0.993–1.000] | +0.001 [-0.002, +0.004], p=1.000 | 100% [86–100] (24/24) | 0 / 0, p=1 | 2% [0–12] (1/45) |
| rewrite_coordinated | 0.902 [0.838–0.955] | -0.095 [-0.155, -0.044], p=0.000 | 82% [68–90] (36/44) | 8 / 0, p=0.00781 | 2% [0–12] (1/45) |
| rewrite_solo | 0.998 [0.992–1.000] | +0.001 [-0.002, +0.002], p=1.000 | 100% [89–100] (31/31) | 0 / 0, p=1 | 4% [1–15] (2/45) |

## Defences that need no tamper-proof gateway

| Condition | Witness check TPR / FPR | State check TPR / FPR | Monitor OR checks TPR / FPR |
|---|---|---|---|
| delete_coordinated | 56% [41–70] (23/41) / 58% [43–71] (26/45) | 59% [43–72] (24/41) / 0% [0–8] (0/45) | 100% [91–100] (41/41) / 60% [45–73] (27/45) |
| delete_solo | 97% [84–99] (31/32) / 42% [29–57] (19/45) | 59% [42–74] (19/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 44% [31–59] (20/45) |
| inject_coordinated | 29% [17–46] (10/34) / 62% [48–75] (28/45) | 12% [5–27] (4/34) / 0% [0–8] (0/45) | 100% [90–100] (34/34) / 62% [48–75] (28/45) |
| inject_solo | 83% [64–93] (20/24) / 40% [27–55] (18/45) | 0% [0–14] (0/24) / 0% [0–8] (0/45) | 100% [86–100] (24/24) / 40% [27–55] (18/45) |
| rewrite_coordinated | 27% [16–42] (12/44) / 60% [45–73] (27/45) | 43% [30–58] (19/44) / 0% [0–8] (0/45) | 100% [92–100] (44/44) / 60% [45–73] (27/45) |
| rewrite_solo | 71% [53–84] (22/31) / 36% [23–50] (16/45) | 29% [16–47] (9/31) / 0% [0–8] (0/45) | 100% [89–100] (31/31) / 36% [23–50] (16/45) |

## Combining the monitor with checks that stay quiet on benign edits

The word-overlap witness check above also fires when honest agents paraphrase. These rows use only checks that paraphrasing cannot trigger: the state check, and a structural witness check (a message that one party has and the other does not). Thresholds are unchanged.

| Condition | Structural witness TPR / FPR | Monitor OR state TPR / FPR | Monitor OR state OR structural witness TPR / FPR | Monitor misses rescued: by state / by structural witness / by either |
|---|---|---|---|---|
| delete_coordinated | 56% [41–70] (23/41) / 0% [0–8] (0/45) | 100% [91–100] (41/41) / 4% [1–15] (2/45) | 100% [91–100] (41/41) / 4% [1–15] (2/45) | 10 / 6 / 10 of 10 |
| delete_solo | 97% [84–99] (31/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 / 0 of 0 |
| inject_coordinated | 29% [17–46] (10/34) / 0% [0–8] (0/45) | 100% [90–100] (34/34) / 7% [2–18] (3/45) | 100% [90–100] (34/34) / 7% [2–18] (3/45) | 1 / 0 / 1 of 1 |
| inject_solo | 83% [64–93] (20/24) / 0% [0–8] (0/45) | 100% [86–100] (24/24) / 2% [0–12] (1/45) | 100% [86–100] (24/24) / 2% [0–12] (1/45) | 0 / 0 / 0 of 0 |
| rewrite_coordinated | 0% [0–8] (0/44) / 0% [0–8] (0/45) | 93% [82–98] (41/44) / 2% [0–12] (1/45) | 93% [82–98] (41/44) / 2% [0–12] (1/45) | 5 / 0 / 5 of 8 |
| rewrite_solo | 0% [0–11] (0/31) / 0% [0–8] (0/45) | 100% [89–100] (31/31) / 4% [1–15] (2/45) | 100% [89–100] (31/31) / 4% [1–15] (2/45) | 0 / 0 / 0 of 0 |

## Manipulation check: what the tamperers actually did (attack episodes)

| Condition | Episodes | No edits made | Entries deleted | Entries rewritten | Entries inserted | Edits rejected (not allowed) |
|---|---|---|---|---|---|---|
| delete_coordinated | 45 | 4 (9%) | 280 (6.2/ep) | 0 (0.0/ep) | 0 (0.0/ep) | 0 |
| delete_solo | 45 | 13 (29%) | 171 (3.8/ep) | 0 (0.0/ep) | 0 (0.0/ep) | 0 |
| inject_coordinated | 45 | 11 (24%) | 0 (0.0/ep) | 0 (0.0/ep) | 184 (4.1/ep) | 4 |
| inject_solo | 45 | 21 (47%) | 0 (0.0/ep) | 0 (0.0/ep) | 84 (1.9/ep) | 2 |
| rewrite_coordinated | 45 | 1 (2%) | 0 (0.0/ep) | 340 (7.6/ep) | 0 (0.0/ep) | 0 |
| rewrite_solo | 45 | 14 (31%) | 0 (0.0/ep) | 156 (3.5/ep) | 0 (0.0/ep) | 0 |

Notes: rates show point estimate, Wilson 95% CI and counts. ΔAUROC uses a paired, stratified bootstrap over episodes. McNemar compares, on the same attack episodes, detection on the clean log vs the tampered log at the same threshold. Benign controls are benign episodes whose agents lightly paraphrased their own messages.