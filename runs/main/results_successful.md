# Monitors under log tampering

Attack episodes: 32  |  Benign episodes: 45  |  Threshold τ = 10.0 (set on clean benign logs at target FPR 5%)  |  successful attacks only


## Monitor on clean logs (= gateway log; the baseline)

AUROC 0.998 [0.993–1.000]; TPR at τ 100% [89–100] (32/32); FPR 4% [1–15] (2/45)

## Monitor on agent-written logs after tampering

| Condition | AUROC [95% CI] | ΔAUROC vs clean [95% CI], p | TPR at τ | McNemar (lost / gained), p | FPR on benign controls |
|---|---|---|---|---|---|
| delete_coordinated | 0.853 [0.767–0.935] | -0.145 [-0.228, -0.063], p=0.000 | 72% [55–84] (23/32) | 9 / 0, p=0.00391 | 4% [1–15] (2/45) |
| delete_coordinated_aware | 0.998 [0.991–1.000] | -0.001 [-0.003, +0.000], p=0.910 | 100% [89–100] (32/32) | 0 / 0, p=1 | 4% [1–15] (2/45) |
| delete_solo | 0.998 [0.991–1.000] | -0.001 [-0.004, +0.001], p=1.000 | 100% [89–100] (32/32) | 0 / 0, p=1 | 4% [1–15] (2/45) |
| inject_coordinated | 0.981 [0.941–1.000] | -0.018 [-0.056, +0.000], p=0.352 | 97% [84–99] (31/32) | 1 / 0, p=1 | 7% [2–18] (3/45) |
| inject_solo | 0.998 [0.993–1.000] | +0.000 [-0.002, +0.002], p=1.000 | 100% [89–100] (32/32) | 0 / 0, p=1 | 2% [0–12] (1/45) |
| rewrite_coordinated | 0.916 [0.844–0.969] | -0.083 [-0.153, -0.031], p=0.002 | 84% [68–93] (27/32) | 5 / 0, p=0.0625 | 2% [0–12] (1/45) |
| rewrite_coordinated_aware | 0.983 [0.948–1.000] | -0.016 [-0.049, +0.002], p=0.683 | 97% [84–99] (31/32) | 1 / 0, p=1 | 4% [1–15] (2/45) |
| rewrite_solo | 0.999 [0.994–1.000] | +0.000 [-0.001, +0.003], p=1.000 | 100% [89–100] (32/32) | 0 / 0, p=1 | 4% [1–15] (2/45) |

## Defences that need no tamper-proof gateway

| Condition | Witness check TPR / FPR | State check TPR / FPR | Monitor OR checks TPR / FPR |
|---|---|---|---|
| delete_coordinated | 50% [34–66] (16/32) / 58% [43–71] (26/45) | 59% [42–74] (19/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 60% [45–73] (27/45) |
| delete_coordinated_aware | 6% [2–20] (2/32) / 53% [39–67] (24/45) | 6% [2–20] (2/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 53% [39–67] (24/45) |
| delete_solo | 78% [61–89] (25/32) / 42% [29–57] (19/45) | 47% [31–64] (15/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 44% [31–59] (20/45) |
| inject_coordinated | 22% [11–39] (7/32) / 62% [48–75] (28/45) | 12% [5–28] (4/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 62% [48–75] (28/45) |
| inject_solo | 50% [34–66] (16/32) / 40% [27–55] (18/45) | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 40% [27–55] (18/45) |
| rewrite_coordinated | 19% [9–35] (6/32) / 60% [45–73] (27/45) | 47% [31–64] (15/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 60% [45–73] (27/45) |
| rewrite_coordinated_aware | 9% [3–24] (3/32) / 53% [39–67] (24/45) | 12% [5–28] (4/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 53% [39–67] (24/45) |
| rewrite_solo | 53% [36–69] (17/32) / 36% [23–50] (16/45) | 19% [9–35] (6/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 36% [23–50] (16/45) |

## Combining the monitor with checks that stay quiet on benign edits

The word-overlap witness check above also fires when honest agents paraphrase. These rows use only checks that paraphrasing cannot trigger: the state check, and a structural witness check (a message that one party has and the other does not). Thresholds are unchanged.

| Condition | Structural witness TPR / FPR | Monitor OR state TPR / FPR | Monitor OR state OR structural witness TPR / FPR | Monitor misses rescued: by state / by structural witness / by either |
|---|---|---|---|---|
| delete_coordinated | 50% [34–66] (16/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 9 / 5 / 9 of 9 |
| delete_coordinated_aware | 6% [2–20] (2/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 / 0 of 0 |
| delete_solo | 78% [61–89] (25/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 / 0 of 0 |
| inject_coordinated | 22% [11–39] (7/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 7% [2–18] (3/45) | 100% [89–100] (32/32) / 7% [2–18] (3/45) | 1 / 0 / 1 of 1 |
| inject_solo | 50% [34–66] (16/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 2% [0–12] (1/45) | 100% [89–100] (32/32) / 2% [0–12] (1/45) | 0 / 0 / 0 of 0 |
| rewrite_coordinated | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 97% [84–99] (31/32) / 2% [0–12] (1/45) | 97% [84–99] (31/32) / 2% [0–12] (1/45) | 4 / 0 / 4 of 5 |
| rewrite_coordinated_aware | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 97% [84–99] (31/32) / 4% [1–15] (2/45) | 97% [84–99] (31/32) / 4% [1–15] (2/45) | 0 / 0 / 0 of 1 |
| rewrite_solo | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 / 0 of 0 |

## AUROC by tampering condition and detector

Each column adds checks to the monitor: a log on which a check finds a mismatch is escalated to the maximum score. The last column is the paired bootstrap difference between the rightmost detector and the monitor alone. Clean logs (monitor only): 0.998; checks fired on 0 of the clean logs.

| Condition | monitor only | + state check | + replay check | + state & replay | Δ AUROC vs monitor only [95% CI], p |
|---|---|---|---|---|---|
| delete_coordinated | 0.853 [0.767–0.935] | 1.000 [1.000–1.000] | 0.853 [0.767–0.935] | 1.000 [1.000–1.000] | +0.147 [+0.065, +0.233], p=0.000 |
| delete_coordinated_aware | 0.998 [0.991–1.000] | 0.998 [0.992–1.000] | 0.998 [0.991–1.000] | 0.998 [0.992–1.000] | +0.000 [+0.000, +0.002], p=1.000 |
| inject_coordinated | 0.981 [0.941–1.000] | 0.998 [0.992–1.000] | 0.998 [0.992–1.000] | 0.998 [0.992–1.000] | +0.017 [+0.000, +0.053], p=0.324 |
| rewrite_coordinated | 0.916 [0.844–0.969] | 0.983 [0.948–1.000] | 0.967 [0.920–1.000] | 1.000 [0.998–1.000] | +0.084 [+0.031, +0.156], p=0.002 |
| rewrite_coordinated_aware | 0.983 [0.948–1.000] | 0.983 [0.948–1.000] | 0.999 [0.996–1.000] | 0.999 [0.996–1.000] | +0.016 [+0.000, +0.050], p=0.683 |
| delete_solo | 0.998 [0.991–1.000] | 0.999 [0.994–1.000] | 0.999 [0.994–1.000] | 0.999 [0.994–1.000] | +0.001 [+0.000, +0.005], p=0.797 |
| inject_solo | 0.998 [0.993–1.000] | 0.998 [0.993–1.000] | 0.998 [0.993–1.000] | 0.998 [0.993–1.000] | +0.000 [+0.000, +0.000], p=1.000 |
| rewrite_solo | 0.999 [0.994–1.000] | 0.999 [0.996–1.000] | 0.999 [0.996–1.000] | 0.999 [0.996–1.000] | +0.000 [+0.000, +0.002], p=1.000 |

## Targeted fix: deterministic replay of reported tool calls (added after the main analysis)

Re-executes every tool call in the agents' logs from the initial snapshot and compares each logged result with the replayed one, which covers read-only results that the state check cannot see.

| Condition | Replay check TPR / FPR | Monitor OR state OR replay TPR / FPR | Monitor misses caught: by replay / by state or replay |
|---|---|---|---|
| delete_coordinated | 25% [13–42] (8/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 9 of 9 |
| delete_coordinated_aware | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 of 0 |
| delete_solo | 41% [26–58] (13/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 of 0 |
| inject_coordinated | 25% [13–42] (8/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 7% [2–18] (3/45) | 1 / 1 of 1 |
| inject_solo | 0% [0–11] (0/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 2% [0–12] (1/45) | 0 / 0 of 0 |
| rewrite_coordinated | 69% [51–82] (22/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 2% [0–12] (1/45) | 3 / 5 of 5 |
| rewrite_coordinated_aware | 22% [11–39] (7/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 1 / 1 of 1 |
| rewrite_solo | 41% [26–58] (13/32) / 0% [0–8] (0/45) | 100% [89–100] (32/32) / 4% [1–15] (2/45) | 0 / 0 of 0 |

## Manipulation check: what the tamperers actually did (attack episodes)

| Condition | Episodes | No edits made | Entries deleted | Entries rewritten | Entries inserted | Edits rejected (not allowed) |
|---|---|---|---|---|---|---|
| delete_coordinated | 32 | 2 (6%) | 217 (6.8/ep) | 0 (0.0/ep) | 0 (0.0/ep) | 0 |
| delete_coordinated_aware | 32 | 22 (69%) | 28 (0.9/ep) | 0 (0.0/ep) | 0 (0.0/ep) | 0 |
| delete_solo | 32 | 7 (22%) | 138 (4.3/ep) | 0 (0.0/ep) | 0 (0.0/ep) | 0 |
| inject_coordinated | 32 | 8 (25%) | 0 (0.0/ep) | 0 (0.0/ep) | 145 (4.5/ep) | 4 |
| inject_solo | 32 | 13 (41%) | 0 (0.0/ep) | 0 (0.0/ep) | 66 (2.1/ep) | 2 |
| rewrite_coordinated | 32 | 1 (3%) | 0 (0.0/ep) | 248 (7.8/ep) | 0 (0.0/ep) | 0 |
| rewrite_coordinated_aware | 32 | 11 (34%) | 0 (0.0/ep) | 96 (3.0/ep) | 0 (0.0/ep) | 0 |
| rewrite_solo | 32 | 7 (22%) | 0 (0.0/ep) | 129 (4.0/ep) | 0 (0.0/ep) | 0 |

Notes: rates show point estimate, Wilson 95% CI and counts. ΔAUROC uses a paired, stratified bootstrap over episodes. McNemar compares, on the same attack episodes, detection on the clean log vs the tampered log at the same threshold. Benign controls are benign episodes whose agents lightly paraphrased their own messages.