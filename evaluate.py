#!/usr/bin/env python3
"""Detection benchmark for the SentinelAI fusion engine.

Runs the full pipeline over the labelled corpus and reports binary detection
metrics, per-class recall, a confusion matrix over threat types, and latency.

Run it with the LLM disabled (the default) to measure the deterministic floor —
the performance the product guarantees even with no API key, no quota and no
internet. Pass --with-llm to measure the ceiling.

    cd backend
    python scripts/evaluate.py
    python scripts/evaluate.py --with-llm --limit 100

Honest caveat, stated up front: this corpus is synthetic and generated from the
same scam grammar the rule engine targets, so these numbers measure internal
consistency, not field accuracy. Real-world validation needs a labelled I4C or
partner-bank feed. We report it because it is reproducible, not because it is
proof.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

DATASET = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "dataset", "scam_messages.json",
)

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def bar(value: float, width: int = 28) -> str:
    filled = int(round(value * width))
    return "█" * filled + "·" * (width - filled)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-llm", action="store_true",
                    help="include the Gemini reasoning layer (slow, needs a key)")
    ap.add_argument("--limit", type=int, default=0, help="evaluate only the first N")
    ap.add_argument("--threshold", type=int, default=35,
                    help="risk score at or above which a message is called a scam")
    ap.add_argument("--dataset", default=DATASET)
    args = ap.parse_args()

    if not args.with_llm:
        os.environ["GOOGLE_API_KEY"] = ""

    from app.services import detector
    from app.services.similarity import matcher

    matcher.build()

    with open(args.dataset, encoding="utf-8") as fh:
        data = json.load(fh)
    if args.limit:
        data = data[: args.limit]

    print(f"\n{BOLD}SentinelAI detection benchmark{RESET}")
    print(f"{DIM}corpus={len(data)}  threshold={args.threshold}  "
          f"llm={'on' if args.with_llm else 'off (deterministic floor)'}{RESET}\n")

    tp = fp = tn = fn = 0
    latencies: list[int] = []
    per_class: dict[str, list[int]] = defaultdict(list)
    confusion: Counter = Counter()
    scores_scam: list[int] = []
    scores_safe: list[int] = []
    llm_calls = 0

    for i, item in enumerate(data, 1):
        result = await detector.analyse(
            content=item["text"],
            channel=item.get("channel", "unknown"),
            sender=item.get("sender"),
            include_llm=args.with_llm,
        )
        score = result["risk_score"]
        predicted_scam = score >= args.threshold
        actual_scam = item["is_scam"]

        latencies.append(result["processing_ms"])
        llm_calls += 1 if result["llm_used"] else 0
        per_class[item["label"]].append(1 if predicted_scam == actual_scam else 0)
        confusion[(item["label"], result["threat_type"])] += 1
        (scores_scam if actual_scam else scores_safe).append(score)

        if actual_scam and predicted_scam:
            tp += 1
        elif actual_scam and not predicted_scam:
            fn += 1
        elif not actual_scam and predicted_scam:
            fp += 1
        else:
            tn += 1

        if args.with_llm and i % 20 == 0:
            print(f"{DIM}  … {i}/{len(data)}{RESET}")

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(data)
    fpr = fp / (fp + tn) if fp + tn else 0.0

    print(f"{BOLD}Binary detection (scam vs legitimate){RESET}")
    print(f"  Accuracy              {accuracy:.4f}   {bar(accuracy)}")
    print(f"  Precision             {precision:.4f}   {bar(precision)}")
    print(f"  Recall                {recall:.4f}   {bar(recall)}")
    print(f"  F1 score              {f1:.4f}   {bar(f1)}")
    print(f"  False positive rate   {fpr * 100:.2f}%")
    print(f"  TP {tp}   FP {fp}   TN {tn}   FN {fn}\n")

    print(f"{BOLD}Per-class detection rate{RESET}")
    for label in sorted(per_class, key=lambda k: -len(per_class[k])):
        vals = per_class[label]
        rate = sum(vals) / len(vals)
        marker = "  " if rate >= 0.98 else ("! " if rate >= 0.90 else "!!")
        print(f"  {marker}{label:<16} {rate:>6.1%}  n={len(vals):<4} {bar(rate, 20)}")

    print(f"\n{BOLD}Threat-type classification{RESET}")
    correct_label = sum(v for (a, p), v in confusion.items() if a == p)
    print(f"  Exact label match     {correct_label / len(data):.4f}")
    misses = [(a, p, v) for (a, p), v in confusion.items() if a != p and v >= 3]
    for actual, pred, count in sorted(misses, key=lambda x: -x[2])[:8]:
        print(f"  {DIM}{actual:>15} → {pred:<15} ×{count}{RESET}")

    print(f"\n{BOLD}Score separation{RESET}")
    if scores_scam and scores_safe:
        print(f"  Scam    mean {statistics.mean(scores_scam):5.1f}  "
              f"median {statistics.median(scores_scam):5.1f}  "
              f"min {min(scores_scam):3d}")
        print(f"  Legit   mean {statistics.mean(scores_safe):5.1f}  "
              f"median {statistics.median(scores_safe):5.1f}  "
              f"max {max(scores_safe):3d}")
        print(f"  Margin  {statistics.mean(scores_scam) - statistics.mean(scores_safe):.1f} points")

    print(f"\n{BOLD}Latency{RESET}")
    print(f"  mean {statistics.mean(latencies):.1f} ms   "
          f"median {statistics.median(latencies):.0f} ms   "
          f"p95 {sorted(latencies)[int(len(latencies) * 0.95)]} ms   "
          f"max {max(latencies)} ms")
    if args.with_llm:
        print(f"  Gemini responded on {llm_calls}/{len(data)} "
              f"({llm_calls / len(data):.0%}) — the rest degraded to rules")

    print(f"\n{DIM}Synthetic corpus. Measures internal consistency, not field "
          f"accuracy.{RESET}\n")
    return 0 if recall >= 0.95 and fpr <= 0.02 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
