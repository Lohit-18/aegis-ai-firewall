"""Threshold calibration.

Run: python bench/calibrate.py [--target-fpr 0.01]

## Why this script exists

The first version of Aegis had hand-picked thresholds - 0.72 for the user
channel, 0.35 for tool and document - chosen because they felt about right.
The evaluation then reported 55.8% recall, and inspection showed why: almost
every miss scored between 0.62 and 0.70, just under a threshold that had been
set higher than any single rule could reach. The thresholds and the rule
weights had been chosen independently, and they disagreed.

Guessing a threshold is the most common unforced error in detection
engineering. The number is not a matter of taste. It is determined by the
question "how much benign traffic am I willing to block?", which is an
operational decision someone can actually answer - and once answered, it fixes
the threshold arithmetically.

So: pick a target false-positive rate per channel, then read the threshold off
the benign score distribution as the (1 - target) quantile. Recall becomes an
*outcome* that is measured, not a target that is tuned toward, which is the
only way to avoid fitting the threshold to the attack set.

## Reading the output

The script prints the chosen threshold, the FPR actually achieved, and the
recall that results. If recall at an acceptable FPR is poor, the answer is
better rules - not a lower threshold.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from aegis.detect.engine import scan_text
from aegis.detect.types import Channel

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

# Different channels justify different appetites. Blocking 1% of user chat is
# a support burden; blocking 5% of retrieved documents is usually invisible,
# because the pipeline can fall back to not using that chunk.
DEFAULT_TARGETS = {
    Channel.USER: 0.010,
    Channel.DOCUMENT: 0.050,
    Channel.TOOL: 0.050,
}


def load() -> list[dict]:
    rows: list[dict] = []
    for name in ("attacks.jsonl", "benign.jsonl"):
        path = CORPUS / name
        if not path.exists():
            raise SystemExit(f"missing {path} - run `python corpus/build_corpus.py`")
        with path.open(encoding="utf-8") as fh:
            rows.extend(json.loads(line) for line in fh if line.strip())
    return rows


def evidence_floor() -> float:
    """Lowest threshold that still honours the minimum-evidence policy.

    The policy: *no single LOW-severity signal may block on its own.*

    A note on why it is LOW and not LOW-plus-MEDIUM, because the first attempt
    got this wrong. Severity and weight measure different things: severity is
    how damaging the attack would be if the signal is right, weight is how
    confident the rule is that it is right. A rule can be highly confident
    about a low-impact behaviour, or barely confident about a catastrophic one.
    Deriving a *confidence* floor from a *severity* label conflated the two and
    produced a floor of 0.62 - high enough to suppress genuine detections.

    LOW severity is the one band where the two do line up: those rules describe
    behaviour that is merely unusual (encoded output requested, heavy newline
    padding, a large base64 blob). Unusual alone is a reason to record and
    watch, never a reason to reject a customer's request.

    Derived from the rule table rather than typed in, so adding a LOW rule with
    a higher weight moves the floor automatically and cannot silently weaken
    the guarantee.

    It matters here because the benign side of this corpus is unusually clean -
    most benign samples score exactly zero - which pulls the quantile-derived
    threshold down to around 0.23. That number is right for this corpus and
    wrong for production, where ordinary traffic carries more low-level noise.
    """
    from aegis.detect.signatures import RULES
    from aegis.detect.types import Severity

    soft = [r.weight for r in RULES if r.severity is Severity.LOW]
    return round(max(soft, default=0.0) + 0.02, 3)


def quantile(values: list[float], q: float) -> float:
    """Upper quantile with linear interpolation."""
    if not values:
        return 1.0
    s = sorted(values)
    if q <= 0:
        return s[0]
    if q >= 1:
        return s[-1]
    pos = q * (len(s) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    frac = pos - lo
    return s[lo] * (1 - frac) + s[hi] * frac


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-fpr", type=float, default=None,
                    help="override the per-channel defaults with one value")
    ap.add_argument("--epsilon", type=float, default=0.005,
                    help="added to the quantile so the threshold sits strictly "
                         "above the highest tolerated benign score")
    args = ap.parse_args()

    rows = load()
    scores: dict[Channel, dict[int, list[float]]] = defaultdict(lambda: {0: [], 1: []})

    for row in rows:
        channel = Channel(row.get("channel", "user"))
        result = scan_text(row["text"], channel)
        scores[channel][row["label"]].append(result.score)

    floor = evidence_floor()
    print(f"minimum-evidence floor: {floor:.3f} "
          f"(no single LOW-severity signal may block alone)\n")

    print(f"{'channel':<10} {'target':>8} {'quantile':>9} {'chosen':>8} "
          f"{'FPR':>8} {'recall':>8}  {'n_ben':>6} {'n_atk':>6}")
    print("-" * 74)

    chosen: dict[str, float] = {}
    for channel in (Channel.USER, Channel.TOOL, Channel.DOCUMENT):
        benign = scores[channel][0]
        attacks = scores[channel][1]
        if not benign:
            continue

        target = args.target_fpr if args.target_fpr is not None else DEFAULT_TARGETS[channel]
        q_thr = min(0.99, quantile(benign, 1.0 - target) + args.epsilon)
        thr = round(max(q_thr, floor), 3)

        fpr = sum(1 for s in benign if s >= thr) / len(benign)
        recall = (sum(1 for s in attacks if s >= thr) / len(attacks)) if attacks else float("nan")

        chosen[channel.value] = thr
        print(f"{channel.value:<10} {target:>7.1%} {q_thr:>9.3f} {thr:>8.3f} "
              f"{fpr:>7.2%} {recall:>7.1%}  {len(benign):>6} {len(attacks):>6}")

    print()
    print("Where 'chosen' exceeds 'quantile', the floor is binding: this corpus "
          "would tolerate a lower threshold, but the minimum-evidence policy "
          "forbids it.")

    print()
    print("Apply by setting these in .env:")
    for name, thr in chosen.items():
        print(f"  AEGIS_THRESHOLD_{name.upper()}={thr}")
    print()
    print("Note: these thresholds are fitted to this corpus. Refit on traffic "
          "from your own deployment before trusting them - the benign score "
          "distribution is what moves between environments, and it is the only "
          "input this calculation has.")

    out = ROOT / "bench" / "thresholds.json"
    out.write_text(json.dumps(chosen, indent=2), encoding="utf-8")
    print(f"\nwritten -> {out}")


if __name__ == "__main__":
    main()
