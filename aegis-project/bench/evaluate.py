"""Evaluation harness.

Run: python bench/evaluate.py [--out bench/report.md]

Produces the numbers in README.md. Everything here scores through
`aegis.detect.engine.scan_text` - the same function the proxy calls - so the
reported figures describe the shipped detector, not a parallel implementation
that can drift.

## What is measured and why

accuracy            Reported once, then set aside. On a 27%-prevalence corpus
                    it is dominated by the majority class and tells you almost
                    nothing. It is included because its absence looks evasive.

precision / recall  The real pair. Recall is what an attacker defeats;
                    precision is what gets the firewall uninstalled.

FPR                 Reported separately from precision because precision moves
                    with prevalence and FPR does not. When you deploy, your
                    prevalence will not be the corpus's prevalence.

Wilson intervals    With 104 attack samples, a point estimate of "94.2% recall"
                    has a 95% interval roughly ±4.5 points wide. Quoting the
                    point estimate alone overstates what this corpus can
                    support. Wilson rather than normal-approximation because
                    the latter is badly behaved near 0 and 1, which is exactly
                    where these rates live.

base-rate analysis  The section that matters most and is almost always missing.
                    See `base_rate_table`.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from aegis.detect.engine import scan_text
from aegis.detect.types import Channel

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"


@dataclass
class Scored:
    id: str
    label: int
    channel: str
    family: str
    technique: str
    score: float
    threshold: float
    rules: list[str]
    elapsed_ms: float
    text: str


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------

def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation because these rates sit near the
    boundaries, where the normal interval can extend below 0 or above 1 and its
    coverage collapses.
    """
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def confusion(rows: list[Scored], threshold_override: float | None = None) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for r in rows:
        thr = threshold_override if threshold_override is not None else r.threshold
        predicted = r.score >= thr
        if r.label == 1 and predicted:
            tp += 1
        elif r.label == 1:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def rates(cm: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total = tp + fp + tn + fn
    return {
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "f1": f1,
        "accuracy": (tp + tn) / total if total else 0.0,
    }


def base_rate_table(recall: float, fpr: float) -> list[dict[str, float]]:
    """Positive predictive value as a function of real-world prevalence.

    This is the section a practitioner should read first, and it is the reason
    the headline precision number on any detection corpus is misleading.

    A detector with 94% recall and 1% false-positive rate sounds excellent. Run
    it against traffic where 1 request in 1000 is an attack and the arithmetic
    changes completely:

        PPV = (recall x prevalence) /
              (recall x prevalence + fpr x (1 - prevalence))

    At 0.1% prevalence that is roughly 8.6% - eleven of every twelve alerts are
    false. This is not a flaw in the detector; it is the base-rate fallacy, and
    it is why a firewall's *action* should scale with confidence rather than
    treating every threshold crossing as an incident. Aegis's FLAG band exists
    for exactly this reason.
    """
    out = []
    for prevalence in (0.5, 0.1, 0.05, 0.01, 0.001):
        num = recall * prevalence
        den = num + fpr * (1 - prevalence)
        ppv = num / den if den else 0.0
        out.append({
            "prevalence": prevalence,
            "ppv": ppv,
            "alerts_per_10k": (num + fpr * (1 - prevalence)) * 10_000,
            "true_alerts_per_10k": num * 10_000,
        })
    return out


def pr_curve(rows: list[Scored], steps: int = 101) -> list[dict[str, float]]:
    curve = []
    for i in range(steps):
        thr = i / (steps - 1)
        cm = confusion(rows, threshold_override=thr)
        r = rates(cm)
        curve.append({"threshold": thr, **r})
    return curve


def average_precision(curve: list[dict[str, float]]) -> float:
    """AP by the step-wise sum used for PR curves (no interpolation)."""
    pts = sorted(curve, key=lambda c: c["recall"])
    ap = 0.0
    prev_recall = 0.0
    for pt in pts:
        ap += (pt["recall"] - prev_recall) * pt["precision"]
        prev_recall = pt["recall"]
    return ap


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def load_corpus() -> list[dict]:
    rows: list[dict] = []
    for name in ("attacks.jsonl", "benign.jsonl"):
        path = CORPUS / name
        if not path.exists():
            raise SystemExit(f"missing {path} - run `python corpus/build_corpus.py` first")
        with path.open(encoding="utf-8") as fh:
            rows.extend(json.loads(line) for line in fh if line.strip())
    return rows


def score_corpus(rows: list[dict], repeats: int = 1) -> list[Scored]:
    scored: list[Scored] = []
    for row in rows:
        channel = Channel(row.get("channel", "user"))
        timings = []
        result = None
        for _ in range(repeats):
            started = time.perf_counter()
            result = scan_text(row["text"], channel)
            timings.append((time.perf_counter() - started) * 1000)
        assert result is not None
        scored.append(Scored(
            id=row["id"], label=row["label"], channel=row.get("channel", "user"),
            family=row.get("family", "?"), technique=row.get("technique", "plain"),
            score=result.score, threshold=result.threshold,
            rules=result.top_rules, elapsed_ms=statistics.median(timings),
            text=row["text"],
        ))
    return scored


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    s = sorted(values)

    def pct(p: float) -> float:
        idx = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
        return s[idx]

    return {
        "mean": statistics.fmean(s), "p50": pct(50), "p90": pct(90),
        "p95": pct(95), "p99": pct(99), "max": s[-1],
    }


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def build_report(scored: list[Scored]) -> str:
    cm = confusion(scored)
    r = rates(cm)
    attacks = [s for s in scored if s.label == 1]
    benign = [s for s in scored if s.label == 0]

    rec_lo, rec_hi = wilson(cm["tp"], cm["tp"] + cm["fn"])
    fpr_lo, fpr_hi = wilson(cm["fp"], cm["fp"] + cm["tn"])
    prec_lo, prec_hi = wilson(cm["tp"], cm["tp"] + cm["fp"])

    lat = percentiles([s.elapsed_ms for s in scored])
    curve = pr_curve(scored)
    ap = average_precision(curve)

    lines: list[str] = []
    w = lines.append

    w("# Aegis evaluation report")
    w("")
    w(f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} · "
      f"{len(scored)} samples ({len(attacks)} attack, {len(benign)} benign)")
    w("")
    w("Scored through `aegis.detect.engine.scan_text`, the same entry point the "
      "proxy uses. Thresholds are the per-channel production values unless a "
      "section says otherwise.")
    w("")

    w("## Headline")
    w("")
    w("| Metric | Value | 95% CI (Wilson) |")
    w("|---|---:|---|")
    w(f"| Recall (detection rate) | {r['recall']:.1%} | {rec_lo:.1%} – {rec_hi:.1%} |")
    w(f"| Precision | {r['precision']:.1%} | {prec_lo:.1%} – {prec_hi:.1%} |")
    w(f"| False-positive rate | {r['fpr']:.2%} | {fpr_lo:.2%} – {fpr_hi:.2%} |")
    w(f"| F1 | {r['f1']:.3f} | — |")
    w(f"| Average precision | {ap:.3f} | — |")
    w(f"| Accuracy | {r['accuracy']:.1%} | — |")
    w("")
    w(f"Confusion matrix: TP {cm['tp']} · FP {cm['fp']} · TN {cm['tn']} · FN {cm['fn']}")
    w("")
    w("Accuracy is listed last deliberately. At this corpus's prevalence it is "
      "the least informative number on the page.")
    w("")

    # -- latency ----------------------------------------------------------
    w("## Latency")
    w("")
    w("Per-scan wall time, median of repeated runs, single core.")
    w("")
    w("| p50 | p90 | p95 | p99 | max | mean |")
    w("|---:|---:|---:|---:|---:|---:|")
    w(f"| {lat['p50']:.3f} ms | {lat['p90']:.3f} ms | {lat['p95']:.3f} ms | "
      f"{lat['p99']:.3f} ms | {lat['max']:.3f} ms | {lat['mean']:.3f} ms |")
    w("")
    w("For context, a chat-completion round trip is 300–3000 ms. Detection "
      "overhead at p99 is well under one percent of that, which is the whole "
      "argument for doing this inline rather than asynchronously.")
    w("")

    # -- per family -------------------------------------------------------
    w("## Recall by attack family")
    w("")
    w("| Family | n | Detected | Recall | 95% CI |")
    w("|---|---:|---:|---:|---|")
    by_family: dict[str, list[Scored]] = defaultdict(list)
    for s in attacks:
        by_family[s.family].append(s)
    for fam in sorted(by_family, key=lambda f: -len(by_family[f])):
        rows_ = by_family[fam]
        hit = sum(1 for s in rows_ if s.score >= s.threshold)
        lo, hi = wilson(hit, len(rows_))
        w(f"| `{fam}` | {len(rows_)} | {hit} | {hit/len(rows_):.0%} | {lo:.0%} – {hi:.0%} |")
    w("")

    w("## False positives by benign family")
    w("")
    w("| Family | n | False positives | FPR |")
    w("|---|---:|---:|---:|")
    by_benign: dict[str, list[Scored]] = defaultdict(list)
    for s in benign:
        by_benign[s.family].append(s)
    for fam in sorted(by_benign, key=lambda f: -len(by_benign[f])):
        rows_ = by_benign[fam]
        fp = sum(1 for s in rows_ if s.score >= s.threshold)
        w(f"| `{fam}` | {len(rows_)} | {fp} | {fp/len(rows_):.1%} |")
    w("")
    w("`security_discussion` is the family that matters. Those are people "
      "talking *about* prompt injection - researchers, technical writers, "
      "support staff. A detector that cannot tell discussion from execution "
      "is a keyword blocklist, and it will be removed from production by "
      "whoever fields the complaints.")
    w("")

    # -- obfuscation ------------------------------------------------------
    w("## Recall by evasion technique")
    w("")
    w("| Technique | n | Detected | Recall |")
    w("|---|---:|---:|---:|")
    by_tech: dict[str, list[Scored]] = defaultdict(list)
    for s in attacks:
        by_tech[s.technique].append(s)
    for tech in sorted(by_tech, key=lambda t: -len(by_tech[t])):
        rows_ = by_tech[tech]
        hit = sum(1 for s in rows_ if s.score >= s.threshold)
        w(f"| `{tech}` | {len(rows_)} | {hit} | {hit/len(rows_):.0%} |")
    w("")

    # -- base rate ---------------------------------------------------------
    w("## Base-rate analysis")
    w("")
    w("Precision above is measured at this corpus's prevalence "
      f"({len(attacks)/len(scored):.0%}), which is nothing like production. "
      "Holding recall and FPR fixed and varying prevalence:")
    w("")
    w("| Attack prevalence | PPV (alert is real) | Alerts / 10k requests | True attacks / 10k |")
    w("|---:|---:|---:|---:|")
    for row in base_rate_table(r["recall"], r["fpr"]):
        w(f"| {row['prevalence']:.1%} | {row['ppv']:.1%} | "
          f"{row['alerts_per_10k']:.0f} | {row['true_alerts_per_10k']:.1f} |")
    w("")
    w("Read the bottom row. At a realistic 0.1% prevalence, most alerts are "
      "false even though the detector is working exactly as measured. Three "
      "consequences shape the design:")
    w("")
    w("1. The FLAG band exists so that near-threshold traffic is recorded "
      "rather than blocked. Blocking on every crossing would generate the "
      "alert volume implied by the table above.")
    w("2. Thresholds are per channel. Tool and document channels carry far "
      "higher prevalence than user chat, so the same FPR buys much better PPV "
      "there - which is precisely where the aggressive thresholds are set.")
    w("3. Any claim of the form 'our filter is 99% accurate' should be met "
      "with 'at what prevalence, and what is your PPV at mine?'")
    w("")

    # -- threshold sweep ---------------------------------------------------
    w("## Threshold sweep")
    w("")
    w("Single global threshold, ignoring per-channel policy, to show the "
      "shape of the trade-off.")
    w("")
    w("| Threshold | Precision | Recall | FPR | F1 |")
    w("|---:|---:|---:|---:|---:|")
    for thr in (0.2, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.72, 0.8, 0.9):
        cm_ = confusion(scored, threshold_override=thr)
        r_ = rates(cm_)
        w(f"| {thr:.2f} | {r_['precision']:.1%} | {r_['recall']:.1%} | "
          f"{r_['fpr']:.2%} | {r_['f1']:.3f} |")
    w("")

    # -- failures ----------------------------------------------------------
    misses = [s for s in attacks if s.score < s.threshold]
    w(f"## Missed attacks ({len(misses)})")
    w("")
    if not misses:
        w("None in this corpus. This is a statement about the corpus, not about "
          "the detector: every example here was written by the same person who "
          "wrote the rules, which is the single largest threat to the validity "
          "of these numbers. See Limitations.")
    else:
        w("| id | family | technique | score | threshold | text |")
        w("|---|---|---|---:|---:|---|")
        for s in sorted(misses, key=lambda s: s.score)[:25]:
            snippet = s.text[:70].replace("|", "\\|").replace("\n", " ")
            w(f"| `{s.id}` | {s.family} | {s.technique} | {s.score:.3f} | "
              f"{s.threshold:.2f} | {snippet}… |")
    w("")

    fps = [s for s in benign if s.score >= s.threshold]
    w(f"## False positives ({len(fps)})")
    w("")
    if not fps:
        w("None at production thresholds.")
    else:
        w("| id | family | score | threshold | rules | text |")
        w("|---|---|---:|---:|---|---|")
        for s in sorted(fps, key=lambda s: -s.score)[:25]:
            snippet = s.text[:60].replace("|", "\\|").replace("\n", " ")
            w(f"| `{s.id}` | {s.family} | {s.score:.3f} | {s.threshold:.2f} | "
              f"{', '.join(s.rules[:2])} | {snippet}… |")
    w("")

    # -- limitations --------------------------------------------------------
    w("## Limitations")
    w("")
    w("Stated in full because a benchmark without them is marketing.")
    w("")
    w("**The corpus and the rules share an author.** This is the dominant "
      "problem. Detection rates measured against attacks written by the person "
      "who wrote the detectors are an upper bound and should be read as "
      "'the rules do what their author intended', not 'the system stops "
      "attackers'. Cross-evaluation against an independently built set is the "
      "single highest-value next step.")
    w("")
    w("**No adaptive attacker.** Every measurement here is against a static "
      "corpus. A real adversary reads `signatures.py` - it is open source - "
      "and paraphrases around it. Semantic rewording ('set aside your earlier "
      "guidance') defeats regex families entirely, and no amount of rule "
      "tuning fixes that; it needs a model-based detector.")
    w("")
    w("**Templated benign rows are correlated.** 200 of the benign samples "
      "come from a small template grammar, so the effective sample size is far "
      "below the nominal count and the FPR interval is optimistic.")
    w("")
    w("**English only.** Every rule is English. A non-English injection passes "
      "the signature layer untouched; only the structural detectors would fire.")
    w("")
    w("**Prevalence is assumed, not measured.** The base-rate table uses "
      "plausible figures. Real prevalence is deployment-specific and should be "
      "measured from the FLAG band before thresholds are tuned.")
    w("")
    w("**Canary detection is not represented here.** It operates on responses, "
      "not prompts, and its precision is definitionally 100% - the token exists "
      "nowhere else. Including it would inflate these numbers without meaning.")
    w("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "bench" / "report.md"))
    ap.add_argument("--repeats", type=int, default=5,
                    help="timing repeats per sample (median is kept)")
    ap.add_argument("--json", default=str(ROOT / "bench" / "results.json"))
    args = ap.parse_args()

    rows = load_corpus()
    print(f"scoring {len(rows)} samples x{args.repeats} ...")
    scored = score_corpus(rows, repeats=args.repeats)

    report = build_report(scored)
    Path(args.out).write_text(report, encoding="utf-8")

    cm = confusion(scored)
    r = rates(cm)
    Path(args.json).write_text(json.dumps({
        "confusion": cm,
        "rates": r,
        "latency": percentiles([s.elapsed_ms for s in scored]),
        "base_rate": base_rate_table(r["recall"], r["fpr"]),
        "pr_curve": pr_curve(scored),
        "per_sample": [
            {"id": s.id, "label": s.label, "score": round(s.score, 4),
             "threshold": s.threshold, "family": s.family,
             "technique": s.technique, "rules": s.rules}
            for s in scored
        ],
    }, indent=2), encoding="utf-8")

    print(f"\nrecall    {r['recall']:.1%}")
    print(f"precision {r['precision']:.1%}")
    print(f"FPR       {r['fpr']:.2%}")
    print(f"F1        {r['f1']:.3f}")
    print(f"\nreport -> {args.out}")
    print(f"json   -> {args.json}")


if __name__ == "__main__":
    main()
