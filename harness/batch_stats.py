"""
Aggregates results across multiple repetitions of the same exercise.

A single run tells you "it worked once." A workshop deliverable needs to
say something defensible about detection RATE - the same standard SADF
used for AI Village (N trials, not one anecdote). This module takes the
per-run summaries the harness already produces and turns them into a
detection-rate table: full-detection rate across N runs, mean/min/max
findings rate, and detection-time variance per engine.
"""
import statistics
from collections import defaultdict


def aggregate_runs(run_results: list[list[dict]]) -> None:
    """run_results: one list per repetition; each inner list is one
    repetition's harness `summary` output (one dict per use case)."""
    n_runs = len(run_results)
    buckets = defaultdict(lambda: defaultdict(list))   # [use_case][engine] -> [(detected, total), ...]
    timing = defaultdict(lambda: defaultdict(list))    # [use_case][engine] -> [detect_time, ...]

    for rep in run_results:
        for uc_result in rep:
            uc_name = uc_result["use_case"]
            for engine in ("scripted", "ai"):
                if engine in uc_result:
                    r = uc_result[engine]
                    buckets[uc_name][engine].append((r["detected"], r["total"]))
                    timing[uc_name][engine].append(r.get("detect_time", 0.0))

    print(f"\n{'=' * 70}\nAGGREGATE RESULTS ACROSS {n_runs} RUNS\n{'=' * 70}")
    for uc_name, engines in buckets.items():
        print(f"\n{uc_name}")
        for engine, pairs in engines.items():
            rates = [d / t if t else 0.0 for d, t in pairs]
            full_detect_runs = sum(1 for d, t in pairs if t > 0 and d == t)
            mean_rate = statistics.mean(rates) if rates else 0.0
            times = timing[uc_name][engine]

            print(f"  {engine}:")
            print(f"    full-detection runs: {full_detect_runs}/{n_runs} "
                  f"({full_detect_runs / n_runs * 100:.0f}%)")
            if rates:
                print(f"    mean findings rate:  {mean_rate * 100:.1f}% "
                      f"(min={min(rates) * 100:.0f}%, max={max(rates) * 100:.0f}%)")
            if times:
                stdev_str = f" stdev={statistics.stdev(times):.2f}s" if len(times) > 1 else ""
                print(f"    detection time:      mean={statistics.mean(times):.2f}s "
                      f"min={min(times):.2f}s max={max(times):.2f}s{stdev_str}")

    print(f"\n{'-' * 70}")
    print(f"Report this as: \"across {n_runs} independent runs, [engine] achieved full "
          f"detection in X/{n_runs} runs (Y%)\" - not a single-run anecdote.")
