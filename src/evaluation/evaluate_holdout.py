"""Compare Baseline V1 and V2 on frozen synthetic holdout scenarios."""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EVENTS_FILE = ROOT / "data/holdout/events.jsonl"
LABELS_FILE = ROOT / "data/holdout/ground_truth.json"
OUTPUT_FILE = ROOT / "results/holdout/holdout_findings.json"

sys.path.insert(0, str(ROOT / "src/investigation"))

from baseline_investigator import investigate_scenario as investigate_v1
from baseline_v2 import investigate_scenario as investigate_v2


def load_events(path):
    """Read security events and reject duplicate event IDs."""
    events = []
    seen_ids = set()

    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            event = json.loads(line)

            event_id = event["event_id"]

            if event_id in seen_ids:
                raise ValueError(
                    f"Duplicate event ID at line {line_number}: {event_id}"
                )

            seen_ids.add(event_id)
            events.append(event)

    return events


def load_labels(path):
    """Read expected classifications and reject duplicate scenarios."""
    labels = json.loads(path.read_text(encoding="utf-8"))

    expected = {}

    for item in labels:
        scenario_id = item["scenario_id"]

        if scenario_id in expected:
            raise ValueError(f"Duplicate label: {scenario_id}")

        expected[scenario_id] = item["expected_classification"]

    return expected


def evaluate(investigator, grouped_events, expected):
    """Run one investigator against every scenario."""
    findings = []
    correct = 0

    for scenario_id in sorted(expected):
        result = investigator(
            scenario_id,
            grouped_events[scenario_id]
        )

        predicted = result["classification"]
        actual = expected[scenario_id]
        match = predicted == actual

        if match:
            correct += 1

        findings.append({
            "scenario_id": scenario_id,
            "expected": actual,
            "predicted": predicted,
            "match": match,
            "matched_rule": result.get("matched_rule"),
            "supporting_event_ids": result.get(
                "supporting_event_ids", []
            ),
            "reasons": result.get("reasons", []),
            "limitations": result.get("limitations", []),
            "full_finding": result,
        })

    return {
        "correct": correct,
        "total": len(expected),
        "agreement": correct / len(expected),
        "findings": findings,
    }


def main():
    events = load_events(EVENTS_FILE)
    expected = load_labels(LABELS_FILE)

    grouped = defaultdict(list)

    for event in events:
        grouped[event["scenario_id"]].append(event)

    if set(grouped) != set(expected):
        raise ValueError(
            "Event scenarios and expected-label scenarios do not match."
        )

    v1 = evaluate(investigate_v1, grouped, expected)
    v2 = evaluate(investigate_v2, grouped, expected)

    report = {
        "experiment": "Experiment 005",
        "dataset": "Frozen synthetic holdout",
        "events": len(events),
        "scenarios": len(expected),
        "baseline_v1": v1,
        "baseline_v2": v2,
        "limitations": [
            "Synthetic manually authored scenarios.",
            "Provisional labels without independent review.",
            "Not an externally independent benchmark.",
            "Classification agreement does not establish real-world accuracy.",
            "No AI-assisted system evaluated.",
        ],
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("EXPERIMENT 005 — HOLDOUT EVALUATION")
    print(f"Events: {len(events)}")
    print(f"Scenarios: {len(expected)}")

    for name, result in [
        ("Baseline V1", v1),
        ("Baseline V2", v2),
    ]:
        print(
            f"\n{name}: "
            f"{result['correct']}/{result['total']} "
            f"({result['agreement']:.1%})"
        )

        for finding in result["findings"]:
            status = "MATCH" if finding["match"] else "MISMATCH"

            print(
                f"  {finding['scenario_id']}: "
                f"{finding['predicted']} "
                f"(expected {finding['expected']}) "
                f"[{status}]"
            )

    print(f"\nReport saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
