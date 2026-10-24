
"""Evaluate the unchanged baseline on synthetic failure-mode scenarios."""

import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENTS_FILE = PROJECT_ROOT / "data" / "failure_modes" / "events.jsonl"
GROUND_TRUTH_FILE = (
    PROJECT_ROOT / "data" / "failure_modes" / "ground_truth.json"
)
OUTPUT_FILE = (
    PROJECT_ROOT / "results" / "failure_modes" / "failure_mode_findings.json"
)

sys.path.insert(
    0, str(PROJECT_ROOT / "src" / "investigation")
)

from baseline_investigator import investigate_scenario


def load_jsonl(path):
    """Load JSON Lines and reject malformed records or duplicate event IDs."""
    events = []

    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path}, line {line_number}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Expected a JSON object at line {line_number}"
                )

            events.append(event)

    required_fields = {
        "event_id", "timestamp", "scenario_id",
        "event_type", "action", "status",
    }

    for index, event in enumerate(events, start=1):
        missing = required_fields - event.keys()
        if missing:
            raise ValueError(
                f"Event record {index} is missing fields: {sorted(missing)}"
            )

    event_ids = [event["event_id"] for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Duplicate event IDs detected.")

    return events


def main():
    events = load_jsonl(EVENTS_FILE)

    with GROUND_TRUTH_FILE.open(encoding="utf-8") as file:
        labels = json.load(file)

    if not isinstance(labels, list) or not labels:
        raise ValueError("Ground truth must be a non-empty JSON list.")

    scenario_labels = [item["scenario_id"] for item in labels]
    if len(scenario_labels) != len(set(scenario_labels)):
        raise ValueError("Duplicate scenario labels detected.")

    events_by_scenario = defaultdict(list)
    for event in events:
        events_by_scenario[event["scenario_id"]].append(event)

    if set(events_by_scenario) != set(scenario_labels):
        raise ValueError(
            "Event scenario IDs do not match ground-truth scenario IDs."
        )

    allowed_labels = {"benign", "suspicious", "inconclusive"}
    for item in labels:
        if item.get("expected_classification") not in allowed_labels:
            raise ValueError(
                f"Invalid expected classification for {item['scenario_id']}"
            )

    results = []

    print("FAILURE-MODE EVALUATION — ORIGINAL BASELINE UNCHANGED")
    print("-" * 75)

    for scenario_id in sorted(scenario_labels):
        expected = next(
            item["expected_classification"]
            for item in labels
            if item["scenario_id"] == scenario_id
        )

        finding = investigate_scenario(
            scenario_id,
            events_by_scenario[scenario_id],
        )

        predicted = finding["classification"]
        matched = predicted == expected

        results.append({
            "scenario_id": scenario_id,
            "expected_classification": expected,
            "predicted_classification": predicted,
            "matched_rule": finding.get("matched_rule"),
            "supporting_event_ids": finding.get(
                "supporting_event_ids", []
            ),
            "reasons": finding.get("reasons", []),
            "match": matched,
        })

        print(
            f"{scenario_id}: expected={expected}, "
            f"predicted={predicted}, "
            f"rule={finding.get('matched_rule')}, "
            f"{'MATCH' if matched else 'MISMATCH'}"
        )

    matches = sum(result["match"] for result in results)
    total = len(results)
    agreement = matches / total

    report = {
        "experiment": "synthetic baseline failure-mode diagnostic",
        "baseline_rules_modified": False,
        "event_count": len(events),
        "scenario_count": total,
        "matches": matches,
        "mismatches": total - matches,
        "scenario_level_agreement": agreement,
        "results": results,
        "limitations": [
            "All events are synthetic and manually constructed.",
            "Expected labels are provisional and not independently validated.",
            "The small diagnostic dataset is not representative of real cloud traffic.",
            "Scenario-level agreement is not a real-world accuracy estimate.",
        ],
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")

    print("-" * 75)
    print(f"Events: {len(events)}")
    print(f"Scenarios: {total}")
    print(f"Matches: {matches}/{total}")
    print(f"Mismatches: {total - matches}")
    print(f"Scenario-level agreement: {agreement:.3f}")
    print(f"Results saved to: {OUTPUT_FILE.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
