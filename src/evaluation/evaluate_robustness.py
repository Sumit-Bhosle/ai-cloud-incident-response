
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src" / "investigation"),
)

from baseline_investigator import investigate_scenario


EVENT_FILES = [
    PROJECT_ROOT / "data" / "robustness" / "events.jsonl",
    PROJECT_ROOT / "data" / "robustness" / "additional_events.jsonl",
]

GROUND_TRUTH_FILE = (
    PROJECT_ROOT / "data" / "robustness" / "ground_truth.json"
)


def load_events():
    events = []

    for filename in EVENT_FILES:
        with filename.open(encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    events.append(json.loads(line))

    event_ids = [event["event_id"] for event in events]

    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Duplicate event IDs found.")

    return events


def main():
    events = load_events()

    with GROUND_TRUTH_FILE.open(encoding="utf-8") as file:
        labels = json.load(file)

    events_by_scenario = defaultdict(list)

    for event in events:
        events_by_scenario[event["scenario_id"]].append(event)

    truth_by_scenario = {
        item["scenario_id"]: item
        for item in labels
    }

    if set(events_by_scenario) != set(truth_by_scenario):
        raise ValueError(
            "Event scenario IDs and ground-truth scenario IDs differ."
        )

    matches = 0
    results = []

    print("ROBUSTNESS EVALUATION — ORIGINAL RULES UNCHANGED")
    print("-" * 65)

    for scenario_id in sorted(truth_by_scenario):
        expected = truth_by_scenario[scenario_id][
            "expected_classification"
        ]

        finding = investigate_scenario(
            scenario_id,
            events_by_scenario[scenario_id],
        )

        predicted = finding["classification"]
        rule_id = finding.get("matched_rule")
        matched = predicted == expected

        if matched:
            matches += 1

        results.append({
            "scenario_id": scenario_id,
            "expected_classification": expected,
            "predicted_classification": predicted,
            "rule_id": rule_id,
            "match": matched,
            "supporting_event_ids": finding.get(
                "supporting_event_ids", []
            ),
        })

        status = "MATCH" if matched else "MISMATCH"

        print(
            f"{scenario_id}: expected={expected}, "
            f"predicted={predicted}, rule={rule_id}, {status}"
        )

    accuracy = matches / len(results) if results else 0.0

    print("-" * 65)
    print(f"Events: {len(events)}")
    print(f"Scenarios evaluated: {len(results)}")
    print(f"Matches: {matches}/{len(results)}")
    print(f"Scenario-level agreement: {accuracy:.3f}")

    output_dir = PROJECT_ROOT / "results" / "robustness"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "robustness_findings.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "evaluation_type": "synthetic robustness diagnostic",
                "original_rules_changed": False,
                "event_count": len(events),
                "scenario_count": len(results),
                "matches": matches,
                "agreement": accuracy,
                "results": results,
                "limitations": [
                    "All data is synthetic.",
                    "The additional scenarios reuse patterns represented "
                    "in the original baseline rules.",
                    "This small diagnostic set does not establish "
                    "generalization to real cloud incidents.",
                ],
            },
            file,
            indent=2,
        )

    print(f"Results saved to: {output_file.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
