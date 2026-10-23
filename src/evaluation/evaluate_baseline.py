
"""Evaluate baseline scenario classifications against pilot ground truth.

Uses only Python's standard library. Metrics are descriptive for this
small synthetic pilot and must not be interpreted as general performance.
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FINDINGS_FILE = PROJECT_ROOT / "results" / "baseline_findings.json"
LABELS_FILE = PROJECT_ROOT / "data" / "ground_truth" / "incident_labels.json"

CLASSES = ("benign", "suspicious")


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_metrics(truth, predictions):
    """Calculate accuracy and per-class precision, recall, and F1."""
    if not truth:
        raise ValueError("Cannot evaluate an empty dataset.")

    correct = sum(
        truth[scenario_id] == predictions[scenario_id]
        for scenario_id in truth
    )
    accuracy = correct / len(truth)

    per_class = {}
    for label in CLASSES:
        true_positive = sum(
            truth[sid] == label and predictions[sid] == label
            for sid in truth
        )
        false_positive = sum(
            truth[sid] != label and predictions[sid] == label
            for sid in truth
        )
        false_negative = sum(
            truth[sid] == label and predictions[sid] != label
            for sid in truth
        )

        precision_denominator = true_positive + false_positive
        recall_denominator = true_positive + false_negative

        precision = (
            true_positive / precision_denominator
            if precision_denominator else 0.0
        )
        recall = (
            true_positive / recall_denominator
            if recall_denominator else 0.0
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )

        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": sum(value == label for value in truth.values()),
        }

    return accuracy, correct, per_class


def main():
    findings = load_json(FINDINGS_FILE)
    labels = load_json(LABELS_FILE)

    truth = {
        item["scenario_id"]: item["expected_classification"]
        for item in labels
    }
    predictions = {
        item["scenario_id"]: item["classification"]
        for item in findings
    }

    if len(truth) != len(labels):
        raise ValueError("Duplicate scenario IDs in ground-truth labels.")
    if len(predictions) != len(findings):
        raise ValueError("Duplicate scenario IDs in baseline findings.")

    missing_predictions = set(truth) - set(predictions)
    unexpected_predictions = set(predictions) - set(truth)

    if missing_predictions or unexpected_predictions:
        raise ValueError(
            f"Scenario mismatch. Missing predictions: "
            f"{sorted(missing_predictions)}; unexpected predictions: "
            f"{sorted(unexpected_predictions)}"
        )

    unsupported_classes = set(predictions.values()) - set(CLASSES)
    unsupported_truth = set(truth.values()) - set(CLASSES)
    if unsupported_classes or unsupported_truth:
        raise ValueError(
            "Unexpected classification labels. "
            f"Predictions: {sorted(unsupported_classes)}; "
            f"ground truth: {sorted(unsupported_truth)}"
        )

    accuracy, correct, metrics = calculate_metrics(truth, predictions)

    print("BASELINE EVALUATION")
    print("===================")
    print(f"Scenarios evaluated: {len(truth)}")
    print(f"Correct classifications: {correct}/{len(truth)}")
    print(f"Accuracy: {accuracy:.3f} ({accuracy * 100:.1f}%)")

    print("\nPer-class metrics")
    print("-----------------")
    print(f"{'Class':<12}{'Precision':>12}{'Recall':>10}{'F1':>10}{'Support':>10}")
    for label, values in metrics.items():
        print(
            f"{label:<12}"
            f"{values['precision']:>12.3f}"
            f"{values['recall']:>10.3f}"
            f"{values['f1']:>10.3f}"
            f"{values['support']:>10}"
        )

    print("\nScenario comparison")
    print("-------------------")
    for scenario_id in sorted(truth):
        match = truth[scenario_id] == predictions[scenario_id]
        result = "MATCH" if match else "MISMATCH"
        print(
            f"{scenario_id}: expected={truth[scenario_id]}, "
            f"predicted={predictions[scenario_id]} [{result}]"
        )

    print("\nInterpretation limits")
    print("---------------------")
    print("- This is a three-scenario synthetic pilot.")
    print("- Rules were designed around these pilot scenarios.")
    print("- Results do not establish performance on unseen incidents.")
    print("- Accuracy does not measure evidence quality or analyst efficiency.")
    print("- No AI-assisted comparison has been conducted.")


if __name__ == "__main__":
    main()
