"""Build label-separated CloudTrail investigation cases."""

import hashlib
import json
import os
import subprocess
import zipfile

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SOURCE = ROOT / (
    "data/lab_evidence/cloudtrail/train_labeled_a.zip"
)

DEST = ROOT / (
    "data/lab_evidence/cloudtrail/development"
)

WINDOW_SECONDS = 1800


def read_records(path):
    """Read CloudTrail records from a dataset ZIP."""

    with zipfile.ZipFile(path) as archive:
        members = [
            member
            for member in archive.infolist()
            if member.filename.endswith(".json")
            and not member.is_dir()
        ]

        if (
            len(members) != 1
            or members[0].file_size > 250_000_000
        ):
            raise ValueError("Unexpected dataset structure")

        data = json.loads(archive.read(members[0]))

    records = data.get("Records")

    if not isinstance(records, list) or not records:
        raise ValueError("Expected nonempty Records list")

    return records


def normalize(record, index):
    """Extract evidence without exposing ground-truth labels."""

    for field in (
        "eventID", "eventTime", "eventSource", "eventName"
    ):
        if (
            not isinstance(record.get(field), str)
            or not record[field]
        ):
            raise ValueError(
                f"Record {index}: missing {field}"
            )

    timestamp = datetime.fromisoformat(
        record["eventTime"].replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        raise ValueError("Event timezone missing")

    timestamp = timestamp.astimezone(timezone.utc)

    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, dict) else {}

    actor = (
        identity.get("principalId")
        or identity.get("arn")
        or identity.get("userName")
        or f"unknown-record-{index}"
    )

    ip = str(record.get("sourceIPAddress") or "unknown-ip")

    request = record.get("requestParameters")
    request = request if isinstance(request, dict) else {}

    allowed_fields = (
        "bucketName", "roleName", "userName",
        "policyArn", "tableName", "name"
    )

    context = {
        key: str(request[key])[:160]
        for key in allowed_fields
        if isinstance(request.get(key), (str, int))
    }

    resources = record.get("resources")
    resources = resources if isinstance(resources, list) else []

    arns = [
        str(item["ARN"])[:180]
        for item in resources
        if isinstance(item, dict)
        and isinstance(item.get("ARN"), str)
    ][:5]

    event = {
        "event_id": f"CLOUD-DEV-EVT-{index:06d}",
        "source_event_id": record["eventID"],
        "source_record_index": index,
        "timestamp_utc": (
            timestamp.isoformat().replace("+00:00", "Z")
        ),
        "source_type": "cloud_audit_log",
        "event_source": record["eventSource"],
        "action": record["eventName"],
        "actor": str(actor),
        "source_ip": ip,
        "aws_region": str(
            record.get("awsRegion") or "unknown"
        ),
        "resources": arns,
        "request_context": context,
        "error_code": (
            record.get("errorCode")
            if isinstance(record.get("errorCode"), str)
            else None
        ),
    }

    case_key = (
        str(actor),
        ip,
        int(timestamp.timestamp() // WINDOW_SECONDS),
    )

    return event, case_key


def write_new_or_verify(path, objects):
    """Save protected evidence without overwriting differences."""

    content = "".join(
        json.dumps(item, sort_keys=True) + "\n"
        for item in objects
    ).encode("utf-8")

    if path.is_symlink():
        raise ValueError("Symbolic-link output refused")

    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(
                f"Existing output differs: {path}"
            )
    else:
        with path.open("xb") as file:
            file.write(content)

        path.chmod(0o600)

    return hashlib.sha256(content).hexdigest()


def main():
    """Create investigation cases and separate ground truth."""

    os.umask(0o077)

    output_names = (
        "cases.jsonl",
        "case_ground_truth.jsonl",
        "event_ground_truth.jsonl",
    )

    for name in output_names:
        relative = (DEST / name).relative_to(ROOT).as_posix()

        check = subprocess.run(
            ["git", "check-ignore", "-q", relative],
            cwd=ROOT,
            check=False,
        )

        if check.returncode != 0:
            raise ValueError(
                f"Output must be Git-ignored: {relative}"
            )

    records = read_records(SOURCE)

    cases = defaultdict(list)
    event_truth = []
    original_ids = []

    for index, record in enumerate(records, start=1):
        if type(record.get("should_sample")) is not bool:
            raise ValueError(
                f"Record {index}: invalid source label"
            )

        event, case_key = normalize(record, index)

        cases[case_key].append(event)
        original_ids.append(event["source_event_id"])

        event_truth.append({
            "event_id": event["event_id"],
            "attack_associated": record["should_sample"],
            "attack_name": (
                record.get("attack_name")
                if record["should_sample"]
                else None
            ),
        })

    truth_index = {
        item["event_id"]: item
        for item in event_truth
    }

    case_rows = []
    case_truth = []

    ordered_cases = sorted(
        cases.items(),
        key=lambda item: (
            item[0][2],
            item[0][0],
            item[0][1],
        ),
    )

    for case_key, grouped in ordered_cases:
        digest = hashlib.sha256(
            json.dumps(case_key).encode()
        ).hexdigest()[:16]

        case_id = "CLOUD-DEV-CASE-" + digest

        grouped.sort(
            key=lambda event: (
                event["timestamp_utc"],
                event["event_id"],
            )
        )

        labels = [
            truth_index[event["event_id"]]
            for event in grouped
        ]

        attack_count = sum(
            item["attack_associated"]
            for item in labels
        )

        benign_count = len(labels) - attack_count

        case_rows.append({
            "case_id": case_id,
            "events": grouped,
            "event_count": len(grouped),
            "correlation_method": "actor+source_ip+30min",
        })

        case_truth.append({
            "case_id": case_id,
            "attack_associated": attack_count > 0,
            "attack_event_count": attack_count,
            "benign_event_count": benign_count,
            "scenario_names": sorted({
                item["attack_name"]
                for item in labels
                if item["attack_name"]
            }),
        })

    if len({
        item["case_id"] for item in case_rows
    }) != len(case_rows):
        raise ValueError("Case ID collision")

    for case in case_rows:
        content = json.dumps(case)

        if (
            "should_sample" in content
            or "attack_name" in content
        ):
            raise ValueError(
                "Ground-truth leakage into AI evidence"
            )

    DEST.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    hashes = {
        "cases.jsonl": write_new_or_verify(
            DEST / "cases.jsonl", case_rows
        ),
        "case_ground_truth.jsonl": write_new_or_verify(
            DEST / "case_ground_truth.jsonl", case_truth
        ),
        "event_ground_truth.jsonl": write_new_or_verify(
            DEST / "event_ground_truth.jsonl", event_truth
        ),
    }

    print("CLOUDTRAIL DEVELOPMENT CASE BUILD PASSED")
    print("Events preserved:", len(records))

    print(
        "Repeated source event IDs:",
        len(original_ids) - len(set(original_ids)),
    )

    print("Correlated cases:", len(case_rows))

    print(
        "Cases containing attack-labeled events:",
        sum(
            item["attack_associated"]
            for item in case_truth
        ),
    )

    print(
        "Cases mixing attack and benign events:",
        sum(
            item["attack_event_count"] > 0
            and item["benign_event_count"] > 0
            for item in case_truth
        ),
    )

    print("No labels in AI case evidence: VERIFIED")

    for name, digest in hashes.items():
        print(name, "SHA-256:", digest)


if __name__ == "__main__":
    main()
