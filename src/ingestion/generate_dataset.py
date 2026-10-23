
import json
from pathlib import Path

# Find the root directory of this Git repository.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "data" / "raw"
GROUND_TRUTH_DIR = PROJECT_ROOT / "data" / "ground_truth"


def write_jsonl(path, records):
    """Write one JSON record per line."""
    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record) + "\n")


def main():
    # All records below are fictional and created for research testing.
    events = [
        {
            "event_id": "EVT-001",
            "timestamp": "2026-10-20T09:00:00Z",
            "scenario_id": "SCN-001",
            "event_type": "ConsoleLogin",
            "source_ip": "198.51.100.24",
            "mfa_used": True,
            "resource": "research-dashboard",
            "action": "LoginSuccess",
            "status": "Success",
            "description": "Successful console login with MFA."
        },
        {
            "event_id": "EVT-002",
            "timestamp": "2026-10-20T09:03:00Z",
            "scenario_id": "SCN-001",
            "event_type": "ListResources",
            "source_ip": "198.51.100.24",
            "mfa_used": True,
            "resource": "research-dashboard",
            "action": "ListResources",
            "status": "Success",
            "description": "Read-only inventory request after login."
        },
        {
            "event_id": "EVT-003",
            "timestamp": "2026-10-20T10:15:00Z",
            "scenario_id": "SCN-002",
            "event_type": "ConsoleLogin",
            "source_ip": "203.0.113.77",
            "mfa_used": False,
            "resource": "admin-console",
            "action": "LoginSuccess",
            "status": "Success",
            "description": "Successful login without MFA."
        },
        {
            "event_id": "EVT-004",
            "timestamp": "2026-10-20T10:18:00Z",
            "scenario_id": "SCN-002",
            "event_type": "CreateAccessKey",
            "source_ip": "203.0.113.77",
            "mfa_used": False,
            "resource": "user-demo",
            "action": "CreateAccessKey",
            "status": "Success",
            "description": "A new access key was created."
        },
        {
            "event_id": "EVT-005",
            "timestamp": "2026-10-20T10:21:00Z",
            "scenario_id": "SCN-002",
            "event_type": "AttachAdminPolicy",
            "source_ip": "203.0.113.77",
            "mfa_used": False,
            "resource": "user-demo",
            "action": "AttachAdminPolicy",
            "status": "Success",
            "description": "An administrative policy was attached."
        },
        {
            "event_id": "EVT-006",
            "timestamp": "2026-10-20T10:24:00Z",
            "scenario_id": "SCN-002",
            "event_type": "ReadSecret",
            "source_ip": "203.0.113.77",
            "mfa_used": False,
            "resource": "secret-demo",
            "action": "ReadSecret",
            "status": "Denied",
            "description": "Secret access was denied; retrieval did not succeed."
        },
        {
            "event_id": "EVT-007",
            "timestamp": "2026-10-20T11:00:00Z",
            "scenario_id": "SCN-003",
            "event_type": "AssumeRole",
            "source_ip": "192.0.2.45",
            "mfa_used": True,
            "resource": "backup-role",
            "action": "AssumeRole",
            "status": "Success",
            "description": "Approved backup role was assumed."
        },
        {
            "event_id": "EVT-008",
            "timestamp": "2026-10-20T11:05:00Z",
            "scenario_id": "SCN-003",
            "event_type": "BackupStart",
            "source_ip": "192.0.2.45",
            "mfa_used": True,
            "resource": "backup-vault",
            "action": "BackupStart",
            "status": "Success",
            "description": "Scheduled backup activity began."
        }
    ]

    # Labels are kept separately from raw event records.
    ground_truth = [
        {
            "scenario_id": "SCN-001",
            "expected_classification": "benign",
            "severity": "low",
            "expected_event_ids": ["EVT-001", "EVT-002"],
            "rationale": "MFA-protected login followed by read-only activity."
        },
        {
            "scenario_id": "SCN-002",
            "expected_classification": "suspicious",
            "severity": "high",
            "expected_event_ids": [
                "EVT-003", "EVT-004", "EVT-005", "EVT-006"
            ],
            "rationale": (
                "Login without MFA followed by access-key creation and "
                "administrative policy attachment. Secret access was denied."
            )
        },
        {
            "scenario_id": "SCN-003",
            "expected_classification": "benign",
            "severity": "low",
            "expected_event_ids": ["EVT-007", "EVT-008"],
            "rationale": "Approved backup role followed by scheduled backup activity."
        }
    ]

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    GROUND_TRUTH_DIR.mkdir(parents=True, exist_ok=True)

    write_jsonl(RAW_DIR / "cloud_audit_events.jsonl", events)

    with (GROUND_TRUTH_DIR / "incident_labels.json").open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(ground_truth, file, indent=2)
        file.write("\n")

    print(f"Generated {len(events)} synthetic events.")
    print(f"Generated {len(ground_truth)} ground-truth scenario labels.")
    print(f"Events: {RAW_DIR / 'cloud_audit_events.jsonl'}")
    print(f"Labels: {GROUND_TRUTH_DIR / 'incident_labels.json'}")
    print("Reminder: this is a small synthetic pilot dataset, not real telemetry.")


if __name__ == "__main__":
    main()
