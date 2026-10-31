"""Generate synthetic security events for Experiment 005."""

import json
from pathlib import Path

OUTPUT = Path("data/holdout/events.jsonl")
events = []


def add_scenario(scenario_id, rows):
    """Convert scenario activities into cloud-audit-style events."""
    hour = 8 + int(scenario_id.split("-")[1])

    for number, row in enumerate(rows, start=1):
        minute, action, actor, mfa, status, resource, ip = row

        event = {
            "event_id": f"{scenario_id}-EVT-{number:02d}",
            "timestamp": f"2026-10-30T{hour:02d}:{minute:02d}:00Z",
            "scenario_id": scenario_id,
            "event_type": action,
            "action": action,
            "status": status,
            "actor": actor,
            "mfa_used": mfa,
            "resource": resource,
        }

        if ip:
            event["source_ip"] = ip

        events.append(event)


# HLD-001: Normal login and resource access.
add_scenario("HLD-001", [
    (1, "ConsoleLogin", "alice", True, "Success", "console", None),
    (2, "ListResources", "alice", True, "Success", "resources", None),
])

# HLD-002: Same actor performs three sensitive actions.
# Records are deliberately stored in reverse timestamp order.
add_scenario("HLD-002", [
    (3, "AttachAdminPolicy", "bob", False, "Success", "admin-policy", None),
    (2, "CreateAccessKey", "bob", False, "Success", "access-key", None),
    (1, "ConsoleLogin", "bob", False, "Success", "console", None),
])

# HLD-003: Three different actors.
add_scenario("HLD-003", [
    (1, "ConsoleLogin", "charlie", False, "Success", "console", None),
    (2, "CreateAccessKey", "david", False, "Success", "access-key", None),
    (3, "AttachAdminPolicy", "emma", False, "Success", "admin-policy", None),
])

# HLD-004: Denied privilege change.
add_scenario("HLD-004", [
    (1, "ConsoleLogin", "frank", True, "Success", "console", None),
    (2, "AttachAdminPolicy", "frank", True, "Denied", "admin-policy", None),
])

# HLD-005: MFA-protected login followed by successful privilege change.
add_scenario("HLD-005", [
    (1, "ConsoleLogin", "grace", True, "Success", "console", None),
    (2, "ListResources", "grace", True, "Success", "resources", None),
    (3, "AttachAdminPolicy", "grace", True, "Success", "admin-policy", None),
])

# HLD-006: Login without MFA, with insufficient other evidence.
add_scenario("HLD-006", [
    (1, "ConsoleLogin", "henry", False, "Success", "console", None),
])

# HLD-007: Expected backup workflow.
add_scenario("HLD-007", [
    (1, "AssumeRole", "backup-role", True, "Success", "backup-role", None),
    (2, "BackupStart", "backup-role", True, "Success", "backup-vault", None),
])

# HLD-008: Longer sequence of read-only activity.
add_scenario("HLD-008", [
    (1, "ConsoleLogin", "irene", True, "Success", "console", None),
    (2, "ListResources", "irene", True, "Success", "resources", None),
    (3, "ListResources", "irene", True, "Success", "storage", None),
    (4, "ListResources", "irene", True, "Success", "compute", None),
])

# HLD-009: Privilege change without surrounding context.
add_scenario("HLD-009", [
    (1, "AttachAdminPolicy", "jack", False, "Success", "admin-policy", None),
])

# HLD-010: Different actors sharing the same source IP.
shared_ip = "198.51.100.50"
add_scenario("HLD-010", [
    (1, "ConsoleLogin", "kate", False, "Success", "console", shared_ip),
    (2, "CreateAccessKey", "leo", False, "Success", "access-key", shared_ip),
    (3, "AttachAdminPolicy", "maya", False, "Success", "admin-policy", shared_ip),
])

# Validate before writing.
ids = [event["event_id"] for event in events]
assert len(ids) == len(set(ids)), "Duplicate event IDs detected"
assert len(set(event["scenario_id"] for event in events)) == 10

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

if OUTPUT.exists():
    raise SystemExit("Holdout dataset already exists; refusing to overwrite.")

with OUTPUT.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

print("Holdout dataset generated successfully.")
print(f"Events: {len(events)}")
print(f"Scenarios: {len(set(e['scenario_id'] for e in events))}")
print(f"Output: {OUTPUT}")
