
"""Baseline V2: identity-aware synthetic cloud event investigation.

This is a deterministic rules-based investigator, not an AI model.
V1 remains unchanged for reproducible comparison.
"""

from datetime import datetime


def parse_timestamp(event):
    """Convert an ISO 8601 event timestamp into a datetime."""
    return datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )


def prepare_events(events):
    """Return events sorted chronologically without modifying input."""
    return sorted(events, key=parse_timestamp)


def get_actor(event):
    """Return an explicit actor identity, if provided."""
    actor = event.get("actor")

    if isinstance(actor, str) and actor.strip():
        return actor.strip()

    return None



def detect_correlated_access_pattern(events):
    """Detect a suspicious three-action pattern for one explicit actor."""
    ordered_events = prepare_events(events)

    actors = sorted({
        get_actor(event)
        for event in ordered_events
        if get_actor(event) is not None
    })

    for actor in actors:
        actor_events = [
            event for event in ordered_events
            if get_actor(event) == actor
            and event["status"] == "Success"
        ]

        login = next((
            event for event in actor_events
            if event["event_type"] == "ConsoleLogin"
            and event.get("mfa_used") is False
        ), None)

        if login is None:
            continue

        key = next((
            event for event in actor_events
            if event["event_type"] == "CreateAccessKey"
            and parse_timestamp(event) >= parse_timestamp(login)
        ), None)

        if key is None:
            continue

        policy = next((
            event for event in actor_events
            if event["event_type"] == "AttachAdminPolicy"
            and parse_timestamp(event) >= parse_timestamp(key)
        ), None)

        if policy is None:
            continue

        return {
            "actor": actor,
            "matched_rule": "V2-RULE-001",
            "supporting_event_ids": [
                login["event_id"],
                key["event_id"],
                policy["event_id"],
            ],
        }

    return None

def detect_privilege_change(events):
    """Identify successful administrative policy attachments.

    This is a security-relevant observation, not proof of compromise.
    """
    ordered_events = prepare_events(events)

    matches = [
        event for event in ordered_events
        if event["event_type"] == "AttachAdminPolicy"
        and event["status"] == "Success"
    ]

    if not matches:
        return None

    return {
        "matched_rule": "V2-RULE-002",
        "observation": "Successful administrative policy attachment.",
        "supporting_event_ids": [
            event["event_id"] for event in matches
        ],
        "actors": sorted({
            get_actor(event)
            for event in matches
            if get_actor(event) is not None
        }),
        "requires_review": True,
    }


def detect_ip_associated_access_pattern(events):
    """Detect an ordered pattern associated with one source IP.

    A shared IP is not proof of shared actor identity.
    """
    ordered = prepare_events(events)

    # This fallback is only for events without explicit actors.
    # Never override explicit identity evidence.
    if any(get_actor(event) is not None for event in ordered):
        return None

    ips = sorted({
        event.get("source_ip")
        for event in ordered
        if isinstance(event.get("source_ip"), str)
        and event.get("source_ip").strip()
    })

    for ip in ips:
        matching = [
            event for event in ordered
            if event.get("source_ip") == ip
            and event["status"] == "Success"
        ]

        login = next((
            event for event in matching
            if event["event_type"] == "ConsoleLogin"
            and event.get("mfa_used") is False
        ), None)

        if login is None:
            continue

        key = next((
            event for event in matching
            if event["event_type"] == "CreateAccessKey"
            and parse_timestamp(event) >= parse_timestamp(login)
        ), None)

        if key is None:
            continue

        policy = next((
            event for event in matching
            if event["event_type"] == "AttachAdminPolicy"
            and parse_timestamp(event) >= parse_timestamp(key)
        ), None)

        if policy is None:
            continue

        return {
            "matched_rule": "V2-RULE-005",
            "source_ip": ip,
            "supporting_event_ids": [
                login["event_id"],
                key["event_id"],
                policy["event_id"],
            ],
            "correlation_basis": "source_ip",
            "identity_verified": False,
        }

    return None

def investigate_scenario(scenario_id, events):
    """Produce a scenario-level V2 investigation finding."""
    ordered = prepare_events(events)
    correlated = detect_correlated_access_pattern(ordered)
    privilege = detect_privilege_change(ordered)

    ip_pattern = detect_ip_associated_access_pattern(ordered)

    if ip_pattern:
        return {
            "scenario_id": scenario_id,
            "classification": "suspicious",
            "severity": "high",
            "matched_rule": ip_pattern["matched_rule"],
            "supporting_event_ids": ip_pattern["supporting_event_ids"],
            "reasons": [
                "An ordered login-without-MFA, access-key creation, "
                "and administrative policy attachment pattern "
                "was observed from the same source IP."
            ],
            "limitations": [
                "A shared source IP does not verify actor identity.",
                "The events do not establish malicious intent.",
                "Session continuity and authorization are unverified."
            ],
            "correlation_basis": "source_ip",
            "identity_verified": False,
        }


    if correlated:
        return {
            "scenario_id": scenario_id,
            "classification": "suspicious",
            "severity": "high",
            "matched_rule": correlated["matched_rule"],
            "supporting_event_ids": correlated["supporting_event_ids"],
            "reasons": [
                "One explicitly identified actor performed a "
                "successful login without MFA, access-key creation, "
                "and administrative policy attachment in sequence."
            ],
            "limitations": [
                "The pattern does not prove malicious intent.",
                "Session continuity has not been independently verified."
            ],
        }

    if privilege:
        policy_events = [
            event for event in ordered
            if event["event_id"] in privilege["supporting_event_ids"]
        ]

        related = any(
            other["status"] == "Success"
            and other["event_type"] in {
                "ConsoleLogin", "ListResources", "CreateAccessKey"
            }
            and get_actor(other) is not None
            and get_actor(other) == get_actor(policy_event)
            and other["event_id"] != policy_event["event_id"]
            for policy_event in policy_events
            for other in ordered
        )

        if related:
            return {
                "scenario_id": scenario_id,
                "classification": "suspicious",
                "severity": "medium",
                "matched_rule": "V2-RULE-002",
                "supporting_event_ids": [
                    event["event_id"] for event in ordered
                    if event["event_id"] in privilege["supporting_event_ids"]
                    or (
                        event["status"] == "Success"
                        and event["event_type"] in {
                            "ConsoleLogin", "ListResources", "CreateAccessKey"
                        }
                        and get_actor(event) in privilege["actors"]
                    )
                ],
                "reasons": [
                    "Successful administrative policy attachment "
                    "was observed alongside activity from the same actor."
                ],
                "limitations": [
                    "Related activity does not establish malicious intent.",
                    "Authorization and business context are unverified."
                ],
            }

        return {
            "scenario_id": scenario_id,
            "classification": "inconclusive",
            "severity": "undetermined",
            "matched_rule": "V2-RULE-002",
            "supporting_event_ids": privilege["supporting_event_ids"],
            "reasons": [
                "Administrative privilege change detected, but "
                "the available events do not establish a correlated incident."
            ],
            "limitations": [
                "Privilege changes require authorization review.",
                "Inconclusive does not mean benign."
            ],
        }

    benign = detect_known_benign_pattern(ordered)

    if benign:
        return {
            "scenario_id": scenario_id,
            "classification": "benign",
            "severity": "low",
            "matched_rule": benign["matched_rule"],
            "supporting_event_ids": benign["supporting_event_ids"],
            "reasons": [
                benign["reason"]
            ],
            "limitations": [
                "This classification applies only to a narrow "
                "synthetic pilot pattern.",
                "Real-world authorization and activity context "
                "have not been independently verified."
            ],
        }


    return {
        "scenario_id": scenario_id,
        "classification": "inconclusive",
        "severity": "undetermined",
        "matched_rule": None,
        "supporting_event_ids": [],
        "reasons": [
            "Insufficient evidence for a V2 suspicious classification."
        ],
        "limitations": [
            "Benign activity is not yet independently classified by V2.",
            "Analyst review may be required."
        ],
    }

def detect_known_benign_pattern(events):
    """Recognize narrowly defined benign synthetic pilot patterns.

    These rules do not establish that similar real-world activity is safe.
    """
    ordered = prepare_events(events)

    if not ordered:
        return None

    # Do not classify a scenario as benign when it contains
    # successful credential or administrative privilege changes.
    sensitive_types = {"CreateAccessKey", "AttachAdminPolicy"}

    if any(
        event["status"] == "Success"
        and event["event_type"] in sensitive_types
        for event in ordered
    ):
        return None

    successful = [
        event for event in ordered
        if event["status"] == "Success"
    ]

    event_types = [event["event_type"] for event in successful]

    # Narrow read-only pilot pattern.
    if (
        len(ordered) == 2
        and event_types == ["ConsoleLogin", "ListResources"]
        and ordered[0].get("mfa_used") is True
    ):
        return {
            "matched_rule": "V2-RULE-003",
            "supporting_event_ids": [
                event["event_id"] for event in ordered
            ],
            "reason": "MFA-protected login followed by read-only activity.",
        }

    # Narrow backup pilot pattern.
    if (
        len(ordered) == 2
        and event_types == ["AssumeRole", "BackupStart"]
        and ordered[0].get("mfa_used") is True
        and ordered[0].get("resource") == "backup-role"
        and ordered[1].get("resource") == "backup-vault"
    ):
        return {
            "matched_rule": "V2-RULE-004",
            "supporting_event_ids": [
                event["event_id"] for event in ordered
            ],
            "reason": "MFA-protected backup-role assumption followed by backup activity.",
        }

    return None
