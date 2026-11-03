"""Validate laboratory records using JSON Schema Draft 2020-12."""

import argparse
import re
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]

SCHEMAS = {
    "execution": ROOT / "schemas/lab_execution.schema.json",
    "ground_truth": ROOT / "schemas/ground_truth.schema.json",
    "event": ROOT / "schemas/normalized_event.schema.json",
}



UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|\+00:00)$"
)

def build_format_checker():
    """Enforce real UTC date-time values without optional dependencies."""

    checker = FormatChecker()

    @checker.checks("date-time")
    def is_valid_utc_timestamp(value):
        if not isinstance(value, str):
            return False

        if not UTC_TIMESTAMP.fullmatch(value):
            return False

        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return False

        return timestamp.utcoffset() == timedelta(0)

    return checker


def load_json(path):
    """Read a JSON document from disk."""
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def validate_record(record_type, record_path):
    """Check a record against its corresponding JSON Schema."""

    schema_path = SCHEMAS[record_type]

    schema = load_json(schema_path)
    record = load_json(record_path)

    # First, verify that our schema itself is valid.
    Draft202012Validator.check_schema(schema)

    # FormatChecker validates date-time formats.
    validator = Draft202012Validator(
        schema,
        format_checker=build_format_checker(),
    )

    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )

    if errors:
        print("VALIDATION FAILED")
        print(f"Record: {record_path}")
        print(f"Errors: {len(errors)}")

        for number, error in enumerate(errors, start=1):
            location = ".".join(
                str(part) for part in error.absolute_path
            ) or "<root>"

            print(f"{number}. Field: {location}")
            print(f"   Reason: {error.message}")

        return 1

    print("VALIDATION PASSED")
    print(f"Record type: {record_type}")
    print(f"Record: {record_path}")
    print("Schema rules satisfied.")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate a security laboratory JSON record."
    )

    parser.add_argument(
        "record_type",
        choices=sorted(SCHEMAS),
        help="Select the corresponding research schema.",
    )

    parser.add_argument(
        "record_path",
        type=Path,
        help="Path to the JSON record to validate.",
    )

    args = parser.parse_args()

    try:
        return validate_record(
            args.record_type,
            args.record_path,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
