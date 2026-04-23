#!/usr/bin/env python3

import json
import sys

from opf import OPF

LABEL_SEVERITY = {
    "secret": "high",
    "account_number": "high",
    "private_email": "high",
    "private_phone": "high",
    "private_address": "medium",
    "private_url": "medium",
    "private_person": "low",
    "private_date": "low",
}

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def highest_severity(*severities):
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def validate(redactor, match):
    result = redactor.redact(match)

    severity = "none"
    for span in result.detected_spans:
        label_sev = LABEL_SEVERITY.get(span.label, "medium")
        severity = highest_severity(severity, label_sev)

    return severity


def main():
    data = json.load(sys.stdin)
    items = data.get("items", [])

    redactor = OPF(device="cpu", output_mode="typed")

    results = []
    for item in items:
        index = item.get("index", 0)
        d = item.get("data", {})
        match = d.get("match", "")

        tags = validate(redactor, match)
        results.append({"index": index, "tags": tags})

    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
