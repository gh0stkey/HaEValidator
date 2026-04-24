#!/usr/bin/env python3

import json
import os
import sys
import urllib.request

OPF_SERVER_URL = os.environ.get("OPF_SERVER_URL", "http://localhost:8000")

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


def redact(text):
    url = f"{OPF_SERVER_URL.rstrip('/')}/redact"
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def severity_from_spans(detected_spans):
    severity = "none"
    for span in detected_spans:
        label_sev = LABEL_SEVERITY.get(span.get("label", ""), "medium")
        severity = highest_severity(severity, label_sev)
    return severity


def main():
    data = json.load(sys.stdin)
    items = data.get("items", [])

    if not items:
        print(json.dumps({"results": []}))
        return

    results = []
    for item in items:
        idx = item.get("index", 0)
        text = item.get("data", {}).get("match", "")
        redact_result = redact(text)
        tags = severity_from_spans(redact_result.get("detected_spans", []))
        results.append({"index": idx, "tags": tags})

    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
