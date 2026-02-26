import base64
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

KV_PATTERN = re.compile(r'"([^"]*?)"\s*[:\uff1a]\s*"([^"]*?)"')
AK_KEYS = re.compile(r"access.?key.?id|aki|ak_id", re.IGNORECASE)
SK_KEYS = re.compile(
    r"access.?key.?secret|secret.?key|aki_secret|ak_secret|\bsk\b", re.IGNORECASE
)
OSS_ENDPOINT = "https://oss-cn-hangzhou.aliyuncs.com"
INVALID_ERRORS = ("InvalidAccessKeyId", "SignatureDoesNotMatch")


def extract(match):
    m = KV_PATTERN.search(match)
    if not m:
        return None, None
    key, value = m.group(1), m.group(2)
    if SK_KEYS.search(key):
        return "sk", value
    if AK_KEYS.search(key):
        return "ak", value
    return None, None


def verify(ak, sk):
    try:
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        sign = base64.b64encode(
            hmac.new(sk.encode(), f"GET\n\n\n{date}\n/".encode(), hashlib.sha1).digest()
        ).decode()
        req = Request(OSS_ENDPOINT + "/?max-keys=1")
        req.add_header("Date", date)
        req.add_header("Authorization", f"OSS {ak}:{sign}")
        urlopen(req, timeout=10)
        return True
    except HTTPError as e:
        if e.code == 403:
            body = e.read().decode(errors="ignore")
            return not any(err in body for err in INVALID_ERRORS)
        return False
    except Exception:
        return False


def main():
    data = json.load(sys.stdin)
    items = data.get("items", [])

    aks, sks = [], []
    for item in items:
        kind, value = extract(item.get("data", {}).get("match", ""))
        idx = item.get("index", 0)
        if kind == "ak":
            aks.append((idx, value))
        elif kind == "sk":
            sks.append((idx, value))

    valid = set()
    for ai, av in aks:
        for si, sv in sks:
            if verify(av, sv):
                valid.add(ai)
                valid.add(si)

    results = [
        {
            "index": item.get("index", 0),
            "tags": "high" if item.get("index", 0) in valid else "none",
        }
        for item in items
    ]
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
