import json
import sys
from datetime import datetime

WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CHECK_MAP = "10X98765432"
VALID_PROVINCES = {
    "11", "12", "13", "14", "15",
    "21", "22", "23",
    "31", "32", "33", "34", "35", "36", "37",
    "41", "42", "43", "44", "45", "46",
    "50", "51", "52", "53", "54",
    "61", "62", "63", "64", "65",
    "71",
    "81", "82",
}


def validate_id_card(id_number):
    if len(id_number) != 18 or not id_number[:17].isdigit():
        return False

    if id_number[:2] not in VALID_PROVINCES:
        return False

    try:
        birth = datetime.strptime(id_number[6:14], "%Y%m%d")
        if not (datetime(1900, 1, 1) <= birth <= datetime.now()):
            return False
    except ValueError:
        return False

    checksum = sum(int(id_number[i]) * WEIGHTS[i] for i in range(17)) % 11
    return CHECK_MAP[checksum] == id_number[-1].upper()


def main():
    data = json.load(sys.stdin)
    items = data.get("items", [])

    results = []
    for item in items:
        index = item.get("index", 0)
        match = item.get("data", {}).get("match", "")
        tags = "high" if validate_id_card(match) else "none"
        results.append({"index": index, "tags": tags})

    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()