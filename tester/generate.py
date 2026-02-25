#!/usr/bin/env python3
"""
HaE Validator 测试数据生成器

用法:
    python3 generate.py net RuleName match1 match2 | python3 ../validator/XXX.py
    python3 generate.py file RuleName match1 match2 | python3 ../validator/XXX.py
"""

import argparse
import json


def build_item(index, match, fmt, args):
    item = {
        "index": index,
        "data": {
            "match": match,
            "context": {"before": args.before, "after": args.after},
        },
    }
    if fmt == "net":
        item["data"]["url"] = args.url
    elif fmt == "file":
        item["data"].update({"file": args.file_path, "line": args.line + index, "column": args.column})
    return item


def main():
    parser = argparse.ArgumentParser(description="HaE Validator 测试数据生成器")
    parser.add_argument("format", choices=["net", "file"], help="net (HaENet) / file (HaEFile)")
    parser.add_argument("rule_name", help="规则名称")
    parser.add_argument("matches", nargs="+", help="匹配数据")
    parser.add_argument("--regex", default="(.*?)")
    parser.add_argument("--group", default="Default")
    parser.add_argument("--before", default="")
    parser.add_argument("--after", default="")
    parser.add_argument("--url", default="https://example.com/api")
    parser.add_argument("--file-path", default="/path/to/File.java")
    parser.add_argument("--line", type=int, default=1)
    parser.add_argument("--column", type=int, default=1)
    args = parser.parse_args()

    data = {
        "rule": {"name": args.rule_name, "regex": args.regex, "group": args.group},
        "items": [build_item(i, m, args.format, args) for i, m in enumerate(args.matches)],
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
