#!/usr/bin/env python3
"""
HaE Validator 测试运行器

用法:
    # 仅生成测试数据（管道模式）
    python3 runner.py net RuleName match1 match2 | python3 ../validator/XXX.py

    # 指定验证器自动运行并统计
    python3 runner.py net RuleName match1 match2 -v ../validator/ChineseIDCard.py

    # 指定期望结果进行验证
    python3 runner.py net 身份证 110101199001011234 123456789012345678 \
        -v ../validator/ChineseIDCard.py -e high none

    # 多次运行取平均时间
    python3 runner.py net RuleName match1 -v ../validator/XXX.py -n 10
"""

import argparse
import json
import subprocess
import sys
import time


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
        item["data"].update(
            {"file": args.file_path, "line": args.line + index, "column": args.column}
        )
    return item


def run_validator(validator_path, input_data, timeout=60):
    """运行验证器脚本并返回结果"""
    try:
        proc = subprocess.run(
            [sys.executable, validator_path],
            input=json.dumps(input_data, ensure_ascii=False),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            return None, proc.stderr or "Unknown error"
        return json.loads(proc.stdout), None
    except subprocess.TimeoutExpired:
        return None, f"Timeout after {timeout}s"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON output: {e}"
    except Exception as e:
        return None, str(e)


def format_duration(ms):
    """格式化时间显示"""
    if ms < 1:
        return f"{ms * 1000:.2f}μs"
    if ms < 1000:
        return f"{ms:.2f}ms"
    return f"{ms / 1000:.2f}s"


def print_results(input_data, output, duration_ms, expected=None):
    """打印测试结果"""
    print("\n" + "=" * 60)
    print("测试结果")
    print("=" * 60)

    rule = input_data.get("rule", {})
    print(f"\n规则: {rule.get('name', 'N/A')} [{rule.get('group', 'N/A')}]")
    print(f"正则: {rule.get('regex', 'N/A')}")
    print(f"耗时: {format_duration(duration_ms)}")

    results = output.get("results", [])
    items = input_data.get("items", [])

    print(f"\n{'序号':<6}{'匹配内容':<30}{'结果':<10}{'期望':<10}{'状态':<6}")
    print("-" * 60)

    all_pass = True
    for i, result in enumerate(results):
        idx = result.get("index", i)
        tags = result.get("tags", "N/A")
        match_text = items[idx]["data"]["match"] if idx < len(items) else "N/A"
        if len(match_text) > 26:
            match_text = match_text[:26] + "..."

        exp = expected[idx] if expected and idx < len(expected) else "-"
        if expected and idx < len(expected):
            status = "✓" if tags == expected[idx] else "✗"
            if tags != expected[idx]:
                all_pass = False
        else:
            status = "-"

        print(f"{idx:<6}{match_text:<30}{tags:<10}{exp:<10}{status:<6}")

    if expected:
        print("-" * 60)
        print(f"验证结果: {'✓ 全部通过' if all_pass else '✗ 存在失败'}")

    return all_pass


def print_benchmark(durations_ms):
    """打印性能基准测试结果"""
    print("\n" + "=" * 60)
    print("性能基准测试")
    print("=" * 60)
    print(f"运行次数: {len(durations_ms)}")
    print(f"最短耗时: {format_duration(min(durations_ms))}")
    print(f"最长耗时: {format_duration(max(durations_ms))}")
    print(f"平均耗时: {format_duration(sum(durations_ms) / len(durations_ms))}")
    if len(durations_ms) > 1:
        sorted_d = sorted(durations_ms)
        median = sorted_d[len(sorted_d) // 2]
        print(f"中位数:   {format_duration(median)}")


def main():
    parser = argparse.ArgumentParser(
        description="HaE Validator 测试数据生成器与运行器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 生成测试数据（管道模式）
  %(prog)s net 身份证 110101199001011234 | python3 ../validator/ChineseIDCard.py

  # 自动调用验证器
  %(prog)s net 身份证 110101199001011234 -v ../validator/ChineseIDCard.py

  # 验证期望结果
  %(prog)s net 身份证 110101199001011234 123456 -v ../validator/ChineseIDCard.py -e high none

  # 性能基准测试（运行10次）
  %(prog)s net 身份证 110101199001011234 -v ../validator/ChineseIDCard.py -n 10
""",
    )
    parser.add_argument(
        "format", choices=["net", "file"], help="net (HaENet) / file (HaEFile)"
    )
    parser.add_argument("rule_name", help="规则名称")
    parser.add_argument("matches", nargs="+", help="匹配数据")
    parser.add_argument("--regex", default="(.*?)", help="规则正则表达式")
    parser.add_argument("--group", default="Default", help="规则分组")
    parser.add_argument("--before", default="", help="上下文-前文")
    parser.add_argument("--after", default="", help="上下文-后文")
    parser.add_argument(
        "--url", default="https://example.com/api", help="URL (net模式)"
    )
    parser.add_argument(
        "--file-path", default="/path/to/File.java", help="文件路径 (file模式)"
    )
    parser.add_argument("--line", type=int, default=1, help="起始行号 (file模式)")
    parser.add_argument("--column", type=int, default=1, help="列号 (file模式)")

    parser.add_argument("-v", "--validator", metavar="PATH", help="验证器脚本路径")
    parser.add_argument(
        "-e",
        "--expected",
        nargs="+",
        metavar="TAG",
        help="期望的标签结果 (high/medium/low/none)",
    )
    parser.add_argument(
        "-n",
        "--runs",
        type=int,
        default=1,
        metavar="N",
        help="运行次数，用于性能基准测试 (默认: 1)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=60,
        help="验证器超时时间，单位秒 (默认: 60)",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")

    args = parser.parse_args()

    data = {
        "rule": {"name": args.rule_name, "regex": args.regex, "group": args.group},
        "items": [
            build_item(i, m, args.format, args) for i, m in enumerate(args.matches)
        ],
    }

    # 如果没有指定验证器，仅输出生成的测试数据
    if not args.validator:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    # 运行验证器
    durations = []
    last_output = None

    for i in range(args.runs):
        start = time.perf_counter()
        output, error = run_validator(args.validator, data, timeout=args.timeout)
        elapsed_ms = (time.perf_counter() - start) * 1000

        if error:
            print(f"错误: {error}", file=sys.stderr)
            sys.exit(1)

        durations.append(elapsed_ms)
        last_output = output

        if args.runs > 1:
            print(f"\r运行进度: {i + 1}/{args.runs}", end="", flush=True)

    if args.runs > 1:
        print()  # 换行

    # 输出结果
    if args.json:
        result = {
            "input": data,
            "output": last_output,
            "duration_ms": durations[0] if len(durations) == 1 else durations,
            "stats": {
                "runs": len(durations),
                "min_ms": min(durations),
                "max_ms": max(durations),
                "avg_ms": sum(durations) / len(durations),
            }
            if len(durations) > 1
            else None,
        }
        if args.expected:
            result["expected"] = args.expected
            result["all_pass"] = all(
                r.get("tags") == args.expected[r.get("index")]
                for r in last_output.get("results", [])
                if r.get("index", 0) < len(args.expected)
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        all_pass = print_results(data, last_output, durations[0], args.expected)
        if len(durations) > 1:
            print_benchmark(durations)

        # 如果有期望结果且验证失败，返回非零退出码
        if args.expected and not all_pass:
            sys.exit(1)


if __name__ == "__main__":
    main()
