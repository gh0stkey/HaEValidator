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
import unicodedata

# ---------------------------------------------------------------------------
# 数据构建
# ---------------------------------------------------------------------------


def build_item(index, match, fmt, args):
    """构建单个测试条目"""
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


def build_test_data(args):
    """根据命令行参数构建完整的测试数据"""
    return {
        "rule": {"name": args.rule_name, "regex": args.regex, "group": args.group},
        "items": [
            build_item(i, m, args.format, args) for i, m in enumerate(args.matches)
        ],
    }


# ---------------------------------------------------------------------------
# 验证器执行
# ---------------------------------------------------------------------------


def run_validator(validator_path, input_data, timeout=60):
    """运行验证器脚本并返回 (output, error)"""
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


def run_benchmark(validator_path, data, runs, timeout):
    """多次运行验证器，返回 (最后一次输出, 耗时列表 ms)"""
    durations = []
    last_output = None

    for i in range(runs):
        start = time.perf_counter()
        output, error = run_validator(validator_path, data, timeout=timeout)
        elapsed_ms = (time.perf_counter() - start) * 1000

        if error:
            print(f"错误: {error}", file=sys.stderr)
            sys.exit(1)

        durations.append(elapsed_ms)
        last_output = output

        if runs > 1:
            print(f"\r运行进度: {i + 1}/{runs}", end="", flush=True)

    if runs > 1:
        print()

    return last_output, durations


# ---------------------------------------------------------------------------
# 结果校验（统一逻辑，消除 text / json 两条路径的重复）
# ---------------------------------------------------------------------------


def check_expected(results, items, expected):
    """对比实际结果与期望，返回 (详情列表, 是否全部通过)

    详情列表每项:
        {"index", "match", "actual", "expected", "passed"}
    """
    details = []
    all_pass = True

    for result in results:
        idx = result.get("index", 0)
        actual = result.get("tags", "N/A")
        match = items[idx]["data"]["match"] if idx < len(items) else "N/A"
        exp = expected[idx] if expected and idx < len(expected) else None
        passed = (actual == exp) if exp is not None else None

        if passed is False:
            all_pass = False

        details.append(
            {
                "index": idx,
                "match": match,
                "actual": actual,
                "expected": exp,
                "passed": passed,
            }
        )

    return details, all_pass


# ---------------------------------------------------------------------------
# 输出格式化
# ---------------------------------------------------------------------------


def display_width(s):
    """计算字符串在终端中的显示宽度（CJK 字符占 2 列）"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1 for ch in s)


def pad(s, width):
    """按显示宽度右填充空格对齐"""
    return s + " " * max(0, width - display_width(s))


def format_duration(ms):
    """格式化时间显示"""
    if ms < 1:
        return f"{ms * 1000:.2f}\u03bcs"
    if ms < 1000:
        return f"{ms:.2f}ms"
    return f"{ms / 1000:.2f}s"


def output_text(data, output, durations, expected=None):
    """文本格式输出，返回 all_pass"""
    rule = data["rule"]
    details, all_pass = check_expected(
        output.get("results", []), data["items"], expected
    )

    print("\n" + "=" * 60)
    print("测试结果")
    print("=" * 60)
    print(f"\n规则: {rule['name']} [{rule['group']}]")
    print(f"正则: {rule['regex']}")
    print(f"耗时: {format_duration(durations[0])}")

    # 逐项结果表格
    cols = (6, 30, 10, 10, 6)
    header = (
        pad("序号", cols[0])
        + pad("匹配内容", cols[1])
        + pad("结果", cols[2])
        + pad("期望", cols[3])
        + pad("状态", cols[4])
    )
    total_width = sum(cols)
    print(f"\n{header}")
    print("-" * total_width)

    for d in details:
        match_text = d["match"]
        if display_width(match_text) > cols[1] - 4:
            while display_width(match_text + "...") > cols[1] - 1:
                match_text = match_text[:-1]
            match_text += "..."
        exp_str = d["expected"] or "-"
        status = {True: "\u2713", False: "\u2717"}.get(d["passed"], "-")
        print(
            pad(str(d["index"]), cols[0])
            + pad(match_text, cols[1])
            + pad(d["actual"], cols[2])
            + pad(exp_str, cols[3])
            + pad(status, cols[4])
        )

    if expected:
        print("-" * total_width)
        verdict = "\u2713 全部通过" if all_pass else "\u2717 存在失败"
        print(f"验证结果: {verdict}")

    # 性能基准（多次运行时）
    if len(durations) > 1:
        print("\n" + "=" * 60)
        print("性能基准测试")
        print("=" * 60)
        print(f"运行次数: {len(durations)}")
        print(f"最短耗时: {format_duration(min(durations))}")
        print(f"最长耗时: {format_duration(max(durations))}")
        print(f"平均耗时: {format_duration(sum(durations) / len(durations))}")
        median = sorted(durations)[len(durations) // 2]
        print(f"中位数:   {format_duration(median)}")

    return all_pass


def output_json(data, output, durations, expected=None):
    """JSON 格式输出，返回 all_pass"""
    _, all_pass = check_expected(output.get("results", []), data["items"], expected)

    result = {
        "input": data,
        "output": output,
        "duration_ms": durations[0] if len(durations) == 1 else durations,
    }

    if len(durations) > 1:
        result["stats"] = {
            "runs": len(durations),
            "min_ms": min(durations),
            "max_ms": max(durations),
            "avg_ms": sum(durations) / len(durations),
        }

    if expected:
        result["expected"] = expected
        result["all_pass"] = all_pass

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return all_pass


# ---------------------------------------------------------------------------
# 参数解析 & 入口
# ---------------------------------------------------------------------------


def parse_args():
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
    return parser.parse_args()


def main():
    args = parse_args()
    data = build_test_data(args)

    # 管道模式：仅输出测试数据
    if not args.validator:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    # 运行验证器
    output, durations = run_benchmark(args.validator, data, args.runs, args.timeout)

    # 输出结果
    if args.json:
        all_pass = output_json(data, output, durations, args.expected)
    else:
        all_pass = output_text(data, output, durations, args.expected)

    if args.expected and not all_pass:
        sys.exit(1)


if __name__ == "__main__":
    main()
