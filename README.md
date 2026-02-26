<div align="center">
<h3>HaE Validator</h3>
<h5>Author: <a href="https://github.com/gh0stkey">EvilChen</a></h5>
</div>

README Version: \[[English](README.md) | [简体中文](README_CN.md)\]

## Project Introduction

HaE Validator is a community-maintained collection of public validators for [HaE](https://github.com/gh0stkey/HaE). Validators are external scripts that classify matched data by severity (`high`/`medium`/`low`/`none`), enhancing the efficiency of data analysis and vulnerability discovery.

## How Validators Work

Validators communicate with HaE via **stdin/stdout** using JSON:

1. HaE sends matched data to the validator script via **stdin**
2. The validator processes each match and assigns a severity level
3. The validator returns results via **stdout**

### Input Format (stdin)


#### HaENet Format

```json
{
  "rule": {
    "name": "Rule Name",
    "regex": "(regex_pattern)",
    "group": "Group Name"
  },
  "items": [
    {
      "index": 0,
      "data": {
        "url": "https://example.com/api",
        "match": "matched_content",
        "context": {
          "before": "50 characters before the match",
          "after": "50 characters after the match"
        }
      }
    }
  ]
}
```

#### HaEFile Format

```json
{
  "rule": {
    "name": "Rule Name",
    "regex": "(regex_pattern)",
    "group": "Group Name"
  },
  "items": [
    {
      "index": 0,
      "data": {
        "file": "/path/to/source/File.java",
        "line": 680,
        "column": 19,
        "match": "matched_content",
        "context": {
          "before": "50 characters before the match",
          "after": "50 characters after the match"
        }
      }
    }
  ]
}
```

### Output Format (stdout)

```json
{
  "results": [
    { "index": 0, "tags": "high" },
    { "index": 1, "tags": "low" }
  ]
}
```

### Field Description

| Field | Description |
|-------|-------------|
| `rule.name` | The name of the matched rule |
| `rule.regex` | The regular expression of the rule |
| `rule.group` | The group the rule belongs to |
| `items[].index` | The index of the matched item |
| `items[].data.url` | *(HaENet only)* The URL where the match was found |
| `items[].data.match` | The matched content |
| `items[].data.file` | *(HaEFile only)* Source file path where the match was found |
| `items[].data.line` | *(HaEFile only)* Line number of the match |
| `items[].data.column` | *(HaEFile only)* Column number of the match |
| `items[].data.context` | Context around the match (before/after 50 characters) |
| `results[].index` | Corresponds to the input item's index |
| `results[].tags` | Severity level: `high`, `medium`, `low`, or `none` |

## Validators

| Name | Description |
|------|-------------|
| [ChineseIDCard](validator/ChineseIDCard.py) | Validates Chinese ID card numbers (checksum, province, date of birth) |
| [OSSAccessKey](validator/OSSAccessKey.py) | Cross-validates Alibaba Cloud OSS AccessKey pairs (AK/SK) via API |
| [OpenAIProvider](validator/OpenAIProvider.py) | AI-powered sensitive data analysis using OpenAI-compatible API |

## Tester

A test runner is provided in the `tester/` directory to help verify validators locally. It supports generating test data, running validators automatically, and benchmarking performance.

### Basic Usage

```bash
# Generate test data only (pipe mode)
python3 tester/runner.py net ChineseIDCard 110101199003071234 | python3 validator/ChineseIDCard.py

# Auto-run validator with -v option
python3 tester/runner.py net ChineseIDCard 110101199001011237 -v validator/ChineseIDCard.py
```

### Verify Expected Results

```bash
# Validate results against expected tags (-e option)
python3 tester/runner.py net ChineseIDCard 110101199001011237 123456789012345678 \
    -v validator/ChineseIDCard.py -e high none
```

### Benchmark Performance

```bash
# Run 10 times and show statistics (-n option)
python3 tester/runner.py net ChineseIDCard 110101199001011237 \
    -v validator/ChineseIDCard.py -n 10
```

### Options

| Option | Description |
|--------|-------------|
| `-v, --validator PATH` | Path to validator script |
| `-e, --expected TAG...` | Expected tags for verification |
| `-n, --runs N` | Number of runs for benchmarking (default: 1) |
| `-t, --timeout SEC` | Validator timeout in seconds (default: 60) |
| `--json` | Output results in JSON format |

## Usage

1. Choose or write a validator script (e.g., Python)
2. In HaE's rule settings, fill in the **Validator** field:
   - **Command**: the command to execute the validator, e.g., `python3 /path/to/validator.py`
   - **Timeout**: maximum wait time per execution in milliseconds (default: 5000)
   - **Bulk**: number of matches sent per invocation (default: 500)
3. HaE will automatically invoke the validator when matches are found and display severity in the Databoard

## Writing a Validator

A minimal Python validator template:

```python
#!/usr/bin/env python3
import json
import sys

def validate(rule, data):
    match = data.get("match", "")
    # Implement your classification logic here
    if "sensitive_keyword" in match:
        return "high"
    return "none"

def main():
    input_data = json.load(sys.stdin)
    rule = input_data.get("rule", {})
    items = input_data.get("items", [])

    results = []
    for item in items:
        index = item.get("index", 0)
        data = item.get("data", {})
        severity = validate(rule, data)
        results.append({"index": index, "tags": severity})

    print(json.dumps({"results": results}))

if __name__ == "__main__":
    main()
```

**Notes**:
- Validators can be written in any language (Python, Node.js, Go, etc.)
- Read JSON from **stdin**, write JSON to **stdout**
- Only use valid severity values: `high`, `medium`, `low`, `none`
- Items not returned in results will keep their original severity
