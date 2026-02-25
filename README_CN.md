<div align="center">
<h3>HaE Validator</h3>
<h5>作者： <a href="https://github.com/gh0stkey">EvilChen</a></h5>
</div>

README 版本: \[[English](README.md) | [简体中文](README_CN.md)\]

## 项目介绍

HaE Validator 是一个社区维护的 [HaE](https://github.com/gh0stkey/HaE) 公共验证器集合。验证器是外部脚本，通过对匹配到的数据进行严重程度分类（`high`/`medium`/`low`/`none`），提升数据分析和漏洞发现效率。

## 验证器工作原理

验证器通过 **stdin/stdout** 与 HaE 进行 JSON 格式的数据通信：

1. HaE 将匹配到的数据通过 **stdin** 发送给验证器脚本
2. 验证器处理每条匹配结果并分配严重程度等级
3. 验证器通过 **stdout** 返回结果

### 输入格式（stdin）


#### HaENet 格式

```json
{
  "rule": {
    "name": "规则名称",
    "regex": "(正则表达式)",
    "group": "分组名称"
  },
  "items": [
    {
      "index": 0,
      "data": {
        "match": "匹配内容",
        "context": {
          "before": "匹配内容前50个字符串",
          "after": "匹配内容后50个字符串"
        }
      }
    }
  ]
}
```

#### HaEFile 格式

```json
{
  "rule": {
    "name": "规则名称",
    "regex": "(正则表达式)",
    "group": "分组名称"
  },
  "items": [
    {
      "index": 0,
      "data": {
        "file": "/path/to/source/File.java",
        "line": 680,
        "column": 19,
        "match": "匹配内容",
        "context": {
          "before": "匹配内容前50个字符串",
          "after": "匹配内容后50个字符串"
        }
      }
    }
  ]
}
```

### 输出格式（stdout）

```json
{
  "results": [
    { "index": 0, "tags": "high" },
    { "index": 1, "tags": "low" }
  ]
}
```

### 字段说明

| 字段 | 说明 |
|------|------|
| `rule.name` | 匹配的规则名称 |
| `rule.regex` | 规则的正则表达式 |
| `rule.group` | 规则所属分组 |
| `items[].index` | 匹配项的索引 |
| `items[].data.match` | 匹配到的内容 |
| `items[].data.file` | *（仅 HaEFile）* 匹配所在的源文件路径 |
| `items[].data.line` | *（仅 HaEFile）* 匹配所在的行号 |
| `items[].data.column` | *（仅 HaEFile）* 匹配所在的列号 |
| `items[].data.context` | 匹配内容的上下文（前/后各50个字符） |
| `results[].index` | 与输入项的 index 对应 |
| `results[].tags` | 严重程度等级：`high`、`medium`、`low` 或 `none` |

## 使用方法

1. 选择或编写一个验证器脚本（如 Python）
2. 在 HaE 的规则设置中填写 **Validator** 字段：
   - **Command**：执行验证器的命令，如 `python3 /path/to/validator.py`
   - **Timeout**：单次执行最大等待时间，单位毫秒（默认：5000）
   - **Bulk**：每次调用发送的匹配数据条数（默认：500）
3. HaE 在匹配到结果后会自动调用验证器，并在 Databoard 中展示严重程度

## 编写验证器

一个最小的 Python 验证器模板：

```python
#!/usr/bin/env python3
import json
import sys

def validate(rule, data):
    match = data.get("match", "")
    # 在此实现你的分类逻辑
    if "敏感关键词" in match:
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

**注意事项**：
- 验证器可以使用任何编程语言编写（Python、Node.js、Go 等）
- 从 **stdin** 读取 JSON，向 **stdout** 写入 JSON
- 仅使用有效的严重程度值：`high`、`medium`、`low`、`none`
- 未在结果中返回的 index 将保持原有严重程度不变