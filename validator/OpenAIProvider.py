import json
import sys

from openai import OpenAI

PROMPT = """你是网络安全和数据安全分析专家,负责基于正则匹配结果及上下文,研判数据的敏感程度与可利用性。请严格遵循以下规则执行任务:

### 核心目标
精准判定每条目标数据的敏感等级,输出JSON数组。

### 分级标准(优先级:规则定义＞主观判断)
1. **high等级**:需同时满足「正则匹配命中」+「上下文验证为真实敏感/可利用数据」
   - 数据内容符合规则定义的格式要求
   - 上下文表明这是真实的、未脱敏的敏感信息
   - 数据具有实际可利用价值(如密钥、凭证、认证信息等)

2. **medium等级**:满足「正则匹配命中」+「上下文无法完全验证真实性,但存在敏感特征」
   - 数据格式符合规则要求,但部分脱敏或模糊化
   - 上下文暗示可能是敏感信息,但缺乏明确证据
   - 数据真实性存疑,但不能完全排除风险

3. **low等级**:满足「正则匹配命中」+「上下文验证为误报,但存在潜在风险」
   - 数据符合正则格式,但上下文表明是测试/示例/占位数据
   - 公开的、已脱敏的或无实际价值的信息
   - 规则弱关联的字符串(仅在描述性文本中出现)

4. **none等级**:满足「正则匹配未命中」或「上下文验证为明确误报/无关联」
   - 占位符或模板文本
   - 规则说明、提示性文本
   - 与规则目标完全无关的普通字符串

### 执行步骤
1. 第一步:理解规则的目标类型(基于规则名、正则表达式、分组信息)
2. 第二步:逐条校验匹配内容是否符合规则定义的格式特征
3. 第三步:结合上下文(前文+后文)验证数据的真实性与可利用性
4. 第四步:对照分级标准判定敏感等级,优先匹配高等级规则
5. 第五步:按指定格式输出JSON数组

### 输出要求
严格遵守如下格式并且只能返回JSON数组,每个元素包含index和tags字段,无任何多余内容。示例:
[{"index":0,"tags":"high"},{"index":1,"tags":"none"}]
"""

VALID_TAGS = {"high", "medium", "low", "none"}


def build_content(rule, items):
    lines = [
        f"规则名：{rule.get('name', '')}，"
        f"规则正则：{rule.get('regex', '')}，"
        f"规则分组：{rule.get('group', '')}",
        "",
        "以下是需要研判的数据列表：",
    ]
    for item in items:
        idx = item.get("index", 0)
        data = item.get("data", {})
        ctx = data.get("context", {})
        lines.append(
            f"[{idx}] 匹配内容：{data.get('match', '')}，"
            f"上文：{ctx.get('before', '')}，"
            f"下文：{ctx.get('after', '')}"
        )
    return "\n".join(lines)


def parse_response(text, items):
    # 提取返回文本中的JSON数组
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1:
        try:
            arr = json.loads(text[start : end + 1])
            result_map = {}
            for entry in arr:
                idx = entry.get("index")
                tags = entry.get("tags", "none")
                if tags not in VALID_TAGS:
                    tags = "none"
                result_map[idx] = tags
            return [
                {
                    "index": item.get("index", 0),
                    "tags": result_map.get(item.get("index", 0), "none"),
                }
                for item in items
            ]
        except (json.JSONDecodeError, TypeError):
            pass

    # 解析失败，全部降级为 none
    return [{"index": item.get("index", 0), "tags": "none"} for item in items]


def main():
    input_data = json.load(sys.stdin)
    rule = input_data.get("rule", {})
    items = input_data.get("items", [])

    client = OpenAI(
        api_key="",  # 修改API Key
        base_url="http://localhost:1234/v1",
    )

    content = build_content(rule, items)
    response = client.chat.completions.create(
        model="",  # 修改模型ID
        max_tokens=4096,
        messages=[{"role": "user", "content": f"{PROMPT}\n\n{content}"}],
    )

    text = response.choices[0].message.content.strip()
    results = parse_response(text, items)
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
