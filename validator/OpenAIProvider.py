import json
import sys

from openai import OpenAI

PROMPT = """你是网络安全和数据安全分析专家，负责基于正则匹配结果及上下文，研判数据的敏感程度与可利用性。请严格遵循以下规则执行任务：

### 核心目标
精准判定每条目标数据的敏感等级，输出JSON数组。

### 分级标准（优先级：规则定义＞主观判断）
1. **high等级**：需同时满足「正则匹配命中」+「上下文验证为真实敏感数据/可被利用数据」。真实敏感数据包括：18位身份证号、16-19位银行卡号、明文/加密后可破解的密码、未脱敏手机号（11位中国大陆手机号，不含虚拟号段）、未脱敏邮箱（含@符号且格式合规）；可被利用数据包括：企业内部系统密钥、用户Session ID、支付凭证token。
2. **medium等级**：满足「正则匹配命中」+「上下文无法完全验证真实性，但存在敏感特征」。例如：模糊手机号（如138****1234，仅部分脱敏）、疑似邮箱（如user#example.com，格式接近但符号错误）、未验证的身份证片段（如仅含前6位地址码）。
3. **low等级**：满足「正则匹配命中」+「上下文验证为误报，但存在潜在风险」。例如：测试用占位数据（如123456789012345678，标注为"测试卡号"）、公共信息（如公开的客服手机号400-xxx-xxxx）、与规则弱关联的字符串（如含"password"但为非密码场景的描述文本）。
4. **none等级**：满足「正则匹配未命中」或「上下文验证为明确误报/无关联」。例如：占位符文本（如"{{sensitivedata}}"）、规则描述性内容（如"请输入银行卡号"）、与敏感数据无关的普通字符串（如"今日天气晴朗"）。

### 执行步骤
1. 第一步：逐条校验输入数据是否被正则匹配命中（需明确匹配的规则类型，如"身份证号规则""手机号规则"）；
2. 第二步：结合上下文文本验证数据真实性（上下文指与目标数据直接关联的前后文内容，如数据标注、场景说明）；
3. 第三步：对照分级标准判定敏感等级，优先匹配高等级规则（如同时满足high和medium，以high为准）；
4. 第四步：按指定格式输出JSON数组。

### 输出要求
严格遵守如下格式并且只能返回JSON数组，每个元素包含index和tags字段，无任何多余内容。示例：
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
