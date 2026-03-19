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

RULE_SPECIFIC_PROMPTS = {
    "Cloud Key": """
### 规则专项指引：Cloud Key（云服务密钥）
- 目标：识别云厂商（AWS、阿里云、腾讯云、华为云等）的 AccessKeyId / AccessKeySecret
- high：符合云厂商密钥格式（如 AKIA...、LTAI...），且上下文无明显测试/示例标记
- medium：格式匹配但变量名含 example/test/demo，或密钥被部分遮掩
- low：仅出现 access_key_id 等字段名，值为空或明确为占位符（xxx、your-key-here）
- none：SDK 文档说明文本、注释中的字段名引用、与密钥无关的普通字符串
""",
    "Password Field": """
### 规则专项指引：Password Field（密码字段）
- 目标：识别键值对形式的密码泄露，如 password="abc123"、passwd: "xxx"
- high：字段名含 pass/pwd/passwd/password 且值为非空的具体字符串，上下文为配置文件、API响应、日志
- medium：值看起来像真实密码但上下文不明确，或值为弱密码（123456、admin等）无法确认是否为生产环境
- low：值为明显的占位符（*****、${password}、<your_password>）、单元测试数据、前端表单校验逻辑
- none：仅出现字段名定义（如 HTML label、schema 描述）、值为空字符串、密码强度校验规则文本
""",
    "Username Field": """
### 规则专项指引：Username Field（用户名字段）
- 目标：识别键值对形式的用户名/账号泄露
- high：字段名含 user/username/account 且值为具体用户名（如 admin、zhangsan、test_user），上下文为配置/响应/日志
- medium：值为非特定人名但可能是用户标识（如纯数字 ID），上下文不明确
- low：值为通用占位符（user1、testuser）、文档示例中的演示账号
- none：字段定义（schema/model）中的属性名、HTML 表单 label、createdBy/updatedBy 等审计字段中的系统用户名
""",
    "Sensitive Field": """
### 规则专项指引：Sensitive Field（敏感字段，含 key/secret/token/auth/access/admin/ticket）
- 目标：识别通用敏感字段的键值对泄露
- high：字段名含 secret/token/auth 等关键词，值为高熵随机字符串（长度>16，含大小写+数字），上下文为配置或 API 响应
- medium：值为中等熵值字符串，或字段名匹配但值可能是非敏感的配置项（如 config_key="theme"）
- low：值为 null/空/占位符/前端常量名（如 accessToken: "ACCESS_TOKEN"）
- none：前端 i18n 文本、UI 配置（如 admin="管理员"）、字段仅用于路由/权限判断的布尔值
注意：区分「认证凭证类」（secret/token/auth → 倾向高等级）和「功能配置类」（config/admin/ticket → 需更多上下文）
""",
    "Mobile Number Field": """
### 规则专项指引：Mobile Number Field（手机号字段）
- 目标：识别键值对形式的手机号泄露
- high：字段名含 mobile/phone 且值为完整的 11 位手机号，上下文为 API 响应/数据库导出/日志
- medium：手机号可能被部分脱敏（如 138****1234）但脱敏不完整，或出现在批量数据中
- low：值为明显的测试号码（13800138000）、值不符合手机号格式
- none：字段定义/schema 中的属性名、表单 placeholder 文本
""",
}

VALID_TAGS = {"high", "medium", "low", "none"}


def build_content(rule, items):
    rule_name = rule.get("name", "")
    specific_prompt = RULE_SPECIFIC_PROMPTS.get(rule_name, "")

    lines = [
        f"规则名：{rule_name}，"
        f"规则正则：{rule.get('regex', '')}，"
        f"规则分组：{rule.get('group', '')}",
    ]

    # 动态Prompt增强
    if specific_prompt:
        lines.append(specific_prompt)

    lines.append("")
    lines.append("以下是需要研判的数据列表：")

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
