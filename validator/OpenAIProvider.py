#!/usr/bin/env python3

import json
import sys

from openai import OpenAI

PROMPT = """You are a cybersecurity and data security analysis expert, responsible for determining the sensitivity and exploitability of data based on regular expression matching results and context. Please strictly follow the following rules to perform the task:

### Core Objective

Accurately determine the sensitivity level of each target data item and output a JSON array.

### Grading Criteria (Priority: Rule Definition > Subjective Judgment)

1. **high level**: Must meet both "Regular expression match" + "Context verification as real sensitive/usable data"
- Data content meets the format requirements defined by the rules
- Context indicates that this is real, unmasked sensitive information
- Data has actual exploitability value (such as keys, credentials, authentication information, etc.)

2. **medium level**: Satisfy "Regular expression match" + "Context cannot fully verify the authenticity, but there are sensitive features"
- Data format meets the rule requirements, but partially masked or blurred
- Context suggests that it may be sensitive information, but lacks clear evidence
- Data authenticity is questionable, but cannot be completely ruled out as a risk

3. **low level**: Satisfy "Regular expression match" + "Context verification as false positive, but there is potential risk"
- Data meets the regular expression format, but context indicates it is test/sample/placeholder data
- Public, masked, or information without actual value
- Weakly associated strings (only appear in descriptive text)

4. **none level**: Satisfy "Regular expression does not match" or "Context verification as clear false positive/no relevance"
- Placeholder or template text
- Rule descriptions, prompt text
- Ordinary strings completely unrelated to the rule objective

### Execution Steps

1. First step: Understand the target type of the rules (based on rule name, regular expression, grouping information)
2. Second step: Check each matched content to see if it meets the format features defined by the rules
3. Third step: Verify the authenticity and exploitability of the data in conjunction with the context (previous text + following text)
4. Fourth step: Determine the sensitivity level according to the grading criteria, prioritizing high-level rules
5. Fifth step: Output in the specified format

### Output Requirements

Strictly adhere to the following format and only return a JSON array, with each element containing the index and tags fields, with no additional content. Example:

[{"index":0,"tags":"high"},{"index":1,"tags":"none"}]
"""

RULE_SPECIFIC_PROMPTS = {
    "Cloud Key": """
### Rule Special Guidance: Cloud Key (Cloud Service Key)
- Objective: Identify the AccessKeyId / AccessKeySecret of cloud vendors (AWS, Alibaba Cloud, Tencent Cloud, Huawei Cloud, etc.)
- High: Matches the cloud vendor key format (such as AKIA..., LTAI...) and has no obvious test/example markings in the context.
- Medium: Format matches but variable names contain example/test/demo, or the key is partially obscured.
- Low: Only the field names such as access_key_id appear, with empty values or explicitly marked as placeholders (xxx, your-key-here).
- None: SDK documentation text, field name references in comments, and general strings unrelated to the key.
""",
    "Password Field": """
### Rule Special Guidance: Password Field (Password Field)
- Objective: Identify password leaks in key-value pair format, such as password="abc123", passwd: "xxx"
- High: Field names containing pass/pwd/passwd/password and non-empty specific string values, context includes configuration files, API responses, logs
- Medium: Values appear to be real passwords but the context is unclear, or values are weak passwords (123456, admin, etc.) and it cannot be confirmed whether they are in a production environment
- Low: Values are obvious placeholders (*****, ${password}, <your_password>), unit test data, frontend form validation logic
- None: Only field name definitions appear (such as HTML label, schema description), values are empty strings, password strength verification rule text
""",
    "Username Field": """
### Special Guidance: Username Field (Username Field)
- Objective: Identify username/account leaks in key-value pair form
- High: Field names containing user/username/account and values being specific usernames (e.g., admin, zhangsan, test_user), context being configuration/response/log
- Medium: Values being non-specific personal names but possibly user identifiers (e.g., numeric ID), context unclear
- Low: Values being generic placeholders (user1, testuser), demonstration accounts in documentation examples
- None: Attribute names in field definitions (schema/model), HTML form labels, and system usernames in audit fields such as createdBy/updatedBy
""",
    "Sensitive Field": """
### Rule Special Guidance: Sensitive Field (Sensitive Field, including key/secret/token/auth/access/admin/ticket)
- Objective: Identify the leakage of key-value pairs of general sensitive fields
- High: Field names contain keywords such as secret/token/auth, and the values are high-entropy random strings (length > 16, containing uppercase and numbers), with context being configuration or API response
- Medium: Values are strings with medium entropy, or field names match but the values may be non-sensitive configuration items (e.g., config_key="theme")
- Low: Values are null/empty/placeholders/frontend constant names (e.g., accessToken: "ACCESS_TOKEN")
- None: Front-end i18n text, UI configuration (e.g., admin="Administrator"), boolean fields used only for routing/permission judgment
Note: Distinguish between "authentication credentials" (secret/token/auth → tend to be high-level) and "functional configuration" (config/admin/ticket → require more context)
""",
    "Mobile Number Field": """
### Rule Special Guidance: Mobile Number Field (Mobile Number Field)
- Objective: Identify mobile number leaks in key-value pair form
- High: Field name contains "mobile" or "phone" and the value is a complete 11-digit mobile number, with context being API response/database export/log
- Medium: The mobile number may be partially masked (e.g., 138****1234) but the masking is incomplete, or it appears in batch data
- Low: The value is an obvious test number (13800138000) or the value does not conform to the mobile number format
- None: Field name in field definition/schema, or placeholder text in forms
""",
}

VALID_TAGS = {"high", "medium", "low", "none"}


def build_content(rule, items):
    rule_name = rule.get("name", "")
    specific_prompt = RULE_SPECIFIC_PROMPTS.get(rule_name, "")

    lines = [
        f"Rule Name:{rule_name}，"
        f"Rule Regex:{rule.get('regex', '')}，"
        f"Rule Group:{rule.get('group', '')}",
    ]

    # Dynamic Prompt
    if specific_prompt:
        lines.append(specific_prompt)

    lines.append("")
    lines.append("Here is the list of data that needs to be analyzed:")

    for item in items:
        idx = item.get("index", 0)
        data = item.get("data", {})
        ctx = data.get("context", {})
        lines.append(
            f"[{idx}] Match content：{data.get('match', '')}，"
            f"Previous Context text：{ctx.get('before', '')}，"
            f"Next Context text：{ctx.get('after', '')}"
        )
    return "\n".join(lines)


def parse_response(text, items):
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

    return [{"index": item.get("index", 0), "tags": "none"} for item in items]


def main():
    input_data = json.load(sys.stdin)
    rule = input_data.get("rule", {})
    items = input_data.get("items", [])

    client = OpenAI(
        api_key="",  # API Key
        base_url="http://localhost:1234/v1",
    )

    content = build_content(rule, items)
    response = client.chat.completions.create(
        model="",  # Model ID
        max_tokens=4096,
        messages=[{"role": "user", "content": f"{PROMPT}\n\n{content}"}],
    )

    text = response.choices[0].message.content.strip()
    results = parse_response(text, items)
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
