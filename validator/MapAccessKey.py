#!/usr/bin/env python3
# 地图 API 密钥验证器
# HAE 正则: ((https?://(?:api\.map\.baidu\.com|webapi\.amap\.com|restapi\.amap\.com|apis\.map\.qq\.com)[^\s"'<>]+?(?:\?|&|&amp;)(?:ak|key)=([A-Za-z0-9\-]{16,64}))|securityJsCode\s*[:=]\s*['"]([a-z0-9]{16,64})['"])
import json
import re
import sys
import ssl
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# 禁用 SSL 证书验证
ssl._create_default_https_context = ssl._create_unverified_context

# 正则表达式模式
KEY_PATTERN = re.compile(r'(?:\?|&|&amp;)(?:ak|key)=([A-Za-z0-9]{16,64})', re.I)
SECURITY_CODE_PATTERN = re.compile(r'securityJsCode\s*[:=]\s*[\'"]([a-z0-9]{16,64})[\'"]', re.I)
KV_PATTERN = re.compile(r'"([^"]*?)"\s*[:\uff1a]\s*"([^"]*?)"')

# 验证接口 URL
AMAP_REGEO_URL = "https://restapi.amap.com/v3/geocode/regeo?key={}&s=rsv3&location=116.434446,39.90816"
AMAP_WALKING_URL = "https://restapi.amap.com/v3/direction/walking?origin=116.434307,39.90909&destination=117.434446,39.90816&key={}&jscode={}&s=rsv3"
BAIDU_PLACE_URL = "https://api.map.baidu.com/place/v2/search?query=ATM&tag=银行&region=北京&output=json&ak={}"
QQ_PLACE_URL = "https://apis.map.qq.com/ws/place/v1/search?keyword=酒店&boundary=nearby(39.908491,116.374328,1000)&key={}"


def extract_credentials(match_string):
    """从字符串中提取 API 密钥或安全代码"""
    if not match_string:
        return None, None
    
    # 匹配 URL 中的 key/ak
    key_match = KEY_PATTERN.search(match_string)
    if key_match:
        return "ak", key_match.group(1)
    
    # 匹配 securityJsCode
    security_code_match = SECURITY_CODE_PATTERN.search(match_string)
    if security_code_match:
        return "jscode", security_code_match.group(1)
    
    return None, None


def send_http_request(url):
    """发送 HTTP GET 请求并返回响应内容"""
    try:
        request = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(request, timeout=8) as response:
            return response.read().decode("utf-8", errors="ignore")
    except HTTPError as http_error:
        try:
            return http_error.read().decode(errors="ignore")
        except Exception:
            return None
    except Exception:
        return None

def verify_amap_key(api_key, security_code=None):
    """验证高德地图 API 密钥"""
    if security_code:
        response = send_http_request(AMAP_WALKING_URL.format(api_key, security_code))
        return bool(response and '"status":"1"' in response)
    else:
        response = send_http_request(AMAP_REGEO_URL.format(api_key))
        return bool(response and '"status":"1"' in response)

def verify_baidu_key(api_key):
    """验证百度地图 API 密钥"""
    response = send_http_request(BAIDU_PLACE_URL.format(api_key))
    return bool(response and '"status":0' in response)

def verify_qq_key(api_key):
    """验证腾讯地图 API 密钥"""
    response = send_http_request(QQ_PLACE_URL.format(api_key))
    return bool(response and '"status":0' in response)

def verify_credentials(api_key, security_code=None):
    """验证 API 密钥是否有效"""
    # 验证高德地图
    if security_code and verify_amap_key(api_key, security_code):
        return True
    if not security_code and verify_amap_key(api_key):
        return True
    
    # 验证百度地图
    if verify_baidu_key(api_key):
        return True
    
    # 验证腾讯地图
    if verify_qq_key(api_key):
        return True
    
    return False

def main():
    """主函数，处理输入数据并验证 API 密钥"""
    data = json.load(sys.stdin)
    items = data.get("items", [])

    api_keys = []  # [(index, key), ...]
    security_codes = []  # [(index, code), ...]
    
    # 提取 API 密钥和安全代码
    for item in items:
        match_data = item.get("data", {}).get("match", "")
        credential_type, credential_value = extract_credentials(match_data)
        item_index = item.get("index", 0)
        
        if credential_type == "ak":
            api_keys.append((item_index, credential_value))
        elif credential_type == "jscode":
            security_codes.append((item_index, credential_value))

    valid_indices = set()
    
    # 验证 API 密钥
    for api_key_index, api_key_value in api_keys:
        if security_codes:
            # 有安全代码，尝试组合验证
            for security_code_index, security_code_value in security_codes:
                try:
                    if verify_credentials(api_key_value, security_code_value):
                        valid_indices.add(api_key_index)
                        valid_indices.add(security_code_index)
                except Exception:
                    pass
        else:
            # 只有 API 密钥
            try:
                if verify_credentials(api_key_value):
                    valid_indices.add(api_key_index)
            except Exception:
                pass

    # 生成结果
    results = [
        {
            "index": item.get("index", 0),
            "tags": "high" if item.get("index", 0) in valid_indices else "none",
        }
        for item in items
    ]
    
    print(json.dumps({"results": results}))

if __name__ == "__main__":
    main()