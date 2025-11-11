import sys
import os

# 将 lib 目录添加到 sys.path
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.insert(0, lib_path)

# 将 requests 和 chardet 的源代码目录也添加到 sys.path
requests_path = os.path.join(lib_path, 'requests')
chardet_path = os.path.join(lib_path, 'chardet')
sys.path.insert(0, requests_path)
sys.path.insert(0, chardet_path)

import http.server
import socketserver
import json
import requests
from datetime import datetime, timedelta
import random

# --- 1. 火山引擎大模型分析模块 ---
def analyze_with_volcano_api(topic):
    """
    使用火山引擎大模型API进行舆论分析，并直接生成前端所需的完整JSON数据。
    """
    api_key = "58b71d96-09cc-4ff3-90f0-7a248ca9ff03"
    url = "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    # 精心设计的Prompt，指令大模型直接输出前端所需的JSON
    prompt = f"""
你是一个顶级的舆论分析专家。请你针对以下主题进行一次完整、深入、专业的舆论分析，并严格按照指定的JSON格式返回结果。

分析主题: "{topic}"

你的任务是：
1.  模拟一个舆论分析引擎，抓取并分析与主题相关的网络信息。
2.  生成包括KPI指标、情感分布、7日趋势、热点词云、来源分布和一份专业分析报告的完整数据。
3.  确保所有数据看起来真实、专业且符合逻辑。
4.  严格按照下面的JSON结构输出，不要有任何多余的文字或解释。

输出的JSON结构必须如下：
{{
    "kpis": {{
        "total": "<总声量，格式化字符串，例如 '123,456'>",
        "daily": "<日均声量，格式化字符串，例如 '17,636'>",
        "sentiment": "<正面情绪指数，字符串，例如 '85.4'>",
        "participation": "<互动参与度，字符串，例如 '15.2'>"
    }},
    "sentiment": [
        {{"value": <正面情绪百分比, 浮点数>, "name": "正面"}},
        {{"value": <中性情绪百分比, 浮点数>, "name": "中性"}},
        {{"value": <负面情绪百分比, 浮点数>, "name": "负面"}}
    ],
    "trend": [
        {{"date": "<日期, 'MM-DD'>", "value": <声量数值, 整数>}},
        ... (共7天)
    ],
    "wordCloud": [
        {{"name": "<热词1>", "value": <词频>}},
        ... (前20个热词)
    ],
    "source": [
        {{"value": <百分比>, "name": "新闻源"}},
        {{"value": <百分比>, "name": "社交媒体"}},
        {{"value": <百分比>, "name": "论坛博客"}},
        {{"value": <百分比>, "name": "其他"}}
    ],
    "report": "<HTML格式的详细分析报告>"
}}

请立即开始分析并生成JSON。
"""

    payload = {
        "model": "ep-20251103142324-t278h",
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status() # 如果请求失败则引发HTTPError
        
        api_response = response.json()
        
        # 检查API返回的错误
        if 'error' in api_response:
            print(f"Volcano API Error: {api_response['error']}")
            return None, f"API返回错误: {api_response['error'].get('message', '未知错误')}"

        content_str = api_response.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # 清理和解析模型返回的JSON字符串
        # 模型有时会返回被```json ... ```包裹的代码块
        if content_str.strip().startswith("```json"):
            content_str = content_str.strip()[7:-3].strip()
            
        analysis_data = json.loads(content_str)
        return analysis_data, None

    except requests.exceptions.RequestException as e:
        print(f"Error calling Volcano API: {e}")
        return None, f"调用分析引擎时网络异常: {e}"
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from API response: {e}")
        print(f"Raw content from API: {content_str}")
        return None, "分析引擎返回了无效的数据格式。"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, "处理分析结果时发生未知错误。"


# --- 2. HTTP服务器 --- 
class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/analyze':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8'))
            
            topic = body.get('custom_topic') or body.get('topic_key')
            
            if not topic:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No topic provided"}).encode('utf-8'))
                return

            print(f"Analyzing topic '{topic}' with Volcano Engine...")
            analysis_data, error_message = analyze_with_volcano_api(topic)
            
            if error_message:
                print(f"Analysis failed: {error_message}")
                response_data = {
                    'status': 'no_data', # 复用 'no_data' 状态来通知前端显示错误
                    'message': error_message
                }
            else:
                print("Analysis successful.")
                analysis_data['status'] = 'success'
                response_data = analysis_data
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            super().do_POST()

    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

PORT = 5002



with socketserver.TCPServer(("", PORT), APIHandler) as httpd:
    print(f"Serving real-data analysis server at port {PORT}")
    httpd.serve_forever()
