# -*- coding: utf-8 -*-
"""
基于Flask的用户登录注册后端服务
功能：用户注册/登录、本地关键词+GLM-4-Flash昵称违规检测、资源权限控制
数据存储：users.json
优化点：本地词库前置过滤、响应日志、超时控制、结果缓存
"""

import json
import os
import time
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# ----------------------------- 配置项 ---------------------------------------
# 智谱API配置
API_KEY = os.getenv("GLM_API_KEY", "")  # 智谱API Key
GLM_API_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions"  # GLM-4-Flash接口地址

# 本地违规词库（包含常见违规词、谐音、变体）
VIOLATION_KEYWORDS = {
    # 辱骂类
    "傻逼", "傻比", "sb", "操你妈", "草泥马", "cnm", "妈的", "md", "智障", "zz",
    "脑瘫", "nt", "废物", "fw", "去死", "滚蛋", "gun", "狗东西", "狗娘养的",
    # 低俗类
    "嫖娼", "约炮", "yp", "做爱", "性交", "鸡巴", "jb", "逼养的", "逼玩意",
    "裸聊", "露点", "黄片", "色情", "seqing", "骚货", "浪货", "破鞋",
    # 广告/导流类
    "加微信", "加wx", "微信红包", "二维码", "刷单", "兼职", "赌博", "博彩",
    # 敏感政治类（示例，可根据实际需求调整）
    "台独", "藏独", "港独", "法轮功", "邪教",
    # 变体/谐音类
    "沙比", "煞笔", "曹尼玛", "操泥马", "智涨", "脑摊", "费物", "苟东西"
}

# LLM请求超时时间（秒）
LLM_TIMEOUT = 3

# 昵称审核结果缓存（内存字典，key=用户名，value=(是否违规, 缓存时间)）
NICKNAME_CACHE = {}
# 缓存过期时间（秒），默认1小时
CACHE_EXPIRE_SECONDS = 3600

# ----------------------------- Flask应用初始化 -------------------------------
app = Flask(__name__)
CORS(app)  # 开启跨域，允许前端跨域请求

# 静态文件目录配置
app.static_folder = './static'
app.static_url_path = '/static'

# ----------------------------- 辅助函数：读写users.json -----------------------
def read_users():
    """
    读取users.json文件，返回用户列表
    若文件不存在或格式错误，返回空列表
    """
    if not os.path.exists('users.json'):
        return []
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            users = json.load(f)
            # 确保每个用户都包含allow_resB字段（兼容旧数据）
            for user in users:
                if 'allow_resB' not in user:
                    user['allow_resB'] = False
            return users
    except (json.JSONDecodeError, IOError) as e:
        print(f"读取users.json失败: {e}")
        return []

def write_users(users):
    """
    将用户列表写入users.json文件
    """
    try:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=4)
        return True
    except IOError as e:
        print(f"写入users.json失败: {e}")
        return False

def find_user_by_username(username):
    """
    根据用户名查找用户，返回用户字典或None
    """
    users = read_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

# ----------------------------- 本地关键词过滤 -------------------------------
def check_local_keyword(username):
    """
    本地关键词匹配检测
    参数：username - 待检测的用户名
    返回值：True表示命中违规词，False表示未命中
    """
    if not username:
        return False
    
    # 统一转为小写，提高匹配率
    username_lower = username.lower()
    
    # 遍历关键词库匹配
    for keyword in VIOLATION_KEYWORDS:
        if keyword.lower() in username_lower:
            print(f"本地词库命中违规关键词: {keyword}，用户名: {username}")
            return True
    return False

# ----------------------------- 缓存管理函数 ----------------------------------
def get_cached_result(username):
    """
    从缓存获取昵称审核结果
    返回：None（无缓存/过期） 或 bool（是否违规）
    """
    if username not in NICKNAME_CACHE:
        return None
    
    # 检查缓存是否过期
    is_illegal, cache_time = NICKNAME_CACHE[username]
    if time.time() - cache_time > CACHE_EXPIRE_SECONDS:
        del NICKNAME_CACHE[username]
        return None
    
    print(f"命中缓存，用户名: {username}，违规状态: {is_illegal}")
    return is_illegal

def set_cached_result(username, is_illegal):
    """
    设置昵称审核结果到缓存
    """
    NICKNAME_CACHE[username] = (is_illegal, time.time())
    # 清理过期缓存（可选，防止内存溢出）
    clean_expired_cache()

def clean_expired_cache():
    """
    清理过期的缓存数据
    """
    current_time = time.time()
    expired_keys = [
        key for key, (_, cache_time) in NICKNAME_CACHE.items()
        if current_time - cache_time > CACHE_EXPIRE_SECONDS
    ]
    for key in expired_keys:
        del NICKNAME_CACHE[key]
    if expired_keys:
        print(f"清理过期缓存，数量: {len(expired_keys)}")

# ----------------------------- GLM-4-Flash昵称违规检测 -----------------------
def check_llm_nickname_violation(username):
    """
    调用智谱GLM-4-Flash检测昵称是否违规
    参数：username - 待检测的用户名
    返回值：True表示违规，False表示正常
    异常或失败时默认返回False（不阻断注册）
    """
    # 构造提示词
    prompt = f"你是社区昵称审核员，判断输入内容是否为违规昵称（包含辱骂、低俗、广告、敏感内容），仅严格返回两个单词：normal 或 illegal，不要任何多余文字。待检测内容：{username}"

    # 构造请求头（直接使用API Key作为Bearer Token）
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }

    # 构造请求体（GLM-4-Flash接口标准格式）
    payload = {
        "model": "glm-4-flash",   # 使用flash模型
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,       # 低温度保证输出确定性
        "max_tokens": 10          # 限制输出长度，只需返回一个单词
    }

    try:
        print(f"正在调用GLM检测昵称: {username}")
        # 设置超时时间，防止请求阻塞
        response = requests.post(GLM_API_URL, json=payload, headers=headers, timeout=LLM_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            # 解析返回结果，获取模型输出的内容
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '').strip().lower()
            print(f"LLM返回内容: {content}")
            if content == 'illegal':
                print(f"昵称 '{username}' 被LLM判定为违规")
                return True   # 违规
            else:
                print(f"昵称 '{username}' 通过LLM检测")
                return False  # 正常或非预期返回
        else:
            print(f"调用GLM接口失败，状态码: {response.status_code}, 响应: {response.text}")
            return False  # 接口失败，默认不违规
    except requests.RequestException as e:
        print(f"请求GLM接口异常/超时: {e}")
        return False  # 网络异常/超时，默认不违规

# ----------------------------- 统一昵称审核入口 -------------------------------
def check_nickname(username):
    """
    统一的昵称审核入口（本地词库 + 缓存 + LLM分层校验）
    参数：username - 待检测的用户名
    返回值：True表示违规，False表示正常
    """
    # 1. 先查缓存
    cached_result = get_cached_result(username)
    if cached_result is not None:
        return cached_result
    
    # 2. 本地关键词过滤（前置校验）
    if check_local_keyword(username):
        set_cached_result(username, True)
        return True
    
    # 3. 本地未命中，调用LLM检测
    llm_result = check_llm_nickname_violation(username)
    set_cached_result(username, llm_result)
    return llm_result

# ----------------------------- API接口实现 -----------------------------------
@app.route('/api/register', methods=['POST'])
def register():
    """
    用户注册接口
    入参：username, password
    逻辑：检查用户名是否存在 -> 统一昵称审核 -> 写入用户数据
    """
    # 记录接口响应开始时间
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"code": 400, "msg": "请求数据不能为空"}), 400

        username = data.get('username')
        password = data.get('password')

        # 参数校验
        if not username or not password:
            return jsonify({"code": 400, "msg": "用户名和密码不能为空"}), 400

        # 1. 判断用户名是否已存在
        existing_user = find_user_by_username(username)
        if existing_user:
            return jsonify({"code": 400, "msg": "用户名已存在"}), 200

        # 2. 统一昵称审核（本地+LLM+缓存）
        is_illegal = check_nickname(username)
        if is_illegal:
            return jsonify({"code": 400, "msg": "昵称违规，无法注册"}), 200

        # 3. 注册通过，写入新用户（默认allow_resB=false）
        new_user = {
            "username": username,
            "password": password,       # 生产环境应加密，此处仅为演示
            "allow_resB": False
        }
        users = read_users()
        users.append(new_user)
        if write_users(users):
            return jsonify({"code": 200, "msg": "注册成功"}), 200
        else:
            return jsonify({"code": 500, "msg": "服务器写入失败"}), 500
    finally:
        # 记录响应时间并打印日志
        response_time = round((time.time() - start_time) * 1000, 2)  # 转为毫秒
        print(f"接口 /api/register 响应时间: {response_time}ms，用户名: {username if 'username' in locals() else '未知'}")

@app.route('/api/login', methods=['POST'])
def login():
    """
    用户登录接口
    入参：username, password
    返回：登录结果及allow_resB权限标志
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"code": 400, "msg": "请求数据不能为空"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"code": 400, "msg": "用户名和密码不能为空"}), 400

        # 查找用户
        user = find_user_by_username(username)
        if user and user.get('password') == password:
            # 确保allow_resB字段存在
            allow_resB = user.get('allow_resB', False)
            return jsonify({
                "code": 200,
                "msg": "登录成功",
                "allow_resB": allow_resB
            }), 200
        else:
            return jsonify({"code": 400, "msg": "账号或密码错误"}), 200
    finally:
        response_time = round((time.time() - start_time) * 1000, 2)
        print(f"接口 /api/login 响应时间: {response_time}ms，用户名: {username if 'username' in locals() else '未知'}")

@app.route('/api/check_auth', methods=['POST'])
def check_auth():
    """
    权限校验接口
    入参：username
    返回：allow_resA（固定true）和 allow_resB（从用户数据读取）
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"code": 400, "msg": "请求数据不能为空"}), 400

        username = data.get('username')
        if not username:
            return jsonify({"code": 400, "msg": "缺少username参数"}), 400

        user = find_user_by_username(username)
        if not user:
            # 用户不存在，但依旧返回allow_resA=true,allow_resB=false
            return jsonify({
                "code": 200,
                "allow_resA": True,
                "allow_resB": False
            }), 200
        else:
            allow_resB = user.get('allow_resB', False)
            return jsonify({
                "code": 200,
                "allow_resA": True,
                "allow_resB": allow_resB
            }), 200
    finally:
        response_time = round((time.time() - start_time) * 1000, 2)
        print(f"接口 /api/check_auth 响应时间: {response_time}ms，用户名: {username if 'username' in locals() else '未知'}")

# ----------------------------- 启动服务 -------------------------------------
if __name__ == '__main__':
    # 确保静态文件目录存在
    if not os.path.exists('./static'):
        os.makedirs('./static')
    app.run(debug=False, host='0.0.0.0')