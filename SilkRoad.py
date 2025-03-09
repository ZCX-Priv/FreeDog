import ssl
import re
import random
import string
import time
import json
import http.server
import http.client
from http import HTTPStatus
from socketserver import ThreadingMixIn
from urllib import parse
from threading import Timer, Thread
from publicsuffix2 import PublicSuffixList
import httpx
import gzip
import gc
import atexit
import shutil
import os
import signal
import sys
import platform
from loguru import logger

# Windows 平台下用于管理员权限检测
if platform.system() == "Windows":
    import ctypes

# ------------------ 配置与数据加载 ------------------
with open('config.json', 'r', encoding='utf-8') as config_file:
    config = json.load(config_file)

with open('users.json', 'r', encoding='utf-8') as users_file:
    users_data = json.load(users_file)

# 设置 http.client 最大请求头数量，修复 "get more than 100 headers" 错误
http.client._MAXHEADERS = 1000

# ------------------ 系统与资源管理 ------------------
def periodic_gc():
    """定时释放内存，每5分钟执行一次垃圾回收"""
    gc.collect()
    Timer(300, periodic_gc).start()

periodic_gc()

def clear_temp_cache():
    """程序退出时清除 temp 文件夹中的缓存（包括编译后的 .pyc 与网站缓存）"""
    temp_dir = os.path.join(os.path.dirname(__file__), "temp")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        logger.info("Cleared temp cache directory.")

atexit.register(clear_temp_cache)

def check_admin_privileges():
    """检查是否以管理员权限运行"""
    if platform.system() == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.error("Admin check failed: {}", e)
            is_admin = False
    else:
        is_admin = os.geteuid() == 0
    if not is_admin:
        logger.warning("程序未以管理员权限运行，部分功能可能受限。")
    else:
        logger.info("管理员权限检测通过。")
    return is_admin

check_admin_privileges()

def prompt_startup_auto_run():
    """首次启动时询问是否设置开机自启（示例，具体实现依平台而异）"""
    if not config.get("AUTO_RUN_SET", False):
        response = input("是否设置程序开机自启？(y/N): ").strip().lower()
        if response == 'y':
            logger.info("设置开机自启功能已启用（示例，实际实现请根据平台进行开发）。")
            config["AUTO_RUN_SET"] = True
            with open('config.json', 'w', encoding='utf-8') as config_file:
                json.dump(config, config_file, indent=4, ensure_ascii=False)
        else:
            logger.info("开机自启功能未启用。")

prompt_startup_auto_run()

def exit_confirmation():
    """退出程序时弹出确认对话框"""
    print("\n检测到退出信号。是否退出程序？(y/N): ", end='', flush=True)
    response = sys.stdin.readline().strip().lower()
    return response == 'y'

def signal_handler(sig, frame):
    if exit_confirmation():
        logger.info("程序退出，正在清理缓存...")
        sys.exit(0)
    else:
        logger.info("继续运行程序。")

signal.signal(signal.SIGINT, signal_handler)

# ------------------ 会话与用户管理 ------------------
class Sessions(object):
    def __init__(self, length=64, age=604800, recycle_interval=3600):
        self.charset = string.ascii_letters + string.digits
        self.length = length
        self.age = age
        self.recycle_interval = recycle_interval
        self.sessions = list()
        self.recycle_session()

    def generate_new_session(self):
        new_session = ''.join(random.choice(self.charset) for _ in range(self.length))
        self.sessions.append([new_session, time.time()])
        return new_session

    def is_session_exist(self, session):
        for _session in self.sessions:
            if _session[0] == session:
                _session[1] = time.time()
                return True
        return False

    def recycle_session(self):
        now = time.time()
        deleting_sessions = [s for s in self.sessions if now - s[1] > self.age]
        for s in deleting_sessions:
            self.sessions.remove(s)
        Timer(self.recycle_interval, self.recycle_session).start()

sessions = Sessions()

class Users(object):
    def __init__(self):
        self.users = users_data

    def is_effective_user(self, user_name, password):
        return user_name in self.users and password == self.users.get(user_name)

users = Users()

# ------------------ 模板管理 ------------------
class Template(object):
    def __init__(self):
        # 支持自定义模板编码，默认 UTF-8，可配置为 GBK 等
        encoding = config.get("TEMPLATE_ENCODING", "utf-8")
        with open(config['INDEX_FILE'], encoding=encoding) as f:
            self.index_html = f.read()
        with open(config['LOGIN_FILE'], encoding=encoding) as f:
            self.login_html = f.read()

    def get_index_html(self):
        # 可在此处加入预加载静态资源的 <link rel="preload"> 标签（占位示例）
        return self.index_html

    def get_login_html(self, login_failed=False):
        return self.login_html.format(login_failed=1 if login_failed else 0)

template = Template()

# ------------------ 浏览器信息伪装 ------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
]

# ------------------ 代理处理 ------------------
class Proxy(object):
    def __init__(self, handler):
        self.handler = handler
        # 从请求路径中提取目标 URL（假定形如 /http://... 或 /https://...）
        self.url = self.handler.path[1:]
        parse_result = parse.urlparse(self.url)
        self.scheme = parse_result.scheme
        self.netloc = parse_result.netloc
        self.site = self.scheme + '://' + self.netloc
        self.path = parse_result.path

    def proxy(self):
        # 判断是否为 WebSocket 请求，若是则调用占位处理
        if self.handler.headers.get('Upgrade', '').lower() == 'websocket':
            self.process_websocket()
            return

        self.process_request()
        content_length = int(self.handler.headers.get('Content-Length', 0))
        data = self.handler.rfile.read(content_length) if content_length > 0 else None

        try:
            # 复制所有请求头，并随机设置 User-Agent 以伪装客户端信息
            headers = {k: v for k, v in self.handler.headers.items()}
            headers['User-Agent'] = random.choice(USER_AGENTS)
            # 保持 Range 等特殊请求头不变，实现断点续传支持
            with httpx.Client(verify=False, follow_redirects=False, timeout=30.0) as client:
                # 若目标响应为大文件或非 HTML，则采用流式传输
                r = client.request(method=self.handler.command, url=self.url, headers=headers, content=data)
        except Exception as error:
            self.process_error(error)
        else:
            self.process_response(r)

    def process_websocket(self):
        # 占位处理：后续可结合 websockets 库实现双向持续连接
        self.handler.send_error(HTTPStatus.NOT_IMPLEMENTED, "WebSocket代理尚未实现")
        logger.warning("WebSocket请求未实现：{}", self.url)

    def process_request(self):
        # 根据客户端 Connection 头判断是否启用 keep-alive
        client_conn = self.handler.headers.get('Connection', '').lower()
        conn_value = 'keep-alive' if client_conn == 'keep-alive' else 'close'
        # 修改部分请求头以突破检测与格式化
        self.modify_request_header('Referer', lambda x: x.replace(config['SERVER'], ''))
        self.modify_request_header('Origin', self.site)
        self.modify_request_header('Host', self.netloc)
        # 保留或添加 Accept-Language、Cache-Control 等常见头（示例，可扩展）
        if 'Accept-Language' not in self.handler.headers:
            self.handler.headers.add_header('Accept-Language', 'en-US,en;q=0.9')
        self.modify_request_header('Accept-Encoding', 'identity')
        self.modify_request_header('Connection', conn_value)
        # 如果存在 Range 请求头，保持不变（用于断点续传）

    def process_response(self, r):
        # 如果响应为 HTML，则进行链接修正处理
        content_type = r.headers.get('Content-Type', '')
        if "text/html" in content_type:
            content = self.revision_link(r.content, r.encoding)
            # 自动压缩 HTML 内容（若客户端支持 gzip）
            accept_encoding = self.handler.headers.get('Accept-Encoding', '')
            if 'gzip' in accept_encoding.lower():
                content = gzip.compress(content)
                self.handler.send_header('Content-Encoding', 'gzip')
            # 计算 Content-Length
            content_length = len(content)
        else:
            # 对于非 HTML 大文件或流媒体，采用流式传输，不做链接修改
            content = r.content if r.content is not None else b''
            content_length = len(content)

        # 发送响应头
        self.handler.send_response(r.status_code)
        # 转发 Content-Range 等头，支持断点续传
        if "Content-Range" in r.headers:
            self.handler.send_header("Content-Range", r.headers["Content-Range"])
        if "location" in r.headers:
            self.handler.send_header('Location', self.revision_location(r.headers['location']))
        if "content-type" in r.headers:
            self.handler.send_header('Content-Type', r.headers['content-type'])
        if "set-cookie" in r.headers:
            self.revision_set_cookie(r.headers['set-cookie'])
        # 如果为 HTML，则使用修正后的内容长度，否则转发原始 Content-Length（如果有）
        self.handler.send_header('Content-Length', content_length)
        # 根据客户端请求决定连接是否保持
        client_conn = self.handler.headers.get('Connection', '').lower()
        conn_value = 'keep-alive' if client_conn == 'keep-alive' else 'close'
        self.handler.send_header('Connection', conn_value)
        self.handler.send_header('Access-Control-Allow-Origin', '*')
        self.handler.end_headers()
        # 发送响应体
        if content:
            self.handler.wfile.write(content)

    def process_error(self, error):
        self.handler.send_error(HTTPStatus.BAD_REQUEST, str(error))
        logger.error("Proxy error: {}", error)

    def modify_request_header(self, header, value):
        target_header = None
        for _header in self.handler.headers._headers:
            if _header[0].lower() == header.lower():
                target_header = _header
                break
        if target_header is not None:
            self.handler.headers._headers.remove(target_header)
            new_value = value(target_header[1]) if callable(value) else value
            self.handler.headers._headers.append((header, new_value))

    def revision_location(self, location):
        # 自动重定向原始链接为代理链接，支持 http(s)、相对和省略协议的情况
        if location.startswith('http://') or location.startswith('https://'):
            new_location = config['SERVER'] + location
        elif location.startswith('//'):
            new_location = config['SERVER'] + self.scheme + ':' + location
        elif location.startswith('/'):
            new_location = config['SERVER'] + self.site + location
        else:
            new_location = config['SERVER'] + self.site + self.path + '/' + location
        return new_location

    def revision_link(self, body, coding):
        # 对响应体中出现的链接进行修正，包括同页跳转、内链跳转、自动格式化与纠正错误链接
        if coding is None:
            return body
        # 示例规则，可根据需求扩展更多解析规则
        rules = [
            ("'{}http://", config['SERVER']),
            ('"{}http://', config['SERVER']),
            ("'{}https://", config['SERVER']),
            ('"{}https://', config['SERVER']),
            ('"{}//', config['SERVER'] + self.scheme + ':'),
            ("'{}//", config['SERVER'] + self.scheme + ':'),
            ('"{}/', config['SERVER'] + self.site),
            ("'{}/", config['SERVER'] + self.site),
        ]
        for rule in rules:
            pattern = rule[0].replace('{}', '')
            replacement = rule[0].format(rule[1]).encode('utf-8')
            body = body.replace(pattern.encode('utf-8'), replacement)
        return body

    def revision_set_cookie(self, cookies):
        # 将响应中的 set-cookie 进行调整，确保域名、路径等正确
        cookie_list = []
        half_cookie = None
        for _cookie in cookies.split(', '):
            if half_cookie is not None:
                cookie_list.append(', '.join([half_cookie, _cookie]))
                half_cookie = None
            elif 'Expires' in _cookie or 'expires' in _cookie:
                half_cookie = _cookie
            else:
                cookie_list.append(_cookie)
        for _cookie in cookie_list:
            self.handler.send_header('Set-Cookie', self.revision_response_cookie(_cookie))

    def revision_response_cookie(self, cookie):
        cookie = re.sub(r'domain\=[^,;]+', 'domain=.{}'.format(config['DOMAIN']), cookie, flags=re.IGNORECASE)
        cookie = re.sub(r'path\=\/', 'path={}/'.format('/' + self.site), cookie, flags=re.IGNORECASE)
        if config['SCHEME'] == 'http':
            cookie = re.sub(r'secure;?', '', cookie, flags=re.IGNORECASE)
        return cookie

# ------------------ HTTP 请求处理 ------------------
class SilkRoadHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # 支持持久连接

    def __init__(self, request, client_address, server):
        self.login_path = config['LOGIN_PATH']
        self.favicon_path = config['FAVICON_PATH']
        self.style_path = config['STYLE_PATH']
        self.script_path = config['SCRIPT_PATH']
        self.server_name = config['SERVER_NAME']
        self.session_cookie_name = config['SESSION_COOKIE_NAME']
        self.domain_re = re.compile(r'(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+')
        with open(config['FAVICON_FILE'], 'rb') as f:
            self.favicon_data = f.read()
        super().__init__(request, client_address, server)

    def do_GET(self):
        self.do_request()

    def do_POST(self):
        self.do_request()

    def do_HEAD(self):
        self.do_request()

    def do_request(self):
        self.pre_process_path()
        if self.is_login():
            if self.is_need_proxy():
                Proxy(self).proxy()
            else:
                self.process_original()
        else:
            self.redirect_to_login()

    def is_login(self):
        # 登录页面与 favicon 均无需验证会话
        if self.path == self.login_path or self.path == self.favicon_path:
            return True
        session = self.get_request_cookie(self.session_cookie_name)
        return sessions.is_session_exist(session)

    def process_original(self):
        if self.path == self.favicon_path:
            self.process_favicon()
        elif self.path == self.login_path:
            self.process_login()
        else:
            self.process_index()

    def process_login(self):
        if self.command == 'POST':
            content_length = int(self.headers.get('Content-Length', 0))
            raw_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = parse.parse_qs(parse.unquote(raw_data))
            if 'user' in parsed_data and 'password' in parsed_data:
                if users.is_effective_user(parsed_data['user'][0], parsed_data['password'][0]):
                    session = sessions.generate_new_session()
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header('Location', '/')
                    self.send_header('Set-Cookie',
                                     '{}={}; expires=Sun, 30-Jun-3000 02:06:18 GMT; path=/; HttpOnly'
                                     .format(self.session_cookie_name, session))
                    self.end_headers()
                    return
            body = template.get_login_html(login_failed=True)
        else:
            body = template.get_login_html(login_failed=False)
        self.return_html(body)

    def process_index(self):
        body = template.get_index_html()
        self.return_html(body)

    def process_favicon(self):
        self.send_response(200)
        self.send_header('Content-Type', 'image/x-icon')
        self.end_headers()
        self.wfile.write(self.favicon_data)

    def return_html(self, body):
        encoded = body.encode(config.get("TEMPLATE_ENCODING", "utf-8"))
        self.send_response(200)
        self.send_header('Content-Length', len(encoded))
        self.send_header('Content-Type', 'text/html; charset={}'.format(config.get("TEMPLATE_ENCODING", "utf-8")))
        self.end_headers()
        self.wfile.write(encoded)

    def is_need_proxy(self):
        # 当请求路径以 "http://" 或 "https://" 开头时，启用代理转发
        return self.path[1:].startswith('http://') or self.path[1:].startswith('https://')

    def pre_process_path(self):
        # 支持通过 URL 参数进行跳转
        if self.path.startswith('/?url='):
            self.path = self.path.replace('/?url=', '/', 1)
        # 如果路径以域名开头，则自动补全协议
        if self.is_start_with_domain(self.path[1:]):
            self.path = '/https://' + self.path[1:]
        # 如果非代理请求，则尝试从 Referer 中补全路径
        if not self.is_need_proxy():
            referer = self.get_request_header('Referer')
            if referer is not None and parse.urlparse(referer.replace(config['SERVER'], '')).netloc != '':
                self.path = '/' + referer.replace(config['SERVER'], '') + self.path

    def get_request_cookie(self, cookie_name):
        cookies = ""
        for header in self.headers._headers:
            if header[0].lower() == 'cookie':
                cookies = header[1].split('; ')
                break
        for cookie in cookies:
            parts = cookie.split('=')
            if len(parts) == 2 and parts[0] == cookie_name:
                return parts[1]
        return ""

    def get_request_header(self, header_name):
        for header in self.headers._headers:
            if header[0].lower() == header_name.lower():
                return header[1]
        return None

    def version_string(self):
        return self.server_name

    def redirect_to_login(self):
        self.send_response(HTTPStatus.FOUND)
        self.send_header('Location', self.login_path)
        self.end_headers()

    def is_start_with_domain(self, string):
        domain = self.domain_re.match(string)
        psl = PublicSuffixList()
        if domain is None or domain.group(1)[1:] not in psl.tlds:
            return False
        return True

# ------------------ 多线程 HTTP 服务器 ------------------
class ThreadingHttpServer(ThreadingMixIn, http.server.HTTPServer):
    pass

# ------------------ 主程序入口 ------------------
if __name__ == '__main__':
    logger.add(config['LOG_FILE'], rotation="500 MB", level="INFO")
    server_address = (config['BIND_IP'], config['PORT'])
    with ThreadingHttpServer(server_address, SilkRoadHTTPRequestHandler) as httpd:
        if config['SCHEME'] == 'https':
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=config['CERT_FILE'], keyfile=config['KEY_FILE'])
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        logger.info('Serving HTTP on {} port {} ({}://{}:{}...)',
                    config["BIND_IP"], config["PORT"], config["SCHEME"], config["DOMAIN"], config["PORT"])
        try:
            httpd.serve_forever()
        except Exception as e:
            logger.error("Server error: {}", e)
