import ssl
import logging
import http.server
import http.client
import re
import random
import string
import time
import urllib3
import json
from socketserver import ThreadingMixIn
from urllib import parse
from threading import Timer
from publicsuffix2 import PublicSuffixList
import requests
from http import HTTPStatus

# Load configuration and users from JSON files
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

with open('users.json', 'r') as users_file:
    users_data = json.load(users_file)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

http.client._MAXHEADERS = 1000

# Session management class
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
        deleting_sessions = list()
        for _session in self.sessions:
            if now - _session[1] > self.age:
                deleting_sessions.append(_session)
        for _session in deleting_sessions:
            self.sessions.remove(_session)
        Timer(self.recycle_interval, self.recycle_session).start()


sessions = Sessions()


# User management class
class Users(object):
    def __init__(self):
        self.users = users_data

    def is_effective_user(self, user_name, password):
        if user_name in self.users and password == self.users.get(user_name):
            return True
        else:
            return False


users = Users()


# Template management class
class Template(object):
    def __init__(self):
        with open(config['INDEX_FILE'], encoding='utf-8') as f:
            self.index_html = f.read()
        with open(config['LOGIN_FILE'], encoding='utf-8') as f:
            self.login_html = f.read()

    def get_index_html(self):
        return self.index_html

    def get_login_html(self, login_failed=False):
        if login_failed:
            return self.login_html.format(login_failed=1)
        else:
            return self.login_html.format(login_failed=0)


template = Template()


# Proxy class
class Proxy(object):
    def __init__(self, handler):
        self.handler = handler
        self.url = self.handler.path[1:]
        parse_result = parse.urlparse(self.url)
        self.scheme = parse_result.scheme
        self.netloc = parse_result.netloc
        self.site = self.scheme + '://' + self.netloc
        self.path = parse_result.path

    def proxy(self):
        self.process_request()
        content_length = int(self.handler.headers.get('Content-Length', 0))
        data = self.handler.rfile.read(content_length)
        try:
            r = requests.request(method=self.handler.command, url=self.url, headers=self.handler.headers,
                                 data=data, verify=False, allow_redirects=False)
        except BaseException as error:
            self.process_error(error)
        else:
            self.process_response(r)

    def process_request(self):
        self.modify_request_header('Referer', lambda x: x.replace(config['SERVER'], ''))
        self.modify_request_header('Origin', self.site)
        self.modify_request_header('Host', self.netloc)
        self.modify_request_header('Accept-Encoding', 'identity')
        self.modify_request_header('Connection', 'close')

    def process_response(self, r):
        self.handler.send_response(r.status_code)
        content = self.revision_link(r.content, r.encoding)
        if 'location' in r.headers._store:
            self.handler.send_header('Location', self.revision_location(r.headers._store['location'][1]))
        if 'content-type' in r.headers._store:
            self.handler.send_header('Content-Type', r.headers._store['content-type'][1])
        if 'set-cookie' in r.headers._store:
            self.revision_set_cookie(r.headers._store['set-cookie'][1])
        self.handler.send_header('Content-Length', len(content))
        self.handler.send_header('Access-Control-Allow-Origin', '*')
        self.handler.send_header('Connection', 'close')
        self.handler.end_headers()
        self.handler.wfile.write(content)

    def process_error(self, error):
        self.handler.send_error(HTTPStatus.BAD_REQUEST, str(error))

    def modify_request_header(self, header, value):
        target_header = None
        for _header in self.handler.headers._headers:
            if _header[0] == header:
                target_header = _header
                break
        if target_header is not None:
            self.handler.headers._headers.remove(target_header)
            if callable(value):
                new_header_value = value(target_header[1])
            else:
                new_header_value = value
            self.handler.headers._headers.append((header, new_header_value))

    def revision_location(self, location):
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
        if coding is None:
            return body
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
            body = body.replace(rule[0].replace('{}', '').encode('utf-8'), rule[0].format(rule[1]).encode('utf-8'))
        return body

    def revision_set_cookie(self, cookies):
        cookie_list = list()
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


# HTTP request handler class
class SilkRoadHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
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
        with open(config['STYLE_FILE'], 'r', encoding='utf-8') as f:
            self.style_data = f.read()
        with open(config['SCRIPT_FILE'], 'r', encoding='utf-8') as f:
            self.script_data = f.read()
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
        if self.path == self.login_path or self.path == self.favicon_path:
            return True
        session = self.get_request_cookie(self.session_cookie_name)
        if sessions.is_session_exist(session):
            return True
        else:
            return False

    def process_original(self):
        if self.path == self.favicon_path:
            self.process_favicon()
        elif self.path == self.style_path:
            self.process_css()
        elif self.path == self.script_path:
            self.process_js()
        elif self.path == self.login_path:
            self.process_login()
        else:
            self.process_index()

    def process_login(self):
        if self.command == 'POST':
            content_length = int(self.headers['Content-Length'])
            raw_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = parse.parse_qs(parse.unquote(raw_data))
            if 'user' in parsed_data and 'password' in parsed_data:
                if users.is_effective_user(parsed_data['user'][0], parsed_data['password'][0]):
                    session = sessions.generate_new_session()
                    self.send_response(http.HTTPStatus.FOUND)
                    self.send_header('Location', '/')
                    self.send_header('Set-Cookie', '{}={}; expires=Sun, 30-Jun-3000 02:06:18 GMT; path=/; HttpOnly'.format(self.session_cookie_name, session))
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

    def process_css(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/css; charset=UTF-8')
        self.end_headers()
        self.wfile.write(self.style_data)

    def process_js(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript; charset=UTF-8')
        self.end_headers()
        self.wfile.write(self.script_data)

    def return_html(self, body):
        self.send_response(200)
        self.send_header('Content-Length', len(body))
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def is_need_proxy(self):
        return self.path[1:].startswith('http://') or self.path[1:].startswith('https://')

    def pre_process_path(self):
        if self.path.startswith('/?url='):
            self.path = self.path.replace('/?url=', '/', 1)
        if self.is_start_with_domain(self.path[1:]):
            self.path = '/https://' + self.path[1:]
        if not self.is_need_proxy():
            referer = self.get_request_header('Referer')
            if referer is not None and parse.urlparse(referer.replace(config['SERVER'], '')).netloc != '':
                self.path = '/' + referer.replace(config['SERVER'], '') + self.path

    def get_request_cookie(self, cookie_name):
        cookies = str()
        for header in self.headers._headers:
            if header[0] == 'Cookie':
                cookies = header[1].split('; ')
                break
        for cookie in cookies:
            _cookie = cookie.split('=')
            if len(_cookie) == 2 and _cookie[0] == cookie_name:
                return _cookie[1]
        return str()

    def get_request_header(self, header_name):
        for header in self.headers._headers:
            if header[0] == header_name:
                return header[1]
        return None

    def version_string(self):
        return self.server_name

    def redirect_to_login(self):
        self.send_response(http.HTTPStatus.FOUND)
        self.send_header('Location', self.login_path)
        self.end_headers()

    def is_start_with_domain(self, string):
        domain = self.domain_re.match(string)
        psl = PublicSuffixList()
        if domain is None or domain.group(1)[1:] not in psl.tlds:
            return False
        else:
            return True


# HTTP Server class with threading
class ThreadingHttpServer(ThreadingMixIn, http.server.HTTPServer):
    pass


# Main server logic
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        filename=config['LOG_FILE'],
        filemode='a',
        format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
    )

    with ThreadingHttpServer((config['BIND_IP'], config['PORT']), SilkRoadHTTPRequestHandler) as httpd:
        if config['SCHEME'] == 'https':
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=config['CERT_FILE'], keyfile=config['KEY_FILE'])
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f'Serving HTTP on {config["BIND_IP"]} port {config["PORT"]} ({config["SCHEME"]}://{config["DOMAIN"]}:{config["PORT"]}/) ...')
        httpd.serve_forever()
