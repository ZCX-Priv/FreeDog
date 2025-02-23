import ssl
import logging
import http.server

import urllib3
from socketserver import ThreadingMixIn

from settings import *
from lib.handler import FreeDogHTTPRequestHandler


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThreadingHttpServer(ThreadingMixIn, http.server.HTTPServer):
    pass


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        filename=LOG_FILE,
        filemode='a',
        format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
    )

    with ThreadingHttpServer((BIND_IP, PORT),FreeDogHTTPRequestHandler) as httpd:
        if SCHEME == 'https':
            # 创建 SSL 上下文
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            # 使用 SSL 上下文包装套接字
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f'Serving HTTP on {BIND_IP} port {PORT} ({SCHEME}://{DOMAIN}:{PORT}/) ...')
        httpd.serve_forever()
