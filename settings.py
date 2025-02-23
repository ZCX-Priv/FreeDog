import os


CERT_FILE = os.path.join('ssl', 'cert.pem')
KEY_FILE = os.path.join('ssl', 'key.pem')
FAVICON_FILE = os.path.join('static', 'favicon.ico')
STYLE_FILE = os.path.join('static', 'style.css')
SCRIPT_FILE = os.path.join('static', 'script.js')
INDEX_FILE = os.path.join('templates', 'index.html')
LOGIN_FILE = os.path.join('templates', 'login.html')
LOG_FILE = 'FreeDog.log'    # Modify this

LOGIN_PATH = '/login'
FAVICON_PATH = '/favicon.ico'
STYLE_PATH = '/style.css'
SCRIPT_PATH = '/script.js'
SERVER_NAME = 'FreeDog/1.0'
SESSION_COOKIE_NAME = 'FreeDog_session'

SCHEME = 'https'
DOMAIN = '127.0.0.1'    # Modify this
BIND_IP = '0.0.0.0'
PORT = 4430   # Modify this
SERVER = '{}://{}:{}/'.format(SCHEME, DOMAIN, PORT)    # Modify this if use Ningx as a reverse proxy

# Modify and add users
USERS = {
    'admin': 'admin',
    'FreeDog': 'GTrrlkabih',
}
