import ipaddress
import os

SUBNET = ipaddress.ip_network('127.0.0.0/24')
REPLICATION_FACTOR = 3
MAX_PING_TRIES = 5

LOGIN_KEY = 'login'
ENCRYPTED_PASS_KEY = 'encrypted_pass'
TOKEN_KEY = 'token'
MESSAGE_KEY = 'message'
PATH_KEY = 'path'
FULL_PATH_KEY = 'full_path'
CONGESTION_KEY = 'congestion'
NODE_IP_KEY = 'node_ip'

TOKEN_TTL_MINUTES = 30

try:
    SECRET_KEY = os.getenv('SECRET_KEY')
except ValueError as e:
    print("Environment variable `SECRET_KEY` is absent.")
