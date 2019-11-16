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
PATH_DESTINATION_KEY = 'path_destination'  # copy destination
FULL_PATH_DESTINATION_KEY = 'full_path_destination'
CONGESTION_KEY = 'congestion'
NODE_IP_KEY = 'node_ip'
FILE_SIZE_KEY = 'file_size'
EXISTS_KEY = 'exists'
DIR_LIST_KEY = 'dir_list'
FORCE_KEY = 'force'

TOKEN_TTL_MINUTES = 30
TOKEN_FILE = "token.tk"

NAMENODE_IP = "127.0.0.1"

ROOT = "/var/storage"

try:
    SECRET_KEY = os.getenv('SECRET_KEY')
except ValueError as e:
    print("Environment variable `SECRET_KEY` is absent.")
