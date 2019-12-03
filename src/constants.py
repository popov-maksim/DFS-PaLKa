import ipaddress
import os

SUBNET = ipaddress.ip_network('192.168.77.0/24')
REPLICATION_FACTOR = 3
MAX_PING_TRIES = 2

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
FILE_BYTES = 'file'

TOKEN_TTL_MINUTES = 30

NAMENODE_IP = "172.31.45.136"

ROOT = '/home/dfs'

# try:
#     SECRET_KEY = os.getenv('SECRET_KEY')
# except ValueError as e:
#     from utils import debug_log
#     debug_log('Environment variable `SECRET_KEY` is absent.')
