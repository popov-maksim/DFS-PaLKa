import datetime
import functools
import json
from http import HTTPStatus
from typing import Optional

import certifi
import flask
import jwt
import urllib3

from constants import *
from logger import debug_log

https_client = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
dump_redis = True


def encode_auth_token(login: str) -> str:
    """
    Generates the Auth Token
    :return: token string
    """
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_TTL_MINUTES),
        'iat': datetime.datetime.utcnow(),
        'sub': login
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode("utf-8")


def decode_auth_token(auth_token: str) -> Optional[str]:
    """
    Decodes the auth token
    :param auth_token:
    :return: string
    """
    try:
        payload = jwt.decode(auth_token.encode("utf-8"), SECRET_KEY)
        return payload['sub']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def read_token():
    with open(TOKEN_FILE, "r") as f:
        token = f.read().strip()
    return token


def save_token(token):
    with open(TOKEN_FILE, "w") as f:
        f.write(token)


def from_subnet_ip(func):
    @functools.wraps(func)
    def wrapped_function(*args, **kwargs):
        ip = flask.request.environ.get('HTTP_X_REAL_IP', flask.request.remote_addr)
        is_allowed = ip and ipaddress.ip_address(ip) in SUBNET
        debug_log(f"Query from {ip} - {'Allowed' if is_allowed else 'Denied'}")
        if is_allowed:
            return func(*args, **kwargs)
        return flask.make_response(flask.jsonify({MESSAGE_KEY: "Who are you? GTFO!"}), HTTPStatus.FORBIDDEN)

    return wrapped_function


def log_route(func):
    @functools.wraps(func)
    def wrapped_function(*args, **kwargs):
        file_name = os.path.basename(func.__globals__['__file__'])
        ip = flask.request.environ.get('HTTP_X_REAL_IP', flask.request.remote_addr)
        debug_log(f"[{file_name}] --> Func <{func.__name__}> called from {ip} | Flask params: {flask.request.form.to_dict()}")

        debug_log(f"[{file_name}] --> Func <{func.__name__}> \033[94m Redis dump BEFORE EXECUTION:\n{dump_all_redis()}\033[0m")
        res = func(*args, **kwargs)
        debug_log(f"[{file_name}] --> Func <{func.__name__}> \033[92m Redis dump BEFORE EXECUTION:\n{dump_all_redis()}\033[0m")

        if isinstance(res, flask.wrappers.Response):
            debug_log(f"[{file_name}] <-- Func <{func.__name__}> responded with ({res._status_code}) {json.loads(res.response[0])}")
        else:
            debug_log(f"[{file_name}] <-- Func <{func.__name__}> returned non flask_response? {type(res)}")
        return res

    return wrapped_function


def dump_all_redis():
    from name_node import redis_test, db_auth, db_node2files, db_user2files, db_file2nodes, db_file2size, db_congestion
    out_strings = []

    for db, name in {redis_test: "redis_test", db_auth: "db_auth", db_file2size: "db_file2size", db_congestion: "db_congestion"}.items():
        dump = {}
        for key in db.keys():
            dump[key] = db.get(key)
        out_strings.append(f"{name} {json.dumps(dump, indent=2)}")

    for db, name in {db_node2files: "db_node2files", db_user2files: "db_user2files", db_file2nodes: "db_file2nodes"}.items():
        dump = {}
        for key in db.keys():
            dump[key] = db.lrange(key, 0, -1)
        out_strings.append(f"{name} {json.dumps(dump, indent=2)}")

    return '\n'.join(out_strings)


def request_node(ip, url, data, files=None):
    try:
        res = https_client.request('POST', f"http://{ip}{url}", fields=data, files=files)
        return json.loads(res.data.decode('utf-8'))
    except Exception as e:
        debug_log(f"Requesting node failed {e}")
        return None
