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
    token = None
    with open(TOKEN_FILE, "r") as f:
        token = f.read().strip()
    return token


def save_token(token):
    with open(TOKEN_FILE, "w") as f:
        token = f.write(token)


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


def request_node(ip, url, data):
    try:
        res = https_client.request('POST', f"http://{ip}{url}", fields=data)
        return json.loads(res.data.decode('utf-8'))
    except Exception as e:
        debug_log(f"Requesting node failed {e}")
        return None
