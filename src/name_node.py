"""
node_id - ip address (127.0.0.28)
file_path - path without login prefix (folder_1/file_1.txt)
full_file_path - full file path with login prefix: (login_1/folder_1/file_1.txt)
"""

import threading
import time
from http import HTTPStatus
from typing import List, Dict

import flask
import redis

from src.constants import *
from src.logger import debug_log
from src.utils import encode_auth_token, decode_auth_token, request_node

application = flask.Flask(__name__)

redis_test = redis.Redis(host='localhost', port=6379, db=10, decode_responses=True)
redis_test.set_response_callback('GET', int)

# login(str): encrypted_pass(str)
db_auth = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
db_auth.set_response_callback('GET', str)

# node_id(str): List[full_file_path(str)]
db_node2files = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
db_node2files.set_response_callback('GET', List[str])

# user_id(str): List[full_file_path(str)]
db_user2files = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
db_user2files.set_response_callback('GET', List[str])

# full_file_path(str): List[node_id(str)]
db_file2nodes = redis.Redis(host='localhost', port=6379, db=3, decode_responses=True)
db_file2nodes.set_response_callback('GET', List[str])

# full_file_path(str): file_size(int)
db_file2size = redis.Redis(host='localhost', port=6379, db=4, decode_responses=True)
db_file2size.set_response_callback('GET', int)

# node_id(str): congestion(float)
db_congestion = redis.Redis(host='localhost', port=6379, db=5, decode_responses=True)
db_congestion.set_response_callback('GET', float)


@application.route("/test", methods=['POST'])
def test():
    param = flask.request.form.get(key='param_1', default=228, type=int)
    redis_test.set(name='key_1', value=param)
    param_from_redis = redis_test.get(name='key_1')
    data = {"answer_param_1": param_from_redis}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/reg", methods=['POST'])
def flask_reg():
    login = flask.request.form.get(key=LOGIN_KEY, default=None, type=str)
    encrypted_pass = flask.request.form.get(key=ENCRYPTED_PASS_KEY, default=None, type=str)

    if not login or not encrypted_pass:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`, `{ENCRYPTED_PASS_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    if db_auth.exists(login):
        data = {MESSAGE_KEY: "The login was already registered, use another one"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    db_auth.set(name=login, value=encrypted_pass)
    return flask.redirect('/login')


@application.route("/login", methods=['POST'])
def flask_login():
    login = flask.request.form.get(key=LOGIN_KEY, default=None, type=str)
    encrypted_pass = flask.request.form.get(key=ENCRYPTED_PASS_KEY, default=None, type=str)

    if not login or not encrypted_pass:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`, `{ENCRYPTED_PASS_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    if not db_auth.exists(login):
        data = {MESSAGE_KEY: "The login is not registered"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    encrypted_pass_db = db_auth.get(login)
    if encrypted_pass_db != encrypted_pass:
        data = {MESSAGE_KEY: "Wrong password"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    token = encode_auth_token(login)
    data = {MESSAGE_KEY: "Success", TOKEN_KEY: token}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/init", methods=['POST'])
def flask_init():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    data_for_node = {LOGIN_KEY: login}
    for node_ip in db_node2files.keys():
        res = request_node(node_ip, '/init', data_for_node)
        debug_log(res)

    full_file_paths = db_user2files.lrange(login, 0, -1)
    was_initialised_before = db_user2files.delete(login)
    for full_file_path in full_file_paths:
        nodes_containing_file = db_file2nodes.lrange(login, 0, -1)
        db_user2files.delete(full_file_path)
        for node in nodes_containing_file:
            db_node2files.lrem(node, 1, full_file_path)

    data = {MESSAGE_KEY: f"Successfully {'removed all data and re' if was_initialised_before else ''}initialized"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fcreate", methods=['POST'])
def flask_fcreate():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_congestion.keys()]
    congestions = sorted(congestions, key=lambda x: x[1])
    nodes = [congestion[0] for congestion in congestions[:REPLICATION_FACTOR]]
    debug_log(f"/fcreate - nodes with lowest congestion: {nodes}")

    data_for_node = {FULL_PATH_KEY: full_file_path}
    for node_ip in nodes:
        res = request_node(node_ip, '/fcreate', data_for_node)
        debug_log(f"/fcreate - storage node {node_ip} response: {res}")
        db_node2files.lpush(node_ip, full_file_path)

    db_file2nodes.lpush(full_file_path, *nodes)
    db_file2size.set(full_file_path, 0)

    data = {MESSAGE_KEY: f"Successfully created the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fread", methods=['POST'])
def flask_fread():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_file2nodes.lrange(full_file_path, 0, -1)]
    congestions = sorted(congestions, key=lambda x: x[1])
    if not congestions:
        data = {MESSAGE_KEY: 'All nodes with ur file are down, sorry lol'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.GONE)
    node_ip = congestions[0][0]

    data = {NODE_IP_KEY: node_ip}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fwrite", methods=['POST'])
def flask_fwrite():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_congestion.keys()]
    congestions = sorted(congestions, key=lambda x: x[1])
    if not congestions:
        data = {MESSAGE_KEY: 'All nodes are down lol'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.GONE)
    node_ip = congestions[0][0]

    data = {NODE_IP_KEY: node_ip}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fdelete", methods=['POST'])
def flask_fdelete():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fdelete', {FULL_PATH_KEY: full_file_path})
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fdelete")

    data = {MESSAGE_KEY: f"Successfully deleted the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


def ping_nodes():
    non_responsive_count: Dict[str, int] = {}
    while True:
        for node_ip in db_congestion.keys():
            if node_ip not in non_responsive_count:
                non_responsive_count[node_ip] = 0
            res = request_node(node_ip, '/ping', {})
            if res is None:
                non_responsive_count[node_ip] += 1
                debug_log(f"Node {node_ip} did not response {non_responsive_count[node_ip]} times")
                if non_responsive_count[node_ip] == MAX_PING_TRIES:
                    remove_node(node_ip)
                    del non_responsive_count[node_ip]
            else:
                debug_log(f"Pinging node {node_ip} - {res}")
                db_congestion.set(node_ip, res[CONGESTION_KEY])
        time.sleep(2)


def remove_node(node_ip):
    db_congestion.delete(node_ip)
    full_file_paths: List[str] = db_node2files.lrange(node_ip, 0, -1)
    db_node2files.delete(node_ip)
    for full_file_path in full_file_paths:
        db_file2nodes.delete(full_file_path)

    # todo replicate


if __name__ == "__main__":
    t1 = threading.Thread(target=ping_nodes).start()
    application.debug = True
    application.run()
