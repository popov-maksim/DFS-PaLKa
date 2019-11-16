"""
node_id - ip address (127.0.0.28)
file_path - path without login prefix (folder_1/file_1.txt)
full_file_path - full file path with login prefix: (login_1/folder_1/file_1.txt)
"""

import re
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
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

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
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

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
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    exists = full_file_path in db_user2files.lrange(login, 0, -1)
    if not exists:
        data = {MESSAGE_KEY: "The file for deleting does not exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_FOUND)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fdelete', {FULL_PATH_KEY: full_file_path})
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fdelete")
        db_node2files.lrem(node_ip, 0, full_file_path)

    db_user2files.lrem(login, 0, full_file_path)
    db_file2nodes.delete(full_file_path)
    db_file2size.delete(full_file_path)

    data = {MESSAGE_KEY: f"Successfully deleted the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fcopy", methods=['POST'])
def flask_fcopy():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    file_destination_path = flask.request.form.get(key=PATH_DESTINATION_KEY, default=None, type=str)

    if not token or not file_path or not file_destination_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)
    full_file_destination_path = os.path.join(login, file_destination_path)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fcopy', {FULL_PATH_KEY: full_file_path,
                                               FULL_PATH_DESTINATION_KEY: full_file_destination_path})
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fcopy")

    data = {MESSAGE_KEY: f"Successfully copied the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fmove", methods=['POST'])
def flask_fmove():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    file_destination_path = flask.request.form.get(key=PATH_DESTINATION_KEY, default=None, type=str)

    if not token or not file_path or not file_destination_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)
    full_file_destination_path = os.path.join(login, file_destination_path)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fmove', {FULL_PATH_KEY: full_file_path,
                                               FULL_PATH_DESTINATION_KEY: full_file_destination_path})
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fmove")

    data = {MESSAGE_KEY: f"Successfully moved the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/finfo", methods=['POST'])
def flask_finfo():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    data = {NODE_IP_KEY: db_file2nodes.lrange(full_file_path, 0, -1),
            FILE_SIZE_KEY: db_file2size.get(full_file_path)}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/dir_exists", methods=['POST'])
def flask_dir_exists():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not dir_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path if dir_path[-1] == '/' else f"{dir_path}/"
    full_dir_path = os.path.join(login, dir_path)

    exists = any(full_file_path.startswith(full_dir_path) for full_file_path in db_user2files.lrange(login, 0, -1))

    data = {EXISTS_KEY: exists}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/rdir", methods=['POST'])
def flask_rdir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not dir_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path if dir_path[-1] == '/' else f"{dir_path}/"
    full_dir_path = os.path.join(login, dir_path)

    inner_paths_list = [full_path[len(full_dir_path):] for full_path in db_user2files.lrange(login, 0, -1) if
                        full_path.startswith(full_dir_path)]
    dir_list = []
    for inner_path in inner_paths_list:
        m = re.search(r'^([^/]+/?)', '')
        if m:
            dir_list.append(m.group(0))

    data = {DIR_LIST_KEY: dir_list}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/mdir", methods=['POST'])
def flask_mdir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not dir_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path if dir_path[-1] == '/' else f"{dir_path}/"
    full_dir_path = os.path.join(login, dir_path)

    db_user2files.lpush(login, full_dir_path)

    data = {MESSAGE_KEY: 'Successfully created a directory'}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/ddir", methods=['POST'])
def flask_ddir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    force = flask.request.form.get(key=FORCE_KEY, default=None, type=bool)

    if not token or not dir_path or force is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{FORCE_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path if dir_path[-1] == '/' else f"{dir_path}/"
    full_dir_path = os.path.join(login, dir_path)

    inner_paths_list = [full_path[len(full_dir_path):] for full_path in db_user2files.lrange(login, 0, -1) if
                        full_path.startswith(full_dir_path)]
    exists = any(inner_paths_list)
    if not exists:
        data = {MESSAGE_KEY: "The folder for deleting does not exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_FOUND)

    lst = inner_paths_list.copy()
    lst.remove('')
    if lst and not force:
        data = {MESSAGE_KEY: 'The directory contains files. `force=true` to delete'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_MODIFIED)

    nodes_ip = []
    for inner_path in inner_paths_list:
        full_file_path = full_dir_path + inner_path
        for node_ip in db_file2nodes.lrange(login, 0, -1):
            if node_ip not in nodes_ip:
                nodes_ip.append(node_ip)
            db_node2files.lrem(node_ip, 0, full_file_path)
        db_file2nodes.delete(full_file_path)
        db_file2size.delete(full_file_path)
        db_user2files.lrem(login, 0, full_file_path)

    for node_ip in nodes_ip:
        res = request_node(node_ip, '/ddir', {FULL_PATH_KEY: full_dir_path})
        if res is None:
            debug_log(f"Node {node_ip} did not response on /ddir")

    data = {MESSAGE_KEY: 'Successfully deleted the directory'}
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
