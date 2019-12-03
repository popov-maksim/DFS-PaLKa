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

from constants import *
from logger import debug_log
from utils import encode_auth_token, decode_auth_token, request_node, from_subnet_ip, log_route, get_dict_from_response

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

# user_id(str): List[full_file_path(str)]
db_user2folders = redis.Redis(host='localhost', port=6379, db=3, decode_responses=True)
db_user2folders.set_response_callback('GET', List[str])

# full_file_path(str): List[node_id(str)]
db_file2nodes = redis.Redis(host='localhost', port=6379, db=4, decode_responses=True)
db_file2nodes.set_response_callback('GET', List[str])

# full_file_path(str): file_size(int)
db_file2size = redis.Redis(host='localhost', port=6379, db=5, decode_responses=True)
db_file2size.set_response_callback('GET', int)

# node_id(str): congestion(float)
db_congestion = redis.Redis(host='localhost', port=6379, db=6, decode_responses=True)
db_congestion.set_response_callback('GET', float)

# node_id(str): pub_ip(str)
db_pub = redis.Redis(host='localhost', port=6379, db=7, decode_responses=True)
db_pub.set_response_callback('GET', str)


@application.route("/test", methods=['POST'])
@log_route(dump_redis=True)
def test():
    param = flask.request.form.get(key='param_1', default=228, type=int)
    redis_test.set(name='key_1', value=param)
    param_from_redis = redis_test.get(name='key_1')
    data = {"answer_param_1": param_from_redis}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/reg", methods=['POST'])
@log_route(dump_redis=True)
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

    init(login)
    return flask.redirect('/login')


@application.route("/login", methods=['POST'])
@log_route(dump_redis=True)
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
@log_route(dump_redis=True)
def flask_init():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)

    if not token:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    was_initialised_before = init(login)

    data = {MESSAGE_KEY: f"Successfully {'removed all data and re' if was_initialised_before else ''}initialized"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


def init(login):
    data_for_node = {LOGIN_KEY: login}
    for node_ip in db_congestion.keys():
        res = request_node(node_ip, '/init', data_for_node)
        res = get_dict_from_response(res)
        debug_log(f"/init - node {node_ip} responded wih {res}")

    full_file_paths = db_user2files.lrange(login, 0, -1)
    was_initialised_before = db_user2files.delete(login)
    for full_file_path in full_file_paths:
        db_file2size.delete(full_file_path)
        nodes_containing_file = db_file2nodes.lrange(full_file_path, 0, -1)
        db_file2nodes.delete(full_file_path)
        db_user2files.delete(full_file_path)
        for node in nodes_containing_file:
            db_node2files.lrem(node, 1, full_file_path)
            res = request_node(node, '/fdelete', {FULL_PATH_KEY: full_file_path})
            res = get_dict_from_response(res)
            if res is None:
                debug_log(f"Node {node_ip} did not response on /fdelete")
    db_user2folders.delete(login)
    db_user2folders.lpush(login, login)
    return was_initialised_before


@application.route("/fcreate", methods=['POST'])
@log_route(dump_redis=True)
def flask_fcreate():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    if os.path.dirname(full_file_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "Can't create the file. Folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_congestion.keys()]
    congestions = sorted(congestions, key=lambda x: x[1])
    nodes = [congestion[0] for congestion in congestions[:REPLICATION_FACTOR]]
    debug_log(f"/fcreate - nodes with lowest congestion: {nodes}")

    data_for_node = {FULL_PATH_KEY: full_file_path}
    for node_ip in nodes:
        res = request_node(node_ip, '/fcreate', data_for_node)
        res = get_dict_from_response(res)
        debug_log(f"/fcreate - storage node {node_ip} response: {res}")
        db_node2files.lpush(node_ip, full_file_path)

    db_user2files.lpush(login, full_file_path)
    db_file2nodes.lpush(full_file_path, *nodes)
    db_file2size.set(full_file_path, 0)

    data = {MESSAGE_KEY: f"Successfully created the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fread", methods=['POST'])
@log_route(dump_redis=True)
def flask_fread():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    if os.path.dirname(full_file_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "Can't read the file. Folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_file2nodes.lrange(full_file_path, 0, -1)]
    congestions = sorted(congestions, key=lambda x: x[1])
    if not congestions:
        data = {MESSAGE_KEY: 'All nodes with ur file are down, sorry lol'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.GONE)
    node_ip = congestions[0][0]

    data = {NODE_IP_KEY: db_pub.get(node_ip), FULL_PATH_KEY: full_file_path}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fwrite", methods=['POST'])
@log_route(dump_redis=True)
def flask_fwrite():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    if os.path.dirname(full_file_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "Can't write to the file. Folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in db_congestion.keys()]
    congestions = sorted(congestions, key=lambda x: x[1])
    if not congestions:
        data = {MESSAGE_KEY: 'All nodes are down lol'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.GONE)
    node_ip = congestions[0][0]

    data = {NODE_IP_KEY: db_pub.get(node_ip), FULL_PATH_KEY: os.path.join(login, file_path)}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fdelete", methods=['POST'])
@log_route(dump_redis=True)
def flask_fdelete():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    exists = full_file_path in db_user2files.lrange(login, 0, -1)
    if not exists:
        data = {MESSAGE_KEY: "The file for deleting does not exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_FOUND)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fdelete', {FULL_PATH_KEY: full_file_path})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fdelete")
        db_node2files.lrem(node_ip, 0, full_file_path)

    db_user2files.lrem(login, 0, full_file_path)
    db_file2nodes.delete(full_file_path)
    db_file2size.delete(full_file_path)

    data = {MESSAGE_KEY: f"Successfully deleted the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fcopy", methods=['POST'])
@log_route(dump_redis=True)
def flask_fcopy():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    file_destination_path = flask.request.form.get(key=PATH_DESTINATION_KEY, default=None, type=str)

    if not token or not file_path or file_destination_path is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    if not os.path.basename(file_destination_path):
        data = {MESSAGE_KEY: "The destination file name is empty"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)
    full_file_destination_path = os.path.join(login, file_destination_path)

    if full_file_path not in db_user2files.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "The source file doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    if os.path.dirname(full_file_destination_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "Can't copy the file. Destination folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fcopy', {FULL_PATH_KEY: full_file_path,
                                               FULL_PATH_DESTINATION_KEY: full_file_destination_path})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fcopy")
        else:
            db_node2files.lpush(node_ip, full_file_destination_path)
            db_file2nodes.lpush(full_file_destination_path, node_ip)

    db_user2files.lpush(login, full_file_destination_path)
    db_file2size.set(full_file_destination_path, db_file2size.get(full_file_path))

    data = {MESSAGE_KEY: f"Successfully copied the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fmove", methods=['POST'])
@log_route(dump_redis=True)
def flask_fmove():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    file_destination_path = flask.request.form.get(key=PATH_DESTINATION_KEY, default=None, type=str)

    if not token or not file_path or file_destination_path is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    if not os.path.basename(file_destination_path):
        data = {MESSAGE_KEY: "The destination file name is empty"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)
    full_file_destination_path = os.path.join(login, file_destination_path)

    if full_file_path not in db_user2files.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "The source file doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    if os.path.dirname(full_file_destination_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "Can't move the file. Destination folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    for node_ip in db_file2nodes.lrange(full_file_path, 0, -1):
        res = request_node(node_ip, '/fmove', {FULL_PATH_KEY: full_file_path,
                                               FULL_PATH_DESTINATION_KEY: full_file_destination_path})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fmove")
        else:
            db_node2files.lrem(node_ip, 0, full_file_path)
            db_node2files.lpush(node_ip, full_file_destination_path)

            db_file2nodes.lrem(full_file_path, 0, node_ip)
            db_file2nodes.lpush(full_file_destination_path, node_ip)

    db_user2files.lrem(login, 0, full_file_path)
    db_user2files.lpush(login, full_file_destination_path)

    db_file2size.set(full_file_destination_path, db_file2size.get(full_file_path))
    db_file2size.delete(full_file_path)

    data = {MESSAGE_KEY: f"Successfully moved the file"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/finfo", methods=['POST'])
@log_route(dump_redis=True)
def flask_finfo():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    file_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_file_path = os.path.join(login, file_path)

    if full_file_path not in db_user2files.lrange(login, 0, -1):
        data = {MESSAGE_KEY: f"The file doesn't exist. (ERR: {full_file_path})"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    data = {NODE_IP_KEY: db_file2nodes.lrange(full_file_path, 0, -1),
            FILE_SIZE_KEY: db_file2size.get(full_file_path)}

    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/rdir", methods=['POST'])
@log_route(dump_redis=True)
def flask_rdir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or dir_path is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path[:-1] if dir_path and dir_path[-1] == '/' else dir_path
    full_dir_path = os.path.join(login, dir_path) if dir_path else login

    if full_dir_path not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: f"Can't read the folder, doesn't exist. (ERR: {full_dir_path})"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_list = []

    inner_files_path_list = [full_path[len(full_dir_path) + 1:] for full_path in db_user2files.lrange(login, 0, -1) if
                             full_path.startswith(full_dir_path + '/')]
    dir_list.extend([inner_path.split('/')[0] for inner_path in inner_files_path_list
                     if len(inner_path.split('/')) == 1])

    inner_folders_path_list = [full_path[len(full_dir_path) + 1:] for full_path in db_user2folders.lrange(login, 0, -1)
                               if full_path.startswith(full_dir_path + '/')]
    dir_list.extend([inner_path.split('/')[0] + '/' for inner_path in inner_folders_path_list
                     if len(inner_path.split('/')) == 1])

    data = {DIR_LIST_KEY: dir_list}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/mdir", methods=['POST'])
@log_route(dump_redis=True)
def flask_mdir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or not dir_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path[:-1] if dir_path and dir_path[-1] == '/' else dir_path
    full_dir_path = os.path.join(login, dir_path) if dir_path else login

    if full_dir_path in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: f"Can't create the folder, it already exists"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    if os.path.dirname(full_dir_path) not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: f"Can't create the folder, parent folder doesn't exist. (ERR: {os.path.dirname(full_dir_path)})"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    db_user2folders.lpush(login, full_dir_path)

    data = {MESSAGE_KEY: 'Successfully created a directory'}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/dir_exists", methods=['POST'])
def flask_dir_exists():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)

    if not token or dir_path is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login:
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path[:-1] if dir_path and dir_path[-1] == '/' else dir_path
    full_dir_path = os.path.join(login, dir_path) if dir_path else login

    if full_dir_path not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "The folder doesn't exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    data = {MESSAGE_KEY: 'It exists!'}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/ddir", methods=['POST'])
@log_route(dump_redis=True)
def flask_ddir():
    token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
    dir_path = flask.request.form.get(key=PATH_KEY, default=None, type=str)
    force = flask.request.form.get(key=FORCE_KEY, default=None, type=str)

    if not token or dir_path is None or force is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`, `{PATH_KEY}`, `{FORCE_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = decode_auth_token(token)
    if not login or (type(login) == str and login not in db_auth.keys()):
        data = {MESSAGE_KEY: "The token is invalid or has expired"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    dir_path = dir_path[:-1] if dir_path and dir_path[-1] == '/' else dir_path

    if not dir_path:
        data = {MESSAGE_KEY: "Can't delete the root directory"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)

    full_dir_path = os.path.join(login, dir_path)

    if full_dir_path not in db_user2folders.lrange(login, 0, -1):
        data = {MESSAGE_KEY: "The folder for deleting does not exist"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_FOUND)

    inner_files_path_list = [full_path for full_path in db_user2files.lrange(login, 0, -1) if
                             full_path.startswith(full_dir_path + '/')]
    inner_folders_path_list = [full_path for full_path in db_user2folders.lrange(login, 0, -1)
                               if full_path.startswith(full_dir_path + '/')]

    if force == 'False' and (inner_files_path_list or inner_folders_path_list):
        data = {MESSAGE_KEY: 'The directory contains files. `force=true` to delete'}
        return flask.make_response(flask.jsonify(data), HTTPStatus.NOT_ACCEPTABLE)

    db_user2folders.lrem(login, 0, full_dir_path)
    for inner_dir in inner_folders_path_list:
        db_user2folders.lrem(login, 0, inner_dir)

    nodes_ip = set()
    for inner_file in inner_files_path_list:
        db_file2size.delete(inner_file)
        db_user2files.lrem(login, 0, inner_file)

        for node_ip in db_file2nodes.lrange(inner_file, 0, -1):
            db_file2nodes.lrem(inner_file, 0, node_ip)
            db_node2files.lrem(node_ip, 0, inner_file)
            nodes_ip.add(node_ip)

    for node_ip in list(nodes_ip):
        res = request_node(node_ip, '/ddir', {FULL_PATH_KEY: full_dir_path})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {node_ip} did not response on /ddir ({full_dir_path})")

    data = {MESSAGE_KEY: 'Successfully deleted the directory'}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/new_node", methods=['POST'])
@log_route(dump_redis=True)
@from_subnet_ip
def flask_new_node():
    new_node_ip = flask.request.environ.get('HTTP_X_REAL_IP', flask.request.remote_addr)
    pub_ip = flask.request.form.get(key='pub', default=None, type=str)
    if new_node_ip in db_congestion.keys():
        debug_log(f"!!!!!!!ERROR!!!!!!!! {new_node_ip} calls /new_node but it's already in the db")
    else:
        debug_log(f"{new_node_ip} calls /new_node and added to db. Pub_ip = {pub_ip}")
    db_congestion.set(new_node_ip, 0)
    db_pub.set(new_node_ip, pub_ip)
    return flask.make_response(flask.jsonify({}), HTTPStatus.OK)


def periodically_ping_nodes():
    @log_route(dump_redis=True, non_flask=True)
    def ping_nodes():
        for node_ip in db_congestion.keys():
            if node_ip not in non_responsive_count:
                non_responsive_count[node_ip] = 0
            res = request_node(node_ip, '/ping', {})
            res = get_dict_from_response(res)
            if res is None:
                non_responsive_count[node_ip] += 1
                debug_log(f"Node {node_ip} did not response {non_responsive_count[node_ip]} times")
                if non_responsive_count[node_ip] == MAX_PING_TRIES:
                    remove_node(node_ip)
                    del non_responsive_count[node_ip]
            else:
                debug_log(f"Pinging node {node_ip} - {res}")
                db_congestion.set(node_ip, res[CONGESTION_KEY])

    non_responsive_count: Dict[str, int] = {}
    while True:
        ping_nodes()
        time.sleep(1.5)


def remove_node(node_ip):
    db_congestion.delete(node_ip)
    full_file_paths: List[str] = db_node2files.lrange(node_ip, 0, -1)
    db_node2files.delete(node_ip)
    for full_file_path in full_file_paths:
        db_file2nodes.lrem(full_file_path, 0, node_ip)
        replicate(full_file_path)


@application.route("/uploaded", methods=['POST'])
@log_route(dump_redis=True)
@from_subnet_ip
def flask_uploaded():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    file_size = flask.request.form.get(key=FILE_SIZE_KEY, default=None, type=str)

    if not full_file_path or not file_size:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{FILE_SIZE_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    login = full_file_path.split('/')[0]

    db_file2size.set(full_file_path, file_size)
    if full_file_path not in db_user2files.lrange(login, 0, -1):
        db_user2files.lpush(login, full_file_path)

    source_node_ip = flask.request.environ.get('HTTP_X_REAL_IP', flask.request.remote_addr)

    nodes_with_obsolete_files = db_file2nodes.lrange(full_file_path, 0, -1)
    if source_node_ip in nodes_with_obsolete_files:
        nodes_with_obsolete_files.remove(source_node_ip)
    else:
        db_node2files.lpush(source_node_ip, full_file_path)
        db_file2nodes.lpush(full_file_path, source_node_ip)

    for node_ip in nodes_with_obsolete_files:
        res = request_node(node_ip, '/fdelete', {FULL_PATH_KEY: full_file_path})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {node_ip} did not response on /fdelete")
        db_node2files.lrem(node_ip, 0, full_file_path)
        db_file2nodes.lrem(full_file_path, 0, node_ip)

    replicate(full_file_path=full_file_path)

    data = {MESSAGE_KEY: 'OK, uploaded.'}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@log_route(dump_redis=True, non_flask=True)
def replicate(full_file_path: str):
    source_nodes_ip = db_file2nodes.lrange(full_file_path, 0, -1)
    assert source_nodes_ip

    target_nodes_ip = db_congestion.keys()
    target_nodes_ip = list(set(target_nodes_ip) - set(source_nodes_ip))

    congestions = [(node_ip, db_congestion.get(node_ip)) for node_ip in target_nodes_ip]
    congestions = sorted(congestions, key=lambda x: x[1])
    target_nodes_ip = [congestion[0] for congestion in congestions[:REPLICATION_FACTOR - len(source_nodes_ip)]]
    debug_log(f"Going to replicate {full_file_path} from {source_nodes_ip} "
              f"to nodes with lowest congestion: {target_nodes_ip}")

    for target_node_ip in target_nodes_ip:
        res = request_node(source_nodes_ip[0], '/replicate', {FULL_PATH_KEY: full_file_path,
                                                              NODE_IP_KEY: target_node_ip})
        res = get_dict_from_response(res)
        if res is None:
            debug_log(f"Node {source_nodes_ip[0]} did not response on /replicate")
        else:
            db_file2nodes.lpush(full_file_path, target_node_ip)
            db_node2files.lpush(target_node_ip, full_file_path)


if __name__ == "__main__":
    threading.Thread(target=periodically_ping_nodes, daemon=True).start()
    # application.debug = True
    application.run(host="0.0.0.0", port=80)
