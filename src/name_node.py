"""
node_id - full file path with login prefix: /login_1/folder_1/file_1.txt
"""

from http import HTTPStatus
from typing import List

import flask
import redis
import requests

from src.constants import *
from src.logger import debug_log
from src.utils import encode_auth_token, decode_auth_token

application = flask.Flask(__name__)

redis_test = redis.Redis(host='localhost', port=6379, db=10, decode_responses=True)
redis_test.set_response_callback('GET', int)

# login(str): encrypted_pass(str)
db_auth = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
db_auth.set_response_callback('GET', str)

# node_id(str): List[file_path(str)]
db_node2files = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
db_auth.set_response_callback('GET', List[str])

# user_id(str): List[file_path(str)]
db_user2files = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
db_auth.set_response_callback('GET', List[str])

# file_path(str): List[node_id(str)]
db_file2nodes = redis.Redis(host='localhost', port=6379, db=3, decode_responses=True)
db_auth.set_response_callback('GET', List[str])

# node_id(str): congestion(float)
db_congestion = redis.Redis(host='localhost', port=6379, db=4, decode_responses=True)
db_auth.set_response_callback('GET', float)


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
        res = requests.post(f"{node_ip}/init", json=data_for_node)
        debug_log(res.json())

    old_file_paths = db_user2files.lrange(login, 0, -1)
    was_initialised_before = db_user2files.delete(login)
    for file_path in old_file_paths:
        nodes_containing_file = db_file2nodes.lrange(login, 0, -1)
        db_user2files.delete(file_path)
        for node in nodes_containing_file:
            db_node2files.lrem(node, 1, file_path)

    data = {MESSAGE_KEY: f"Successfully {'removed all data and re' if was_initialised_before else ''}initialized"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


# @application.route("/fcreate", methods=['POST'])
# def flask_fcreate():
#     token = flask.request.form.get(key=TOKEN_KEY, default=None, type=str)
#
#     if not token:
#         data = {MESSAGE_KEY: f"Missing required parameters: `{TOKEN_KEY}`"}
#         return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)
#
#     login = decode_auth_token(token)
#     if not login:
#         data = {MESSAGE_KEY: "The token is invalid or has expired"}
#         return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)
#
#     data_for_node = {LOGIN_KEY: login}
#     for node_ip in db_node2files.keys():
#         res = requests.post(f"{node_ip}/init", json=data_for_node)
#         debug_log(res.json())
#
#     old_file_paths = db_user2files.lrange(login, 0, -1)
#     was_initialised_before = db_user2files.delete(login)
#     for file_path in old_file_paths:
#         nodes_containing_file = db_file2nodes.lrange(login, 0, -1)
#         db_user2files.delete(file_path)
#         for node in nodes_containing_file:
#             db_node2files.lrem(node, 1, file_path)
#
#     data = {MESSAGE_KEY: f"Successfully {'removed all data and re' if was_initialised_before else ''}initialized"}
#     return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


# @application.route("/login", methods=['POST'])
# @from_subnet_ip
# def flask_node_status():
#     login = flask.request.form.get(key=LOGIN_KEY, default=None, type=str)
#     encrypted_pass = flask.request.form.get(key=ENCRYPTED_PASS_KEY, default=None, type=str)
#
#     if login is None or encrypted_pass is None:
#         data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`, `{ENCRYPTED_PASS_KEY}`"}
#         return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)
#
#     if not db_auth.exists(login):
#         data = {MESSAGE_KEY: "The login is not registered"}
#         return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)
#
#     encrypted_pass_db = db_auth.get(login)
#     if encrypted_pass_db != encrypted_pass:
#         data = {MESSAGE_KEY: "Wrong password"}
#         return flask.make_response(flask.jsonify(data), HTTPStatus.FORBIDDEN)
#
#     token = encode_auth_token(login)
#     data = {MESSAGE_KEY: "Success", TOKEN_KEY: token}
#     return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


if __name__ == "__main__":
    application.debug = True
    application.run()
