import base64
import shutil
import threading
from http import HTTPStatus
from os import statvfs
from time import sleep

import flask
import requests

from constants import *
from logger import debug_log
from utils import request_node, from_subnet_ip, log_route, get_dict_from_response

application = flask.Flask(__name__)


def get_path(path):
    return os.path.join(ROOT, path)


@application.route("/init", methods=['POST'])
@log_route()
def flask_init():
    login = flask.request.form.get(key=LOGIN_KEY, default=None, type=str)

    if not login:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    user_folder = get_path(login)

    if os.path.exists(user_folder):
        # rm user's folder if exists
        try:
            shutil.rmtree(user_folder)
        except OSError:
            debug_log(f"Deletion of the directory {user_folder} failed")
            data = {MESSAGE_KEY: "The folder is already exists. Couldn't delete it."}
            return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    # create user's folder
    try:
        os.mkdir(user_folder)
    except OSError:
        debug_log(f"Creation of the directory {user_folder} failed")
        data = {MESSAGE_KEY: "Failed during folder creation."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fcreate", methods=['POST'])
@log_route()
def flask_fcreate():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    # create new empty file
    try:
        # create all subdirs
        all_dirs = full_file_path.split("/")[:-1]
        dir_path = ROOT
        for directory in all_dirs:
            dir_path = os.path.join(dir_path, directory)
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        # create new file there
        with open(get_path(full_file_path), "w"):
            pass
    except OSError:
        debug_log(f"Creation of the file {full_file_path} failed")
        data = {MESSAGE_KEY: "Failed during file creation."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fdelete", methods=['POST'])
@log_route()
def flask_fdelete():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)

    # delete a file
    try:
        os.remove(file_path)
    except OSError:
        debug_log(f"Creation of the file {file_path} failed")
        data = {MESSAGE_KEY: "Failed during file creation."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fread", methods=['POST'])
@log_route()
def flask_fread():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)

    try:
        with open(file_path, 'rb') as f:
            file_data = str(base64.encodebytes(f.read()), 'utf-8')
    except OSError as e:
        debug_log(e.strerror)
        data = {MESSAGE_KEY: "Error on storage server"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {FILE_BYTES: file_data}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fwrite", methods=['POST'])
@log_route()
def flask_fwrite():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    file_bytes = flask.request.form.get(key=FILE_BYTES, default=None, type=str)

    if not full_file_path or file_bytes is None:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{FILE_BYTES}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_bytes = base64.decodebytes(file_bytes.encode())

    try:
        all_dirs = full_file_path.split("/")[:-1]
        dir_path = ROOT
        for directory in all_dirs:
            dir_path = os.path.join(dir_path, directory)
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        # writeing to file
        with open(file_path, 'wb') as f:
            f.write(file_bytes)
    except OSError as e:
        debug_log(e.strerror)
        data = {MESSAGE_KEY: "Error on the server"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {FULL_PATH_KEY: full_file_path, FILE_SIZE_KEY: len(file_bytes)}
    res = request_node(NAMENODE_IP, '/uploaded', data)
    if res.status != HTTPStatus.OK:
        data = {MESSAGE_KEY: get_dict_from_response(res)[MESSAGE_KEY]}
        return flask.make_response(flask.jsonify(data), HTTPStatus.OK)

    data = {MESSAGE_KEY: "OK"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/replicate", methods=['POST'])
@log_route()
@from_subnet_ip
def flask_replicate():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    target_node_ip = flask.request.form.get(key=NODE_IP_KEY, default=None, type=str)

    if not full_file_path or not target_node_ip:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{NODE_IP_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)

    try:
        with open(file_path, "rb") as f:
            file_data = str(base64.encodebytes(f.read()), 'utf-8')
    except OSError as e:
        debug_log(e.strerror)
        data = {MESSAGE_KEY: "Error on storage server"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {FULL_PATH_KEY: full_file_path, FILE_BYTES: file_data}
    request_node(target_node_ip, '/save_replication', data)

    return flask.make_response(flask.jsonify({}), HTTPStatus.OK)


@application.route("/save_replication", methods=['POST'])
@log_route()
@from_subnet_ip
def flask_save_replication():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    file_bytes = flask.request.form.get(key=FILE_BYTES, default=None, type=str)

    if not full_file_path or not file_bytes:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{FILE_BYTES}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_bytes = base64.decodebytes(file_bytes.encode())

    try:
        with open(file_path, 'wb') as f:
            f.write(file_bytes)
    except OSError as e:
        debug_log(e.strerror)
        data = {MESSAGE_KEY: "Error on the server"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "OK"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fcopy", methods=['POST'])
@log_route()
def flask_fcopy():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    full_file_path_dest = flask.request.form.get(key=FULL_PATH_DESTINATION_KEY, default=None, type=str)

    if not full_file_path or not full_file_path_dest:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{FULL_PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_path_dest = get_path(full_file_path_dest)

    try:
        # create all subdirs
        all_dirs = full_file_path_dest.split("/")[:-1]
        dir_path = ROOT
        for directory in all_dirs:
            dir_path = os.path.join(dir_path, directory)
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        # create copy of file there
        shutil.copyfile(file_path, file_path_dest)
    except OSError:
        debug_log(f"Copying of the file {file_path} failed")
        data = {MESSAGE_KEY: "Failed during file copying."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fmove", methods=['POST'])
@log_route()
def flask_fmove():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    full_file_path_dest = flask.request.form.get(key=FULL_PATH_DESTINATION_KEY, default=None, type=str)

    if not full_file_path or not full_file_path_dest:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`, `{FULL_PATH_DESTINATION_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_path_dest = get_path(full_file_path_dest)

    try:
        # create all subdirs
        all_dirs = full_file_path_dest.split("/")[:-1]
        dir_path = ROOT
        for directory in all_dirs:
            dir_path = os.path.join(dir_path, directory)
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        # move file
        shutil.move(file_path, file_path_dest)
    except OSError:
        debug_log(f"Moving of the file {file_path} failed")
        data = {MESSAGE_KEY: "Failed during file moving."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/ddir", methods=['POST'])
@log_route()
def flask_ddir():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{FULL_PATH_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)

    try:
        shutil.rmtree(file_path)
    except OSError:
        debug_log(f"Delete the directory {file_path} failed")
        data = {MESSAGE_KEY: "Failed during dir delete."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/ping", methods=["POST"])
@log_route()
@from_subnet_ip
def ping():
    try:
        st = statvfs(ROOT)
        congestion = f'{(st.f_blocks - st.f_bavail) / st.f_blocks:.2f}'
    except OSError as e:
        debug_log(f"statvfs failed {e}")
        congestion = 0
    data = {CONGESTION_KEY: congestion}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


def tell_naming_node_im_born():
    debug_log("Wait 7 sec...")
    sleep(7)
    pub_ip = requests.request("GET", "http://169.254.169.254/latest/meta-data/public-ipv4").text
    debug_log(f"Going to tell that I'm born, pub_ip = {pub_ip}")
    request_node(NAMENODE_IP, '/new_node', {'pub': pub_ip})


if __name__ == "__main__":
    # Creating root of DS
    if os.path.exists(ROOT):
        try:
            shutil.rmtree(ROOT)
        except OSError:
            debug_log(f"Deletion of the directory {ROOT} failed")

    try:
        os.mkdir(ROOT)
    except OSError:
        debug_log(f"Creation of the directory {ROOT} failed")

    threading.Thread(target=tell_naming_node_im_born, daemon=True).start()
    # application.debug = True
    application.run(host="0.0.0.0", port=80)
