import flask
from http import HTTPStatus
import os
import shutil
from src.logger import debug_log
from src.constants import *


application = flask.Flask(__name__)


def get_path(path):
    return os.path.join(ROOT, path)


@application.route("/init", methods=['POST'])
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
def flask_fcreate():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)

    # create new empty file
    try:
        # create all subdirs
        all_dirs = file_path.split("/")[:-1]
        dir_path = ROOT
        for directory in all_dirs:
            dir_path = os.path.join(dir_path, directory)
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        # create new file there
        with open(file_path, "w"): pass
    except OSError:
        debug_log(f"Creation of the file {file_path} failed")
        data = {MESSAGE_KEY: "Failed during file creation."}
        return flask.make_response(flask.jsonify(data), HTTPStatus.INTERNAL_SERVER_ERROR)

    data = {MESSAGE_KEY: "Success"}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/fdelete", methods=['POST'])
def flask_fdelete():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
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
def flask_fread():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    # TODO donwnload file


@application.route("/fwrite", methods=['POST'])
def flask_fwrite():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    # TODO upload file


@application.route("/fcopy", methods=['POST'])
def flask_fcopy():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    full_file_path_dest = flask.request.form.get(key=FULL_PATH_DESTINATION_KEY, default=None, type=str)

    if not full_file_path or not full_file_path_dest:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_path_dest = get_path(full_file_path_dest)

    try:
        # create all subdirs
        all_dirs = file_path_dest.split("/")[:-1]
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
def flask_fmove():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)
    full_file_path_dest = flask.request.form.get(key=FULL_PATH_DESTINATION_KEY, default=None, type=str)

    if not full_file_path or not full_file_path_dest:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    file_path = get_path(full_file_path)
    file_path_dest = get_path(full_file_path_dest)

    try:
        # create all subdirs
        all_dirs = file_path_dest.split("/")[:-1]
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
def flask_ddir():
    full_file_path = flask.request.form.get(key=FULL_PATH_KEY, default=None, type=str)

    if not full_file_path:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
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


if __name__ == "__main__":
    application.debug = True
    application.run()
    