import flask
from http import HTTPStatus
import os
import shutil
from src.logger import debug_log
from src.constants import *

application = flask.Flask(__name__)

@application.route("/init", methods=['POST'])
def flask_init():
    login = flask.request.form.get(key=LOGIN_KEY, default=None, type=str)

    if not login:
        data = {MESSAGE_KEY: f"Missing required parameters: `{LOGIN_KEY}`"}
        return flask.make_response(flask.jsonify(data), HTTPStatus.UNPROCESSABLE_ENTITY)

    user_folder = os.path.join(ROOT, login)
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


if __name__ == "__main__":
    application.debug = True
    application.run()