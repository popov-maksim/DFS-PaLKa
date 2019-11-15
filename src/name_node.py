import flask
from http import HTTPStatus
import redis
from src.constants import *
from src.auth import encode_auth_token

application = flask.Flask(__name__)

redis_test = redis.Redis(host='localhost', port=6379, db=99, decode_responses=True)
redis_test.set_response_callback('GET', int)

db_auth = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
db_auth.set_response_callback('GET', str)


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

    if login is None or encrypted_pass is None:
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

    if login is None or encrypted_pass is None:
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


if __name__ == "__main__":
    application.debug = True
    application.run()
