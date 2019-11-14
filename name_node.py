import flask
from http import HTTPStatus
import redis

application = flask.Flask(__name__)
redis_test = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
redis_test.set_response_callback('GET', int)


@application.route("/", methods=['POST'])
def login():
    param = flask.request.form.get(key='param_1', default=228, type=int)
    redis_test.set(name='key_1', value=param)
    param_from_redis = redis_test.get(name='key_1')
    data = {"answer_param_1": param_from_redis}
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


if __name__ == "__main__":
    application.debug = True
    application.run()

