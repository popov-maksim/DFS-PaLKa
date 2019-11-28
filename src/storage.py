import base64
import io
import os
import re
import threading
import time
from http import HTTPStatus
from typing import List, Dict

import flask
import redis

# from utils import encode_auth_token, decode_auth_token, request_node, from_subnet_ip

application = flask.Flask(__name__)

root = '/home/ubuntu/dfs-PLK/'
BINARY_FILE = 'binary_file'


def _full_path(partial):
    if partial.startswith("/"):
        partial = partial[1:]
    path = os.path.join(root, partial)
    return path


@application.route("/getattr", methods=['POST'])
def get_attributes():
    """
    On OS exception return error code, this is necessary for mkdir
    """
    path = flask.request.form.get(key="path", default=None, type=str)
    full_path = _full_path(path)
    try:
        st = os.lstat(full_path)
        data = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size',
                                                        'st_uid',
                                                        'st_blocks'))
    except OSError as e:
        data = e.errno
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/readdir", methods=['POST'])
def read_dir():
    path = flask.request.form.get(key="path", default=None, type=str)
    full_path = _full_path(path)

    dirents = ['.', '..']
    if os.path.isdir(full_path):
        dirents.extend(os.listdir(full_path))
    data = []
    for r in dirents:
        data.append(r)
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


@application.route("/readlink", methods=['POST'])
def read_link(path):
    pathname = os.readlink(_full_path(path))
    if pathname.startswith("/"):
        # Path name is absolute, sanitize it.
        data = os.path.relpath(pathname, self.root)
    else:
        data = pathname
    return flask.make_response(flask.jsonify(data), HTTPStatus.OK)


def mknod(self, path, mode, dev):
    return os.mknod(self._full_path(path), mode, dev)


@application.route("/rmdir", methods=['POST'])
def remove_dir():
    path = flask.request.form.get(key="path", default=None, type=str)
    full_path = _full_path(path)
    return flask.make_response(flask.jsonify(os.rmdir(full_path)))


@application.route("/mkdir", methods=['POST'])
def make_dir():
    path = flask.request.form.get(key="path", default=None, type=str)
    mode = flask.request.form.get(key="mode", default=None, type=int)
    full_path = _full_path(path)
    print('mkdir', path, mode)
    return flask.make_response(flask.jsonify(os.mkdir(full_path, mode)))


# def statfs(self, path):
#     full_path = self._full_path(path)
#     stv = os.statvfs(full_path)
#     return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
#         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
#         'f_frsize', 'f_namemax'))

@application.route("/unlink", methods=["POST"])
def unlink_file():
    path = flask.request.form.get(key="path", default=None, type=str)
    try:
        print(_full_path(path))
        os.unlink(_full_path(path))
        return flask.make_response(flask.jsonify(0))
    except OSError as e:
        return flask.make_response(flask.jsonify(e.errno), HTTPStatus.INTERNAL_SERVER_ERROR)


@application.route("/symlink", methods=["POST"])
def symlink(self, name, target):
    return flask.make_response(flask.jsonify(0), HTTPStatus.NOT_IMPLEMENTED)
    # return os.symlink(name, self._full_path(target))


@application.route("/rename", methods=["POST"])
def rename(self, old, new):
    return flask.make_response(flask.jsonify(0), HTTPStatus.NOT_IMPLEMENTED)
    # return os.rename(self._full_path(old), self._full_path(new))


@application.route("/link", methods=["POST"])
def link(self, target, name):
    return flask.make_response(flask.jsonify(0), HTTPStatus.NOT_IMPLEMENTED)
    # return os.link(self._full_path(target), self._full_path(name))


@application.route("/utimens", methods=["POST"])
def utimens():
    path = flask.request.form.get(key='path', default=None, type=str)
    times = flask.request.form.get(key='times', default=None, type=int)
    try:
        os.utime(self._full_path(path), times)
        return flask.make_response(flask.jsonify(0))
    except OSError as e:
        return flask.make_response(flask.jsonify(e.errno))


# File methods
# ============

@application.route("/open", methods=["POST"])
def open_file():
    path = flask.request.form.get(key="path", default=None, type=str)
    flags = flask.request.form.get(key="flags", default=None, type=int)
    full_path = _full_path(path)
    data = os.open(full_path, flags)
    return flask.make_response(flask.jsonify(data))


@application.route("/create", methods=["POST"])
def create_file():
    path = flask.request.form.get(key="path", default=None, type=str)
    mode = flask.request.form.get(key="mode", default=None, type=int)
    full_path = _full_path(path)
    data = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
    return flask.make_response(flask.jsonify(data))


@application.route("/read", methods=["POST"])
def read_file():
    path = flask.request.form.get(key="path", default=None, type=str)
    length = flask.request.form.get(key="length", default=None, type=int)
    offset = flask.request.form.get(key="offset", default=None, type=int)
    fh = flask.request.form.get(key="fh", default=None, type=int)
    os.lseek(fh, offset, os.SEEK_SET)
    data = os.read(fh, length).decode()
    return {BINARY_FILE: data}


@application.route('/write', methods=['POST'])
def write_file():
    data = flask.request.form.get(key='buf', default=None, type=str)
    buf = base64.b64decode(data)
    print('buf', data, buf)
    offset = flask.request.form.get(key='offset', default=None, type=int)
    fh = flask.request.form.get(key='fh', default=None, type=int)
    try:
        os.lseek(fh, offset, os.SEEK_SET)
        n = os.write(fh, buf)
        return flask.make_response(flask.jsonify(n))
    except OSError as e:
        print('WRITE HAS JUST FAILED')
        return flask.make_response(flask.jsonify(e.errno), HTTPStatus.INTERNAL_SERVER_ERROR)


@application.route('/truncate', methods=['POST'])
def truncate():
    path = flask.request.form.get(key='path', default=None, type=str)
    length = flask.request.form.get(key='length', default=None, type=int)
    full_path = _full_path(path)
    try:
        with open(full_path, 'r+') as f:
            f.truncate(length)
        return flask.make_response(flask.jsonify(0))
    except OSError as e:
        return flask.make_response(flask.jsonify(e.errno))


@application.route("/flush", methods=["POST"])
def flush_file():
    fh = flask.request.form.get(key="fh", default=None, type=int)
    try:
        os.fsync(fh)
        return flask.make_response(flask.jsonify(0))
    except OSError as e:
        return flask.make_response(flask.jsonify(e).errno, HTTPStatus.INTERNAL_SERVER_ERROR)


@application.route("/release", methods=["POST"])
def release():
    fh = flask.request.form.get(key="fh", default=None, type=int)
    try:
        os.close(fh)
        return flask.make_response(flask.jsonify(0))
    except OSError as e:
        return flask.make_response(flask.jsonify(e.errno))


@application.route("/fsync", methods=["POST"])
def fsync(self, path, fdatasync, fh):
    return flask.make_response(flask.jsonify(0), HTTPStatus.NOT_IMPLEMENTED)
    # return self.flush(path, fh)


if __name__ == "__main__":
    application.debug = True
    application.run(host='0.0.0.0', port=80)
