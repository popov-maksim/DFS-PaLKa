import re
import threading
import time
from http import HTTPStatus
from typing import List, Dict

import flask
import redis

import os

# from utils import encode_auth_token, decode_auth_token, request_node, from_subnet_ip

application = flask.Flask(__name__)

root = '/home/palka/dfs-PLK/'


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
    #
    # def mknod(self, path, mode, dev):
    #     return os.mknod(self._full_path(path), mode, dev)
    #


@application.route("/rmdir", methods=['POST'])
def remove_dir():
    path = flask.request.form.get(key="path", default=None, type=str)
    full_path = _full_path(path)
    return flask.make_response(flask.jsonify(os.rmdir(full_path)))


@application.route("/mkdir", methods=['POST'])
def mkdir():
    path = flask.request.form.get(key="path", default=None, type=str)
    mode = flask.request.form.get(key="mode", default=None, type=int)
    full_path = _full_path(path)
    return flask.make_response(flask.jsonify(os.mkdir(full_path)))


    # def statfs(self, path):
    #     full_path = self._full_path(path)
    #     stv = os.statvfs(full_path)
    #     return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
    #         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
    #         'f_frsize', 'f_namemax'))
    #
    # def unlink(self, path):
    #     return os.unlink(self._full_path(path))
    #
    # def symlink(self, name, target):
    #     return os.symlink(name, self._full_path(target))
    #
    # def rename(self, old, new):
    #     return os.rename(self._full_path(old), self._full_path(new))
    #
    # def link(self, target, name):
    #     return os.link(self._full_path(target), self._full_path(name))
    #
    # def utimens(self, path, times=None):
    #     return os.utime(self._full_path(path), times)
    #
    # # File methods
    # # ============
    #
    # def open(self, path, flags):
    #     full_path = self._full_path(path)
    #     return os.open(full_path, flags)
    #
    # def create(self, path, mode, fi=None):
    #     full_path = self._full_path(path)
    #     return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
    #
    # def read(self, path, length, offset, fh):
    #     os.lseek(fh, offset, os.SEEK_SET)
    #     return os.read(fh, length)
    #
    # def write(self, path, buf, offset, fh):
    #     os.lseek(fh, offset, os.SEEK_SET)
    #     return os.write(fh, buf)
    #
    # def truncate(self, path, length, fh=None):
    #     full_path = self._full_path(path)
    #     with open(full_path, 'r+') as f:
    #         f.truncate(length)
    #
    # def flush(self, path, fh):
    #     return os.fsync(fh)
    #
    # def release(self, path, fh):
    #     return os.close(fh)
    #
    # def fsync(self, path, fdatasync, fh):
    #     return self.flush(path, fh)


if __name__ == "__main__":
    application.debug = True
    application.run(host='0.0.0.0', port=80)
