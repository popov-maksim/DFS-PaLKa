import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations
from utils import read_token, save_token, request_node
from constants import *
from logger import debug_log
import base64


class Client(Operations):

    def __init__(self, root):
        self.root = root

    def _full_path(self, partial):
        return os.path.join(self.root, partial)

    def access(self, path, mode):
        pass

    def getattr(self, path, fh=None):
        """
        On error (e.g. file doesn't exist) raise an exception,
        this is necessary for mkdir
        """
        print('getattr', path)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/getattr', {'path': full_path})
        if type(res) != dict:
            raise FuseOSError(res)
        print('getattr', res)
        return res

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readdir', {'path': full_path})
        print('readdir', res)
        return res

    def readlink(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readlink', {'path': full_path})
        print('readlink', res)
        return res

    def mknod(self, path, mode, dev):
        print('MKNOD HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readlink', {'path': full_path, 'mode': mode, 'dev': dev})
        print('mknod', res)
        return res

    def rmdir(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/rmdir', {'path': full_path})
        print('rmdir', res)
        return res

    def mkdir(self, path, mode):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/mkdir', {'path': full_path, 'mode': mode})
        print('mkdir', res)
        return res

    def statfs(self, path):
        return 'OK'

    # def statfs(self, path):
    #     full_path = self._full_path(path)
    #     stv = os.statvfs(full_path)
    #     return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
    #         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
    #         'f_frsize', 'f_namemax'))
    #
    def unlink(self, path):
        print('UNLINK HERE', path)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/unlink', {'path': path})
        print('unlink', res)
        return res

    def symlink(self, name, target):
        print('SYMLINK')
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        print('RENAME HERE')
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        print('LINK HERE')
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        print('UTIMENS HERE')
        return os.utime(self._full_path(path), times)

    # # File methods
    # # ============

    def open(self, path, flags):
        print('OPEN HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/open', {'path': full_path, 'flags': flags})
        print('open', res)
        return res

    def create(self, path, mode, fh=None):
        print('CREATION HERE')
        print(path, mode, fh)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/create', {'path': full_path, 'mode': mode})
        print('create', res)
        return res

    def read(self, path, length, offset, fh):
        print('READ HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/read', {'path': full_path, 'length': length, 'offset': offset, 'fh': fh})
        return res[BINARY_FILE].encode()

    def write(self, path, buf, offset, fh):
        print('WRITE HERE')
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        print('TRUNC HERE')
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print('FLUSH HERE', path, fh)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/flush', {'path': path, 'fh': fh})
        return res

    def release(self, path, fh):
        print('RELEASE HERE', path, fh)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/release', {'path': full_path, 'fh': fh})
        print('release', res)
        return 0

    def fsync(self, path, fdatasync, fh):
        print('FSYNC HERE')
        return self.flush(path, fh)


def main(mountpoint):
    root = '/'
    FUSE(Client(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    main(sys.argv[1])
