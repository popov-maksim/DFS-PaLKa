import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations
from utils import read_token, save_token, request_node
from constants import *
from logger import debug_log


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
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/getattr', {'path': full_path})
        if type(res) != dict:
            raise FuseOSError(res)
        return res

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readdir', {'path': full_path})
        print(res)
        return res

    def readlink(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readlink', {'path': full_path})
        print(res)
        return res

    #
    # def mknod(self, path, mode, dev):
    #     return os.mknod(self._full_path(path), mode, dev)
    #
    def rmdir(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/rmdir', {'path': full_path})
        print(res)
        return res

    #
    def mkdir(self, path, mode):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/mkdir', {'path': full_path, 'mode': mode})
        print(res)
        return res
    #
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


def main(mountpoint):
    root = '/'
    FUSE(Client(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    main(sys.argv[1])
