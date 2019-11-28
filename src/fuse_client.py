import base64
import sys

from fuse import FUSE, FuseOSError, Operations

from constants import *
from logger import debug_log
from utils import request_node


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
        debug_log('getattr', path)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/getattr', {'path': full_path})
        if type(res) != dict:
            raise FuseOSError(res)
        debug_log('getattr', res)
        return res

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readdir', {'path': full_path})
        debug_log('readdir', res)
        return res

    def readlink(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readlink', {'path': full_path})
        debug_log('readlink', res)
        return res

    def mknod(self, path, mode, dev):
        debug_log('MKNOD HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/readlink', {'path': full_path, 'mode': mode, 'dev': dev})
        debug_log('mknod', res)
        return res

    def rmdir(self, path):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/rmdir', {'path': full_path})
        debug_log('rmdir', res)
        return res

    def mkdir(self, path, mode):
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/mkdir', {'path': full_path, 'mode': mode})
        debug_log('mkdir', res)
        return res

    def statfs(self, path):
        return 'OK'

    # def statfs(self, path):
    #     full_path = self._full_path(path)
    #     stv = os.statvfs(full_path)
    #     return dict((key, getattr(stv,  key)) for key in ('f_bavail', 'f_bfree',
    #         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
    #         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        debug_log('UNLINK HERE', path)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/unlink', {'path': path})
        debug_log('unlink', res)
        return res

    def symlink(self, name, target):
        debug_log('SYMLINK')
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        debug_log('RENAME HERE')
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        debug_log('LINK HERE')
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        debug_log('UTIMENS HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/utimens', {'path': path})
        debug_log('utimens', res)
        return res

    # File methods
    # ============

    def open(self, path, flags):
        debug_log('OPEN HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/open', {'path': full_path, 'flags': flags})
        debug_log('open', res)
        return res

    def create(self, path, mode, fh=None):
        debug_log('CREATION HERE')
        debug_log(path, mode, fh)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/create', {'path': full_path, 'mode': mode})
        debug_log('create', res)
        return res

    def read(self, path, length, offset, fh):
        debug_log('READ HERE')
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/read', {'path': full_path, 'length': length, 'offset': offset, 'fh': fh})
        return res[BINARY_FILE].encode()

    def write(self, path, buf, offset, fh):
        debug_log('WRITE HERE', path, buf, offset, fh)
        full_path = self._full_path(path)
        data = base64.b64encode(buf)
        res = request_node(NAMENODE_IP, '/write', {'path': full_path, 'buf': data, 'offset': offset, 'fh': fh})
        debug_log('write', res)
        return res

    def truncate(self, path, length, fh=None):
        debug_log('TRUNC HERE')
        res = request_node(NAMENODE_IP, '/truncate', {'path': path, 'length': length})
        debug_log('truncate', res)
        return res

    def flush(self, path, fh):
        debug_log('FLUSH HERE', path, fh)
        res = request_node(NAMENODE_IP, '/flush', {'path': path, 'fh': fh})
        return res

    def release(self, path, fh):
        debug_log('RELEASE HERE', path, fh)
        full_path = self._full_path(path)
        res = request_node(NAMENODE_IP, '/release', {'path': full_path, 'fh': fh})
        debug_log('release', res)
        return 0

    def fsync(self, path, fdatasync, fh):
        debug_log('FSYNC HERE')
        return self.flush(path, fh)


def main(mountpoint):
    root = '/'
    FUSE(Client(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    main(sys.argv[1])
