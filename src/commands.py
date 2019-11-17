import requests
import hashlib
from src.utils import read_token, save_token, request_node
from src.constants import *
from src.logger import debug_log


def _update_current_path(new_path):
    with open(CURRENT_PATH, "w") as f:
        f.write(new_path)


def _get_current_path():
    current_path = None
    with open(CURRENT_PATH, "r") as f:
        current_path = f.read().strip()
    return current_path


def _auth(params, action):
    if len(params) < 2:
        print("Specify login and password please.")
        return
    
    login = params[0]
    password = params[1]
    
    if login == "" or password == "":
        print("Please give me non-empty login and password")
        return
    
    encrypted_pass = hashlib.md5(password)
    data = {LOGIN_KEY: login, ENCRYPTED_PASS_KEY: encrypted_pass}
    res = request_node(NAMENODE_IP, f"/{action}", data)

    if res.ok:
        token = res.json[TOKEN_KEY]
        save_token(token)
        _update_current_path(f"{login}")
        print("Success!\nYou were logged in.")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def _command(params, keys, action):
    token = read_token()

    params.append(token)
    keys.append(TOKEN_KEY)

    params = _get_dict(params, keys)

    res = request_node(NAMENODE_IP, f"/{action}", params)
    debug_log(res.json())

    if res.ok:
        print("Success!")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def _get_dict(params, keys):
    assert(len(params) == len(keys))

    res = {}
    for i in range(len(params)):
        res[keys[i]] = params[i]

    return res


def help_command(params=None):
    print("Available commands:\n")
    for cmd, descript in COMMAND_DESCRIPTIONS.items():
        print(f"-- {cmd}: {descript}")
    print("\nYou also can use short names for commands")


def reg_command(params):
    _auth(params, "reg")


def login_command(params):
    _auth(params, "login")


def init_command(params=[]):
    _command(params, [], "init")


def fdelete_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]
    
    _command(params, [PATH_KEY], "fdelete")


def fcreate_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    _command(params, [PATH_KEY], "fcreate")


def fread_command(params):
    pass
    # _command(params, [PATH_KEY], "fread")


def fwrite_command(params):
    pass
    # _command(params, [PATH_KEY], "fwrite")


def finfo_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/finfo", params)
    debug_log(res.json())

    if res.ok:
        file_size = res.json[FILE_SIZE_KEY]
        print(f"{params[0]} has size {file_size}")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def fcopy_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    if params[1][0] == "/":
        params[1] = params[1][1:]
    else:    
        params[1] = current_path + params[1]

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fcopy")


def fmove_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    if params[1][0] == "/":
        params[1] = params[1][1:]
    else:    
        params[1] = current_path + params[1]

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fmove")


def odir_command(params):
    # without relational path only absolute
    new_path = params[0]
    token = read_token()

    current_path = _get_current_path()

    if new_path[0] == "/":
        new_path = new_path[1:]
    else:    
        new_path = current_path + new_path

    if ".." in new_path or "." in new_path:
        print("Pease use only absolute path")
        print(f"Your current path is {_get_current_path()}")
        return

    data = { TOKEN_KEY: token, PATH_KEY: new_path }
    res = request_node(NAMENODE_IP, "/dir_exists", data)

    if res.ok:
        _update_current_path(f"{new_path}")
        print(f"Your current path is {new_path}")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)
    

def rdir_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/rdir", params)
    debug_log(res.json())

    if res.ok:
        dir_list = res.json[DIR_LIST_KEY]
        for l in dir_list:
            print(f" -- {l}")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def mdir_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    _command(params, [PATH_KEY], "mdir")


def ddir_command(params):
    current_path = _get_current_path()

    if params[0][0] == "/":
        params[0] = params[0][1:]
    else:    
        params[0] = current_path + params[0]

    _command(params, [PATH_KEY], "ddir")


AVAILABLE_COMMANDS = {
    "init": ["initialize", "init", "i"],
    "fcreate": ["filecreate", "fcreate", "fcr"],
    "fread": ["fileread", "fread", "fr"],
    "fwrite": ["filewrite", "fwrite", "fwr"],
    "fdelete": ["filedelete", "fdelete", "fdel", "fdl"],
    "finfo": ["fileinfo", "finfo", "fi"],
    "fcopy": ["filecopy", "fcopy", "fcp"],
    "fmove": ["filemove", "fmove", "fmv"],
    "odir": ["opendirectory", "odir", "opdir", "opendir"],
    "rdir": ["readdirectory", "rdir", "readdir"],
    "mdir": ["makedirectory", "mkdir", "mdir", "makedir"],
    "ddir": ["deletedirectory", "ddir", "deldir", "deld"],
    "reg": ["registration", "reg", "registrate"],
    "login": ["login", "signin"],
    "help": "help",
}

COMMAND_DESCRIPTIONS = {
    "init": "Initialize the client storage on a new system, should remove any existing file in the dfs root directory and return available size.",
    "fcreate": "Create a new empty file.",
    "fread": "Read any file from DFS (download a file from the DFS to the Client side)",
    "fwrite": "Put any file to DFS (upload a file from the Client side to the DFS)",
    "fdelete": "Delete any file from DFS",
    "finfo": "Provide information about the file (any useful information - size, node id, etc.)",
    "fcopy": "Create a copy of file.",
    "fmove": "Move a file to the specified path.",
    "odir": "Change directory",
    "rdir": "Return list of files, which are stored in the directory.",
    "mdir": "Create a new directory.",
    "ddir": "Delete directory. If the directory contains files the system should ask for confirmation from the user before deletion.",
    "reg": "Registrate(create) new user",
    "login": "Login as a user",
    "help": "Show available commands",
}

executor = {
    "init": init_command,
    "fcreate": fcreate_command,
    "fread": fread_command,
    "fwrite": fwrite_command,
    "fdelete": fdelete_command,
    "finfo": finfo_command,
    "fcopy": fcopy_command,
    "fmove": fmove_command,
    "odir": odir_command,
    "rdir": rdir_command,
    "mdir": mdir_command,
    "ddir": ddir_command,
    "reg": reg_command,
    "login": login_command,
    "help": help_command,
}
