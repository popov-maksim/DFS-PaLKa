import hashlib
from utils import read_token, save_token, request_node, get_dict_from_response
from constants import *
from logger import debug_log
import configparser
from http import HTTPStatus


START_PATH = ""

config = configparser.ConfigParser()
config.read('../client.conf')
NAMENODE_IP = config['SERVER']['IP']


def _update_current_path(new_path):
    # saving user's work directory
    config.set('SERVER', 'CURRENT_PATH', new_path)
    with open('../client.conf', 'w') as f:
        config.write(f)


def _get_current_path():
    return config['SERVER']['CURRENT_PATH']


def _get_path(path):
    current_path = _get_current_path()

    if path and path[0] == "/":
        # absolute path to user's home directory
        path = path[1:]
    else:
        # relative path to current path
        path = os.path.join(current_path, path) if path != "." else current_path

    return path


def _dir_exists(path):
    token = read_token()

    data = {TOKEN_KEY: token, PATH_KEY: path}
    res = request_node(NAMENODE_IP, "/dir_exists", data)

    if res.ok:
        return True
    else:
        return False


def _auth(params, action):
    # login and registration with getting token
    if len(params) < 2:
        print("Specify login and password please.")
        return
    
    login = params[0]
    password = params[1]
    
    if login == "" or password == "":
        print("Please give me non-empty login and password")
        return
    
    encrypted_pass = hashlib.md5(password.encode('utf-8')).hexdigest()
    data = {LOGIN_KEY: login, ENCRYPTED_PASS_KEY: encrypted_pass}
    res = request_node(NAMENODE_IP, f"/{action}", data)

    if res.status == HTTPStatus.OK:
        token = get_dict_from_response(res)[TOKEN_KEY]
        save_token(token)
        _update_current_path(START_PATH)
        print("Success!\nYou were logged in.")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def _command(params, keys, action):
    # executing command with token
    token = read_token()

    params.append(token)
    keys.append(TOKEN_KEY)

    params = _get_dict(params, keys)

    res = request_node(NAMENODE_IP, f"/{action}", params)
    debug_log(get_dict_from_response(res))

    if res.status == HTTPStatus.OK:
        print("Success!")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def _get_dict(params, keys):
    assert(len(params) == len(keys))

    res = {}
    for i in range(len(params)):
        res[keys[i]] = params[i]

    return res


def help_command(params):
    print("Available commands:\n")
    for cmd, descript in COMMAND_DESCRIPTIONS.items():
        print(f"-- {cmd}: {descript}")
    print("\nYou also can use short names for commands")


def reg_command(params):
    _auth(params, "reg")


def login_command(params):
    _auth(params, "login")


def init_command(params):
    _command(params, [], "init")


def fdelete_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    _command(params, [PATH_KEY], "fdelete")


def fcreate_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    _command(params, [PATH_KEY], "fcreate")


def fread_command(params):
    token = read_token()

    filename = os.path.basename(params[0])

    # getting right path
    params[0] = _get_path(params[0])

    res = request_node(NAMENODE_IP, "/fread", {TOKEN_KEY: token, PATH_KEY: params[0]})
    debug_log(get_dict_from_response(res))

    if res.status == HTTPStatus.OK:
        storage_node_ip = get_dict_from_response(res)[NODE_IP_KEY]
        full_path = get_dict_from_response(res)[FULL_PATH_KEY]

        storage_res = request_node(storage_node_ip, "/fread", {FULL_PATH_KEY: full_path})
        debug_log(get_dict_from_response(storage_res))

        if storage_res.headers['status'] == HTTPStatus.OK:
            file_data = storage_res.data
            with open(filename, "wb") as f:
                f.write(file_data)
            print("Success!")
        else:
            print("Unsuccessful")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def fwrite_command(params):
    token = read_token()

    filename = params[0]

    # getting right path
    params[0] = _get_path(os.path.basename(params[0]))

    res = request_node(NAMENODE_IP, "/fwrite", {TOKEN_KEY: token, PATH_KEY: params[0]})
    debug_log(get_dict_from_response(res))

    if res.status == HTTPStatus.OK:
        storage_node_ip = get_dict_from_response(res)[NODE_IP_KEY]

        storage_res = request_node(storage_node_ip, "/fwrite",
                                   {FULL_PATH_KEY: get_dict_from_response(res)[FULL_PATH_KEY]},
                                   [(FILE, (filename, open(filename, 'rb'), 'application/octet'))])
        debug_log(get_dict_from_response(storage_res))

        if storage_res.status == HTTPStatus.OK:
            print("Success!")
        else:
            msg = get_dict_from_response(storage_res)[MESSAGE_KEY]
            print(msg)
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def finfo_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/finfo", params)
    debug_log(get_dict_from_response(res))

    if res.status == HTTPStatus.OK:
        file_size = get_dict_from_response(res)[FILE_SIZE_KEY]
        nodes_ip = get_dict_from_response(res)[NODE_IP_KEY]
        print(f"Size of `{params[PATH_KEY]}` = {file_size} bytes\n"
              f"It's stored on {len(nodes_ip)} nodes: {nodes_ip}")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def fcopy_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    # getting right path
    params[1] = _get_path(params[1])

    print(params)

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fcopy")


def fmove_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    # getting right path
    params[1] = _get_path(params[1])

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fmove")


def odir_command(params):
    token = read_token()

    # getting right path
    new_path = _get_path(params[0])

    if ".." in new_path or "." in new_path:
        print("Please use only absolute path or forward relative")
        print(f"Your current path is {_get_current_path()}")
        return

    data = {TOKEN_KEY: token, PATH_KEY: new_path}
    print(new_path)
    res = request_node(NAMENODE_IP, "/dir_exists", data)

    if res.status == HTTPStatus.OK:
        _update_current_path(f"{new_path}")
        print(f"Your current path is {new_path}")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)
    

def rdir_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/rdir", params)
    debug_log(get_dict_from_response(res))

    if res.status == HTTPStatus.OK:
        dir_list = get_dict_from_response(res)[DIR_LIST_KEY]
        for l in dir_list:
            print(f" -- {l}")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def mdir_command(params):
    # getting right path
    params[0] = _get_path(params[0])

    _command(params, [PATH_KEY], "mdir")


def ddir_command(params):
    # getting right path
    params[0] = _get_path(params[0])
    params.append(True)

    _command(params, [PATH_KEY, FORCE_KEY], "ddir")


def pwd(params):
    current_path = _get_current_path()
    print(f"You are at {current_path if current_path else '$HOME'}")


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
    "pwd": "pwd",
    "help": "help",
}

COMMAND_DESCRIPTIONS = {
    "init": "Initialize the client storage on a new system, should remove any existing file in the dfs root directory "
            "and return available size.",
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
    "ddir": "Delete directory. If the directory contains files the system should ask for confirmation from the user"
            " before deletion.",
    "reg": "Registrate(create) new user",
    "login": "Login as a user",
    "help": "Show available commands",
    "pwd": "Show current directory",
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
    "pwd": pwd,
}
