import hashlib
import base64
from utils import read_token, save_token, request_node, get_dict_from_response
from constants import *
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
    if path[0] == "/":
        res_path = [""]
    else:
        res_path = _get_current_path().split("/")

    splitted_path = path.split("/")

    for dir in splitted_path:
        if dir == "..":
            if len(res_path) > 0 and res_path[-1] != "":
                res_path.pop()
            else:
                return None, False
        elif dir != ".":
            res_path.append(dir)

    if len(res_path) == 0:
        res_path.append('')

    return os.path.join(*res_path), True


def _dir_exists(path):
    token = read_token()

    data = {TOKEN_KEY: token, PATH_KEY: path}
    res = request_node(NAMENODE_IP, "/dir_exists", data)

    if res.status == HTTPStatus.OK:
        return True, get_dict_from_response(res)[MESSAGE_KEY]
    else:
        return False, get_dict_from_response(res)[MESSAGE_KEY]


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
    if len(params) < 1:
        print("Please specify a file to delete")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    _command(params, [PATH_KEY], "fdelete")


def fcreate_command(params):
    if len(params) < 1:
        print("Please specify name of a file")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    _command(params, [PATH_KEY], "fcreate")


def fread_command(params):
    if len(params) < 1:
        print("Please specify a file to read")
        return

    token = read_token()

    filename = os.path.basename(params[0])

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    res = request_node(NAMENODE_IP, "/fread", {TOKEN_KEY: token, PATH_KEY: params[0]})

    if res.status == HTTPStatus.OK:
        storage_node_ip = get_dict_from_response(res)[NODE_IP_KEY]
        full_path = get_dict_from_response(res)[FULL_PATH_KEY]

        storage_res = request_node(storage_node_ip, "/fread", {FULL_PATH_KEY: full_path})

        if storage_res.status == HTTPStatus.OK:
            file_data = get_dict_from_response(storage_res)[FILE_BYTES]
            with open(filename, "wb") as f:
                f.write(base64.decodebytes(file_data.encode()))
            print("Success!")
        else:
            print("Unsuccessful")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def fwrite_command(params):
    if len(params) < 1:
        print("Please specify a file to write to")
        return

    token = read_token()

    filename = params[0]

    if not os.path.exists(filename):
        print("There is no such file")
        return

    # getting right path
    params[0], result = _get_path(os.path.basename(params[0]))

    if not result:
        print("Wrong path")
        return

    res = request_node(NAMENODE_IP, "/fwrite", {TOKEN_KEY: token, PATH_KEY: params[0]})

    if res.status == HTTPStatus.OK:
        storage_node_ip = get_dict_from_response(res)[NODE_IP_KEY]

        with open(filename, 'rb') as f:
            file_data = f.read()

        storage_res = request_node(storage_node_ip, "/fwrite",
                                   {FULL_PATH_KEY: get_dict_from_response(res)[FULL_PATH_KEY],
                                    FILE_BYTES: str(base64.encodebytes(file_data), 'utf-8')})

        if storage_res.status == HTTPStatus.OK:
            print("Success!")
        else:
            msg = get_dict_from_response(storage_res)[MESSAGE_KEY]
            print(msg)
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def finfo_command(params):
    if len(params) < 1:
        print("Please specify a file")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/finfo", params)

    if res.status == HTTPStatus.OK:
        file_size = get_dict_from_response(res)[FILE_SIZE_KEY]
        nodes_ip = get_dict_from_response(res)[NODE_IP_KEY]
        print(f"Size of `{params[PATH_KEY]}` = {file_size} bytes\n"
              f"It's stored on {len(nodes_ip)} nodes: {nodes_ip}")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def fcopy_command(params):
    if len(params) < 2:
        print("Please specify files: source and destination (copy to)")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    # getting right path
    params[1], result = _get_path(params[1])

    if not result:
        print("Wrong path")
        return

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fcopy")


def fmove_command(params):
    if len(params) < 2:
        print("Please specify files: source and destination (move to)")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    # getting right path
    params[1], result = _get_path(params[1])

    if not result:
        print("Wrong path")
        return

    _command(params, [PATH_KEY, PATH_DESTINATION_KEY], "fmove")


def odir_command(params):
    if len(params) < 1:
        print("Please specify new directory")
        return

    # getting right path
    new_path, result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    exists, msg = _dir_exists(new_path)

    if not exists:
        print(msg)
        return

    _update_current_path(f"{new_path}")
    pwd()
    

def rdir_command(params):
    if len(params) < 1:
        print("Please specify a directory to read")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    token = read_token()

    params.append(token)
    params = _get_dict(params, [PATH_KEY, TOKEN_KEY])

    res = request_node(NAMENODE_IP, "/rdir", params)

    if res.status == HTTPStatus.OK:
        dir_list = get_dict_from_response(res)[DIR_LIST_KEY]
        for l in dir_list:
            print(f" -- {l}")
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def mdir_command(params):
    if len(params) < 1:
        print("Please specify directory name")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    _command(params, [PATH_KEY], "mdir")


def ddir_command(params):
    if len(params) < 1:
        print("Please specify a directory to delete")
        return

    # getting right path
    params[0], result = _get_path(params[0])

    if not result:
        print("Wrong path")
        return

    if _get_current_path() == params[0] or params[0] == '':
        print("Denied")
        return

    token = read_token()

    res = request_node(NAMENODE_IP, "/ddir", {TOKEN_KEY: token, PATH_KEY: params[0], FORCE_KEY: False})

    if res.status == HTTPStatus.OK:
        print("Success!")
    elif res.status == HTTPStatus.NOT_ACCEPTABLE:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)
        answer = input("Delete? [Y/n]: ")
        if answer.lower() == "y":
            res = request_node(NAMENODE_IP, "/ddir", {TOKEN_KEY: token, PATH_KEY: params[0], FORCE_KEY: True})
            if res.status == HTTPStatus.OK:
                print("Success!")
            else:
                msg = get_dict_from_response(res)[MESSAGE_KEY]
                print(msg)
    else:
        msg = get_dict_from_response(res)[MESSAGE_KEY]
        print(msg)


def pwd(params=None):
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
