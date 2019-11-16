import requests
import hashlib
from src.utils import read_token, save_token
from src.constants import *
from src.logger import debug_log


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
    res = requests.post(f"{NAMENODE_IP}/{action}", json=data)

    if res.ok:
        token = res.json[TOKEN_KEY]
        save_token(token)
        print("Success!\nYou were logged in.")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def _command(params, action):
    token = read_token()

    res = requests.post(f"{NAMENODE_IP}/{action}", json={TOKEN_KEY: token})
    debug_log(res.json())

    if res.ok:
        print("Success!")
    else:
        msg = res.json[MESSAGE_KEY]
        print(msg)


def help_command(params=None):
    print("Available commands:\n")
    for cmd, descript in COMMAND_DESCRIPTIONS.items():
        print(f"-- {cmd}: {descript}")
    print("\nYou also can use short names for commands")


def reg_command(params):
    _auth(params, "reg")


def login_command(params):
    _auth(params, "login")


def init_command(params=None):
    _command(params, "init")


def fdelete_command(params):
    _command(params, "fdelete")


def fcreate_command(params):
    _command(params, "fcreate")


def fread_command(params):
    _command(params, "fread")


def fwrite_command(params):
    _command(params, "fwrite")


def finfo_command(params):
    _command(params, "finfo")


def fcopy_command(params):
    _command(params, "fcopy")


def fmove_command(params):
    _command(params, "fmove")


def odir_command(params):
    _command(params, "odir")


def rdir_command(params):
    _command(params, "rdir")


def mdir_command(params):
    _command(params, "mdir")


def ddir_command(params):
    _command(params, "ddir")


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
