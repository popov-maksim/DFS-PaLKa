def help_command(params=None):
    print("Available commands:\n")
    for cmd, descript in COMMAND_DESCRIPTIONS.items():
        print(f"-- {cmd}: {descript}")
    print("\nYou also can use short names for commands")


def reg_command(params):
    pass


def login_command(params):
    pass


def init_command(params):
    pass


def fdelete_command(params):
    pass


def fcreate_command(params):
    pass


def fread_command(params):
    pass


def fwrite_command(params):
    pass


def finfo_command(params):
    pass


def fcopy_command(params):
    pass


def fmove_command(params):
    pass


def odir_command(params):
    pass


def rdir_command(params):
    pass


def mdir_command(params):
    pass


def ddir_command(params):
    pass


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
