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
    "help": "Show available commands",
}