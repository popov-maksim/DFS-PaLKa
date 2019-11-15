#!/usr/bin/env python3

import requests
import sys
import os
from commands import *

def help_command(params=None):
    print("Available commands:\n")
    for cmd, descript in COMMAND_DESCRIPTIONS.items():
        print(f"--{cmd}: {descript}")
    print("\nYou also can use short names for commands")


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


def show_usage():
    name = os.path.basename(sys.argv[0])
    print(f"Usage: {name} <cmd> [params]")
    print("Use command <help> for list of available commands")


def execute(command, params):
    cmd = None
    for base_cmd, synonyms in AVAILABLE_COMMANDS.items():
        if command in synonyms:
            cmd = base_cmd
            break
    
    if cmd is None:
        print("No such command!")
        return
    
    {
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
        "help": help_command,
    }[cmd](params)


def main():
    args = sys.argv[1:]
    if len(args) < 1:
        show_usage()
        return

    execute(args[0], args[1:])
    
    
if __name__ == "__main__":
    main()
