#!/usr/bin/env python3

import sys

from commands import *


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

    executor[cmd](params)


def main():
    args = sys.argv[1:]
    if len(args) < 1:
        show_usage()
        return

    execute(args[0], args[1:])


if __name__ == "__main__":
    main()
