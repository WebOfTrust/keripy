# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import multicommand
from keri import help

from keri.app import directing
from keri.app.cli import commands

logger = help.ogler.getLogger()


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, 'handler'):
        parser.print_help()
        return

    try:
        doers = args.handler(args)
        directing.runController(doers=doers, expire=0.0)

    except Exception as ex:
        import os
        if os.getenv('DEBUG_KLI'):
            import traceback
            traceback.print_exc()
        else:
            print(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
