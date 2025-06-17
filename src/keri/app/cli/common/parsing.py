# -*- encoding: utf-8 -*-
"""
keri.app..cli.common.habbing module

"""

from argparse import ArgumentParser
from os import getenv

class Parsery:
    """
    Defines utility methods creating common argument parsers.
    Can be used as parents to other argument parsers.
    """

    @staticmethod
    def keystore(required: bool = True):
        """
        Returns an ArgumentParser for a keystore parameters.

        Returns:
            ArgumentParser
        """
        parser = ArgumentParser(add_help=False)

        env_name=getenv("KLI_KEYSTORE_NAME", None)
        parser.add_argument('--name', '-n',
                            help='keystore name and file location of KERI keystore',
                            required=required if env_name is None else False,
                            default=env_name)

        parser.add_argument('--base', '-b',
                            help='additional optional prefix to file location of KERI keystore',
                            required=False,
                            default=getenv("KLI_KEYSTORE_BASE", ""))
        parser.add_argument('--passcode', '-p',
                            help='21 character encryption passcode for keystore (is not saved)', 
                            dest="bran",
                            default=getenv("KLI_KEYSTORE_PASSCODE", None))

        return parser
