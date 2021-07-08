# -*- encoding: utf-8 -*-
"""
keri.kli.commands.witness module

"""

import argparse

parser = argparse.ArgumentParser(description='Stop witness')
parser.set_defaults(handler=lambda args: handler())


def handler():
    print('witness stop')
