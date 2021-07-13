# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""

import argparse

parser = argparse.ArgumentParser(description='Stop watcher instance')
parser.set_defaults(handler=lambda args: handler())


def handler():
    print('watcher stop')
