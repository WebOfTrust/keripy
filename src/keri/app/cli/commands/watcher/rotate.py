# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

parser = argparse.ArgumentParser(description='Rotate watcher prefix')
parser.set_defaults(handler=lambda args: handler())


def handler():
    print('watcher rotate')
