# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import os

parser = argparse.ArgumentParser(description='Print version of KLI')
parser.set_defaults(handler=lambda args: exit())


def exit():
    os._exit(os.EX_OK)
