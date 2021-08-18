# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import keri

parser = argparse.ArgumentParser(description='Print version of KLI')
parser.set_defaults(handler=lambda args: version(args))


def version(args):
    print(keri.__version__)
