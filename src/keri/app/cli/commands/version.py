# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

parser = argparse.ArgumentParser(description='Print version of KLI')
parser.set_defaults(handler=lambda args: version(args.hab))


def version(hab):
    print("0.1.0", hab)
