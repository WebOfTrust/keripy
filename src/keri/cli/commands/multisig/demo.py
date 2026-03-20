import argparse
import json

from .incept import GroupMultisigIncept


parser = argparse.ArgumentParser(description="Run a demo collection of witnesses")
parser.set_defaults(handler=lambda args: demo(args))
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)


def demo(args):
    f = open(args.file)
    opts = json.load(f)

    ms1 = GroupMultisigIncept(name="multisig1", group="multigroup1", proto="http", **opts)
    ms2 = GroupMultisigIncept(name="multisig2", group="multigroup2", proto="http", **opts)
    ms3 = GroupMultisigIncept(name="multisig3", group="multigroup3", proto="http", **opts)

    doers = [ms1, ms2, ms3]
    return doers
