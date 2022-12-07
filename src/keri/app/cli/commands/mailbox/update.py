# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.db import basing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Update the index for a given topic for a witness')
parser.set_defaults(handler=lambda args: handler(args), transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")

parser.add_argument("--witness", "-w", help="qualified b64 AID of witness to update", required=True)
parser.add_argument("--topic", "-t", help="topic name to update", required=True)
parser.add_argument("--index", "-i", help="new index for topic on witness", required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(update, **kwa)]


def update(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    witness = args.witness
    topic = args.topic
    idx = int(args.index)

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            hab = hby.habByName(name=alias)

            if topic[0] != "/":
                topic = "/" + topic

            witrec = hab.db.tops.get((hab.pre, witness))
            if witrec is None:
                witrec = basing.TopicsRecord(topics=dict())

            witrec.topics[topic] = int(idx)
            hab.db.tops.pin((hab.pre, witness), witrec)

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
