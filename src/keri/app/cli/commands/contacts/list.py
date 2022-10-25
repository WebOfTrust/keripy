# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

from hio import help
from hio.base import doing

from keri.app import connecting
from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(list, **kwa)]


def list(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)
            for c in org.list():

                aid = c['id']
                accepted = [saider.qb64 for saider in hby.db.chas.get(keys=(aid,))]
                received = [saider.qb64 for saider in hby.db.reps.get(keys=(aid,))]
                valid = set(accepted) & set(received)

                challenges = []
                for said in valid:
                    exn = hby.db.exns.get(keys=(said,))
                    challenges.append(dict(dt=exn.ked['dt'], words=exn.ked['a']['words']))

                c["challenges"] = challenges

                wellKnowns = []
                wkans = hby.db.wkas.get(keys=(aid,))
                for wkan in wkans:
                    wellKnowns.append(dict(url=wkan.url, dt=wkan.dt))

                c["wellKnowns"] = wellKnowns

                print(json.dumps(c, indent=2))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
