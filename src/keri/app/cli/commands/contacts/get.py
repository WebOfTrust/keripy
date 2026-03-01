# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.get module

"""
import argparse
import json

from ..... import help, kering
from hio.base import doing

from .... import organizing as connecting
from ...common import existing
from .....kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Get a single contact')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aid', '-a', help='contact AID prefix', required=False, default=None)
parser.add_argument('--alias', help='contact alias to lookup', required=False, default=None)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(get, **kwa)]


def get(tymth, tock=0.0, **opts):
    """ Command line handler for getting a single contact

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    aid = args.aid
    alias = args.alias

    if aid is None and alias is None:
        print("Either --aid or --alias is required")
        return -1

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)

            contact = None
            pre = None

            if aid:
                pre = aid
                contact = org.get(aid)
            elif alias:
                contacts = org.find('alias', f"^{alias}$")  # Exact match
                if len(contacts) > 1:
                    print(f"Multiple contacts match alias '{alias}'")
                    return -1
                if len(contacts) == 1:
                    contact = contacts[0]
                    pre = contact['id']

            if contact is None:
                print("Contact not found")
                return -1

            accepted = [diger.qb64 for diger in hby.db.chas.get(keys=(pre,))]
            received = [diger.qb64 for diger in hby.db.reps.get(keys=(pre,))]
            valid = set(accepted) & set(received)

            challenges = []
            for said in valid:
                try:
                    exn = hby.db.exns.get(keys=(said,))
                except kering.ValidationError:
                    val = hby.db.getVal(db=hby.db.exns.sdb, key=hby.db.exns._tokey((said,)))
                    d = json.loads(bytes(val).decode("utf-8"))
                    challenges.append(dict(dt=d['dt'], words=d['a']['words']))
                else:
                    challenges.append(dict(dt=exn.ked['dt'], words=exn.ked['a']['words']))

            contact["challenges"] = challenges

            wellKnowns = []
            wkans = hby.db.wkas.get(keys=(pre,))
            for wkan in wkans:
                wellKnowns.append(dict(url=wkan.url, dt=wkan.dt))

            contact["wellKnowns"] = wellKnowns

            print(json.dumps(contact, indent=2))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        return -1
