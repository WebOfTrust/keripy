# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""

import argparse
import json

from hio.base import doing

from ..... import help
from ...common import existing
from ...common.parsing import Parsery
from .....core import eventing
from .....kering import ConfigurationError
from .....vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(
    description="Views events in escrow state.", parents=[Parsery.keystore()]
)
parser.set_defaults(handler=lambda args: handler(args))

parser.add_argument(
    "--escrow", "-e", help="show values for one specific escrow", default=None
)


def handler(args):
    """Command line escrow handler"""
    kwa = dict(args=args)
    return [doing.doify(escrows, **kwa)]


def escrows(tymth, tock=0.0, **opts):
    _ = yield tock

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    escrow = args.escrow

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            reger = viring.Reger(name=hby.name, db=hby.db, temp=False)

            escrows = dict()
            if (not escrow) or escrow == "out-of-order-events":
                oots = list()
                key = ekey = b""  # both start same. when not same means escrows found
                while True:
                    for pre, sn, edig in hby.db.ooes.getOnItemIterAll(keys=key):
                        try:
                            oots.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if (
                        ekey == key
                    ):  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["out-of-order-events"] = oots

            if (not escrow) or escrow == "partially-witnessed-events":
                pwes = list()
                key = ekey = b""  # both start same. when not same means escrows found
                while True:  # break when done
                    for pre, sn, edig in hby.db.pwes.getOnItemIterAll(keys=key):
                        try:
                            pwes.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if (
                        ekey == key
                    ):  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["partially-witnessed-events"] = pwes

            if (not escrow) or escrow == "partially-signed-events":
                pses = list()
                key = ekey = b""  # both start same. when not same means escrows found
                while True:  # break when done
                    for pre, sn, edig in hby.db.pses.getOnItemIterAll(keys=key):
                        try:
                            pses.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if (
                        ekey == key
                    ):  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["partially-signed-events"] = pses

            if (not escrow) or escrow == "likely-duplicitous-events":
                ldes = list()
                for (pre,), sn, edig in hby.db.ldes.getOnItemIterAll(keys=b""):
                    if hasattr(edig, "encode"):
                        edig = edig.encode("utf-8")  # Suber returns str, loadEvent expects bytes

                    try:
                        ldes.append(eventing.loadEvent(hby.db, pre, edig))
                    except ValueError as e:
                        raise e

                escrows["likely-duplicitous-events"] = ldes

            if (not escrow) or escrow == "missing-registry-escrow":
                creds = list()
                for (said,), dater in reger.mre.getItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["missing-registry-escrow"] = creds

            if (not escrow) or escrow == "broken-chain-escrow":
                creds = list()
                for (said,), dater in reger.mce.getItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["broken-chain-escrow"] = creds

            if (not escrow) or escrow == "missing-schema-escrow":
                creds = list()
                for (said,), dater in reger.mse.getItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["missing-schema-escrow"] = creds

            print(json.dumps(escrows, indent=2))

            if not (escrow) or escrow == "tel-partial-witness-escrow":
                for (regk, snq), (prefixer, number, diger) in reger.tpwe.getItemIter():
                    pass

    except ConfigurationError:
        print(
            f"identifier prefix for {name} does not exist, incept must be run first",
        )
        return -1
