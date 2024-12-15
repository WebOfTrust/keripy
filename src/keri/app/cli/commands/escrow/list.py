# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""
import argparse
import json

from keri import help
from hio.base import doing

from keri.core import eventing
from keri.app.cli.common import existing
from keri.db import dbing
from keri.kering import ConfigurationError
from keri.vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Views events in escrow state.')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--escrow", "-e", help="show values for one specific escrow", default=None)


def handler(args):
    """ Command line escrow handler

    """
    kwa = dict(args=args)
    return [doing.doify(escrows, **kwa)]


def escrows(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    escrow = args.escrow

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            escrows = dict()

            # KEL / Baser escrows

            if (not escrow) or escrow == "unverified-receipts":
                escrows["unverified-receipts"] = sum(1 for key, _ in hby.db.getUreItemIter())

            if (not escrow) or escrow == "verified-receipts":
                escrows["verified-receipts"] = sum(1 for key, _ in hby.db.getVreItemIter())

            if (not escrow) or escrow == "partially-signed-events":
                pses = list()
                key = ekey = b''  # both start same. when not same means escrows found
                while True:  # break when done
                    for ekey, edig in hby.db.getPseItemsNextIter(key=key):
                        pre, sn = dbing.splitSnKey(ekey)  # get pre and sn from escrow item

                        try:
                            pses.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if ekey == key:  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["partially-signed-events"] = pses

            if (not escrow) or escrow == "partially-witnessed-events":
                pwes = list()
                key = ekey = b''  # both start same. when not same means escrows found
                while True:  # break when done
                    for ekey, edig in hby.db.getPweItemIter(key=key):
                        pre, sn = dbing.splitSnKey(ekey)  # get pre and sn from escrow item

                        try:
                            pwes.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if ekey == key:  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["partially-witnessed-events"] = pwes

            if (not escrow) or escrow == "unverified-event-indexed-couples":
                escrows["unverified-event-indexed-couples"] = sum(1 for key, _ in hby.db.getUweItemIter())

            if (not escrow) or escrow == "out-of-order-events":
                oots = list()
                key = ekey = b''  # both start same. when not same means escrows found
                while True:
                    for ekey, edig in hby.db.getOoeItemIter(key=key):
                        pre, sn = dbing.splitSnKey(ekey)  # get pre and sn from escrow item

                        try:
                            oots.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if ekey == key:  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["out-of-order-events"] = oots

            if (not escrow) or escrow == "likely-duplicitous-events":
                ldes = list()
                key = ekey = b''  # both start same. when not same means escrows found
                while True:  # break when done
                    for ekey, edig in hby.db.getLdeItemIter(key=key):
                        pre, sn = dbing.splitSnKey(ekey)  # get pre and sn from escrow item

                        try:
                            ldes.append(eventing.loadEvent(hby.db, pre, edig))
                        except ValueError as e:
                            raise e

                    if ekey == key:  # still same so no escrows found on last while iteration
                        break
                    key = ekey  # setup next while iteration, with key after ekey

                escrows["likely-duplicitous-events"] = ldes

            if (not escrow) or escrow == "query-not-found":
                escrows["query-not-found"] = sum(1 for key, _ in hby.db.getQnfItemsNextIter())

            if (not escrow) or escrow == "partially-delegated-events":
                escrows["partially-delegated-events"] = sum(1 for key, _ in hby.db.getPdeItemsNextIter())

            if (not escrow) or escrow == "reply":
                escrows["reply"] = sum(1 for key, _ in hby.db.rpes.getItemIter())

            if (not escrow) or escrow == "failed-oobi":
                escrows["failed-oobi"] = sum(1 for key, _ in hby.db.eoobi.getItemIter())

            if (not escrow) or escrow == 'group-partial-witness':
                escrows["group-partial-witness"] = sum(1 for key, _ in hby.db.gpwe.getItemIter())

            if (not escrow) or escrow == 'group-delegate':
                escrows["group-delegate"] = sum(1 for key, _ in hby.db.gdee.getItemIter())

            if (not escrow) or escrow == 'delegated-partial-witness':
                escrows["delegated-partial-witness"] = sum(1 for key, _ in hby.db.dpwe.getItemIter())

            if (not escrow) or escrow == 'group-partial-signed':
                escrows["group-partial-signed"] = sum(1 for key, _ in hby.db.gpse.getItemIter())

            if (not escrow) or escrow == 'exchange-partial-signed':
                escrows["exchange-partial-signed"] = sum(1 for key, _ in hby.db.epse.getItemIter())

            if (not escrow) or escrow == 'delegated-unanchored':
                escrows["delegated-unanchored"] = sum(1 for key, _ in hby.db.dune.getItemIter())

            # TEL / Reger escrows
            reger = viring.Reger(name=hby.name, db=hby.db, temp=False)

            if (not escrow) or escrow == 'tel-out-of-order':
                escrows["tel-out-of-order"] = sum(1 for key, _ in reger.getOotItemIter())

            if (not escrow) or escrow == 'tel-partially-witnessed':
                escrows["tel-partially-witnessed"] = sum(1 for key, _ in reger.getAllItemIter(reger.twes))

            if (not escrow) or escrow == 'tel-anchorless':
                escrows["tel-anchorless"] = sum(1 for key, _ in reger.getAllItemIter(reger.taes))

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

            if (not escrow) or escrow == 'tel-missing-signature':
                escrows["tel-missing-signature"] = sum(1 for key, _ in reger.cmse.getItemIter())

            if (not escrow) or escrow == 'tel-partial-witness-escrow':
                escrows["tel-partial-witness-escrow"] = sum(1 for key, _ in reger.tpwe.getItemIter())

            if (not escrow) or escrow == 'tel-multisig':
                escrows["tel-multisig"] = sum(1 for key, _ in reger.tmse.getItemIter())

            if (not escrow) or escrow == 'tel-event-dissemination':
                escrows["tel-event-dissemination"] = sum(1 for key, _ in reger.tede.getItemIter())

            print(json.dumps(escrows, indent=2))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
