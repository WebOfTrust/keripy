# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""
import argparse
import json

from hio import help
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
                count = 0
                for key, _ in hby.db.getUreItemIter():
                    count += 1
                escrows["unverified-receipts"] = count

            if (not escrow) or escrow == "verified-receipts":
                count = 0
                for key, _ in hby.db.getVreItemIter():
                    count += 1
                escrows["verified-receipts"] = count

            if (not escrow) or escrow == "partially-signed-events":
                pses = list()
                key = ekey = b''  # both start same. when not same means escrows found
                while True:  # break when done
                    for ekey, edig in hby.db.getPseItemIter(key=key):
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
                count = 0
                for key, _ in hby.db.getUweItemIter():
                    count += 1
                escrows["unverified-event-indexed-couples"] = count

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
                count  = 0
                for key, _ in hby.db.getQnfItemsNextIter():
                    count += 1
                escrows["query-not-found"] = count

            if (not escrow) or escrow == "partially-delegated-events":
                count = 0
                for key, _ in hby.db.getPdesItemsNextIter():
                    count += 1
                escrows["partially-delegated-events"] = count

            if (not escrow) or escrow == "reply":
                count = 0
                for key, _ in hby.db.rpes.getItemIter():
                    count += 1
                escrows["reply"] = count

            if (not escrow) or escrow == "failed-oobi":
                count = 0
                for key, _ in hby.db.eoobi.getItemIter():
                    count += 1
                escrows["failed-oobi"] = count

            if (not escrow) or escrow == 'group-partial-witness':
                count = 0
                for key, _ in hby.db.gpwe.getItemIter():
                    count += 1
                escrows["group-partial-witness"] = count

            if (not escrow) or escrow == 'group-delegate':
                count = 0
                for key, _ in hby.db.gdee.getItemIter():
                    count += 1
                escrows["group-delegate"] = count

            if (not escrow) or escrow == 'delegated-partial-witness':
                count = 0
                for key, _ in hby.db.dpwe.getItemIter():
                    count += 1
                escrows["delegated-partial-witness"] = count

            if (not escrow) or escrow == 'group-partial-signed':
                count = 0
                for key, _ in hby.db.gpse.getItemIter():
                    count += 1
                escrows["group-partial-signed"] = count

            if (not escrow) or escrow == 'exchange-partial-signed':
                count = 0
                for key, _ in hby.db.epse.getItemIter():
                    count += 1
                escrows["exchange-partial-signed"] = count

            if (not escrow) or escrow == 'delegated-unanchored':
                count = 0
                for key, _ in hby.db.dune.getItemIter():
                    count += 1
                escrows["delegated-unanchored"] = count

            # TEL / Reger escrows
            reger = viring.Reger(name=hby.name, db=hby.db, temp=False)

            if (not escrow) or escrow == 'tel-out-of-order':
                count = 0
                for key, _ in reger.getOotItemIter():
                    count += 1
                escrows["tel-out-of-order"] = count

            if (not escrow) or escrow == 'tel-partially-witnessed':
                count = 0
                for key, _ in reger.getAllItemIter(reger.twes):
                    count += 1
                escrows["tel-partially-witnessed"] = count

            if (not escrow) or escrow == 'tel-anchorless':
                count = 0
                for key, _ in reger.getAllItemIter(reger.taes):
                    count += 1
                escrows["tel-anchorless"] = count

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
                count = 0
                for key, _ in reger.cmse.getItemIter():
                    count += 1
                escrows["tel-missing-signature"] = count

            if (not escrow) or escrow == 'tel-partial-witness-escrow':
                count = 0
                for (regk, snq), (prefixer, seqner, saider) in reger.tpwe.getItemIter():
                    count += 1
                escrows["tel-partial-witness-escrow"] = count

            if (not escrow) or escrow == 'tel-multisig':
                count = 0
                for key, _ in reger.tmse.getItemIter():
                    count += 1
                escrows["tel-multisig"] = count

            if (not escrow) or escrow == 'tel-event-dissemination':
                count = 0
                for key, _ in reger.tede.getItemIter():
                    count += 1
                escrows["tel-event-dissemination"] = count

            print(json.dumps(escrows, indent=2))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
