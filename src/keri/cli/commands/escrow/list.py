# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""

import argparse
import json

from hio.base import doing
from hio.help import ogler

from ...common import existingHby, Parsery

from ....kering import ConfigurationError
from ....core import loadEvent
from ....vdr import Reger


logger = ogler.getLogger()

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
        with existingHby(name=name, base=base, bran=bran) as hby:
            reger = Reger(name=hby.name, db=hby.db, temp=False)

            escrows = dict()
            if (not escrow) or escrow == "out-of-order-events":
                oots = list()
                key = ekey = b""  # both start same. when not same means escrows found
                while True:
                    for pre, sn, edig in hby.db.ooes.getAllItemIter(keys=key):
                        try:
                            oots.append(loadEvent(hby.db, pre, edig))
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
                    for pre, sn, edig in hby.db.pwes.getAllItemIter(keys=key):
                        try:
                            pwes.append(loadEvent(hby.db, pre, edig))
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
                    for pre, sn, edig in hby.db.pses.getAllItemIter(keys=key):
                        try:
                            pses.append(loadEvent(hby.db, pre, edig))
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
                for (pre,), sn, edig in hby.db.ldes.getAllItemIter(keys=b""):
                    if hasattr(edig, "encode"):
                        edig = edig.encode("utf-8")  # Suber returns str, loadEvent expects bytes

                    try:
                        ldes.append(loadEvent(hby.db, pre, edig))
                    except ValueError as e:
                        raise e

                escrows["likely-duplicitous-events"] = ldes

            if (not escrow) or escrow == "partially-delegated-events":
                pdes = list()
                for pre, sn, edig in hby.db.pdes.getAllItemIter():
                    try:
                        pdes.append(loadEvent(hby.db, pre, edig))
                    except ValueError:
                        continue
                escrows["partially-delegated-events"] = pdes

            if (not escrow) or escrow == "query-not-found":
                items = list()
                for (pre, said), saidb in hby.db.qnfs.getTopItemIter():
                    try:
                        items.append(loadEvent(hby.db,
                                                        pre.encode("utf-8"),
                                                        saidb))
                    except ValueError:
                        continue
                escrows["query-not-found"] = items

            if (not escrow) or escrow == "misfits":
                items = list()
                for (pre, snh), saidb in hby.db.misfits.getTopItemIter():
                    try:
                        items.append(loadEvent(hby.db,
                                                        pre.encode("utf-8"),
                                                        saidb))
                    except ValueError:
                        continue
                escrows["misfits"] = items

            if (not escrow) or escrow == "missing-registry-escrow":
                creds = list()
                for (said,), dater in reger.mre.getTopItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["missing-registry-escrow"] = creds

            if (not escrow) or escrow == "broken-chain-escrow":
                creds = list()
                for (said,), dater in reger.mce.getTopItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["broken-chain-escrow"] = creds

            if (not escrow) or escrow == "missing-schema-escrow":
                creds = list()
                for (said,), dater in reger.mse.getTopItemIter():
                    creder, *_ = reger.cloneCred(said)
                    creds.append(creder.sad)

                escrows["missing-schema-escrow"] = creds

            if (not escrow) or escrow == "tel-partial-witness-escrow":
                tpwes = list()
                for (regk, snq), (prefixer, number, diger) in reger.tpwe.getTopItemIter():
                    tpwes.append(dict(
                        registry=regk,
                        prefix=prefixer.qb64,
                        sn=number.sn,
                        digest=diger.qb64,
                    ))
                escrows["tel-partial-witness-escrow"] = tpwes

            if (not escrow) or escrow == "group-partially-signed-events":
                items = list()
                for (pre,), (number, diger) in hby.db.gpse.getTopItemIter():
                    items.append(dict(prefix=pre, sn=number.sn,
                                      digest=diger.qb64))
                escrows["group-partially-signed-events"] = items

            if (not escrow) or escrow == "group-delegated-events":
                items = list()
                for (pre,), (number, diger) in hby.db.gdee.getTopItemIter():
                    items.append(dict(prefix=pre, sn=number.sn,
                                      digest=diger.qb64))
                escrows["group-delegated-events"] = items

            if (not escrow) or escrow == "group-partially-witnessed-events":
                items = list()
                for (pre,), (number, diger) in hby.db.gpwe.getTopItemIter():
                    items.append(dict(prefix=pre, sn=number.sn,
                                      digest=diger.qb64))
                escrows["group-partially-witnessed-events"] = items

            if (not escrow) or escrow == "escrowed-partially-signed-exchange":
                items = list()
                for keys, serder in hby.db.epse.getTopItemIter():
                    items.append(serder.sad)
                escrows["escrowed-partially-signed-exchange"] = items

            if (not escrow) or escrow == "escrowed-exchange-datetime":
                items = list()
                for (dig,), dater in hby.db.epsd.getTopItemIter():
                    items.append(dict(said=dig, datetime=dater.dts))
                escrows["escrowed-exchange-datetime"] = items

            if (not escrow) or escrow == "delegated-partially-witnessed-events":
                items = list()
                for keys, serder in hby.db.dpwe.getTopItemIter():
                    items.append(serder.sad)
                escrows["delegated-partially-witnessed-events"] = items

            if (not escrow) or escrow == "delegated-unverified-events":
                items = list()
                for keys, serder in hby.db.dune.getTopItemIter():
                    items.append(serder.sad)
                escrows["delegated-unverified-events"] = items

            if (not escrow) or escrow == "delegated-partially-unduplicated-backer":
                items = list()
                for keys, serder in hby.db.dpub.getTopItemIter():
                    items.append(serder.sad)
                escrows["delegated-partially-unduplicated-backer"] = items

            if (not escrow) or escrow == "reply-escrow":
                items = list()
                for (route,), diger in hby.db.rpes.getTopItemIter():
                    items.append(dict(route=route, said=diger.qb64))
                escrows["reply-escrow"] = items

            if (not escrow) or escrow == "delegable-events":
                escrows["delegable-events"] = {"count": hby.db.delegables.cnt()}

            if (not escrow) or escrow == "unverified-delegated-events":
                escrows["unverified-delegated-events"] = {"count": hby.db.udes.cnt()}

            if (not escrow) or escrow == "escrowed-oobi":
                escrows["escrowed-oobi"] = {"count": hby.db.eoobi.cnt()}

            if (not escrow) or escrow == "unverified-receipt-escrow":
                escrows["unverified-receipt-escrow"] = {"count": hby.db.ures.cnt()}

            if (not escrow) or escrow == "unverified-witness-escrow":
                escrows["unverified-witness-escrow"] = {"count": hby.db.uwes.cnt()}

            if (not escrow) or escrow == "unverified-transferable-receipt-escrow":
                escrows["unverified-transferable-receipt-escrow"] = {
                    "count": hby.db.vres.cnt()
                }

            print(json.dumps(escrows, indent=2))

    except ConfigurationError:
        print(
            f"identifier prefix for {name} does not exist, incept must be run first",
        )
        return -1
