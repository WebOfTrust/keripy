# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app.cli.common import existing
from keri.core import coring, serdering
from keri.db import koming, subing, dbing
from keri.db.basing import KeyStateRecord, StateEERecord
from keri.kering import ConfigurationError, Version
from keri.vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='View status of a local AID')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--force', action="store_true", required=False,
                    help='True means perform migration without prompting the user')


def handler(args):
    if not args.force:
        print()
        print("This command will migrate your datastore to the next version of KERIpy and is not reversible.")
        print("After this command, you will not be able to access your data store with this version.")
        print()
        yn = input("Are you sure you want to continue? [y|N]: ")

        if yn not in ("y", "Y"):
            print("...exiting")
            return []

    kwa = dict(args=args)
    return [doing.doify(migrate, **kwa)]


def migrate(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with dbing.openLMDB(name=name, base=base, bran=bran, temp=False) as db:
            print(db.path)
            states = koming.Komer(db=db,
                                  schema=dict,
                                  subkey='stts.')
            nstates = koming.Komer(db=db,
                                   schema=KeyStateRecord,
                                   subkey='stts.')

            for keys, sad in states.getItemIter():
                ksr = KeyStateRecord(
                    vn=Version,  # version number as list [major, minor]
                    i=sad['i'],  # qb64 prefix
                    s=sad['s'],  # lowercase hex string no leading zeros
                    p=sad['p'],
                    d=sad['d'],
                    f=sad['f'],  # lowercase hex string no leading zeros
                    dt=sad['dt'],
                    et=sad['et'],
                    kt=sad['kt'],
                    k=sad['k'],
                    nt=sad['nt'],
                    n=sad['n'],
                    bt=sad['bt'],
                    b=sad['b'],
                    c=sad['c'],
                    ee=StateEERecord._fromdict(sad['ee']),  # latest est event dict
                    di=sad['di'] if sad['di'] else None
                )

                nstates.pin(keys=keys, val=ksr)

        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            rgy = viring.Reger(name=name, base=base, db=hby.db, temp=False,
                               reopen=True)

            rstates = koming.Komer(db=rgy,
                                   schema=dict,
                                   subkey='stts.')

            for _, sad in rstates.getItemIter():
                rsr = viring.RegStateRecord(
                    vn=list(Version),  # version number as list [major, minor]
                    i=sad['i'],  # qb64 registry SAID
                    s=sad['s'],  # lowercase hex string no leading zeros
                    d=sad['d'],
                    ii=sad['ii'],
                    dt=sad['dt'],
                    et=sad['et'],
                    bt=sad['bt'],  # hex string no leading zeros lowercase
                    b=sad['b'],  # list of qb64 may be empty
                    c=sad['c'],
                )
                # ksr = stateFromKever(kever)
                rgy.states.pin(sad['i'], val=rsr)

            for (said,), _ in rgy.saved.getItemIter():
                snkey = dbing.snKey(said, 0)
                dig = rgy.getTel(key=snkey)

                prefixer = coring.Prefixer(qb64=said)
                seqner = coring.Seqner(sn=0)
                saider = coring.Saider(qb64b=bytes(dig))
                rgy.cancs.pin(keys=said, val=[prefixer, seqner, saider])

            migrateKeys(hby.db)

            # clear escrows
            print("clearing escrows")
            hby.db.gpwe.trim()
            hby.db.gdee.trim()
            hby.db.dpwe.trim()
            hby.db.gpse.trim()
            hby.db.epse.trim()
            hby.db.dune.trim()

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1


def migrateKeys(db):
    # public keys mapped to the AID and event seq no they appeared in
    pubs = subing.CatCesrIoSetSuber(db=db, subkey="pubs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    # next key digests mapped to the AID and event seq no they appeared in
    digs = subing.CatCesrIoSetSuber(db=db, subkey="digs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    for pre, fn, dig in db.getFelItemAllPreIter(key=b''):
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := db.getEvt(key=dgkey)):
            print(f"Migrate keys: missing event for dig={dig}, skipped.")
            continue
        serder = serdering.SerderKERI(raw=bytes(raw))
        val = (coring.Prefixer(qb64b=serder.preb), coring.Seqner(sn=serder.sn))
        verfers = serder.verfers or []
        for verfer in verfers:
            pubs.add(keys=(verfer.qb64,), val=val)
        ndigers = serder.ndigers or []
        for diger in ndigers:
            digs.add(keys=(diger.qb64,), val=val)
