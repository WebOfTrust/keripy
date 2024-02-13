# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app.cli.common import displaying, existing
from keri.core import coring, serdering
from keri.db import dbing, basing
from keri.help import helping
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Revert an unpublished interaction event at the end of a local KEL')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(rollback, **kwa)]


def rollback(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = existing.aliasInput(hby)

            hab = hby.habByName(alias)

            if hab.kever.ilk not in (coring.Ilks.ixn,):
                raise kering.ValidationError(f"only interaction events can be rolled back, top event is "
                                             f"{hab.kever.ilk}")

            serder = hab.kever.serder
            dgkey = dbing.dgKey(hab.pre, serder.saidb)
            wigs = hby.db.getWigs(dgkey)

            if len(wigs) > 0:
                raise kering.ValidationError(f"top event at sequence number {hab.kever.sn} has been published to "
                                             f"{len(wigs)} witnesses, unable to rollback.")

            ked = hby.db.states.getDict(keys=serder.pre)
            pdig = hby.db.getKeLast(dbing.snKey(serder.preb, serder.sn - 1))

            pDgKey = dbing.dgKey(serder.preb, bytes(pdig))  # get message
            raw = hby.db.getEvt(key=pDgKey)
            pserder = serdering.SerderKERI(raw=bytes(raw))

            dgkey = dbing.dgKey(serder.preb, serder.saidb)
            hby.db.delEvt(dgkey)
            hby.db.wits.rem(keys=dgkey)
            hby.db.delWigs(dgkey)
            hby.db.delSigs(dgkey)  # idempotent
            hby.db.delDts(dgkey)  # idempotent do not change dts if already
            hby.db.delKes(dbing.snKey(serder.preb, serder.sn))

            seqner = coring.Number(num=serder.sn - 1)
            fner = coring.Number(numh=ked['f'])
            fner = coring.Number(num=fner.num - 1)

            # Update the only items in state that will change after rolling back an ixn
            ked['s'] = seqner.numh
            ked['et'] = pserder.ked['t']
            ked['p'] = pserder.ked['p']
            ked['d'] = pserder.said
            ked['f'] = fner.numh
            ked['dt'] = helping.nowIso8601()

            state = serdering.SerderKERI(ked=ked)  # This is wrong key state is not Serder anymore
            hby.db.states.pin(keys=hab.pre,
                              val=helping.datify(basing.KeyStateRecord,
                                                 state.ked))

            # Refresh all habs to reload this one
            hby.db.reload()
            hby.loadHabs()

            print(f"Key event at {hab.kever.sn} rolledback, current state:")
            displaying.printIdentifier(hby, hab.pre)

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, rollback failed")
        return -1
