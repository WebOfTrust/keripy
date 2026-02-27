# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing

from .... import kering, help
from ..common import displaying, existing 
from ..common.parsing import Parsery
from ....core import coring, serdering
from ....db import dbing, basing
from ....help import helping
from ....kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Revert an unpublished interaction event at the end of a local KEL', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)


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
            wigers = hby.db.wigs.get(hab.pre, serder.saidb)

            if len(wigers) > 0:
                raise kering.ValidationError(f"top event at sequence number {hab.kever.sn} has been published to "
                                             f"{len(wigers)} witnesses, unable to rollback.")

            ked = hby.db.states.getDict(keys=serder.pre)
            pdig = hby.db.kels.getOnLast(keys=serder.preb, on=serder.sn - 1)
            pdig = pdig.encode("utf-8")

            pserder = hby.db.evts.get(keys=(serder.preb, bytes(pdig)))

            dgkey = dbing.dgKey(serder.preb, serder.saidb)
            hby.db.wigs.rem(keys=(serder.preb, serder.saidb))
            hby.db.evts.rem(keys=(serder.preb, serder.saidb))
            hby.db.wits.rem(keys=(serder.preb, serder.saidb))
            hby.db.sigs.rem(keys=(serder.preb, serder.saidb))  # idempotent
            hby.db.dtss.rem(keys=dgkey)  # idempotent
            hby.db.kels.remOn(keys=serder.preb, on=serder.sn)

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
