# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ..common import Parsery, printIdentifier, existingHby, aliasInput

from ...kering import ValidationError, Ilks
from ...core import Number, SerderKERI
from ...db import dgKey
from ...help import helping
from ...kering import ConfigurationError
from ...recording import KeyStateRecord

logger = ogler.getLogger()

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
        with existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = aliasInput(hby)

            hab = hby.habByName(alias)

            if hab.kever.ilk not in (Ilks.ixn,):
                raise ValidationError(f"only interaction events can be rolled back, top event is "
                                             f"{hab.kever.ilk}")

            serder = hab.kever.serder
            wigers = hby.db.wigs.get(hab.pre, serder.saidb)

            if len(wigers) > 0:
                raise ValidationError(f"top event at sequence number {hab.kever.sn} has been published to "
                                             f"{len(wigers)} witnesses, unable to rollback.")

            ked = hby.db.states.getDict(keys=serder.pre)
            pdig = hby.db.kels.getLast(keys=serder.preb, on=serder.sn - 1)
            pdig = pdig.encode("utf-8")

            pserder = hby.db.evts.get(keys=(serder.preb, bytes(pdig)))

            dgkey = dgKey(serder.preb, serder.saidb)
            hby.db.wigs.rem(keys=(serder.preb, serder.saidb))
            hby.db.evts.rem(keys=(serder.preb, serder.saidb))
            hby.db.wits.rem(keys=(serder.preb, serder.saidb))
            hby.db.sigs.rem(keys=(serder.preb, serder.saidb))  # idempotent
            hby.db.dtss.rem(keys=dgkey)  # idempotent
            hby.db.kels.rem(keys=serder.preb, on=serder.sn)

            seqner = Number(num=serder.sn - 1)
            fner = Number(numh=ked['f'])
            fner = Number(num=fner.num - 1)

            # Update the only items in state that will change after rolling back an ixn
            ked['s'] = seqner.numh
            ked['et'] = pserder.ked['t']
            ked['p'] = pserder.ked['p']
            ked['d'] = pserder.said
            ked['f'] = fner.numh
            ked['dt'] = helping.nowIso8601()

            state = SerderKERI(ked=ked)  # This is wrong key state is not Serder anymore
            hby.db.states.pin(keys=hab.pre,
                              val=helping.datify(KeyStateRecord,
                                                 state.ked))

            # Refresh all habs to reload this one
            hby.db.reload()
            hby.loadHabs()

            print(f"Key event at {hab.kever.sn} rolledback, current state:")
            printIdentifier(hby, hab.pre)

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, rollback failed")
        return -1
