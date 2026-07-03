# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ...common import Parsery, setupHby, printIdentifier, parseVersion

from ....app import (GroupHab, MailboxDirector,
                     Counselor, WitnessInquisitor)
from ....kering import Kinds


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Process any incoming events that will progress local pending multisig '
                                             'events.',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args) )
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--version', default=None, required=False, type=parseVersion,
                    help='KERI protocol version for mailbox recovery and follow-up queries, such as 1.0 or 2.0')


def handler(args):
    kever = ContinueDoer(name=args.name, base=args.base, bran=args.bran, alias=args.alias, version=args.version)
    return [kever]


class ContinueDoer(doing.DoDoer):
    """ DoDoer running the doers for recovering pending multisig events. """

    def __init__(self, name, base, bran, alias, version=None):
        self.hby = setupHby(name=name, base=base, bran=bran)
        self.alias = alias
        self.version = version
        self.kind = Kinds.json
        self.counselor = Counselor(hby=self.hby, version=version, kind=Kinds.json)
        self.witq = WitnessInquisitor(hby=self.hby)
        kwa = dict(version=version, gvrsn=version, kind=self.kind) if version is not None else {}
        self.mbx = MailboxDirector(hby=self.hby,
                                   topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate",
                                           "/challenge", "/oobi"],
                                   **kwa)
        doers = [self.mbx, self.counselor, self.witq, doing.doify(self.recover)]
        super(ContinueDoer, self).__init__(doers=doers)

    def recover(self, tymth, tock=0.0, **opts):
        """ Command line status handler

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield tock)

        hab = self.hby.habByName(self.alias)
        if hab is None:
            raise ValueError(f"no AID with alias {self.alias}")

        esc = self.hby.db.gdee.get(keys=(hab.pre,))
        if not esc:
            raise ValueError(f"no escrowed events for {self.alias} ({hab.pre})")

        (number, diger) = esc[0]
        src = hab.mhab.pre if isinstance(hab, GroupHab) else hab.pre
        anchor = dict(i=hab.pre, s=number.numh, d=diger.qb64)
        kwa = dict(version=self.version, gvrsn=self.version, kind=self.kind) if self.version is not None else {}
        self.witq.query(src=src, pre=hab.kever.delpre, anchor=anchor, **kwa)

        print(f"Checking mailboxes for any events to process")
        while self.hby.db.cgms.get(keys=(hab.pre, number.qb64)) is None:
            yield 1.0

        print()
        printIdentifier(self.hby, hab.pre)

        self.remove([self.mbx, self.counselor, self.witq])
        return True
