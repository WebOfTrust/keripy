# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import indirecting, grouping, agenting
from keri.app.cli.common import existing, displaying
from keri.app.habbing import GroupHab

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Process any incoming events that will progress local pending multisig '
                                             'events.')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    kever = ContinueDoer(name=args.name, base=args.base, bran=args.bran, alias=args.alias)
    return [kever]


class ContinueDoer(doing.DoDoer):
    """ DoDoer running the doers for recovering pending multisig events. """

    def __init__(self, name, base, bran, alias):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.alias = alias
        self.counselor = grouping.Counselor(hby=self.hby)
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.mbx = indirecting.MailboxDirector(hby=self.hby,
                                               topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate",
                                                       "/challenge", "/oobi"])
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

        (seqner, saider) = esc[0]
        src = hab.mhab.pre if isinstance(hab, GroupHab) else hab.pre
        anchor = dict(i=hab.pre, s=seqner.snh, d=saider.qb64)
        self.witq.query(src=src, pre=hab.kever.delpre, anchor=anchor)

        print(f"Checking mailboxes for any events to process")
        while self.hby.db.cgms.get(keys=(hab.pre, seqner.qb64)) is None:
            yield 1.0

        print()
        displaying.printIdentifier(self.hby, hab.pre)

        self.remove([self.mbx, self.counselor, self.witq])
        return True
