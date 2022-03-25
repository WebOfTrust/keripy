# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse

from hio.base import doing

from keri import help
from keri.app import directing, habbing, indirecting, agenting
from keri.app.cli.common import existing
from keri.core import coring
from keri.db import dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Confirm success delegate event (icp or rot) and gather and '
                                             'propagate witness recripts.')
parser.set_defaults(handler=lambda args: confirm(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--interact", "-i", help="anchor the delegation approval in an interaction event.  "
                                             "Default is to use a rotation event.", action="store_true")


def confirm(args):
    """

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    interact = args.interact

    confirmDoer = ConfirmDoer(name=name, base=base, alias=alias, bran=bran, interact=interact)

    doers = [confirmDoer]
    return doers


class ConfirmDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, interact=False):
        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.mbx = indirecting.MailboxDirector(hby=hby, topics=["/receipt", "/delegate"])
        doers = [self.hbyDoer, self.witq, self.mbx, doing.doify(self.confirmDo)]

        self.alias = alias
        self.hby = hby
        self.interact = interact
        super(ConfirmDoer, self).__init__(doers=doers)

    def confirmDo(self, tymth, tock=0.0):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            esc = self.escrowed()
            for ekey, edig in esc:
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                dgkey = dbing.dgKey(pre, bytes(edig))
                eraw = self.hby.db.getEvt(dgkey)
                if eraw is None:
                    continue
                eserder = coring.Serder(raw=bytes(eraw))  # escrowed event

                ilk = eserder.ked["t"]
                if ilk in (coring.Ilks.dip,):
                    typ = "inception"
                    delpre = eserder.ked["di"]
                    wits = eserder.ked["b"]

                elif ilk in (coring.Ilks.drt,):
                    typ = "rotation"
                    dkever = self.hby.kevers[eserder.pre]
                    delpre = dkever.delegator
                    wits = dkever.wits

                else:
                    continue

                if delpre in self.hby.prefixes:
                    hab = self.hby.habs[delpre]
                    yn = input(f"Delegation {typ} request from {eserder.pre}.\nAccept [Y|n]? ")
                    if yn in ('', 'y', 'Y'):
                        cur = hab.kever.sn
                        seqner = coring.Seqner(sn=eserder.sn)
                        anchor = dict(i=eserder.ked["i"], s=seqner.snh, d=eserder.said)
                        if self.interact:
                            hab.interact(data=[anchor])
                        else:
                            hab.rotate(data=[anchor])

                        witDoer = agenting.WitnessReceiptor(hby=self.hby)
                        self.extend(doers=[witDoer])
                        yield self.tock

                        if hab.kever.wits:
                            witDoer.msgs.append(dict(pre=hab.pre, sn=cur+1))
                            while not witDoer.cues:
                                _ = yield self.tock

                        print(f'Delegagtor Prefix  {hab.pre}')
                        print(f'\tDelegate {eserder.pre} {typ} Anchored at Seq. No.  {hab.kever.sn}')

                        # wait for confirmation of fully commited event
                        wits = [werfer.qb64 for werfer in eserder.werfers]
                        self.witq.query(src=hab.pre, pre=eserder.pre, sn=eserder.sn, wits=wits)

                        while eserder.pre not in self.hby.kevers:
                            yield self.tock

                        print(f"Delegate {eserder.pre} {typ} event committed.")
                        toRemove = [self.hbyDoer, self.mbx, self.witq, witDoer]
                        self.remove(toRemove)
                        return True

                yield self.tock

            yield self.tock

    def escrowed(self):
        esc = []
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.hby.db.getPseItemsNextIter(key=key):
                esc.append((ekey, edig))
            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        return esc
