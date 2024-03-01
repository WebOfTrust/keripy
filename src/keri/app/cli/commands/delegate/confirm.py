# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
from ordered_set import OrderedSet as oset

from hio.base import doing

from keri import help
from keri.app import habbing, indirecting, agenting, grouping, forwarding, delegating, notifying
from keri.app.cli.common import existing
from keri.app.habbing import GroupHab
from keri.core import coring, serdering
from keri.db import dbing
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Confirm success delegate event (icp or rot) and gather and '
                                             'propagate witness receipts.')
parser.set_defaults(handler=lambda args: confirm(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--interact", "-i", help="anchor the delegation approval in an interaction event.  "
                                             "Default is to use a rotation event.", action="store_true")
parser.add_argument("--auto", "-Y", help="auto approve any delegation request non-interactively", action="store_true")


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
    auto = args.auto

    confirmDoer = ConfirmDoer(name=name, base=base, alias=alias, bran=bran, interact=interact, auto=auto)

    doers = [confirmDoer]
    return doers


class ConfirmDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, interact=False, auto=False):
        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.postman = forwarding.Poster(hby=hby)
        self.counselor = grouping.Counselor(hby=hby)
        self.notifier = notifying.Notifier(hby=hby)
        self.mux = grouping.Multiplexor(hby=hby, notifier=self.notifier)

        exc = exchanging.Exchanger(hby=hby, handlers=[])
        delegating.loadHandlers(hby=hby, exc=exc, notifier=self.notifier)
        grouping.loadHandlers(exc=exc, mux=self.mux)

        self.mbx = indirecting.MailboxDirector(hby=hby, topics=['/receipt', '/multisig', '/replay', '/delegate'],
                                               exc=exc)
        doers = [self.hbyDoer, self.witq, self.postman, self.counselor, self.mbx]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.confirmDo)])

        self.alias = alias
        self.hby = hby
        self.interact = interact
        self.auto = auto
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
                eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event

                ilk = eserder.sad["t"]
                if ilk in (coring.Ilks.dip,):
                    typ = "inception"
                    delpre = eserder.sad["di"]

                elif ilk in (coring.Ilks.drt,):
                    typ = "rotation"
                    dkever = self.hby.kevers[eserder.pre]
                    delpre = dkever.delegator

                else:
                    continue

                if delpre in self.hby.prefixes:
                    hab = self.hby.habs[delpre]

                    if self.auto:
                        approve = True
                    else:
                        yn = input(f"Delegation {typ} request from {eserder.pre}.\nAccept [Y|n]? ")
                        approve = yn in ('', 'y', 'Y')

                    if not approve:
                        continue

                    if isinstance(hab, GroupHab):
                        aids = hab.smids
                        seqner = coring.Seqner(sn=eserder.sn)
                        anchor = dict(i=eserder.ked["i"], s=seqner.snh, d=eserder.said)
                        if self.interact:
                            msg = hab.interact(data=[anchor])
                        else:
                            print("Confirm does not support rotation for delegation approval with group multisig")
                            continue

                        serder = serdering.SerderKERI(raw=msg)
                        exn, atc = grouping.multisigInteractExn(ghab=hab, aids=aids, ixn=bytearray(msg))
                        others = list(oset(hab.smids + (hab.rmids or [])))
                        others.remove(hab.mhab.pre)

                        for recpt in others:  # send notification to other participants as a signalling mechanism
                            self.postman.send(src=hab.mhab.pre, dest=recpt, topic="multisig", serder=exn,
                                              attachment=atc)

                        prefixer = coring.Prefixer(qb64=hab.pre)
                        seqner = coring.Seqner(sn=serder.sn)
                        saider = coring.Saider(qb64b=serder.saidb)
                        self.counselor.start(ghab=hab, prefixer=prefixer, seqner=seqner, saider=saider)

                        while True:
                            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
                            if saider is not None:
                                break

                            yield self.tock

                        print(f"Delegate {eserder.pre} {typ} event committed.")

                        self.remove(self.toRemove)
                        return True

                    else:
                        cur = hab.kever.sner.num
                        seqner = coring.Seqner(sn=eserder.sn)
                        anchor = dict(i=eserder.ked["i"], s=seqner.snh, d=eserder.said)
                        if self.interact:
                            hab.interact(data=[anchor])
                        else:
                            hab.rotate(data=[anchor])

                        witDoer = agenting.WitnessReceiptor(hby=self.hby)
                        self.extend(doers=[witDoer])
                        self.toRemove.append(witDoer)
                        yield self.tock

                        if hab.kever.wits:
                            witDoer.msgs.append(dict(pre=hab.pre, sn=cur+1))
                            while not witDoer.cues:
                                _ = yield self.tock

                        print(f'Delegagtor Prefix  {hab.pre}')
                        print(f'\tDelegate {eserder.pre} {typ} Anchored at Seq. No.  {hab.kever.sner.num}')

                        # wait for confirmation of fully commited event
                        if eserder.pre in self.hby.kevers:
                            self.witq.query(src=hab.pre, pre=eserder.pre, sn=eserder.sn)

                            while eserder.sn < self.hby.kevers[eserder.pre].sn:
                                yield self.tock

                            print(f"Delegate {eserder.pre} {typ} event committed.")
                        else:  # It should be an inception event then...
                            wits = [werfer.qb64 for werfer in eserder.berfers]
                            self.witq.query(src=hab.pre, pre=eserder.pre, sn=eserder.sn, wits=wits)

                            while eserder.pre not in self.hby.kevers:
                                yield self.tock

                            print(f"Delegate {eserder.pre} {typ} event committed.")

                        self.remove(self.toRemove)
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
