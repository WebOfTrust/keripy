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
from keri import core
from keri.core import coring, serdering
from keri.db import dbing
from keri.help import helping
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Confirm success delegate event (icp or rot) and gather and '
                                             'propagate witness receipts.')
parser.set_defaults(handler=lambda args: confirm(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--interact", "-i", help="anchor the delegation approval in an interaction event.  "
                                             "Default is to use a rotation event.", action="store_true")
parser.add_argument("--auto", "-Y", help="auto approve any delegation request non-interactively", action="store_true")
parser.add_argument("--authenticate", '-z', help="Prompt the controller for authentication codes for each witness",
                    action='store_true')
parser.add_argument('--code', help='<Witness AID>:<code> formatted witness auth codes.  Can appear multiple times',
                    default=[], action="append", required=False)
parser.add_argument('--code-time', help='Time the witness codes were captured.', default=None, required=False)


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
    authenticate = args.authenticate
    codes = args.code
    codeTime = args.code_time

    confirmDoer = ConfirmDoer(name=name, base=base, alias=alias, bran=bran, interact=interact, auto=auto,
                              authenticate=authenticate, codes=codes, codeTime=codeTime)

    doers = [confirmDoer]
    return doers


class ConfirmDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, interact=False, auto=False, authenticate=False, codes=None,
                 codeTime=None):
        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.postman = forwarding.Poster(hby=hby)
        self.counselor = grouping.Counselor(hby=hby)
        self.notifier = notifying.Notifier(hby=hby)
        self.mux = grouping.Multiplexor(hby=hby, notifier=self.notifier)
        self.authenticate = authenticate
        self.codes = codes if codes is not None else []
        self.codeTime = codeTime

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
            for pre, sn, edig in esc:
                dgkey = dbing.dgKey(pre, edig)
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
                    delpre = dkever.delpre

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

                        anchor = dict(i=eserder.ked["i"], s=eserder.snh, d=eserder.said)
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
                        sner = core.Number(num=serder.sn, code=core.NumDex.Huge)  # maybe serder.sner instead so not Huge
                        saider = coring.Saider(qb64b=serder.saidb)
                        self.counselor.start(ghab=hab, prefixer=prefixer, seqner=sner, saider=saider)

                        while True:
                            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, sner.qb64))
                            if saider is not None:
                                break

                            yield self.tock

                        print(f"Delegate {eserder.pre} {typ} event committed.")

                        self.remove(self.toRemove)
                        return True

                    else:
                        cur = hab.kever.sner.num

                        anchor = dict(i=eserder.ked["i"], s=eserder.snh, d=eserder.said)
                        if self.interact:
                            hab.interact(data=[anchor])
                        else:
                            hab.rotate(data=[anchor])

                        auths = {}
                        if self.authenticate:
                            codeTime = helping.fromIso8601(
                                self.codeTime) if self.codeTime is not None else helping.nowIso8601()
                            for arg in self.codes:
                                (wit, code) = arg.split(":")
                                auths[wit] = f"{code}#{codeTime}"

                            for wit in hab.kever.wits:
                                if wit in auths:
                                    continue
                                code = input(f"Entire code for {wit}: ")
                                auths[wit] = f"{code}#{helping.nowIso8601()}"

                        witDoer = agenting.WitnessReceiptor(hby=self.hby, auths=auths)
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

                        self.hby.db.delegables.rem(keys=(pre, sn))
                        self.remove(self.toRemove)
                        return True

                yield self.tock

            yield self.tock

    def escrowed(self):
        esc = []
        for (pre, sn), edig in self.hby.db.delegables.getItemIter():
            esc.append((pre, sn, edig))
        return esc
