# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.ipex module

Join multisig ipex messages
"""
import argparse

from hio.base import doing

from keri import help
from keri.app import habbing, indirecting, agenting, notifying, grouping, connecting, forwarding
from keri.app.cli.common import existing
from keri.core import parsing, routing, serdering, coring
from keri.peer import exchanging
from keri.vdr import verifying, credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Join group multisig ipex events')
parser.set_defaults(handler=lambda args: join(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--auto", "-Y", help="auto approve any delegation request non-interactively", action="store_true")


def join(args):
    """  Wait for and provide interactive confirmation of group multisig inception, rotation or interaction events

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    auto = args.auto

    joinDoer = JoinDoer(name=name, base=base, bran=bran, auto=auto)

    doers = [joinDoer]
    return doers


class JoinDoer(doing.DoDoer):
    """  Doist doer capable of polling for group ipex events and prompting user for action

    """

    def __init__(self, name, base, bran, auto=False):
        """ Create doer for polling for group ipex events and either approve automatically or prompt user

        Parameters:
            name (str): database environment name
            base (str): database directory prefix
            bran (str): passcode to unlock keystore

        """
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.org = connecting.Organizer(hby=self.hby)
        self.notifier = notifying.Notifier(hby=self.hby)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.rvy = routing.Revery(db=self.hby.db,  lax=True)
        self.hby.kvy.registerReplyRoutes(self.rvy.rtr)
        self.psr = parsing.Parser(kvy=self.hby.kvy, tvy=self.rgy.tvy, rvy=self.rvy, vry=self.verifier, exc=self.exc)

        mux = grouping.Multiplexor(hby=self.hby, notifier=self.notifier)
        grouping.loadHandlers(exc=self.exc, mux=mux)
        self.counselor = grouping.Counselor(hby=self.hby)

        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.credentialer = credentialing.Credentialer(hby=self.hby, rgy=self.rgy, registrar=self.registrar,
                                                       verifier=self.verifier)

        self.mbx = indirecting.MailboxDirector(hby=self.hby, exc=self.exc, topics=['/receipt', '/multisig', '/replay',
                                                                                   '/delegate'])
        self.postman = forwarding.Poster(hby=self.hby)

        doers = [self.hbyDoer, self.witq,  self.mbx, self.counselor, self.registrar, self.credentialer, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.joinDo)])
        self.auto = auto
        super(JoinDoer, self).__init__(doers=doers)

    def joinDo(self, tymth, tock=0.0):
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

        print("Waiting for group ipex events...")

        while True:

            found = False
            for keys, notice in self.notifier.noter.notes.getItemIter():
                attrs = notice.attrs
                route = attrs['r']

                if route == '/multisig/exn':
                    said = attrs["d"]
                    exn, pathed = exchanging.cloneMessage(self.hby, said=said)
                    embeds = exn.ked['e']

                    if embeds['exn']['r'].startswith("/ipex"):
                        done = yield from self.ipex(exn, pathed)

                        if done:
                            self.notifier.noter.notes.rem(keys=keys)

                        else:
                            delete = input(f"\nDelete event [Y|n]? ")
                            if delete in ("Y", "y"):
                                self.notifier.noter.notes.rem(keys=keys)
                        found = True
            if found:
                break

            yield self.tock

        self.remove(self.toRemove)

    def ipex(self, exn, pathed):
        """  Handle exn messages for ipex

        Parameters:
            exn (SerderKERI): exn message
            pathed (dict): pathed attachments dict

        Returns:

        """
        embeds = exn.ked['e']
        sender = exn.ked['i']

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        eexn = embeds['exn']

        route = eexn['r']

        group = eexn["i"]
        hab = self.hby.habs[group] if group in self.hby.habs else None
        if hab is None:
            raise ValueError(f"message sender not a valid AID={group}")

        print()
        print(f"Group IPEX Message proposal (from {senderAlias}):")
        print(f"    Message Type: {eexn['r']}")
        print(f"    Message SAID: {eexn['d']}")
        print(f"    Sending From: {hab.name} ({hab.pre})")

        match route:
            case "/ipex/admit":
                recp = yield from self.getAdmitRecp(eexn)
            case "/ipex/agree":
                recp = self.getAgreeRecp(eexn)
            case "/ipex/apply":
                recp = self.getApplyRecp(eexn)
            case "/ipex/grant":
                recp = self.getGrantRecp(eexn)
            case "/ipex/offer":
                recp = self.getOfferRecp(eexn)
            case "/ipex/spurn":
                recp = self.getSpurnRecp(eexn)
            case _:
                return False

        contact = self.org.get(recp)
        if contact is not None and "alias" in contact:
            print(f"    Sending To: {contact['alias']} ({recp})")
        else:
            print(f"    Sending To: Unknown AID ({recp})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            eserder = serdering.SerderKERI(sad=eexn)
            anc = bytearray(eserder.raw) + pathed["exn"]
            self.psr.parseOne(ims=bytes(anc))

            msg = hab.endorse(serder=eserder, last=False, pipelined=False)
            msg = msg + pathed["exn"]
            self.psr.parseOne(ims=bytes(msg))

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for smid in smids:  # this goes to other participants only as a signaling mechanism
                rexn, atc = grouping.multisigExn(ghab=hab, exn=msg)
                self.postman.send(src=hab.mhab.pre,
                                  dest=smid,
                                  topic="multisig",
                                  serder=rexn,
                                  attachment=atc)
                while not self.postman.sent(said=rexn.said):
                    yield self.tock

            while not self.exc.complete(said=eserder.said):
                self.exc.processEscrow()
                yield self.tock

            if self.exc.lead(hab, said=exn.said):
                print(f"Sending message {eserder.said} to {recp}")
                atc = exchanging.serializeMessage(self.hby, eserder.said)
                del atc[:eserder.size]
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="credential",
                                  serder=eserder,
                                  attachment=atc)

                while not self.postman.sent(said=eserder.said):
                    yield self.tock

                print("... ipex message sent")
                return True

            return True
        return False

    def getAdmitRecp(self, exn):
        grant, pathed = exchanging.cloneMessage(self.hby, exn['p'])
        if grant is None:
            raise ValueError(f"exn message said={exn['p']} not found")

        embeds = grant.ked['e']
        acdc = embeds["acdc"]
        for label in ("anc", "iss", "acdc"):
            ked = embeds[label]
            sadder = coring.Sadder(ked=ked)
            ims = bytearray(sadder.raw) + pathed[label]
            self.psr.parseOne(ims=ims)

        said = acdc["d"]
        while not self.rgy.reger.saved.get(keys=said):
            yield self.tock

        return acdc['i']

    def getAgreeRecp(self, exn):
        pass

    def getApplyRecp(self, exn):
        return exn['a']['i']

    def getGrantRecp(self, exn):
        return exn['a']['i']

    def getOfferRecp(self, exn):
        pass

    def getSpurnRecp(self, exn):
        pass
