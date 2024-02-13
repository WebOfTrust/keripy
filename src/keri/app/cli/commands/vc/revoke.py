# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app import indirecting, habbing, grouping, forwarding, connecting, notifying
from keri.app.cli.common import existing
from keri.app.habbing import GroupHab
from keri.core import coring, serdering
from keri.core.eventing import SealEvent
from keri.peer import exchanging
from keri.vdr import credentialing, verifying

parser = argparse.ArgumentParser(description='Revoke a verifiable credential')
parser.set_defaults(handler=lambda args: revokeCredential(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--said', help='is SAID vc content qb64')
parser.add_argument('--send', help='alias of contact to send the revocation events to (can be repeated)',
                    required=False, action="append")
parser.add_argument("--time", help="timestamp for the revocation", required=False, default=None)


def revokeCredential(args):
    name = args.name

    revokeDoer = RevokeDoer(name=name, alias=args.alias, said=args.said, base=args.base, bran=args.bran,
                            registryName=args.registry_name, timestamp=args.time, send=args.send)

    doers = [revokeDoer]
    return doers


class RevokeDoer(doing.DoDoer):

    def __init__(self, name, alias, said, base, bran, registryName, send, timestamp, **kwa):
        self.said = said
        self.send = send
        self.timestamp = timestamp
        self.registryName = registryName
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = connecting.Organizer(hby=self.hby)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.counselor = grouping.Counselor(hby=self.hby)
        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.postman = forwarding.Poster(hby=self.hby)
        notifier = notifying.Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/credential"],
                                          verifier=self.verifier, exc=exc)

        doers = [self.hbyDoer, mbx, self.counselor, self.registrar, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.revokeDo)])
        super(RevokeDoer, self).__init__(doers=doers, **kwa)

    def revokeDo(self, tymth, tock=0.0):
        """  Revoke Credential doer method


        Parameters:
             tymth (function): injected function wrapper closure returned by .tymen() of
                 Tymist instance. Calling tymth() returns associated Tymist .tyme.
             tock (float): injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        registry = self.rgy.registryByName(self.registryName)
        if registry is None:
            print(f"invalid registry name {self.registryName}")
            return

        try:
            creder = self.verifier.reger.creds.get(keys=(self.said,))
            if creder is None:
                print(f"invalid credential SAID {self.said}")
                return

            kwargs = dict()
            if self.timestamp is not None:
                kwargs['dt'] = self.timestamp

            registry = self.rgy.regs[registry.regk]
            hab = registry.hab

            state = registry.tever.vcState(vci=creder.said)
            if state is None or state.et not in (coring.Ilks.iss, coring.Ilks.rev):
                raise kering.ValidationError(f"credential {creder.said} not is correct state for revocation")

            rserder = registry.revoke(said=creder.said, **kwargs)

            vcid = rserder.ked["i"]
            rseq = coring.Seqner(snh=rserder.ked["s"])
            rseal = SealEvent(vcid, rseq.snh, rserder.said)
            rseal = dict(i=rseal.i, s=rseal.s, d=rseal.d)

            if registry.estOnly:
                anc = hab.rotate(data=[rseal])
            else:
                anc = hab.interact(data=[rseal])

            aserder = serdering.SerderKERI(raw=bytes(anc))
            self.registrar.revoke(creder, rserder, aserder)

            senderHab = self.hab
            if isinstance(self.hab, GroupHab):
                senderHab = self.hab.mhab
                smids = self.hab.db.signingMembers(pre=self.hab.pre)
                smids.remove(self.hab.mhab.pre)

                for recp in smids:  # this goes to other participants only as a signaling mechanism
                    exn, atc = grouping.multisigRevokeExn(ghab=self.hab, said=creder.said, rev=rserder.raw, anc=anc)
                    self.postman.send(src=self.hab.mhab.pre,
                                      dest=recp,
                                      topic="multisig",
                                      serder=exn,
                                      attachment=atc)

            while not self.registrar.complete(creder.said, sn=1):
                yield self.tock

            if self.hab.witnesser() and 'i' in creder.attrib:
                recp = creder.attrib['i']
                msgs = []
                for msg in self.hby.db.clonePreIter(pre=creder.issuer):
                    serder = serdering.SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))
                for msg in self.rgy.reger.clonePreIter(pre=creder.said):
                    serder = serdering.SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))

                for (serder, atc) in msgs:
                    self.postman.send(src=senderHab.pre, dest=recp, topic="credential", serder=serder,
                                      attachment=atc)

                last = msgs[-1][0]
                while not self.postman.sent(said=last.said):
                    yield self.tock

        except kering.ValidationError as ex:
            raise ex

        self.remove(self.toRemove)
