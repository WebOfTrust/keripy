# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import indirecting, habbing, grouping, forwarding, connecting
from keri.app.cli.common import existing
from keri.core import coring
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


def revokeCredential(args):
    name = args.name

    revokeDoer = RevokeDoer(name=name, alias=args.alias, said=args.said, base=args.base, bran=args.bran,
                            registryName=args.registry_name,
                            send=args.send)

    doers = [revokeDoer]
    return doers


class RevokeDoer(doing.DoDoer):

    def __init__(self, name, alias, said, base, bran, registryName, send, **kwa):
        self.said = said
        self.send = send
        self.registryName = registryName
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = connecting.Organizer(hby=self.hby)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.counselor = grouping.Counselor(hby=self.hby)
        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.postman = forwarding.Postman(hby=self.hby)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/credential"],
                                          verifier=self.verifier)

        doers = [self.hbyDoer, mbx, self.counselor, self.registrar, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.revokeDo)])
        super(RevokeDoer, self).__init__(doers=doers, **kwa)

    def revokeDo(self, tymth, tock=0.0, **opts):
        """

        Parameters:
            tymth:
            tock:
            **opts:

        Returns:

        """
        yield self.tock

        registry = self.rgy.registryByName(self.registryName)
        if registry is None:
            print(f"invalid registry name {self.registryName}")
            return

        try:
            creder = self.verifier.reger.creds.get(keys=(self.said,))
            if creder is None:
                print(f"invalid credential SAID {self.said}")
                return

            self.registrar.revoke(regk=registry.regk, said=creder.said)

            while not self.registrar.complete(creder.said, sn=1):
                yield self.tock

            recps = [creder.subject['i']] if 'i' in creder.subject else []
            if self.send is not None:
                recps.extend(self.send)

            if len(recps) > 0:
                msgs = []
                for msg in self.hby.db.clonePreIter(pre=creder.issuer):
                    serder = coring.Serder(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))
                for msg in self.rgy.reger.clonePreIter(pre=creder.said):
                    serder = coring.Serder(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))

                sent = 0
                for send in recps:
                    if send in self.hby.kevers:
                        recp = send
                    else:
                        recp = self.org.find("alias", send)
                        if len(recp) != 1:
                            raise ValueError(f"invalid recipient {send}")
                        recp = recp[0]['id']
                    for (serder, atc) in msgs:
                        self.postman.send(src=self.hab.pre, dest=recp, topic="credential", serder=serder,
                                          attachment=atc)
                        sent += 1

                while not len(self.postman.cues) == sent:
                    yield self.tock

        except kering.ValidationError as ex:
            raise ex

        self.remove(self.toRemove)
