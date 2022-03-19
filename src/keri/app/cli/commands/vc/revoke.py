# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import decking

from keri.app import directing, indirecting, agenting
from keri.app.cli.common import existing
from keri.core import eventing
from keri.vdr import viring
from keri.vdr.credentialing import Registry

parser = argparse.ArgumentParser(description='Revoke a verifiable credential')
parser.set_defaults(handler=lambda args: revokeCredential(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--said', help='is SAID vc content qb64')


def revokeCredential(args):
    name = args.name

    revokeDoer = RevokeDoer(name=name, said=args.said, registryName=args.registry_name)

    doers = [revokeDoer]
    return doers


class RevokeDoer(doing.DoDoer):

    def __init__(self, name, said, registryName, **kwa):
        self.cues = decking.Deck()
        self.registryName = registryName
        self.hab, doers = existing.setupHabitat(name=name)
        self.said = said

        reger = viring.Reger(name=self.registryName, db=self.hab.db)
        self.issuer = Registry(hab=self.hab, name=self.hab.name, reger=reger)

        mbx = indirecting.MailboxDirector(hab=self.hab, topics=["/receipt", "/multisig"])
        doers.extend([mbx, doing.doify(self.issuerDo)])

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

        creder = self.issuer.reger.creds.get(keys=self.said)
        if creder is None:
            print(f"Invalid credential SAID {self.said}")
            return

        self.issuer.revoke(creder=creder)

        published = False
        witnessed = False
        while not (published and witnessed):
            while self.cues:
                cue = self.cues.popleft()
                if cue["kin"] == "witnessed":
                    witnessed = True

                elif cue["kin"] == "published":
                    published = True

                yield self.tock
            yield

        print(f"Revoked credential {creder.said}")

        self.remove(self.toRemove)

    def enter(self, **kwargs):
        if not self.issuer.inited:
            self.issuer.make(**self.issuer._inits)
        return super(RevokeDoer, self).enter(**kwargs)

    def issuerDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from credential issue coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.issuer.cues:
                cue = self.issuer.cues.popleft()

                cueKin = cue['kin']
                if cueKin == "send":
                    tevt = cue["msg"]
                    witSender = agenting.WitnessPublisher(hab=self.hab, msg=tevt)
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])
                    self.cues.append(dict(kin="published", regk=self.issuer.regk))
                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    serder = eventing.Serder(raw=bytearray(kevt))
                    witDoer = agenting.WitnessReceiptor(hby=self.hby)
                    self.extend([witDoer])

                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])
                    self.cues.append(dict(kin="witnessed", regk=self.issuer.regk))

                yield self.tock

            yield self.tock


