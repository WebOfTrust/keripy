# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from hio.base import doing

from keri.app import habbing
from keri.core.coring import Matter, MtrDex, Diger
from keri.help import helping
from keri.vdr import issuing

parser = argparse.ArgumentParser(description='Issue a verifiable credential')
parser.set_defaults(handler=lambda args: IssueDoer(hab=args.hab,
                                                   recipientIdentifier=args.recipientIdentifier,
                                                   lei=args.lei,
                                                   vcfile=args.vcfile))
parser.add_argument('--recipientIdentifier', '-ri', help='DID Subject ID')
parser.add_argument('--lei', help='Legal Entity Identifier')
parser.add_argument('--vcfile', '-vc', help='output file name')


class IssueDoer(doing.Doer):

    def __init__(self, recipientIdentifier, lei, vcfile, tock=0.0, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        self.recipientIdentifier = recipientIdentifier
        self.lei = lei
        self.vcfile = vcfile

        super(IssueDoer, self).__init__(tock, **kwa)

    def do(self, tymth, tock=0.0, **opts):
        issuer = issuing.Issuer(hab=self.hab, name=self.hab.name, noBackers=True)
        now = helping.nowIso8601()
        vlei = dict(
            type=[
                "VerifiableCredential",
                "vLEIGLEIFCredential"
            ],
        )
        cred = dict(vlei)
        cred['id'] = "{}".format("#" * Matter.Codes[MtrDex.Blake3_256].fs)
        cred['issuer'] = f"did:keri:{self.hab.pre}"
        cred['issuanceDate'] = now
        cred['credentialSubject'] = dict(
            id=f"did:keri:{self.recipientIdentifier}",
            lei=self.lei
        )

        vcdig = Diger(raw=json.dumps(cred).encode("utf-8"))
        cred['id'] = f"did:keri:{vcdig.qb64}"
        msg = json.dumps(cred).encode("utf-8")

        cigers = self.hab.mgr.sign(ser=msg, verfers=self.hab.kever.verfers, indexed=False)

        cred['proof'] = dict(
            type=[
                "KERISignature2021"
            ],
            created=now,
            jws=cigers[0].qb64,
            verificationMethod=f"did:keri:{self.hab.pre}/{issuer.regk}#0",
            proofPurpose="assertionMethod"
        )

        # tevt, kevt = issuer.issue(vcdig=vcdig.qb64)
        # self.client.tx(kevt)  # send to connected remote
        # logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(kevt))
        # tyme = (yield (self.tock))
        #
        # self.client.tx(tevt)  # send to connected remote
        # logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(tevt))
        # tyme = (yield (self.tock))

        with open(self.vcfile, "w") as f:
            f.write(json.dumps(cred, indent=4))

        print(f'wrote {self.vcfile}')

        return super().do(tymth, tock, **opts)
