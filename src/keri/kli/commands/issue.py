# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from keri.app import keeping
from keri.app.habbing import Habitat
from keri.core.coring import Matter, MtrDex, Diger
from keri.db import dbing, basing
from keri.help import helping
from keri.vdr.issuing import Issuer

parser = argparse.ArgumentParser(description='Issue a verifiable credential')
parser.set_defaults(handler=lambda args: issue(args.name, args.didSubjectId, args.lei))
parser.add_argument('--name', '-n', help='Humane reference')
parser.add_argument('--didSubjectId', '-dsi', help='DID Subject ID')
parser.add_argument('--lei', help='Legal Entity Identifier')

vlei = dict(
    type=[
        "VerifiableCredential",
        "vLEIGLEIFCredential"
    ],
)


def issue(name, didSubjectId, lei):
    with basing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, temp=False)

        iss = Issuer(name=f"{name}_tel", hab=hab, noBackers=True, estOnly=True)
        now = helping.nowIso8601()

        cred = dict(vlei)
        cred['id'] = "{}".format("#" * Matter.Codes[MtrDex.Blake3_256].fs)
        cred['issuer'] = f"did:keri:{hab.pre}"
        cred['issuanceDate'] = now
        cred['credentialSubject'] = dict(
            id=f"did:keri:{didSubjectId}",
            lei=lei
        )

        vcdig = Diger(raw=json.dumps(cred).encode("utf-8"))
        cred['id'] = f"did:keri:{vcdig.qb64}"
        msg = json.dumps(cred).encode("utf-8")

        cigers = hab.mgr.sign(ser=msg, verfers=hab.kever.verfers, indexed=False)
        cred['proof'] = dict(
            type=[
                "KERISignature2021"
            ],
            created=now,
            jws=cigers[0].qb64,
            verificationMethod=f"did:keri:{hab.pre}",
            proofPurpose="assertionMethod"
        )

        tevt, kevt = iss.issue(vcdig=vcdig.qb64)
        print(tevt)
        print()
        print(kevt)
        print(json.dumps(cred, indent=4))
