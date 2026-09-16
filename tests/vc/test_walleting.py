# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""
from keri.core import (Salter, Counter, Seqner, Diger, Prefixer,
                       Parser, SealEvent, Codens)
from keri.kering import Vrsn_1_0, Kinds
from keri.app import openHby

from keri.vc import credential
from keri.vdr import Verifier, Regery



def test_wallet(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    sidSalt = Salter(raw=b'0123456789abcdef').qb64

    with openHby(name="sid", base="test", salt=sidSalt) as sidHby:
        sidHab = sidHby.makeHab(name="test")
        seeder.seedSchema(db=sidHby.db)
        assert sidHab.pre == "ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU"

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
        credSubject = dict(
            LEI="254900OPPU84GM83MG36"
        )

        sidReg = Regery(hby=sidHby, name="bob", temp=True)
        verifier = Verifier(hby=sidHby, reger=sidReg.reger)
        issuer = sidReg.makeRegistry(prefix=sidHab.pre, name="bob", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal], framed=True)
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidReg.processEscrows()

        creder = credential(issuer=sidHab.pre,
                            recipient=sidHab.pre,
                            schema=schema,
                            data=credSubject,
                            status=issuer.regk,
                            version=Vrsn_1_0, kind=Kinds.json)
        assert creder.said == "EN3QlKaGReOMnaiRxytYyNQyL2n52BZkfZOfuExgLJd6"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal], framed=True)
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidReg.processEscrows()

        msg = bytearray(creder.raw)
        msg.extend(Counter(Codens.SealSourceTriples, count=1,
                                version=Vrsn_1_0).qb64b)
        msg.extend(Prefixer(qb64=iss.pre).qb64b)
        msg.extend(Seqner(sn=0).qb64b)
        msg.extend(iss.saidb)

        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EN3QlKaGReOMnaiRxytYyNQyL2n52BZkfZOf'
                       b'uExgLJd6","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":'
                       b'"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1ha'
                       b'tTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EAtlWMVcG6dzH74UOuEKVCtW'
                       b'zJr0IeAiT8YWkpvCTyXQ","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-'
                       b'EoJzU","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"254900OPPU84'
                       b'GM83MG36"}}-IABEN3QlKaGReOMnaiRxytYyNQyL2n52BZkfZOfuExgLJd60AAAAAA'
                       b'AAAAAAAAAAAAAAAAAENGQqVeE9MbdxVsFDbparc17DVyYqnAY17UgwKLqqpZh')

        ser = (b'{"v":"ACDC10JSON000197_","d":"EN3QlKaGReOMnaiRxytYyNQyL2n52BZkfZOf'
               b'uExgLJd6","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":'
               b'"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1ha'
               b'tTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EAtlWMVcG6dzH74UOuEKVCtW'
               b'zJr0IeAiT8YWkpvCTyXQ","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-'
               b'EoJzU","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"254900OPPU84'
               b'GM83MG36"}}')

        Parser(version=Vrsn_1_0).parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        creder, *_ = verifier.reger.cloneCred(said=creder.said)
        assert creder.raw == ser
