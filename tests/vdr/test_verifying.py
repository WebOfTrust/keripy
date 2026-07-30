# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""

import pytest

from keri import (MissingRegistryError, MissingEntryError,
                  MissingChainError, RevokedChainError, ValidationError, Vrsn_1_0)
from keri.app import openHab
from keri.core import (Saider, Kevery, SerderKERI, Seqner,
                       Diger, Parser, SealEvent,
                       MtrDex, Saids, Aggor, Noncer)
from keri.kering import Ilks, Kinds, Vrsn_2_0
from keri.help import helping
from keri.vc import credential
from keri.acdc import acdcagg
from keri.acdc.messaging import acgSchemaDefault
from keri.vdr import Verifier, Regery, Tevery



def test_verifier_query(mockHelpingNowUTC, mockCoringRandomNonce):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (hby, hab):
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", version=Vrsn_1_0, kind=Kinds.json)

        verfer = Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", version=Vrsn_1_0, kind=Kinds.json)
        assert msg == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"EFa6oMZA5bgpALIc7yykT6O6'
                       b'ovdbDQnRFeTPDI4zaOhr","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"tels","rr":"","q":{"i":"EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-g'
                       b'KXqgcX4","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ"}}-V'
                       b'Aj-HABEMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl-AABAABGnrnayV'
                       b'yK1siivaffGHpWWhcVThPN_dsePQvMXrlsOYNf0UdT0e6ch-0bN-UuOJCd1behue'
                       b'Zs_0V9FQ9vw0wK')


def test_verifier_query_v2(mockHelpingNowUTC, mockCoringRandomNonce):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef',
                 version=Vrsn_2_0, kind=Kinds.json) as (hby, hab):
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", version=Vrsn_1_0, kind=Kinds.json)

        verfer = Verifier(hby=hby, reger=regery.reger)
        qry = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", version=Vrsn_2_0, kind=Kinds.json)
        serder = SerderKERI(raw=qry)
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "tels"
        assert serder.ked["q"]["i"] == "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4"
        assert serder.ked["q"]["ri"] == issuer.regk
        assert serder.ked["q"]["src"] == hab.pre

        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby.cf.put(cf)
        kvy = Kevery(db=hby.db, cf=hby.cf, enableKram=True, lax=False, local=False)
        tvy = Tevery(db=hby.db, reger=regery.reger, local=False)
        assert kvy.kramer.enabled is True

        Parser(version=Vrsn_2_0).parse(ims=bytearray(qry), kvy=kvy, tvy=tvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000


def test_verifier(seeder):
    with (openHab(name="sid", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (hby, hab),
          openHab(name="recp", transferable=True, temp=True, version=Vrsn_1_0, kind=Kinds.json) as (recpHby, recp)):
        seeder.seedSchema(db=hby.db)
        seeder.seedSchema(db=recpHby.db)
        assert hab.pre == "EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o"

        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()

        verifier = Verifier(hby=hby, reger=regery.reger)

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = Saider.saidify(sad=credSubject, code=MtrDex.Blake3_256, label=Saids.d)

        creder = credential(issuer=hab.pre,
                            schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                            data=d,
                            status=issuer.regk,
                            version=Vrsn_1_0, kind=Kinds.json)
        missing = False
        try:
            # Specify an anchor directly in the KEL
            verifier.processCredential(creder, prefixer=hab.kever.prefixer, seqner=seqner,
                                       saider=Diger(qb64=hab.kever.serder.said))
        except MissingRegistryError:
            missing = True

        assert missing is True
        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == issuer.regk
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()

        # Now that the credential has been issued, process escrows and it will find the TEL event
        verifier.processEscrows()

        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        dcre, *_ = regery.reger.cloneCred(said=creder.said)

        assert dcre.raw == creder.raw

        saider = regery.reger.issus.get(hab.pre)
        assert saider[0].qb64 == creder.said
        saider = regery.reger.subjs.get(recp.pre)
        assert saider[0].qb64 == creder.said
        saider = regery.reger.schms.get("EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC")
        assert saider[0].qb64 == creder.said

        # also try it via the cloneCreds function
        creds = regery.reger.cloneCreds(saids=saider, db=hab.db)

        for cred in creds:
            assert dcre.sad == cred["sad"]
            assert cred['rev'] is None

        with pytest.raises(MissingEntryError):
            regery.reger.cloneCred(said="nonexistantsaid")

    """End Test"""



def test_verifier_chained_credential(seeder):
    qviSchema = "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs"
    vLeiSchema = "ED892b40P_GcESs3wOcc2zFvL_GVi2Ybzp9isNTZKqP0"
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    with openHab(name="ron", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ronHby, ron), \
            openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (hanHby, han), \
            openHab(name="vic", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (vicHby, vic):
        seeder.seedSchema(db=ronHby.db)
        seeder.seedSchema(db=ianHby.db)
        seeder.seedSchema(db=hanHby.db)
        seeder.seedSchema(db=vicHby.db)

        assert ron.pre == "EOp2vZP2BrlH3DX9H3w-ghvr3c9kkDv0gS5ELFyutxwk"
        assert ian.pre == "EN6Ta5X_B7DrYR1HVGw25YgFVep4zGb5TMIoyCBaKb7R"
        assert han.pre == "EBwEKSIMG_3tp7kVCLWJ9c-tPdwtDXIeLlfdm5-IMTZv"
        assert vic.pre == "EGPhh6seaUvJy-nXFkiEdsfwekEhSm3lCVrP-tcoeL0H"

        ronreg = Regery(hby=ronHby, name="ron", temp=True)
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        vicreg = Regery(hby=vicHby, name="vic", temp=True)
        roniss = ronreg.makeRegistry(prefix=ron.pre, name="test", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(roniss.regk, "0", roniss.regd)._asdict()
        ron.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ron.kever.sn)
        diger = Diger(qb64=ron.kever.serder.said)
        roniss.anchorMsg(pre=roniss.regk,
                         regd=roniss.regd,
                         seqner=seqner,
                         saider=diger)
        ronreg.processEscrows()

        ronverfer = Verifier(hby=ronHby, reger=ronreg.reger)

        credSubject = dict(
            d="",
            i=ian.pre,
            dt=helping.nowIso8601(),
            LEI="5493001KJTIIGC8Y1R12",
        )
        _, d = Saider.saidify(sad=credSubject, code=MtrDex.Blake3_256, label=Saids.d)

        creder = credential(issuer=ron.pre,
                            schema=qviSchema,
                            data=d,
                            status=roniss.regk,
                            version=Vrsn_1_0, kind=Kinds.json)

        missing = False
        try:
            ronverfer.processCredential(creder, prefixer=ron.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ron.kever.serder.said))
        except MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ronverfer.cues) == 1
        cue = ronverfer.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == roniss.regk

        iss = roniss.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ron.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ron.kever.sn)
        diger = Diger(qb64=ron.kever.serder.said)
        roniss.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        ronreg.processEscrows()

        # Now that the credential has been issued, process escrows and it will find the TEL event
        ronverfer.processEscrows()

        assert len(ronverfer.cues) == 1
        cue = ronverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        dcre, *_ = ronreg.reger.cloneCred(said=creder.said)
        assert dcre.raw == creder.raw

        saider = ronreg.reger.issus.get(ron.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.reger.subjs.get(ian.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.reger.schms.get(qviSchema)
        assert saider[0].qb64 == creder.said

        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ian.kever.sn)
        diger = Diger(qb64=ian.kever.serder.said)
        ianiss.anchorMsg(pre=ianiss.regk,
                         regd=ianiss.regd,
                         seqner=seqner,
                         saider=diger)
        ianreg.processEscrows()

        ianverfer = Verifier(hby=ianHby, reger=ianreg.reger)

        leiCredSubject = dict(
            d="",
            i=han.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = Saider.saidify(sad=leiCredSubject, code=MtrDex.Blake3_256, label=Saids.d)

        chain = dict(
            d=creder.said,
            qualifiedvLEIIssuervLEICredential=dict(
                n=creder.said,
            ),
        )

        vLeiCreder = credential(issuer=ian.pre,
                                schema=vLeiSchema,
                                data=d,
                                status=ianiss.regk,
                                source=chain,
                                rules=[dict(
                                    usageDisclaimer="Use carefully."
                                )],
                                version=Vrsn_1_0, kind=Kinds.json)

        missing = False
        try:
            ianverfer.processCredential(vLeiCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ian.kever.serder.said))
        except MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ianverfer.cues) == 1
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == ianiss.regk

        iss = ianiss.issue(said=vLeiCreder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ian.kever.sn)
        diger = Diger(qb64=ian.kever.serder.said)
        ianiss.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        ianreg.processEscrows()

        # Now that the credential has been issued, process escrows and it will find the TEL event
        ianverfer.processEscrows()

        dcre, *_ = ianreg.reger.cloneCred(said=vLeiCreder.said)
        assert dcre.raw == vLeiCreder.raw

        dater = ianreg.reger.mce.get(vLeiCreder.saidb)
        assert dater is not None

        assert len(ianverfer.cues) == 1
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "proof"

        # Now lets get Ron's credential into Ian's Tevers and Database
        iankvy = Kevery(db=ian.db, lax=False, local=False)
        iantvy = Tevery(reger=ianreg.reger, db=ian.db, local=False)
        ianverfer = Verifier(hby=ianHby, reger=ianreg.reger)

        # Now process all the events that Ron's issuer has generated so far
        for msg in ron.db.clonePreIter(pre=ron.pre, version=ron.kever.serder.pvrsn):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=iankvy, tvy=iantvy)
        for msg in ronverfer.reger.clonePreIter(pre=roniss.regk):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=iankvy, tvy=iantvy)
        for msg in ronverfer.reger.clonePreIter(pre=creder.said):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=iankvy, tvy=iantvy)

        ianverfer.processCredential(creder, prefixer=ron.kever.prefixer, seqner=seqner,
                                    saider=Diger(qb64=ron.kever.serder.said))

        # Process the escrows to get Ian's credential out of missing chain escrow
        ianverfer.processEscrows()

        # And now it should be in the indexes
        saider = ianreg.reger.issus.get(ian.pre)  # Ian is the issuer
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.reger.subjs.get(han.pre)  # Han is the holder
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.reger.schms.get(vLeiSchema)
        assert saider[0].qb64 == vLeiCreder.said

        # test operators

        untargetedSubject = dict(
            d="",
            dt=helping.nowIso8601(),
            claim="An outrageous claim.",
        )
        _, d = Saider.saidify(sad=untargetedSubject, code=MtrDex.Blake3_256, label=Saids.d)

        chainSad = dict(
            d='',
            targetedEdge=dict(
                n=vLeiCreder.said,
            ),
        )
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)

        untargetedCreder = credential(issuer=ian.pre,
                                      schema=optionalIssueeSchema,
                                      data=d,
                                      status=ianiss.regk,
                                      source=chain,
                                      rules={},
                                      version=Vrsn_1_0, kind=Kinds.json)

        missing = False
        try:
            ianverfer.processCredential(untargetedCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ian.kever.serder.said))
        except MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ianverfer.cues) == 3
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "saved"
        cue["creder"] = untargetedCreder.raw

        iss = ianiss.issue(said=untargetedCreder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ian.kever.sn)
        diger = Diger(qb64=ian.kever.serder.said)
        ianiss.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        ianreg.processEscrows()

        # Now that the credential has been issued, process escrows and it will find the TEL event
        ianverfer.processEscrows()

        chainedSubject = dict(
            d="",
            dt=helping.nowIso8601(),
            claim="An outrageous claim.",
        )
        _, d = Saider.saidify(sad=chainedSubject, code=MtrDex.Blake3_256, label=Saids.d)

        chainSad = dict(
            d='',
            untargetedButI2I=dict(
                n=untargetedCreder.said,
                o="I2I"
            ),
        )
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)

        chainedCreder = credential(issuer=ian.pre,
                                   schema=optionalIssueeSchema,
                                   data=d,
                                   status=ianiss.regk,
                                   source=chain,
                                   rules={},
                                   version=Vrsn_1_0, kind=Kinds.json)

        missing = False
        try:
            ianverfer.processCredential(chainedCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ian.kever.serder.said))
        except MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ianverfer.cues) == 4
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "saved"
        cue["creder"] = chainedCreder.raw

        iss = ianiss.issue(said=chainedCreder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ian.kever.sn)
        diger = Diger(qb64=ian.kever.serder.said)
        ianiss.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        ianreg.processEscrows()

        # Ensure that when specifying I2I it is enforced
        try:
            ianverfer.processCredential(chainedCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ian.kever.serder.said))
        except MissingChainError:
            pass

        # Now lets get Ron's credential into Vic's Tevers and Database
        vickvy = Kevery(db=vic.db, lax=False, local=False)
        victvy = Tevery(reger=vicreg.reger, db=vic.db, local=False)
        vicverfer = Verifier(hby=vicHby, reger=vicreg.reger)

        for msg in ron.db.clonePreIter(pre=ron.pre, version=ron.kever.serder.pvrsn):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ronverfer.reger.clonePreIter(pre=roniss.regk):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ronverfer.reger.clonePreIter(pre=creder.said):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        vicverfer.processCredential(creder, prefixer=ian.kever.prefixer, seqner=seqner,
                                    saider=Diger(qb64=ian.kever.serder.said))
        assert len(vicverfer.cues) == 1
        cue = vicverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        # Vic should be able to verify Han's credential
        # Get Ian's icp into Vic's db
        for msg in ian.db.clonePreIter(pre=ian.pre, version=ian.kever.serder.pvrsn):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ianverfer.reger.clonePreIter(pre=ianiss.regk):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ianverfer.reger.clonePreIter(pre=vLeiCreder.said):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        # And now verify the credential:
        vicverfer.processCredential(vLeiCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                    saider=Diger(qb64=ian.kever.serder.said))

        assert len(vicverfer.cues) == 1
        cue = vicverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == vLeiCreder.raw

        # Revoke Ian's issuer credential and vic should no longer be able to verify
        # Han's credential that's linked to it
        rev = roniss.revoke(said=creder.said)
        rseq = Seqner(sn=rev.sn)
        rseal = SealEvent(rev.pre, rseq.snh, rev.said)._asdict()
        ron.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        seqner = Seqner(sn=ron.kever.sn)
        diger = Diger(qb64=ron.kever.serder.said)
        roniss.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=diger)
        ronreg.processEscrows()

        for msg in ron.db.clonePreIter(pre=ron.pre, version=ron.kever.serder.pvrsn):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ronverfer.reger.clonePreIter(pre=roniss.regk):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)
        for msg in ronverfer.reger.clonePreIter(pre=creder.said):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        with pytest.raises(RevokedChainError):
            vicverfer.processCredential(vLeiCreder, prefixer=ian.kever.prefixer, seqner=seqner,
                                        saider=Diger(qb64=ian.kever.serder.said))

        creds = ronreg.reger.cloneCreds(saids=[Diger(qb64=creder.said)], db=ronHby.db)
        for cred in creds:
            assert cred['status']['et'] == 'rev'
            assert cred['rev'] is not None
            assert cred['rev']['i'] == creder.said
            assert cred['revatc'] is not None
            assert cred['revanc'] is not None
            assert cred['revanc']['s'] == '3'
            assert cred['revanc']['a'][0]['s'] == '1'
            assert cred['revancatc'] is not None

    """End Test"""


def test_verifier_e1e_identity_edge(seeder):
    """E1E identity edge: near issuee must equal far issuee; issuer != issuee allowed.

    Models the SEDI core-identity <-> entitlement relationship (discussion #1515):
    two credentials issued by the same third party (ian) to the same subject (han),
    linked by an edge whose operator is the identity relation E1E. The near
    (entitlement) credential's issuer is ian and its issuee is han, so
    ``issuer != issuee``. The delegative I2I operator would reject that binding
    (I2I requires the near issuer to be the far issuee), which is exactly the case
    the identity operator E1E exists to allow: it constrains the near *issuee* to
    equal the far issuee and says nothing about the issuer.
    """
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) \
            as (hanHby, han):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer = Verifier(hby=ianHby, reger=ianreg.reger)

        def issueAndSave(creder):
            """Run creder through the full issue -> anchor -> escrow -> save flow."""
            try:
                verfer.processCredential(creder, prefixer=ian.kever.prefixer,
                                         seqner=Seqner(sn=ian.kever.sn),
                                         saider=Diger(qb64=ian.kever.serder.said))
            except MissingRegistryError:
                pass  # expected: the TEL issuance event is anchored just below
            iss = ianiss.issue(said=creder.said)
            rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
            ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
            ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                             seqner=Seqner(sn=ian.kever.sn),
                             saider=Diger(qb64=ian.kever.serder.said))
            ianreg.processEscrows()
            verfer.processEscrows()

        # far ("core identity") credential: ian -> han, no edge.
        coreSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="core identity")
        _, cd = Saider.saidify(sad=coreSubject, code=MtrDex.Blake3_256, label=Saids.d)
        core = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=cd,
                          status=ianiss.regk, source={}, rules={}, version=Vrsn_1_0, kind=Kinds.json)
        assert core.israid == ian.pre        # issuer
        assert core.iseaid == han.pre        # issuee (a.i)
        issueAndSave(core)
        assert verfer.reger.saved.get(keys=core.saidb) is not None

        # near ("entitlement") credential: ian -> han, E1E identity edge -> core.
        chainSad = dict(d='', coreIdentity=dict(n=core.said, o="E1E"))
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
        entSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="over 21")
        _, ed = Saider.saidify(sad=entSubject, code=MtrDex.Blake3_256, label=Saids.d)
        ent = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=ed,
                         status=ianiss.regk, source=chain, rules={}, version=Vrsn_1_0, kind=Kinds.json)
        assert ent.israid == ian.pre         # issuer is ian ...
        assert ent.iseaid == han.pre         # ... but issuee is han: issuer != issuee
        assert ent.israid != ent.iseaid

        issueAndSave(ent)

        # The identity edge validates: near issuee (han) == far issuee (han), even
        # though the near issuer (ian) is not the issuee. Under the old coercion to
        # I2I this credential would be stuck in missing-chain escrow, not saved.
        assert verfer.reger.saved.get(keys=ent.saidb) is not None
        saider = ianreg.reger.subjs.get(han.pre)
        assert ent.said in [s.qb64 for s in saider]

        # Guardrail: an E1E edge whose near issuee does NOT equal the far issuee must
        # be rejected. Here the near cred is issued by ian to ian (issuee == ian), so
        # its issuee differs from the far node's issuee (han). Note this is the inverse
        # of I2I: because issuer == issuee, an I2I edge would accept it -- E1E does not.
        badSubject = dict(d="", i=ian.pre, dt=helping.nowIso8601(), claim="wrong subject")
        _, bd = Saider.saidify(sad=badSubject, code=MtrDex.Blake3_256, label=Saids.d)
        bad = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=bd,
                         status=ianiss.regk, source=chain, rules={}, version=Vrsn_1_0, kind=Kinds.json)
        assert bad.iseaid == ian.pre         # near issuee (ian) != far issuee (han)
        issueAndSave(bad)
        assert verfer.reger.saved.get(keys=bad.saidb) is None

        # Guardrail: an E1E edge to an UNTARGETED far node (no issuee) must be rejected.
        # Both the near and far issuee resolve, and "same subject" is undefined when the
        # far node has none -- so the `farIssuee is None` guard rejects. (Without it, two
        # untargeted creds would compare None == None and wrongly bind as one subject.)
        orphanSubject = dict(d="", dt=helping.nowIso8601(), claim="untargeted")  # no 'i'
        _, od = Saider.saidify(sad=orphanSubject, code=MtrDex.Blake3_256, label=Saids.d)
        orphan = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=od,
                            status=ianiss.regk, source={}, rules={}, version=Vrsn_1_0, kind=Kinds.json)
        assert orphan.iseaid is None         # untargeted far node
        issueAndSave(orphan)
        assert verfer.reger.saved.get(keys=orphan.saidb) is not None
        orphanChain = dict(d='', coreIdentity=dict(n=orphan.said, o="E1E"))
        _, ochain = Saider.saidify(sad=orphanChain, code=MtrDex.Blake3_256, label=Saids.d)
        toOrphanSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="to orphan")
        _, td = Saider.saidify(sad=toOrphanSubject, code=MtrDex.Blake3_256, label=Saids.d)
        toOrphan = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=td,
                              status=ianiss.regk, source=ochain, rules={}, version=Vrsn_1_0, kind=Kinds.json)
        issueAndSave(toOrphan)
        assert verfer.reger.saved.get(keys=toOrphan.saidb) is None

    """End Test"""


def _aggregate_far_node(ian, ianiss, ianreg, issueeAid):
    """Build an aggregative ('acg') far-node credential and issue its SAID into
    ian's registry TEL so ``vcState`` resolves it to issued.

    The credential is issued by ian to ``issueeAid``. For an aggregate ACDC the
    issuee lives at ``.sad["A"][1]["i"]`` (not ``.sad["a"]["i"]``), so ``.attrib``
    is None and ``.iseaid`` is the only way to resolve the issuee -- exactly the
    case that the attributive-only paths in verifying.py mishandle.
    """
    raws = [b'2lb6aggverifchn' + b'%0x' % (i,) for i in range(3)]
    nonces = [Noncer(raw=r).qb64 for r in raws]
    # element 0 is the AGID placeholder; element 1 carries the issuee (i).
    ael = ['', dict(d='', u=nonces[0], i=issueeAid),
           dict(d='', u=nonces[1], over21=True)]
    aggor = Aggor(ael=ael, makify=True, kind=Kinds.json)
    sschema, _ = acgSchemaDefault(kind=Kinds.json)  # SAID string, not the block
    agg = acdcagg(israid=ian.pre, uuid=nonces[2], regid=ianiss.regk,
                  schema=sschema, aggregate=aggor.ael, kind=Kinds.json)

    # anchor a TEL issuance event for the aggregate SAID so it is "issued".
    iss = ianiss.issue(said=agg.said)
    rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
    ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
    ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                     seqner=Seqner(sn=ian.kever.sn),
                     saider=Diger(qb64=ian.kever.serder.said))
    ianreg.processEscrows()
    return agg


def test_verifier_saves_aggregate_credential(seeder):
    """saveCredential indexes an aggregate ('acg') credential's subject via .iseaid.

    Regression for tick 2lb6: saveCredential guarded subject indexing on
    ``'i' in creder.attrib``, but ``creder.attrib`` is None for an aggregate
    credential (the issuee is at ``.sad["A"][1]["i"]``), so the membership test
    raised ``TypeError`` and the aggregate credential could not be saved or
    subject-indexed at all. It must instead resolve the issuee via ``.iseaid``,
    identically to an attributive credential.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) \
            as (hanHby, han):
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer = Verifier(hby=ianHby, reger=ianreg.reger)

        agg = _aggregate_far_node(ian, ianiss, ianreg, han.pre)
        assert agg.attrib is None            # aggregate: no 'a' section
        assert agg.iseaid == han.pre         # issuee resolves from A[1].i
        assert agg.israid == ian.pre

        # Before the fix this raised TypeError on ``'i' in creder.attrib`` (None).
        verfer.saveCredential(agg, prefixer=ian.kever.prefixer,
                              seqner=Seqner(sn=ian.kever.sn),
                              saider=Diger(qb64=ian.kever.serder.said))

        assert verfer.reger.saved.get(keys=agg.saidb) is not None
        # subject indexed under the aggregate issuee (han), via .iseaid.
        saiders = verfer.reger.subjs.get(han.pre)
        assert agg.said in [s.qb64 for s in saiders]

    """End Test"""


def test_verifier_aggregate_far_node_chain(seeder):
    """verifyChain resolves an aggregate ('acg') far node's issuee via .iseaid.

    Regression for tick 2lb6: verifyChain coerced the default/unknown operator via
    ``'i' in creder.attrib`` and resolved the I2I issuee via ``creder.attrib['i']``.
    Both raise ``TypeError`` for an aggregate far node (``.attrib`` is None). The
    verifier must resolve targeted-ness and the issuee via ``.iseaid`` so an edge
    to an aggregate far node behaves identically to an attributive one.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) \
            as (hanHby, han):
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer = Verifier(hby=ianHby, reger=ianreg.reger)

        agg = _aggregate_far_node(ian, ianiss, ianreg, han.pre)
        assert agg.attrib is None
        assert agg.iseaid == han.pre

        # Populate the reger indices directly (isolate this from saveCredential):
        # creds (SerderSuber -> SerderACDC), saved, and the subject index.
        verfer.reger.logCred(agg, ian.kever.prefixer, Seqner(sn=ian.kever.sn),
                             Diger(qb64=ian.kever.serder.said))
        saider = Saider(qb64=agg.said)
        verfer.reger.saved.pin(keys=saider.qb64b, val=saider)
        verfer.reger.subjs.add(keys=agg.iseaidb, val=saider)

        # Default operator (None): coerced to a targeted (I2I) edge because the far
        # node has an issuee (.iseaid). Before the fix this raised TypeError on the
        # ``'i' in creder.attrib`` coercion. The near issuer (han) equals the far
        # issuee (han), so the I2I binding is accepted.
        state = verfer.verifyChain(agg.said, None, han.pre)
        assert state is not None

        # Explicit I2I with the same binding is accepted.
        state = verfer.verifyChain(agg.said, 'I2I', han.pre, issuee=han.pre)
        assert state is not None

        # I2I mismatch: the near issuer (ian) does not equal the far issuee (han),
        # so the binding is rejected (returns None, no TypeError).
        assert verfer.verifyChain(agg.said, 'I2I', ian.pre) is None

        # NI2I is untargeted: accepted regardless of issuer/issuee.
        state = verfer.verifyChain(agg.said, 'NI2I', ian.pre)
        assert state is not None

    """End Test"""


def test_verifier_e1e_aggregate_far_node(seeder):
    """verifyChain's E1E identity edge resolves an aggregate ('acg') far node.

    Closes the coverage gap left open across the E1E stack. #1527's E1E test uses
    only an attributive (``.sad["a"]["i"]``) far node, and this PR's other
    aggregate tests exercise only the default/I2I/NI2I operators against an
    aggregate far node -- never E1E. Here an E1E edge points at an aggregate far
    node (issuee at ``.sad["A"][1]["i"]``, ``.attrib`` is None), confirming the
    identity relation is decided on ``.iseaid``, not ``.attrib``.

    End to end this depends on the whole 2lb6 change: the aggregate far node must
    first be savable (``saveCredential`` resolving the subject via ``.iseaid``),
    which the pre-fix ``'i' in creder.attrib`` guard cannot do -- it raises
    ``TypeError`` on the None attribute. The E1E branch was already ``.iseaid``
    based; this locks in that it works for an aggregate far node through the real
    verifier, not just a bespoke example verifier.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) \
            as (hanHby, han):
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer = Verifier(hby=ianHby, reger=ianreg.reger)

        # Aggregate far node: ian -> han, issuee (han) at A[1].i, .attrib is None.
        agg = _aggregate_far_node(ian, ianiss, ianreg, han.pre)
        assert agg.attrib is None
        assert agg.iseaid == han.pre

        # Save it through the real path. With the pre-fix saveCredential this raises
        # TypeError on the aggregate credential; the fix indexes the subject via
        # .iseaid so the far node can be resolved by verifyChain below.
        verfer.saveCredential(agg, prefixer=ian.kever.prefixer,
                              seqner=Seqner(sn=ian.kever.sn),
                              saider=Diger(qb64=ian.kever.serder.said))
        assert verfer.reger.saved.get(keys=agg.saidb) is not None

        # E1E accepts when the near issuee equals the far (aggregate) issuee and
        # says nothing about the issuer: here issuer=ian != issuee=han, the SEDI
        # "same subject, third-party issuer" case that E1E exists to allow.
        assert verfer.verifyChain(agg.said, 'E1E', ian.pre, issuee=han.pre) is not None

        # E1E does work I2I cannot on this same aggregate far node: the identical
        # binding (near issuer=ian, far aggregate issuee=han, issuer != issuee) that
        # E1E accepted above is rejected by I2I.
        assert verfer.verifyChain(agg.said, 'I2I', ian.pre, issuee=han.pre) is None

        # E1E rejects a near issuee that differs from the far (aggregate) issuee.
        assert verfer.verifyChain(agg.said, 'E1E', ian.pre, issuee=ian.pre) is None

        # E1E rejects a missing near issuee (untargeted near ACDC carrying the edge).
        assert verfer.verifyChain(agg.said, 'E1E', ian.pre, issuee=None) is None

    """End Test"""


def setupOperatorFixture(ian, ianHby, ianreg, ianiss):
    """Wire ian's registry into a Verifier and return (verfer, issueAndSave).

    Shared by the operator-dispatch tests below, which all need the same shape:
    one issuer (ian) with an anchored registry, and a way to run a credential
    through the full issue -> anchor -> escrow -> save flow.
    """
    verfer = Verifier(hby=ianHby, reger=ianreg.reger)

    def issueAndSave(creder):
        try:
            verfer.processCredential(creder, prefixer=ian.kever.prefixer,
                                     seqner=Seqner(sn=ian.kever.sn),
                                     saider=Diger(qb64=ian.kever.serder.said))
        except MissingRegistryError:
            pass  # expected: the TEL issuance event is anchored just below
        iss = ianiss.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()
        verfer.processEscrows()

    return verfer, issueAndSave


def test_verifier_list_valued_operator(seeder):
    """A list-valued `o` is a spec-legal spelling and MUST NOT fall to the default.

    ACDC spec-body.md L1186: "When more than one unary Operator is applied to a given
    Edge, then the value of the Operator, `o`, field is a list of those unary
    Operators. When multiple unary Operators appear in the list, and there is a
    conflict between Operators, the latest Operator among the conflicting Operators
    in the list takes precedence."

    Previously ``op not in ['I2I','DI2I','NI2I','E1E']`` was tested against the list
    itself, which never matches, so every list form silently fell through to the
    default inference -- I2I for a targeted far node. A conforming producer writing
    ``"o": ["NI2I"]`` therefore got I2I semantics, and the same bytes verified
    differently on a conforming non-keripy validator: an interop split with no
    wire-visible cause.
    """
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0,
                 kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef',
                    version=Vrsn_1_0, kind=Kinds.json) as (hanHby, han):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0,
                                     kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer, issueAndSave = setupOperatorFixture(ian, ianHby, ianreg, ianiss)

        # Far node: targeted, ian -> han. Every near credential below is issued by
        # ian, so `near issuer (ian) != far issuee (han)` -- I2I rejects, NI2I allows.
        # That asymmetry is what makes the effective operator observable.
        farSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="far node")
        _, fd = Saider.saidify(sad=farSubject, code=MtrDex.Blake3_256, label=Saids.d)
        far = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=fd,
                         status=ianiss.regk, source={}, rules={}, version=Vrsn_1_0,
                         kind=Kinds.json)
        assert far.iseaid == han.pre
        issueAndSave(far)
        assert verfer.reger.saved.get(keys=far.saidb) is not None

        def nearWithOp(op, claim):
            """Issue a near credential whose single edge carries operator `op`."""
            chainSad = dict(d='', node=dict(n=far.said, o=op))
            _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
            subject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim=claim)
            _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
            near = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                              status=ianiss.regk, source=chain, rules={},
                              version=Vrsn_1_0, kind=Kinds.json)
            issueAndSave(near)
            return near

        # Single-element list: ["NI2I"] must mean NI2I, not the I2I default.
        # This is the red case -- before the fix the list fell through to I2I and
        # the credential sat in missing-chain escrow.
        near = nearWithOp(["NI2I"], "single element list")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # Latest-wins: ["I2I", "NI2I"] resolves to NI2I, so the edge is accepted
        # even though the near issuer is not the far issuee.
        near = nearWithOp(["I2I", "NI2I"], "latest wins to NI2I")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # Latest-wins in the other direction: ["NI2I", "I2I"] resolves to I2I, which
        # rejects. Ordering must matter -- a set-membership implementation that just
        # asked "is NI2I present?" would wrongly accept this one.
        near = nearWithOp(["NI2I", "I2I"], "latest wins to I2I")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # Unrecognized tokens are skipped, not treated as conflicting: the latest
        # *recognized* operator wins.
        near = nearWithOp(["NI2I", "BOGUS"], "unrecognized token skipped")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # A list with no recognized operator falls to the default rule, which for a
        # targeted far node is I2I -- and so rejects.
        near = nearWithOp(["BOGUS"], "no recognized operator")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # An empty list likewise falls to the default rule.
        near = nearWithOp([], "empty list")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # Scalar forms are unchanged: "NI2I" still means NI2I.
        near = nearWithOp("NI2I", "scalar NI2I")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # A tuple is accepted as a sequence too, not just a list.
        near = nearWithOp(("NI2I",), "tuple form")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # E1E alone imposes no issuer constraint, and reaching it via a list must not
        # change that. Here the near issuer is ian and the far issuee is han, so I2I
        # would reject; E1E's own check (near issuee han == far issuee han) passes, so
        # the edge is accepted. Composition of E1E with a delegative operator is
        # covered by test_verifier_nonconflicting_operators_compose.
        near = nearWithOp(["E1E"], "E1E via list")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # The flagship interop case from the review: "o": ["DI2I"] previously resolved
        # to I2I via the default rule, silently downgrading a delegated-issuer edge to
        # a strict issuer==issuee one. It must now reach DI2I and fail closed.
        chainSad = dict(d='', node=dict(n=far.said, o=["DI2I"]))
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
        subject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="di2i in list")
        _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
        listDi2i = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                              status=ianiss.regk, source=chain, rules={},
                              version=Vrsn_1_0, kind=Kinds.json)
        iss = ianiss.issue(said=listDi2i.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()
        with pytest.raises(ValidationError) as excinfo:
            verfer.processCredential(listDi2i, prefixer=ian.kever.prefixer,
                                     seqner=Seqner(sn=ian.kever.sn),
                                     saider=Diger(qb64=ian.kever.serder.said))
        assert "DI2I" in str(excinfo.value)

        # NOT is normative (spec L1195: the far node's validity is inverted) and
        # unimplemented here. It must fail closed like DI2I rather than being skipped
        # as an unrecognized token -- otherwise an edge asserting "this node must be
        # INVALID" would be accepted as valid.
        chainSad = dict(d='', node=dict(n=far.said, o=["NOT"]))
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
        subject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="not operator")
        _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
        notCred = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                             status=ianiss.regk, source=chain, rules={},
                             version=Vrsn_1_0, kind=Kinds.json)
        iss = ianiss.issue(said=notCred.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()
        with pytest.raises(ValidationError) as excinfo:
            verfer.processCredential(notCred, prefixer=ian.kever.prefixer,
                                     seqner=Seqner(sn=ian.kever.sn),
                                     saider=Diger(qb64=ian.kever.serder.said))
        assert "NOT" in str(excinfo.value)

    """End Test"""


def test_verifier_nonconflicting_operators_compose(seeder):
    """A non-delegative operator composes with the delegative winner, not overridden.

    ACDC spec-body.md L1186 scopes latest-wins to "the conflicting Operators". I2I,
    NI2I and DI2I all constrain the near ACDC's *issuer* relative to the far node's
    issuee, so they conflict with one another. E1E constrains the near *issuee*, so it
    conflicts with none of them and must be conjoined (AND).

    Collapsing the whole list to a single operator drops the constraint that loses,
    which is a silent weakening: ``["E1E", "I2I"]`` from a producer requiring both
    relations would enforce only I2I and accept a far node whose issuee differs from
    the near ACDC's.
    """
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0,
                 kind=Kinds.json) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef',
                    version=Vrsn_1_0, kind=Kinds.json) as (hanHby, han):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0,
                                     kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer, issueAndSave = setupOperatorFixture(ian, ianHby, ianreg, ianiss)

        # Far node issued by ian to ian, so the far issuee is ian. Every near
        # credential below is issued by ian, so I2I (near issuer ian == far issuee ian)
        # is always satisfied -- which isolates E1E as the only constraint that can
        # decide the outcome.
        farSubject = dict(d="", i=ian.pre, dt=helping.nowIso8601(), claim="far node")
        _, fd = Saider.saidify(sad=farSubject, code=MtrDex.Blake3_256, label=Saids.d)
        far = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=fd,
                         status=ianiss.regk, source={}, rules={}, version=Vrsn_1_0,
                         kind=Kinds.json)
        assert far.iseaid == ian.pre
        issueAndSave(far)
        assert verfer.reger.saved.get(keys=far.saidb) is not None

        def nearWithOp(op, nearIssuee, claim):
            chainSad = dict(d='', node=dict(n=far.said, o=op))
            _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
            subject = dict(d="", i=nearIssuee, dt=helping.nowIso8601(), claim=claim)
            _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
            near = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                              status=ianiss.regk, source=chain, rules={},
                              version=Vrsn_1_0, kind=Kinds.json)
            issueAndSave(near)
            return near

        # Both satisfied: I2I (issuer ian == far issuee ian) and E1E (near issuee ian ==
        # far issuee ian). Accepted.
        near = nearWithOp(["E1E", "I2I"], ian.pre, "both hold")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

        # I2I still satisfied, E1E violated: the near issuee is han, the far issuee is
        # ian. Must be REJECTED. This is the red case -- collapsing the list to the
        # latest operator (I2I) would accept it and drop the E1E constraint entirely.
        near = nearWithOp(["E1E", "I2I"], han.pre, "e1e violated, i2i holds")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # Order must not matter for a non-conflicting pair -- E1E composes either way.
        near = nearWithOp(["I2I", "E1E"], han.pre, "order reversed, still rejected")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # E1E composed with NI2I: NI2I wins the delegative conflict (no issuer
        # constraint), but E1E still applies and still rejects a mismatched issuee.
        near = nearWithOp(["E1E", "NI2I"], han.pre, "ni2i wins but e1e still applies")
        assert verfer.reger.saved.get(keys=near.saidb) is None

        # Same pair with the issuee matching: NI2I drops the issuer constraint, E1E is
        # satisfied, so the edge is accepted.
        near = nearWithOp(["E1E", "NI2I"], ian.pre, "ni2i wins, e1e satisfied")
        assert verfer.reger.saved.get(keys=near.saidb) is not None

    """End Test"""


def test_verifier_di2i_rejects_diagnosably(seeder):
    """An unimplemented DI2I edge must fail closed *diagnosably*, not vanish.

    DI2I previously raised a bare ``NotImplementedError``, which is not a
    ValidationError, so every caller mishandled it: ``Parser.allParsator``'s blanket
    ``except (ValidationError, Exception)`` logged and discarded the ACDC, and
    ``_processEscrow``'s generic arm unescrowed it. Neither produced a signal an
    operator could act on.

    DI2I is still unimplemented -- this test pins the *failure mode*, not the
    operator semantics. A ValidationError names the cause and stops the retry loop,
    which is correct here: unlike a missing chain, retrying cannot help.
    """
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    # Single party: every credential here is issued by ian to ian, so no second hab is
    # needed to exercise the operator's failure mode.
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0,
                 kind=Kinds.json) as (ianHby, ian):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0,
                                     kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer, issueAndSave = setupOperatorFixture(ian, ianHby, ianreg, ianiss)

        farSubject = dict(d="", i=ian.pre, dt=helping.nowIso8601(), claim="far node")
        _, fd = Saider.saidify(sad=farSubject, code=MtrDex.Blake3_256, label=Saids.d)
        far = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=fd,
                         status=ianiss.regk, source={}, rules={}, version=Vrsn_1_0,
                         kind=Kinds.json)
        issueAndSave(far)
        assert verfer.reger.saved.get(keys=far.saidb) is not None

        chainSad = dict(d='', node=dict(n=far.said, o="DI2I"))
        _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
        subject = dict(d="", i=ian.pre, dt=helping.nowIso8601(), claim="di2i edge")
        _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
        near = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                          status=ianiss.regk, source=chain, rules={},
                          version=Vrsn_1_0, kind=Kinds.json)

        # Anchor the TEL issuance so processCredential reaches the edge walk rather
        # than bailing out earlier on a missing registry.
        iss = ianiss.issue(said=near.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        with pytest.raises(ValidationError) as excinfo:
            verfer.processCredential(near, prefixer=ian.kever.prefixer,
                                     seqner=Seqner(sn=ian.kever.sn),
                                     saider=Diger(qb64=ian.kever.serder.said))

        # Diagnosable: the message names the operator, the far node the edge points to,
        # and the near credential that carried the edge -- an operator triaging a stream
        # needs the last of those to know which credential to fix.
        assert "DI2I" in str(excinfo.value)
        assert far.said in str(excinfo.value)
        assert near.said in str(excinfo.value)
        # Fails closed -- the credential is not saved on the strength of an edge the
        # verifier cannot evaluate.
        assert verfer.reger.saved.get(keys=near.saidb) is None
        # Not a MissingChainError: the chain is present, the operator is unsupported.
        # Escrowing it would promise a retry that can never succeed.
        assert not isinstance(excinfo.value, MissingChainError)

    """End Test"""


def test_verifier_escrow_pass_survives_argless_exception(seeder):
    """One poisoned escrow entry must not abort the whole escrow pass.

    ``_processEscrow``'s generic arm removed the entry and then evaluated
    ``ex.args[0]`` to log it. For an exception raised with no arguments -- which is
    exactly what ``raise NotImplementedError()`` produced -- that indexes an empty
    tuple, so the IndexError escaped ``_processEscrow`` *and* ``processEscrows``,
    skipping every remaining entry in the current table and both subsequent tables
    (mce -> mse -> mre).

    Pinned independently of DI2I: any argless exception from any credential reaches
    the same handler, so fixing only the DI2I raise would leave the trap armed.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0,
                 kind=Kinds.json) as (ianHby, ian):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", version=Vrsn_1_0,
                                     kind=Kinds.json)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, version=Vrsn_1_0, kind=Kinds.json,
                     gvrsn=Vrsn_1_0)
        ianiss.anchorMsg(pre=ianiss.regk, regd=ianiss.regd,
                         seqner=Seqner(sn=ian.kever.sn),
                         saider=Diger(qb64=ian.kever.serder.said))
        ianreg.processEscrows()

        verfer = Verifier(hby=ianHby, reger=ianreg.reger)

        optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"
        saids = []
        for n in range(2):
            subject = dict(d="", i=ian.pre, dt=helping.nowIso8601(), claim=f"poison {n}")
            _, sd = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
            creder = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=sd,
                                status=ianiss.regk, source={}, rules={},
                                version=Vrsn_1_0, kind=Kinds.json)
            verfer.escrowMCE(creder, prefixer=ian.kever.prefixer,
                             seqner=Seqner(sn=ian.kever.sn),
                             saider=Diger(qb64=ian.kever.serder.said))
            saids.append(creder.said)

        assert len(saids) == 2
        for said in saids:
            assert verfer.reger.mce.get(keys=said) is not None

        # Every entry raises an argless exception, the shape that used to detonate.
        def poisoned(*args, **kwa):
            raise NotImplementedError()

        verfer.processCredential = poisoned

        # Must not raise. Before the fix this propagated IndexError out of
        # processEscrows on the first entry.
        verfer.processEscrows()

        # Both entries were reached and unescrowed -- proving the pass continued past
        # the first poisoned entry rather than aborting on it.
        for said in saids:
            assert verfer.reger.mce.get(keys=said) is None

    """End Test"""
