# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""

import copy

import pytest

from keri import (MissingRegistryError, MissingEntryError,
                  MissingChainError, RevokedChainError, Vrsn_1_0)
from keri.app import openHab
from keri.core import (Saider, Kevery, SerderKERI, Seqner,
                       Diger, Parser, SealEvent,
                       MtrDex, Saids, Aggor, Noncer, Schemer)
from keri.kering import Ilks, Kinds, Vrsn_2_0, MissingSchemaError
from keri.help import helping
from keri.vc import credential
from keri.acdc import acdcagg
from keri.acdc.messaging import acgSchemaDefault
from keri.vdr import Verifier, Regery, Tevery
from tests.common import CUE_KWA, KWA


def test_verifier_query(mockHelpingNowUTC, mockCoringRandomNonce):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)

        verfer = Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", **KWA)
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
    with (openHab(name="sid", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab),
          openHab(name="recp", transferable=True, temp=True, **KWA) as (recpHby, recp)):
        seeder.seedSchema(db=hby.db)
        seeder.seedSchema(db=recpHby.db)
        assert hab.pre == "EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o"

        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal], framed=True, **CUE_KWA)
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
                            **KWA)
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
        hab.interact(data=[rseal], framed=True, **CUE_KWA)
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

    with openHab(name="ron", temp=True, salt=b'0123456789abcdef', **KWA) as (ronHby, ron), \
            openHab(name="ian", temp=True, salt=b'0123456789abcdef', **KWA) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (hanHby, han), \
            openHab(name="vic", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (vicHby, vic):
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
        roniss = ronreg.makeRegistry(prefix=ron.pre, name="test", **KWA)
        rseal = SealEvent(roniss.regk, "0", roniss.regd)._asdict()
        ron.interact(data=[rseal], framed=True, **CUE_KWA)
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
                            **KWA)

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
        ron.interact(data=[rseal], framed=True, **CUE_KWA)
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

        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", **KWA)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
                                **KWA)

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
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
                                      **KWA)

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
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
                                   **KWA)

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
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
        ron.interact(data=[rseal], framed=True, **CUE_KWA)
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

    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', **KWA) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) \
            as (hanHby, han):
        seeder.seedSchema(db=ianHby.db)

        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", **KWA)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
            ian.interact(data=[rseal], framed=True, **CUE_KWA)
            ianiss.anchorMsg(pre=iss.pre, regd=iss.said,
                             seqner=Seqner(sn=ian.kever.sn),
                             saider=Diger(qb64=ian.kever.serder.said))
            ianreg.processEscrows()
            verfer.processEscrows()

        # far ("core identity") credential: ian -> han, no edge.
        coreSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="core identity")
        _, cd = Saider.saidify(sad=coreSubject, code=MtrDex.Blake3_256, label=Saids.d)
        core = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=cd,
                          status=ianiss.regk, source={}, rules={}, **KWA)
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
                         status=ianiss.regk, source=chain, rules={}, **KWA)
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
                         status=ianiss.regk, source=chain, rules={}, **KWA)
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
                            status=ianiss.regk, source={}, rules={}, **KWA)
        assert orphan.iseaid is None         # untargeted far node
        issueAndSave(orphan)
        assert verfer.reger.saved.get(keys=orphan.saidb) is not None
        orphanChain = dict(d='', coreIdentity=dict(n=orphan.said, o="E1E"))
        _, ochain = Saider.saidify(sad=orphanChain, code=MtrDex.Blake3_256, label=Saids.d)
        toOrphanSubject = dict(d="", i=han.pre, dt=helping.nowIso8601(), claim="to orphan")
        _, td = Saider.saidify(sad=toOrphanSubject, code=MtrDex.Blake3_256, label=Saids.d)
        toOrphan = credential(issuer=ian.pre, schema=optionalIssueeSchema, data=td,
                              status=ianiss.regk, source=ochain, rules={}, **KWA)
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
    ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', **KWA) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) \
            as (hanHby, han):
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", **KWA)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef', **KWA) as (ianHby, ian), \
            openHab(name="han", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) \
            as (hanHby, han):
        ianreg = Regery(hby=ianHby, name="ian", temp=True)
        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian", **KWA)
        rseal = SealEvent(ianiss.regk, "0", ianiss.regd)._asdict()
        ian.interact(data=[rseal], framed=True, **CUE_KWA)
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


def test_verifier_edge_schema_constraint(seeder):
    """verifyChain enforces an edge's declared far-node schema ('s') by validation.

    Regression for tick 6ggh (issue #1534). An ACDC edge may declare 's', the SAID
    of a schema its far node must *satisfy*. As S. Smith clarified on #1534, 's' is
    a *satisfiability* constraint, not a SAID-equality one: when the edge's 's'
    differs from the far node's own schema SAID, the far node's SAD must ALSO be
    validated against the edge schema, and both must pass. A different-but-
    backwards-compatible edge schema (an "upgrade") that the far node still
    satisfies is accepted -- without reissuing the far node; only an edge schema
    the far node fails to satisfy is rejected. A naive SAID-equality check wrongly
    rejects the compatible-upgrade case, so that case is the load-bearing one here.

    Four cases against a far node whose own schema is ``optionalIssueeSchema``:
      * edge 's' = a resolvable *incompatible* schema the far node fails -> rejected;
      * edge 's' = the far node's own schema SAID -> verifies;
      * edge 's' = a resolvable *different but compatible* schema the far node still
        satisfies -> verifies (the case a SAID-equality check breaks);
      * edge 's' = a schema *not yet in cache* -> escrowed as missing-schema
        (transient) with a schema-query cue, then self-heals once the schema is
        supplied and escrows are reprocessed -- the near ACDC's own schema is
        handled the same way, so an edge schema must not fail permanently just
        because it has not been fetched yet.
    """
    optionalIssueeSchema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"

    with openHab(name="sid", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        seeder.seedSchema(db=hby.db)

        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal], framed=True, **CUE_KWA)
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=diger)
        regery.processEscrows()

        verifier = Verifier(hby=hby, reger=regery.reger)

        # Derive extra schemas from the far node's own schema. makeSchema builds
        # (but does not cache) a variant; pinSchema adds it to the resolver cache so
        # the edge-schema check can validate the far node against it.
        baseSchemer = hby.db.schema.get(optionalIssueeSchema)

        def makeSchema(mutate):
            sed = copy.deepcopy(baseSchemer.sed)
            sed['$id'] = ''  # cleared so saidify recomputes the SAID over the mutation
            mutate(sed)
            _, sed = Saider.saidify(sed, label=Saids.dollar)
            return Schemer(sed=sed)

        def pinSchema(schemer):
            hby.db.schema.pin(schemer.said, schemer)
            return schemer.said

        # Compatible upgrade: identical constraints, only the human-readable title
        # differs, so the SAID changes but the far node still validates against it.
        compatSchemer = makeSchema(
            lambda sed: sed.__setitem__('title', 'Optional Issuee (compatible upgrade)'))
        # Incompatible: additionally require an issuee ('i') in the attribute block,
        # which the untargeted far node lacks, so the far node fails this schema.
        incompatSchemer = makeSchema(
            lambda sed: sed['properties']['a'].__setitem__('required', ['dt', 'claim', 'i']))
        # Compatible, but deliberately left out of the cache to drive the missing-
        # edge-schema escrow/self-heal path (case 4); pinned partway through.
        deferredSchemer = makeSchema(
            lambda sed: sed.__setitem__('title', 'Optional Issuee (deferred)'))

        compatSchema = pinSchema(compatSchemer)
        incompatSchema = pinSchema(incompatSchemer)
        deferredSchema = deferredSchemer.said  # not pinned yet
        assert len({compatSchema, incompatSchema, deferredSchema,
                    optionalIssueeSchema}) == 4
        assert hby.db.schema.get(deferredSchema) is None

        def issueCred(creder):
            """Issue creder's SAID into the registry TEL and process escrows."""
            iss = issuer.issue(said=creder.said)
            rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
            hab.interact(data=[rseal], framed=True, **CUE_KWA)
            sq = Seqner(sn=hab.kever.sn)
            dg = Diger(qb64=hab.kever.serder.said)
            issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=sq, saider=dg)
            regery.processEscrows()

        def buildCred(claim, source=None):
            subject = dict(d="", dt=helping.nowIso8601(), claim=claim)
            _, d = Saider.saidify(sad=subject, code=MtrDex.Blake3_256, label=Saids.d)
            return credential(issuer=hab.pre, schema=optionalIssueeSchema, data=d,
                              status=issuer.regk, source=source, rules={}, **KWA)

        anchor = dict(prefixer=hab.kever.prefixer, seqner=seqner,
                      saider=Diger(qb64=hab.kever.serder.said))

        # Far-node credential: untargeted, real schema == optionalIssueeSchema.
        # The schema requires an 'e' block, so give it an empty one (no edges).
        farCreder = buildCred("A far node claim.", source={})
        issueCred(farCreder)
        verifier.processCredential(farCreder, **anchor)
        assert regery.reger.saved.get(keys=farCreder.said) is not None

        def nearCred(claim, farSchema):
            """Near credential with a single edge to farCreder declaring farSchema."""
            chainSad = dict(d="", farEdge=dict(n=farCreder.said, s=farSchema))
            _, chain = Saider.saidify(sad=chainSad, code=MtrDex.Blake3_256, label=Saids.d)
            creder = buildCred(claim, source=chain)
            issueCred(creder)
            return creder

        # (1) Edge declares an INCOMPATIBLE schema the far node fails -> rejected.
        # Assert the schema resolves, so the rejection is provably a validation
        # failure (far node fails the edge schema) and not a missing-schema miss.
        assert verifier.resolver.resolve(incompatSchema)
        badCreder = nearCred("A near claim, incompatible edge schema.", incompatSchema)
        with pytest.raises(MissingChainError):
            verifier.processCredential(badCreder, **anchor)

        # (2) Edge declares the far node's OWN schema -> verifies.
        sameCreder = nearCred("A near claim, same edge schema.", optionalIssueeSchema)
        verifier.processCredential(sameCreder, **anchor)
        saved = [s.qb64 for s in regery.reger.schms.get(optionalIssueeSchema)]
        assert sameCreder.said in saved

        # (3) Edge declares a DIFFERENT but backwards-compatible schema the far node
        # still satisfies -> verifies (a SAID-equality check would wrongly reject).
        upCreder = nearCred("A near claim, compatible upgrade edge schema.", compatSchema)
        verifier.processCredential(upCreder, **anchor)
        saved = [s.qb64 for s in regery.reger.schms.get(optionalIssueeSchema)]
        assert upCreder.said in saved

        # (4) Edge declares a schema NOT yet in cache -> escrowed as missing-schema
        # (transient), not rejected. Once the schema is supplied and escrows are
        # reprocessed, the far node satisfies it and the chain self-heals.
        deferredCreder = nearCred("A near claim, deferred edge schema.", deferredSchema)
        with pytest.raises(MissingSchemaError):
            verifier.processCredential(deferredCreder, **anchor)
        assert verifier.reger.mse.get(keys=deferredCreder.said) is not None
        assert verifier.reger.saved.get(keys=deferredCreder.said) is None

        pinSchema(deferredSchemer)  # supply the previously-missing edge schema
        verifier.processEscrows()
        assert verifier.reger.mse.get(keys=deferredCreder.said) is None
        saved = [s.qb64 for s in regery.reger.schms.get(optionalIssueeSchema)]
        assert deferredCreder.said in saved

    """End Test"""
