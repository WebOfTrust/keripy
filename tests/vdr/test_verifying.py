# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""
import json

import pytest

from keri import kering
from keri.app import habbing, grouping
from keri.core import eventing as ceventing, scheming
from keri.core import parsing, coring
from keri.db import dbing
from keri.help import helping
from keri.vc import proving
from keri.vdr import verifying, issuing, viring, eventing
from ..app import test_grouping


def test_verifier_query(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        assert msg == (b'{"v":"KERI10JSON0000cb_","t":"qry","dt":"2021-01-01T00:00:00.000'
                    b'000+00:00","r":"tels","rr":"","q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55c'
                    b'nHl4WgNZ_RE-gKXqgcX4","ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT7'
                    b'8Tt2r9M4"}}-VAj-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E-'
                    b'AABAA4WmPtNJALt6f4Xn-HnsPrfplKgAeyxQIxsYm9T-rTNFIpdyOnxynA0wgcEJ'
                    b'_FOcTo9R0krY25tQvpBOzfT0aDA')


def test_verifier():
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as hab, \
            habbing.openHab(name="recp", transferable=True, temp=True) as recp, \
            viring.openReg(temp=True) as reger:
        assert hab.pre == "ELfzj-TkiKYWsNKk2WE8F8VEgbu3P-_HComVHcKrvGmY"

        issuer = issuing.Issuer(hab=hab, reger=reger, noBackers=True, estOnly=True, temp=True)
        verifier = verifying.Verifier(hab=hab, name="verifier", reger=reger, tevers=issuer.tevers)

        types = ["VerifiableCredential", "GLEIFvLEICredential"]

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
            t=types,
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=hab.pre,
                                    schema="ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc",
                                    subject=d,
                                    status=issuer.regk)

        msg = hab.endorse(serder=creder)
        del msg[:creder.size]
        parsing.Parser.extract(ims=msg, klas=coring.Counter)
        prefixer, seqner, diger, sigers = proving.parseProof(ims=msg)

        missing = False
        try:
            verifier.processCredential(creder, prefixer, seqner, diger, sigers)
        except kering.MissingRegistryError:
            missing = True

        assert missing is True
        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == issuer.regk
        issuer.issue(creder=creder)

        # Now that the credential has been issued, process escrows and it will find the TEL event
        verifier.processEscrows()

        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        dcre = reger.creds.get(creder.saider.qb64b)
        assert dcre.raw == creder.raw
        seals = reger.seals.get(creder.saider.qb64b)
        assert len(seals) == 1
        (pre, sn, dig, sig) = seals[0]
        assert pre.qb64 == prefixer.qb64
        assert sn.qb64 == seqner.qb64
        assert dig.qb64 == diger.qb64
        assert sig.qb64 == sigers[0].qb64

        saider = reger.issus.get(hab.pre)
        assert saider[0].qb64 == creder.said
        saider = reger.subjs.get(recp.pre)
        assert saider[0].qb64 == creder.said
        saider = reger.schms.get("ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc")
        assert saider[0].qb64 == creder.said


def test_verifier_multisig():
    with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3), \
            habbing.openHab(name="recp", transferable=True, temp=True) as recp, \
            habbing.openHab(name="verfer", transferable=True, temp=True) as verfer, \
            viring.openReg(temp=True) as reger:

        gid = "EbRGD66vYtbohJwGh-B2uPwHUDH3WrLcc_1Gn1ksSEu0"
        group1 = hab1.group()
        assert group1.gid == gid

        # Keverys so we can process the final message.
        kev1 = ceventing.Kevery(db=hab1.db, lax=False, local=False)
        kev2 = ceventing.Kevery(db=hab2.db, lax=False, local=False)
        kev3 = ceventing.Kevery(db=hab3.db, lax=False, local=False)
        vkev = ceventing.Kevery(db=verfer.db, lax=False, local=False)

        micp = hab1.makeOtherEvent(gid, sn=0)
        parsing.Parser().parse(ims=bytearray(micp), kvy=vkev)

        g1 = grouping.Groupy(hab=hab1)
        g2 = grouping.Groupy(hab=hab2)
        g3 = grouping.Groupy(hab=hab3)

        groupies = [g1, g2, g3]

        issuer = issuing.Issuer(hab=hab1, reger=reger, noBackers=True, estOnly=True, temp=True)
        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()
        rseal = cue["data"]

        imsg = dict(
            op=grouping.Ops.ixn,
            data=rseal,
        )

        for idx, groupy in enumerate(groupies):
            missing = False
            try:
                groupy.processMessage(imsg)
            except kering.MissingSignatureError:
                missing = True
            assert missing is True

        raw = hab1.db.gpse.getLast(hab1.pre)
        msg = json.loads(raw)
        gid = msg["pre"]
        dig = msg["dig"]

        dgkey = dbing.dgKey(gid, dig)
        eraw = hab1.db.getEvt(dgkey)
        mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
        sigs = hab1.db.getSigs(dgkey)
        sigs.extend(hab2.db.getSigs(dgkey))
        sigs.extend(hab3.db.getSigs(dgkey))

        sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigers)).qb64b)  # attach cnt
        for sig in sigs:
            evt.extend(sig)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(evt), kvy=vkev)

        g1.processEscrows()
        g2.processEscrows()
        g3.processEscrows()

        issuer.processEscrows()
        assert issuer.regk in issuer.tevers

        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()
        assert cue["kin"] == "logEvent"

        verifier = verifying.Verifier(hab=verfer, name="verifier", reger=reger, tevers=issuer.tevers)

        types = ["VerifiableCredential", "GLEIFvLEICredential"]

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
            t=types,
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=group1.gid,
                                    schema="ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc",
                                    subject=d,
                                    status=issuer.regk)

        missing = False
        try:
            issuer.issue(creder)
        except kering.MissingAnchorError:
            missing = True
        assert missing is True

        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()
        rseal = cue["data"]

        imsg = dict(
            op=grouping.Ops.ixn,
            data=rseal,
        )

        for idx, groupy in enumerate(groupies):
            missing = False
            try:
                groupy.processMessage(imsg)
            except kering.MissingSignatureError:
                missing = True
            assert missing is True

        raw = hab1.db.gpse.getLast(hab1.pre)
        msg = json.loads(raw)
        gid = msg["pre"]
        dig = msg["dig"]

        dgkey = dbing.dgKey(gid, dig)
        eraw = hab1.db.getEvt(dgkey)
        mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
        sigs = hab1.db.getSigs(dgkey)
        sigs.extend(hab2.db.getSigs(dgkey))
        sigs.extend(hab3.db.getSigs(dgkey))

        sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigers)).qb64b)  # attach cnt
        for sig in sigs:
            evt.extend(sig)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(evt), kvy=vkev)

        g1.processEscrows()
        g2.processEscrows()
        g3.processEscrows()

        kever = hab1.kevers[gid]
        assert kever.sn == 2

        issuer.processEscrows()
        status = issuer.tvy.tevers[issuer.regk].vcState(creder.said)
        assert status.ked["et"] == coring.Ilks.iss

        gkev = hab1.kevers[gid]
        sigers = []
        for idx, hab in enumerate([hab1, hab2, hab3]):
            sig = hab.mgr.sign(ser=creder.raw,
                               verfers=hab.kever.verfers,
                               indexed=True,
                               indices=[idx])
            sigers.extend(sig)
        prefixer = coring.Prefixer(qb64=gid)
        seqner = coring.Seqner(sn=gkev.lastEst.s)
        diger = coring.Diger(qb64=gkev.lastEst.d)

        verifier.processCredential(creder, prefixer, seqner, diger, sigers)
        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw


def test_verifier_chained_credential():
    qviSchema = "E-_XCbf1LJ0v9CR7g-_gOknf5dpoZROgF7qG5T8mXCv8"
    vLeiSchema = "EC9rQ-xi_3cRrjANStL6tn6Kn4Z444r9rvTr_Vfi-750"

    with habbing.openHab(name="ron", temp=True, salt=b'0123456789abcdef') as ron, \
            habbing.openHab(name="ian", temp=True, salt=b'0123456789abcdef') as ian, \
            habbing.openHab(name="han", transferable=True, temp=True) as han, \
            habbing.openHab(name="vic", transferable=True, temp=True) as vic, \
            viring.openReg(temp=True, name="ron") as ronreg, \
            viring.openReg(temp=True, name="ian") as ianreg, \
            viring.openReg(temp=True, name="vic") as vicreg:

        assert ron.pre == "Ea3bJPQxG2p31BjpjuNz4w9bGO4LUBrL8pZIJQSs5JFg"
        assert ian.pre == "Et2DOOu4ivLsjpv89vgv6auPntSLx4CvOhGUxMhxPS24"
        assert han.pre == "ESS6Ep6l0QpbLXLBMdZMxt1NX4AzHO5yJoTm_uMEX58o"
        assert vic.pre == "EV3GzB-qIh4fmO5RKUuEtE8WcPqZHDUBseEYDUNZiLqo"

        roniss = issuing.Issuer(hab=ron, reger=ronreg, noBackers=True, estOnly=True, temp=True)
        ronverfer = verifying.Verifier(hab=ron, reger=ronreg, tevers=roniss.tevers)

        credSubject = dict(
            d="",
            i=ian.pre,
            dt=helping.nowIso8601(),
            LEI="5493001KJTIIGC8Y1R12",
            t=[
                "VerifiableCredential",
                "QualifiedvLEIIssuervLEICredential"
            ],
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=ron.pre,
                                    schema=qviSchema,
                                    subject=d,
                                    status=roniss.regk)

        msg = ron.endorse(serder=creder)
        del msg[:creder.size]
        parsing.Parser.extract(ims=msg, klas=coring.Counter)
        prefixer, seqner, diger, sigers = proving.parseProof(ims=msg)

        missing = False
        try:
            ronverfer.processCredential(creder, prefixer, seqner, diger, sigers)
        except kering.MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ronverfer.cues) == 1
        cue = ronverfer.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == roniss.regk

        roniss.issue(creder=creder)

        # Now that the credential has been issued, process escrows and it will find the TEL event
        ronverfer.processEscrows()

        assert len(ronverfer.cues) == 1
        cue = ronverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        dcre = ronreg.creds.get(creder.saider.qb64b)
        assert dcre.raw == creder.raw
        seals = ronreg.seals.get(creder.saider.qb64b)
        assert len(seals) == 1
        (pre, sn, dig, sig) = seals[0]
        assert pre.qb64 == prefixer.qb64
        assert sn.qb64 == seqner.qb64
        assert dig.qb64 == diger.qb64
        assert sig.qb64 == sigers[0].qb64

        saider = ronreg.issus.get(ron.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.subjs.get(ian.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.schms.get(qviSchema)
        assert saider[0].qb64 == creder.said

        ianiss = issuing.Issuer(hab=ian, reger=ianreg, noBackers=True, estOnly=True, temp=True)
        ianverfer = verifying.Verifier(hab=ian, reger=ianreg)

        leiCredSubject = dict(
            d="",
            i=han.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
            t=[
                "VerifiableCredential",
                "LegalEntityvLEICredential"
            ],
        )
        _, d = scheming.Saider.saidify(sad=leiCredSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        chain = dict(
            qualifiedvLEIIssuervLEICredential=dict(
                d=creder.said,
                i=ian.pre,
            ),
        )

        vLeiCreder = proving.credential(issuer=ian.pre,
                                        schema=vLeiSchema,
                                        subject=d,
                                        status=ianiss.regk,
                                        source=[chain])

        msg = ian.endorse(serder=vLeiCreder)
        del msg[:vLeiCreder.size]
        parsing.Parser.extract(ims=msg, klas=coring.Counter)
        vLeiPrefixer, vLeiSeqner, vLeiDiger, vLeiSigers = proving.parseProof(ims=msg)

        missing = False
        try:
            ianverfer.processCredential(vLeiCreder, vLeiPrefixer, vLeiSeqner, vLeiDiger, vLeiSigers)
        except kering.MissingRegistryError:
            missing = True

        assert missing is True
        assert len(ianverfer.cues) == 1
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "telquery"
        q = cue["q"]
        assert q["ri"] == ianiss.regk


        ianiss.issue(creder=vLeiCreder)

        # Now that the credential has been issued, process escrows and it will find the TEL event
        ianverfer.processEscrows()

        dcre = ianreg.creds.get(vLeiCreder.saider.qb64b)
        assert dcre.raw == vLeiCreder.raw
        seals = ianreg.seals.get(vLeiCreder.saider.qb64b)
        assert len(seals) == 1
        (pre, sn, dig, sig) = seals[0]
        assert pre.qb64 == vLeiPrefixer.qb64
        assert sn.qb64 == vLeiSeqner.qb64
        assert dig.qb64 == vLeiDiger.qb64
        assert sig.qb64 == vLeiSigers[0].qb64

        dater = ianreg.mce.get(vLeiCreder.saider.qb64b)
        assert dater is not None

        assert len(ianverfer.cues) == 1
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "proof"

        # Now lets get Ron's crecential into Ian's Tevers and Database
        iankvy = ceventing.Kevery(db=ian.db, lax=False, local=False)
        iantvy = eventing.Tevery(reger=ianreg, db=ian.db, local=False)
        ianverfer = verifying.Verifier(hab=ian, reger=ianreg)

        # first get Ron's inception event into Ian's db
        ronIcp = ron.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ronIcp), kvy=iankvy, tvy=iantvy)

        # Now process all the events that Ron's issuer has generated so far
        for cue in roniss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=iankvy, tvy=iantvy)


        ianverfer.processCredential(creder, prefixer, seqner, diger, sigers)

        # Process the escrows to get Ian's credential out of missing chain escrow
        ianverfer.processEscrows()

        # And now it should be in the indexes
        saider = ianreg.issus.get(ian.pre)  # Ian is the issuer
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.subjs.get(han.pre)  # Han is the holder
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.schms.get(vLeiSchema)
        assert saider[0].qb64 == vLeiCreder.said


        # Now lets get Ron's crecential into Vic's Tevers and Database
        vickvy = ceventing.Kevery(db=vic.db, lax=False, local=False)
        victvy = eventing.Tevery(reger=vicreg, db=vic.db, local=False)
        vicverfer = verifying.Verifier(hab=vic, reger=vicreg)

        # Get Ron's icp into Vic's db
        parsing.Parser().parse(ims=bytearray(ronIcp), kvy=vickvy, tvy=victvy)

        for cue in roniss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)


        vicverfer.processCredential(creder, prefixer, seqner, diger, sigers)
        assert len(vicverfer.cues) == 1
        cue = vicverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == creder.raw

        # Vic should be able to verify Han's credential
        # Get Ian's icp into Vic's db
        ianIcp = ian.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ianIcp), kvy=vickvy, tvy=victvy)

        # Get Ian's events in Vic's Tevery
        for cue in ianiss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        # And now verify the credential:
        vicverfer.processCredential(vLeiCreder, vLeiPrefixer, vLeiSeqner, vLeiDiger, vLeiSigers)

        assert len(vicverfer.cues) == 1
        cue = vicverfer.cues.popleft()
        assert cue["kin"] == "saved"
        assert cue["creder"].raw == vLeiCreder.raw

        # Revoke Ian's issuer credential and vic should no longer be able to verify
        # Han's credential that's linked to it
        roniss.cues.clear()  # empty Ron's cue, we're done with all the previous events
        roniss.revoke(creder=creder)
        for cue in roniss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        with pytest.raises(kering.RevokedChainError):
            vicverfer.processCredential(vLeiCreder, vLeiPrefixer, vLeiSeqner, vLeiDiger, vLeiSigers)



if __name__ == '__main__':
    test_verifier_query()
