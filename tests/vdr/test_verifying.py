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
    with habbing.openHabitat(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        assert msg == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"Efp5Surn_KGO6S4G6ZnExhK8'
                  b'3kCEIpVQA3QihDyeHG-Y","dt":"2021-01-01T00:00:00.000000+00:00","r'
                  b'":"tels","rr":"","q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-g'
                  b'KXqgcX4","ri":"ERAY2VjFALVZAAuC3GDM-36qKD8ZhUaKF55MWtITBFnc"}}-V'
                  b'Aj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAfmxUPkuS'
                  b'zu50ixd9C5NwXzI7Dm2IdtD_PKExpzz0CQRwa9d3fvuWG-iQKiPxPCMCDEOmDwx9'
                  b'iBO55UL94q0CAQ')


def test_verifier():
    with habbing.openHabitat(name="sid", temp=True, salt=b'0123456789abcdef') as hab, \
            habbing.openHabitat(name="recp", transferable=True, temp=True) as recp, \
            viring.openReg(temp=True) as reger:
        assert hab.pre == "EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w"

        issuer = issuing.Issuer(hab=hab, reger=reger, noBackers=True, estOnly=True, temp=True)
        verifier = verifying.Verifier(hab=hab, name="verifier", reger=reger, tevers=issuer.tevers)

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=hab.pre,
                                    schema="EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg",
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
        saider = reger.schms.get("EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg")
        assert saider[0].qb64 == creder.said


def test_verifier_multisig():
    with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3), \
            habbing.openHabitat(name="recp", transferable=True, temp=True) as recp, \
            habbing.openHabitat(name="verfer", transferable=True, temp=True) as verfer, \
            viring.openReg(temp=True) as reger:

        gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
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

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
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

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=group1.gid,
                                    schema="EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg",
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

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
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
    qviSchema = "ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo"
    vLeiSchema = "EYKd_PUuCGvoMfTu6X3NZrLKl1LsvFN60M-P23ZTiKQ0"

    with habbing.openHabitat(name="ron", temp=True, salt=b'0123456789abcdef') as ron, \
            habbing.openHabitat(name="ian", temp=True, salt=b'0123456789abcdef') as ian, \
            habbing.openHabitat(name="han", transferable=True, temp=True) as han, \
            habbing.openHabitat(name="vic", transferable=True, temp=True) as vic, \
            viring.openReg(temp=True, name="ron") as ronreg, \
            viring.openReg(temp=True, name="ian") as ianreg, \
            viring.openReg(temp=True, name="vic") as vicreg:

        assert ron.pre == "EoovZ8CJiavhb1hpjcmCjUUPglFR3AdRA9VUhXu-Px_4"
        assert ian.pre == "EbgpwKmMagky9SvCGXrcsT0-YlbPnmAXqRSK1an7IzvI"
        assert han.pre == "EmQqEDpWMGGt-zmXxe7vEbyWIZOm4XwUU0J177rUMhRw"
        assert vic.pre == "E-1sk6rrObrEjysK7gsfbNyr4V4qFJsnrFiU5EDBO2Vo"

        roniss = issuing.Issuer(hab=ron, reger=ronreg, noBackers=True, estOnly=True, temp=True)
        ronverfer = verifying.Verifier(hab=ron, reger=ronreg, tevers=roniss.tevers)

        credSubject = dict(
            d="",
            i=ian.pre,
            dt=helping.nowIso8601(),
            LEI="5493001KJTIIGC8Y1R12",
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
                                        source=[chain],
                                        rules=[dict(
                                            usageDisclaimer="Use carefully."
                                        )])

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
