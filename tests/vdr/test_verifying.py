# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""
import json

from ..app import test_grouping
from keri import kering
from keri.app import habbing, grouping
from keri.core import scheming, parsing, coring
from keri.core import eventing as ceventing
from keri.db import dbing
from keri.vc import proving
from keri.vdr import verifying, issuing, viring, eventing


def test_verifier_query():
    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           res="tels")
        assert msg == b'{"v":"KERI10JSON00009b_","t":"req","r":"tels",' \
                      b'"q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",' \
                      b'"ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4"}}-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP' \
                      b'-c7AH_K7pEE-YfcI9E-AABAAhulhMW2RDUCHK5mxHryjlQ0i3HW_6CXbAGjNnHb9U9pq6N0C9DiavUbX6SgDsk' \
                      b'KIfoQLtV_EqTI_q9AyNAstAQ'


def test_verifier():
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as hab, \
            habbing.openHab(name="recp", transferable=True, temp=True) as recp, \
            viring.openReg(temp=True) as reger:
        assert hab.pre == "ELfzj-TkiKYWsNKk2WE8F8VEgbu3P-_HComVHcKrvGmY"

        issuer = issuing.Issuer(hab=hab, reger=reger, noBackers=True, estOnly=True, temp=True)
        verifier = verifying.Verifier(hab=hab, name="verifier", reger=reger, tevers=issuer.tevers)

        typ = scheming.JSONSchema()
        credSubject = dict(
            si=recp.pre,
            LEI="254900OPPU84GM83MG36",
        )

        creder = proving.credential(issuer=hab.pre,
                                    schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                    subject=credSubject,
                                    status=issuer.regk,
                                    typ=typ)

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
        assert cue["kin"] == "query"
        q = cue["q"]
        assert q["pre"] == creder.said

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
        saider = reger.schms.get("E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4")
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

        typ = scheming.JSONSchema()
        credSubject = dict(
            si=recp.pre,
            LEI="254900OPPU84GM83MG36",
        )

        creder = proving.credential(issuer=group1.gid,
                                    schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                    subject=credSubject,
                                    status=issuer.regk,
                                    typ=typ)

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
        assert issuer.tvy.tevers[issuer.regk].vcState(creder.said) == eventing.VcStates.issued

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


if __name__ == '__main__':
    test_verifier_query()
