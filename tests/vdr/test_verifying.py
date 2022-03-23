# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""

import pytest

from keri import kering
from keri.app import habbing, signing
from keri.core import eventing as ceventing, scheming
from keri.core import parsing, coring
from keri.help import helping
from keri.vc import proving
from keri.vdr import verifying, credentialing, eventing


def test_verifier_query(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        assert msg == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"EXOG6T6nt1BABGbD1OtypQe6'
                       b'SjZAAsrnHFZYwkCneA1k","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"tels","rr":"","q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-g'
                       b'KXqgcX4","ri":"EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs"}}-V'
                       b'Aj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuArHNOMt'
                       b'9SxHkUhHh8-f27XpHDe8lMVAiYPqvbynY2xc_XbvgTWsPn4VAOO-0nuOGVCzwWzC'
                       b'sVOyc8LLiOF-Ag')


def test_verifier(seeder):
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab), \
            habbing.openHab(name="recp", transferable=True, temp=True) as (recpHby, recp):
        seeder.seedSchema(db=hby.db)
        seeder.seedSchema(db=recpHby.db)
        assert hab.pre == "ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50"

        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        credSubject = dict(
            d="",
            i=recp.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = proving.credential(issuer=hab.pre,
                                    schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                    subject=d,
                                    status=issuer.regk)

        sadsigers, sadcigars = signing.signPaths(hab=hab, serder=creder, paths=[[]])
        missing = False
        try:
            verifier.processCredential(creder, sadsigers=sadsigers, sadcigars=sadcigars)
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

        dcre, sadsigers, sadcigars = regery.reger.cloneCred(said=creder.saider.qb64)

        assert dcre.raw == creder.raw
        assert len(sadsigers) == 1

        saider = regery.reger.issus.get(hab.pre)
        assert saider[0].qb64 == creder.said
        saider = regery.reger.subjs.get(recp.pre)
        assert saider[0].qb64 == creder.said
        saider = regery.reger.schms.get("ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI")
        assert saider[0].qb64 == creder.said

    """End Test"""


# def test_verifier_multisig():
#     with test_grouping.openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
#             habbing.openHab(name="recp", transferable=True, temp=True) as (recpHab, recp), \
#             habbing.openHab(name="verfer", transferable=True, temp=True) as (verferHab, verfer), \
#             viring.openReg(temp=True) as reger:
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.group()
#         assert group1.gid == gid
#
#         # Keverys so we can process the final message.
#         kev1 = ceventing.Kevery(db=hab1.db, lax=False, local=False)
#         kev2 = ceventing.Kevery(db=hab2.db, lax=False, local=False)
#         kev3 = ceventing.Kevery(db=hab3.db, lax=False, local=False)
#         vkev = ceventing.Kevery(db=verfer.db, lax=False, local=False)
#
#         micp = hab1.makeOtherEvent(gid, sn=0)
#         parsing.Parser().parse(ims=bytearray(micp), kvy=vkev)
#
#         g1 = grouping.Groupy(hby=hby1)
#         g2 = grouping.Groupy(hby=hby2)
#         g3 = grouping.Groupy(hby=hby3)
#
#         groupies = [g1, g2, g3]
#
#         issuer = credentialing.Issuer(hab=hab1, reger=reger, noBackers=True, estOnly=True, temp=True)
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         rseal = cue["data"]
#
#         imsg = dict(
#             op=grouping.Ops.ixn,
#             data=rseal,
#         )
#
#         for idx, groupy in enumerate(groupies):
#             missing = False
#             try:
#                 groupy.processMessage(imsg)
#             except kering.MissingSignatureError:
#                 missing = True
#             assert missing is True
#
#         raw = hab1.db.gpse.getLast(hab1.pre)
#         msg = json.loads(raw)
#         gid = msg["pre"]
#         dig = msg["dig"]
#
#         dgkey = dbing.dgKey(gid, dig)
#         eraw = hab1.db.getEvt(dgkey)
#         mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event
#
#         dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
#         sigs = hab1.db.getSigs(dgkey)
#         sigs.extend(hab2.db.getSigs(dgkey))
#         sigs.extend(hab3.db.getSigs(dgkey))
#
#         sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
#
#         evt = bytearray(eraw)
#         evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
#                                   count=len(sigers)).qb64b)  # attach cnt
#         for sig in sigs:
#             evt.extend(sig)
#
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=vkev)
#
#         g1.processEscrows()
#         g2.processEscrows()
#         g3.processEscrows()
#
#         issuer.processEscrows()
#         assert issuer.regk in issuer.tevers
#
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "logEvent"
#
#         verifier = verifying.Verifier(hab=verfer, reger=reger)
#
#         credSubject = dict(
#             d="",
#             i=recp.pre,
#             dt=helping.nowIso8601(),
#             LEI="254900OPPU84GM83MG36",
#         )
#         _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)
#
#         creder = proving.credential(issuer=group1.gid,
#                                     schema="EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg",
#                                     subject=d,
#                                     status=issuer.regk)
#
#         missing = False
#         try:
#             issuer.issue(creder)
#         except kering.MissingAnchorError:
#             missing = True
#         assert missing is True
#
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         rseal = cue["data"]
#
#         imsg = dict(
#             op=grouping.Ops.ixn,
#             data=rseal,
#         )
#
#         for idx, groupy in enumerate(groupies):
#             missing = False
#             try:
#                 groupy.processMessage(imsg)
#             except kering.MissingSignatureError:
#                 missing = True
#             assert missing is True
#
#         raw = hab1.db.gpse.getLast(hab1.pre)
#         msg = json.loads(raw)
#         gid = msg["pre"]
#         dig = msg["dig"]
#
#         dgkey = dbing.dgKey(gid, dig)
#         eraw = hab1.db.getEvt(dgkey)
#         mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event
#
#         dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
#         sigs = hab1.db.getSigs(dgkey)
#         sigs.extend(hab2.db.getSigs(dgkey))
#         sigs.extend(hab3.db.getSigs(dgkey))
#
#         sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
#
#         evt = bytearray(eraw)
#         evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
#                                   count=len(sigers)).qb64b)  # attach cnt
#         for sig in sigs:
#             evt.extend(sig)
#
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=vkev)
#
#         g1.processEscrows()
#         g2.processEscrows()
#         g3.processEscrows()
#
#         kever = hab1.kevers[gid]
#         assert kever.sn == 2
#
#         issuer.processEscrows()
#         status = issuer.tvy.tevers[issuer.regk].vcState(creder.said)
#         assert status.ked["et"] == coring.Ilks.iss
#
#         gkev = hab1.kevers[gid]
#         prefixer = coring.Prefixer(qb64=gid)
#         seqner = coring.Seqner(sn=gkev.lastEst.s)
#         saider = coring.Saider(qb64=gkev.lastEst.d)
#
#         sigers = []
#         for idx, hab in enumerate([hab1, hab2, hab3]):
#             pather = coring.Pather(path=[])
#             data = pather.rawify(serder=creder)
#
#             sig = hab.sign(ser=data,
#                                verfers=hab.kever.verfers,
#                                indexed=True,
#                                indices=[idx])
#             sigers.extend(sig)
#
#         sadsigers = [(pather, prefixer, seqner, saider, sigers)]
#         verifier.processCredential(creder, sadsigers=sadsigers, sadcigars=[])
#
#         assert len(verifier.cues) == 1
#         cue = verifier.cues.popleft()
#         assert cue["kin"] == "saved"
#         assert cue["creder"].raw == creder.raw
#
#     """End Test"""


def test_verifier_chained_credential(seeder):
    qviSchema = "EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw"
    vLeiSchema = "EPz3ZvjQ_8ZwRKzfA5xzbMW8v8ZWLZhvOn2Kw1Nkqo_Q"

    with habbing.openHab(name="ron", temp=True, salt=b'0123456789abcdef') as (ronHby, ron), \
            habbing.openHab(name="ian", temp=True, salt=b'0123456789abcdef') as (ianHby, ian), \
            habbing.openHab(name="han", transferable=True, temp=True) as (hanHby, han), \
            habbing.openHab(name="vic", transferable=True, temp=True) as (vicHby, vic):
        seeder.seedSchema(db=ronHby.db)
        seeder.seedSchema(db=ianHby.db)
        seeder.seedSchema(db=hanHby.db)
        seeder.seedSchema(db=vicHby.db)

        assert ron.pre == "EkaWvr-o2ktpq6nIYL-KlCd_hfVkhIxVRfBOOjETday8"
        assert ian.pre == "EHcaV00uLjd7zXDt_FnH-gCNYG-HC2D2R1GsHDt6-eoc"
        assert han.pre == "ErqUTGqxVQzG3oYuyKVi2zKQvtUqHHMz3t_BaMt9nbPo"
        assert vic.pre == "EI4-27_xnAB2I7LXgIjKUl8APR4iZV_LY64Am5TyBilE"

        ronreg = credentialing.Regery(hby=ronHby, name="ron", temp=True)
        ianreg = credentialing.Regery(hby=ianHby, name="ian", temp=True)
        vicreg = credentialing.Regery(hby=vicHby, name="vic", temp=True)
        roniss = ronreg.makeRegistry(prefix=ron.pre, name="test")
        ronverfer = verifying.Verifier(hby=ronHby, reger=ronreg.reger)

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

        sadsigers, sadcigars = signing.signPaths(hab=ron, serder=creder, paths=[[]])

        missing = False
        try:
            ronverfer.processCredential(creder, sadsigers=sadsigers, sadcigars=sadcigars)
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

        dcre, sadsig, sadcig = ronreg.reger.cloneCred(said=creder.said)
        assert dcre.raw == creder.raw
        assert len(sadsig) == 1
        assert len(sadcig) == 0

        expect = [m.qb64 for m in sadsig[0][:-1]]
        actual = [m.qb64 for m in sadsigers[0][:-1]]
        assert expect == actual

        sig0 = sadsig[-1][0]
        sig1 = sadsigers[-1][0]
        assert sig0.qb64b == sig1.qb64b

        saider = ronreg.reger.issus.get(ron.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.reger.subjs.get(ian.pre)
        assert saider[0].qb64 == creder.said
        saider = ronreg.reger.schms.get(qviSchema)
        assert saider[0].qb64 == creder.said

        ianiss = ianreg.makeRegistry(prefix=ian.pre, name="ian")
        ianverfer = verifying.Verifier(hby=ianHby, reger=ianreg.reger)

        leiCredSubject = dict(
            d="",
            i=han.pre,
            dt=helping.nowIso8601(),
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=leiCredSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        chain = dict(
            d=creder.said,
            qualifiedvLEIIssuervLEICredential=dict(
                n=creder.said,
            ),
        )

        vLeiCreder = proving.credential(issuer=ian.pre,
                                        schema=vLeiSchema,
                                        subject=d,
                                        status=ianiss.regk,
                                        source=chain,
                                        rules=[dict(
                                            usageDisclaimer="Use carefully."
                                        )])

        vLeiSadsigers, vLeiSadcigars = signing.signPaths(hab=ian, serder=vLeiCreder, paths=[[]])

        missing = False
        try:
            ianverfer.processCredential(vLeiCreder, sadsigers=vLeiSadsigers, sadcigars=vLeiSadcigars)
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

        dcre, sadsig, sadcig = ianreg.reger.cloneCred(said=vLeiCreder.said)
        assert dcre.raw == vLeiCreder.raw
        assert len(sadsig) == 1
        assert len(sadcig) == 0

        expect = [m.qb64 for m in sadsig[0][:-1]]
        actual = [m.qb64 for m in vLeiSadsigers[0][:-1]]
        assert expect == actual

        sig0 = sadsig[-1][0]
        sig1 = vLeiSadsigers[-1][0]
        assert sig0.qb64b == sig1.qb64b

        dater = ianreg.reger.mce.get(vLeiCreder.saider.qb64b)
        assert dater is not None

        assert len(ianverfer.cues) == 1
        cue = ianverfer.cues.popleft()
        assert cue["kin"] == "proof"

        # Now lets get Ron's crecential into Ian's Tevers and Database
        iankvy = ceventing.Kevery(db=ian.db, lax=False, local=False)
        iantvy = eventing.Tevery(reger=ianreg.reger, db=ian.db, local=False)
        ianverfer = verifying.Verifier(hby=ianHby, reger=ianreg.reger)

        # first get Ron's inception event into Ian's db
        ronIcp = ron.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ronIcp), kvy=iankvy, tvy=iantvy)

        # Now process all the events that Ron's issuer has generated so far
        for cue in roniss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=iankvy, tvy=iantvy)

        ianverfer.processCredential(creder, sadsigers=sadsigers, sadcigars=sadcigars)

        # Process the escrows to get Ian's credential out of missing chain escrow
        ianverfer.processEscrows()

        # And now it should be in the indexes
        saider = ianreg.reger.issus.get(ian.pre)  # Ian is the issuer
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.reger.subjs.get(han.pre)  # Han is the holder
        assert saider[0].qb64 == vLeiCreder.said
        saider = ianreg.reger.schms.get(vLeiSchema)
        assert saider[0].qb64 == vLeiCreder.said

        # Now lets get Ron's crecential into Vic's Tevers and Database
        vickvy = ceventing.Kevery(db=vic.db, lax=False, local=False)
        victvy = eventing.Tevery(reger=vicreg.reger, db=vic.db, local=False)
        vicverfer = verifying.Verifier(hby=vicHby, reger=vicreg.reger)

        # Get Ron's icp into Vic's db
        parsing.Parser().parse(ims=bytearray(ronIcp), kvy=vickvy, tvy=victvy)

        for cue in roniss.cues:
            msg = cue["msg"]
            parsing.Parser().parse(ims=bytearray(msg), kvy=vickvy, tvy=victvy)

        vicverfer.processCredential(creder, sadsigers=sadsigers, sadcigars=sadcigars)
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
        vicverfer.processCredential(vLeiCreder, sadsigers=vLeiSadsigers, sadcigars=vLeiSadcigars)

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
            vicverfer.processCredential(vLeiCreder, sadsigers=vLeiSadsigers, sadcigars=vLeiSadcigars)

    """End Test"""
