from keri.app import habbing
from keri.core import routing, parsing, coring
from keri.core.eventing import Kevery, SealEvent

from keri.vc import proving
from keri.vdr import viring, credentialing, eventing


def test_tsn_message_out_of_order(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    with (habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6",'
                        b'"s":"0","d":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6","ii":"EA_SbBUZYwq'
                        b'LVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","dt":"2021-01-01T00:00:00.000000+00:00","'
                        b'et":"vcp","a":{"s":1,"d":"EIei8AjSQ9pGJp-UfcFNcxQxzsVHQCgCsViNr81Hl3pd"},"bt'
                        b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'EEPziN_7emWTt94juY7X3Nlo44dTAaoCz7PGorkZAWVo'

        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)
        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()
        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, bobHab.pre))
        assert saider.qb64b == b'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'


def test_tsn_message_missing_anchor(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with (habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6",'
                            b'"s":"0","d":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6","ii":"EA_SbBUZYwq'
                            b'LVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","dt":"2021-01-01T00:00:00.000000+00:00","'
                            b'et":"vcp","a":{"s":1,"d":"EIei8AjSQ9pGJp-UfcFNcxQxzsVHQCgCsViNr81Hl3pd"},"bt'
                            b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, bobHab.pre))
        said = b'EEPziN_7emWTt94juY7X3Nlo44dTAaoCz7PGorkZAWVo'
        assert saider[0].qb64b == said
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue['q']['pre'] == bobHab.pre

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == said

        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)
        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, bobHab.pre))
        assert saider.qb64b == b'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'


def test_tsn_from_witness(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    #raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    #salter = coring.Salter(raw=raw)
    #salt = salter.qb64
    #assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # Habery.makeHab uses name as stem path for salt so different pre
    with (habbing.openHby(name="wes", base="test") as wesHby,
          habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, wits=[wesHab.pre])
        assert bobHab.pre == 'EDroh9lTel0P1YQaiL7shXG63SRSzKSDek7PaceOs6bY'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EBrr1pxZoY5nY38YifrGvn5HSMv0sAwvTTAQ5e3_-ivP'

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesHby.db, lax=False, local=False)

        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
            iserder = coring.Serder(raw=bytearray(msg))
            wesHab.receipt(serder=iserder)

        assert bobHab.pre in wesHab.kevers

        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        wesReger = viring.Reger(name="wes", temp=True)
        wesRtr = routing.Router()
        wesRvy = routing.Revery(db=bamHby.db, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesHby.db, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EBrr1pxZoY5nY38YifrGvn5HSMv0sAwvTTAQ5e3_-ivP",'
                        b'"s":"0","d":"EBrr1pxZoY5nY38YifrGvn5HSMv0sAwvTTAQ5e3_-ivP","ii":"EDroh9lTel0'
                        b'P1YQaiL7shXG63SRSzKSDek7PaceOs6bY","dt":"2021-01-01T00:00:00.000000+00:00","'
                        b'et":"vcp","a":{"s":1,"d":"EHXALltba7vs56tixvcYsZv-JVI1-MlZ60Jk40DuyWFh"},"bt'
                        b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, wesHab.pre))
        said = b'EMpMvmRARP3rm_JmO57iZ6zhEELmAuVVELo660CMapg5'
        assert saider[0].qb64b == said
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue['q']['pre'] == bobHab.pre

        wesIcp = wesHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(wesIcp), kvy=bamKvy)
        assert wesHab.pre in bamHby.db.kevers

        msgs = bytearray()
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)
        assert bobHab.pre in bamHby.db.kevers

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, wesHab.pre))
        assert saider[0].qb64b == said

        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=bamTvy, rvy=bamRvy)

        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, wesHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre))
        assert saider.qb64b == b'EBrr1pxZoY5nY38YifrGvn5HSMv0sAwvTTAQ5e3_-ivP'


def test_tsn_from_no_one(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    #raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    #salter = coring.Salter(raw=raw)
    #salt = salter.qb64
    #assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # Habery.makeHab uses name as stem path for salt so different pre
    with (habbing.openHby(name="wes", base="test") as wesHby,
          habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1)
        assert bobHab.pre == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'


        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesHby.db, lax=False, local=False)

        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)

        assert bobHab.pre in wesHab.kevers

        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        wesReger = viring.Reger(name="wes", temp=True)
        wesRtr = routing.Router()
        wesRvy = routing.Revery(db=bamHby.db, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesHby.db, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6",'
                    b'"s":"0","d":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6","ii":"EA_SbBUZYwq'
                    b'LVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","dt":"2021-01-01T00:00:00.000000+00:00","'
                    b'et":"vcp","a":{"s":1,"d":"EIei8AjSQ9pGJp-UfcFNcxQxzsVHQCgCsViNr81Hl3pd"},"bt'
                    b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')


        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)

        msgs = bytearray()
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)
        assert bobHab.pre in bamHby.db.kevers

        # Parse TSN from someone who is not authorized to provide it
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        # Assert that the TSN did not end up in escrow or the database
        assert bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, wesHab.pre)) == []
        assert bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, wesHab.pre)) == []
        assert bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre)) is None

        assert len(bamTvy.cues) == 0


def test_credential_tsn_message(mockHelpingNowUTC, mockCoringRandomNonce, mockHelpingNowIso8601):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    with (habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6'

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        credSubject = dict(
            LEI="254900OPPU84GM83MG36",
        )

        creder = proving.credential(issuer=bobHab.pre,
                                    recipient="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
                                    schema="EAbrwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                    data=credSubject,
                                    status=issuer.regk)

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6",'
                           b'"s":"0","d":"ECbNKwkTjZqsfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6","ii":"EA_SbBUZYwq'
                           b'LVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","dt":"2021-06-27T21:26:21.233257+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"EIei8AjSQ9pGJp-UfcFNcxQxzsVHQCgCsViNr81Hl3pd"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        ctsn = tever.vcState(vci=creder.said)
        assert ctsn.raw == (b'{"v":"KERI10JSON000135_","i":"EEqcwL-ew_OaQphSQvy8bRGtnKlL_g_SkXjsAGWgtFGl",'
                            b'"s":"0","d":"EIxhyBA8h6BMmtWEJzqNkoAquIkMucpXbdY3kQX25GQu","ri":"ECbNKwkTjZq'
                            b'sfwNLxTnraPImegy1YeQ2-pCrTBQmu3i6","ra":{},"a":{"s":2,"d":"EGJIFzWexy6LQbW4-'
                            b'IQqhGLD6wA9yR7pcLzxomjb40Ku"},"dt":"2021-06-27T21:26:21.233257+00:00","et":"'
                            b'iss"}')

        rpy = bobHab.reply(route="/tsn/credential/" + bobHab.pre, data=ctsn.ked)

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-mre", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'EAxn6pBNsNuGXP7Ngrr80t5PbJ_XuzDvY7DQ5SYodpin'
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)
        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-ooo", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'EAxn6pBNsNuGXP7Ngrr80t5PbJ_XuzDvY7DQ5SYodpin'

        vci = creder.said
        tmsgs = bytearray()
        cloner = regery.reger.clonePreIter(pre=vci, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(creder.said, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(creder.said, bobHab.pre))
        assert saider.qb64b == b'EIxhyBA8h6BMmtWEJzqNkoAquIkMucpXbdY3kQX25GQu'
