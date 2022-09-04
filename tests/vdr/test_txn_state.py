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
        assert bobHab.pre == 'EGVXhrXg11xopD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'

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

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT",'
                           b'"s":"0","d":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT","ii":"EGVXhrXg11x'
                           b'opD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"ENAmYVz8G7DN3xHwVocNSlVGJiLVmaXig2QTTRxLcH55"},"bt'
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
        assert saider[0].qb64b == b'EEjyMwazY1uIVU4z2pI08btAcift2YGjTD5X_bEPYpgM'

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
        assert saider.qb64b == b'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'


def test_tsn_message_missing_anchor(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with (habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EGVXhrXg11xopD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT",'
                        b'"s":"0","d":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT","ii":"EGVXhrXg11x'
                        b'opD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD","dt":"2021-01-01T00:00:00.000000+00:00","'
                        b'et":"vcp","a":{"s":1,"d":"ENAmYVz8G7DN3xHwVocNSlVGJiLVmaXig2QTTRxLcH55"},"bt'
                        b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'EEjyMwazY1uIVU4z2pI08btAcift2YGjTD5X_bEPYpgM'
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
        assert saider[0].qb64b == b'EEjyMwazY1uIVU4z2pI08btAcift2YGjTD5X_bEPYpgM'

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
        assert saider.qb64b == b'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'


def test_tsn_from_witness(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    with (habbing.openHby(name="wes", base="test", salt=salt) as wesHby,
          habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, wits=[wesHab.pre])
        assert bobHab.pre == 'EDHw1T1h9OOYP-V8P324HC7xw8ns4tEt5Mt7zIrLacJf'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EGSb12dIgYkyRXvhxViwPQ21NCakppPgDWgfVaIVIGhl'

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

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EGSb12dIgYkyRXvhxViwPQ21NCakppPgDWgfVaIVIGhl",'
                    b'"s":"0","d":"EGSb12dIgYkyRXvhxViwPQ21NCakppPgDWgfVaIVIGhl","ii":"EDHw1T1h9OO'
                    b'YP-V8P324HC7xw8ns4tEt5Mt7zIrLacJf","dt":"2021-01-01T00:00:00.000000+00:00","'
                    b'et":"vcp","a":{"s":1,"d":"EIejOVSqOjsDF5524DZiZabBFmDCK198VLdqY9ZTB8Bs"},"bt'
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
        assert saider[0].qb64b == b'ENWVH4NE9YBuUrIpLGoCdtObz7mmKU_Id40qjzs5hk5K'
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
        assert saider[0].qb64b == b'ENWVH4NE9YBuUrIpLGoCdtObz7mmKU_Id40qjzs5hk5K'

        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=bamTvy, rvy=bamRvy)

        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, wesHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre))
        assert saider.qb64b == b'EGSb12dIgYkyRXvhxViwPQ21NCakppPgDWgfVaIVIGhl'


def test_tsn_from_no_one(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    with (habbing.openHby(name="wes", base="test", salt=salt) as wesHby,
          habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1)
        assert bobHab.pre == 'EGVXhrXg11xopD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'

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

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT",'
                        b'"s":"0","d":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT","ii":"EGVXhrXg11x'
                        b'opD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD","dt":"2021-01-01T00:00:00.000000+00:00","'
                        b'et":"vcp","a":{"s":1,"d":"ENAmYVz8G7DN3xHwVocNSlVGJiLVmaXig2QTTRxLcH55"},"bt'
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


def test_credential_tsn_message(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    with (habbing.openHby(name="bob", base="test") as bobHby,
          habbing.openHby(name="bam", base="test") as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EGVXhrXg11xopD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        assert issuer.regk == 'EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT'

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        credSubject = dict(
            d="",
            i="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
            LEI="254900OPPU84GM83MG36",
        )

        creder = proving.credential(issuer=bobHab.pre,
                                    schema="EAbrwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                    subject=credSubject,
                                    status=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=bobHab.kever.serder.saider)
        regery.processEscrows()

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT",'
                           b'"s":"0","d":"EOe54WjNGYljVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT","ii":"EGVXhrXg11x'
                           b'opD9o_gH3iWZfu4RRUaKWrnKa4gfCIxsD","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"ENAmYVz8G7DN3xHwVocNSlVGJiLVmaXig2QTTRxLcH55"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        ctsn = tever.vcState(vci=creder.said)
        assert ctsn.raw == (b'{"v":"KERI10JSON000135_","i":"EN84pfn6KEyJ4qcz_-IMwe4I0UfDJFg3QyWy5zIzMzfW",'
                        b'"s":"0","d":"EJ7J8W4gkCaQygwRSWixQfeaU39tLY5YgZVxSy20cZPp","ri":"EOe54WjNGYl'
                        b'jVS0InRDLdFDxwuQ6lVjjHXv7Kc3hXLyT","ra":{},"a":{"s":2,"d":"ECxtyV-WGeuV2zh5z'
                        b'kcFR-af1SCLoWOUcQgNyQ5BP1vs"},"dt":"2021-01-01T00:00:00.000000+00:00","et":"'
                        b'iss"}')

        rpy = bobHab.reply(route="/tsn/credential/" + bobHab.pre, data=ctsn.ked)

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-mre", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'ENvNSW-RGwslJxbwRqPQSkwF_fSl0nNN6vy_aMQwV461'
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
        assert saider[0].qb64b == b'ENvNSW-RGwslJxbwRqPQSkwF_fSl0nNN6vy_aMQwV461'

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
        assert saider.qb64b == b'EJ7J8W4gkCaQygwRSWixQfeaU39tLY5YgZVxSy20cZPp'
