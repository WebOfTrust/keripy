from dataclasses import asdict

from keri import core
from keri.core import routing, parsing, coring, serdering

from keri.core.eventing import Kevery, SealEvent

from keri.app import habbing

from keri.vc import proving
from keri.vdr import viring, credentialing, eventing


def test_tsn_message_out_of_order(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    default_salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
          habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'

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
        rsr = tever.state()

        assert asdict(rsr) == {'b': [],
                               'bt': '0',
                               'c': ['NB'],
                               'd': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'dt': '2021-01-01T00:00:00.000000+00:00',
                               'et': 'vcp',
                               'i': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'ii': 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj',
                               's': '0',
                               'vn': [1, 0]}

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=rsr._asdict())

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'ECZWYxq_Qgs0J0ls_imRWRYxrojzTKL2REjqe0rN8kWy'

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
        assert saider.qb64b == b'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'


def test_tsn_message_missing_anchor(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64
    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
          habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert asdict(tsn) == {'b': [],
                               'bt': '0',
                               'c': ['NB'],
                               'd': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'dt': '2021-01-01T00:00:00.000000+00:00',
                               'et': 'vcp',
                               'i': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'ii': 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj',
                               's': '0',
                               'vn': [1, 0]}

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=asdict(tsn))

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, bobHab.pre))
        said = b'ECZWYxq_Qgs0J0ls_imRWRYxrojzTKL2REjqe0rN8kWy'
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
        assert saider.qb64b == b'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'


def test_tsn_from_witness(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    # Habery.makeHab uses name as stem path for salt so different pre
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64
    with (habbing.openHby(name="wes", base="test", salt=default_salt) as wesHby,
          habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
          habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BJX05FKbj6M7EoUp53nKJNdG5eDZMGBatlDjg_QcpuqE'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, wits=[wesHab.pre])
        assert bobHab.pre == 'EPa6GLVG4lFV9oi28WQbC7UfcSoDb7kMlZkaa3qaj4UA'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EH3hN33719ybSg21Kboy-V2jafwvQSHnY1HUGzzBqqk6'

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesHby.db, lax=False, local=False)

        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy, local=True)
            iserder = serdering.SerderKERI(raw=bytearray(msg))
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

        assert asdict(tsn) == {'b': [],
                               'bt': '0',
                               'c': ['NB'],
                               'd': 'EH3hN33719ybSg21Kboy-V2jafwvQSHnY1HUGzzBqqk6',
                               'dt': '2021-01-01T00:00:00.000000+00:00',
                               'et': 'vcp',
                               'i': 'EH3hN33719ybSg21Kboy-V2jafwvQSHnY1HUGzzBqqk6',
                               'ii': 'EPa6GLVG4lFV9oi28WQbC7UfcSoDb7kMlZkaa3qaj4UA',
                               's': '0',
                               'vn': [1, 0]}

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=asdict(tsn))

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy, local=True)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, wesHab.pre))
        said = b'EPKAvk7JJzylDFPjOxfanPjqDvUk_a-hzjNTT9Svhik1'
        assert saider[0].qb64b == said
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue['q']['pre'] == bobHab.pre

        wesIcp = wesHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(wesIcp), kvy=bamKvy, local=True)
        assert wesHab.pre in bamHby.db.kevers

        msgs = bytearray()
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy, local=True)
        assert bobHab.pre in bamHby.db.kevers

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, wesHab.pre))
        assert saider[0].qb64b == said

        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=bamTvy, rvy=bamRvy, local=True)

        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, wesHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre))
        assert saider.qb64b == b'EH3hN33719ybSg21Kboy-V2jafwvQSHnY1HUGzzBqqk6'


def test_tsn_from_no_one(mockHelpingNowUTC, mockCoringRandomNonce):
    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    #raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    #salter = core.Salter(raw=raw)
    #salt = salter.qb64
    #assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # Habery.makeHab uses name as stem path for salt so different pre
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64
    with (habbing.openHby(name="wes", base="test", salt=default_salt) as wesHby,
          habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
          habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1,transferable=False,)
        assert wesHab.pre == 'BJX05FKbj6M7EoUp53nKJNdG5eDZMGBatlDjg_QcpuqE'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1)
        assert bobHab.pre == 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'


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

        assert asdict(tsn) == {'b': [],
                               'bt': '0',
                               'c': ['NB'],
                               'd': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'dt': '2021-01-01T00:00:00.000000+00:00',
                               'et': 'vcp',
                               'i': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                               'ii': 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj',
                               's': '0',
                               'vn': [1, 0]}

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=asdict(tsn))

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

    default_salt = core.Salter(raw=b'0123456789abcdef').qb64
    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
          habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj'

        regery = credentialing.Regery(hby=bobHby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'

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
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        tever = issuer.tevers[issuer.regk]
        rsr = tever.state()

        assert rsr._asdict() == {'b': [],
                                 'bt': '0',
                                 'c': ['NB'],
                                 'd': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                                 'dt': '2021-06-27T21:26:21.233257+00:00',
                                 'et': 'vcp',
                                 'i': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                                 'ii': 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj',
                                 's': '0',
                                 'vn': [1, 0]}

        ctsn = tever.vcState(vci=creder.said)
        assert asdict(ctsn) == {'a': {'d': 'EJEsBdnprtcNR-QaFM-h1OPaiGDBikgDk7aqVXPHAhPL', 's': 2},
                                'd': 'EGE5B5vYhHNYHN0g8YHIcAIu3LR0vJQ9fCXqjJunEZf1',
                                'dt': '2021-06-27T21:26:21.233257+00:00',
                                'et': 'iss',
                                'i': 'EPQNM4YNlVZ6nGu7ElGC6GhAHdLBLnoxYXKFP4R_ZbGz',
                                'ra': {},
                                'ri': 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ',
                                's': '0',
                                'vn': [1, 0]}

        rpy = bobHab.reply(route="/tsn/credential/" + bobHab.pre, data=asdict(ctsn))

        bamReger = viring.Reger(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-mre", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'EHERhBLfaMik0Ne9ysU3UICXWge0yobK0FQv3QhyeqF7'
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
        assert saider[0].qb64b == b'EHERhBLfaMik0Ne9ysU3UICXWge0yobK0FQv3QhyeqF7'

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
        keys = (creder.said, bobHab.pre)
        saider = bamReger.txnsb.saiderdb.get(keys=keys)
        assert saider.qb64b == b'EGE5B5vYhHNYHN0g8YHIcAIu3LR0vJQ9fCXqjJunEZf1'


def test_tever_reload(mockHelpingNowUTC, mockCoringRandomNonce, mockHelpingNowIso8601):
    with habbing.openHby(name="bob", base="test", salt=core.Salter(raw=b'0123456789abcdef').qb64) as hby:
        bobHab = hby.makeHab(name="bob", isith='1', icount=1,)
        assert bobHab.pre == 'EFggrgspyZwbi-zB2iJzjHu0QU5dh89mA8jOhDcgrTqj'

        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=bobHab.pre, name=bobHab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        bobHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=bobHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=bobHab.kever.serder.said))
        regery.processEscrows()

        assert issuer.regk == 'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ'

        rsr = regery.reger.states.get(keys=issuer.regk)
        tever = eventing.Tever(rsr=rsr, reger=regery.reger)
        assert tever.regk == issuer.regk
        assert tever.pre == bobHab.pre
