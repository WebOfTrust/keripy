from keri.app import habbing, keeping
from keri.core import routing, parsing, coring
from keri.core.eventing import Kevery

from keri.db import basing
from keri.vc import proving
from keri.vdr import viring, issuing, eventing


def test_tsn_message_out_of_order(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        bobHab = bobHby.makeHab(name="bob", isith=1, icount=1,)
        assert bobHab.pre == "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU"

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

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU",'
                           b'"s":"0","d":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU","ii":"Et78eYkh8A3'
                           b'H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"E-H2udL7vQADRbeDID2ApJ8NKyQx-c7TUpCe7Oxriax8"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'EkuNMOhl1lMQXbp4V7rNHAMhp4NGy4k1tlg4bXzD_m4c'

        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)
        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()
        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, bobHab.pre))
        assert saider.qb64b == b'E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU'


def test_tsn_message_missing_anchor(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        bobHab = bobHby.makeHab(name="bob", isith=1, icount=1,)
        assert bobHab.pre == "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU"

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU",'
                           b'"s":"0","d":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU","ii":"Et78eYkh8A3'
                           b'H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"E-H2udL7vQADRbeDID2ApJ8NKyQx-c7TUpCe7Oxriax8"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'EkuNMOhl1lMQXbp4V7rNHAMhp4NGy4k1tlg4bXzD_m4c'
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
        assert saider[0].qb64b == b'EkuNMOhl1lMQXbp4V7rNHAMhp4NGy4k1tlg4bXzD_m4c'

        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)
        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, bobHab.pre))
        assert saider.qb64b == b'E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU'


def test_tsn_from_witness(mockHelpingNowUTC):
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    with habbing.openHby(name="wes", base="test", salt=salt) as wesHby, \
         habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith=1, icount=1,transferable=False,)
        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = bobHby.makeHab(name="bob", isith=1, icount=1, wits=[wesHab.pre])
        assert bobHab.pre == "ECJTKtR-GlybCmn1PCiVwIuGBjaOUXI09XWDdXkrJNj0"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "E83bZ5DV-FSe8WeldHfVBGmvJ1LBnV8RBXUyNzrTClZ8"

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesHby.db, lax=False, local=False)

        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
            iserder = coring.Serder(raw=bytearray(msg))
            wesHab.receipt(serder=iserder)

        assert bobHab.pre in wesHab.kevers

        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        wesReger = viring.Registry(name="wes", temp=True)
        wesRtr = routing.Router()
        wesRvy = routing.Revery(db=bamHby.db, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesHby.db, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"E83bZ5DV-FSe8WeldHfVBGmvJ1LBnV8RBXUyNzrTClZ8",'
                           b'"s":"0","d":"E83bZ5DV-FSe8WeldHfVBGmvJ1LBnV8RBXUyNzrTClZ8","ii":"ECJTKtR-Gly'
                           b'bCmn1PCiVwIuGBjaOUXI09XWDdXkrJNj0","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"Ensje9wtQ6Pa5ed1QmYxrXMb9lFUnLy09nKHdcTioSdg"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, wesHab.pre))
        assert saider[0].qb64b == b'Ee7FzyMw4Ys4NACg7Luv9p-wYHf9kfY-qwqayrd_Faqo'
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
        assert saider[0].qb64b == b'Ee7FzyMw4Ys4NACg7Luv9p-wYHf9kfY-qwqayrd_Faqo'

        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=bamTvy, rvy=bamRvy)

        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, wesHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre))
        assert saider.qb64b == b'E83bZ5DV-FSe8WeldHfVBGmvJ1LBnV8RBXUyNzrTClZ8'


def test_tsn_from_no_one(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    with habbing.openHby(name="wes", base="test", salt=salt) as wesHby, \
         habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith=1, icount=1,transferable=False,)
        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = bobHby.makeHab(name="bob", isith=1, icount=1)
        assert bobHab.pre == "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU"

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesHby.db, lax=False, local=False)

        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)

        assert bobHab.pre in wesHab.kevers

        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        wesReger = viring.Registry(name="wes", temp=True)
        wesRtr = routing.Router()
        wesRvy = routing.Revery(db=bamHby.db, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesHby.db, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU",'
                           b'"s":"0","d":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU","ii":"Et78eYkh8A3'
                           b'H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"E-H2udL7vQADRbeDID2ApJ8NKyQx-c7TUpCe7Oxriax8"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Registry(name="bam", temp=True)
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


def test_credential_tsn_message(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way


    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        bobHab = bobHby.makeHab(name="bob", isith=1, icount=1,)
        assert bobHab.pre == "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU"
        assert len(issuer.cues) == 2

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
                                    schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                    subject=credSubject,
                                    status=issuer.regk)
        issuer.issue(creder=creder)
        assert len(issuer.cues) == 4

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU",'
                           b'"s":"0","d":"E_dyu0_yRduOU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU","ii":"Et78eYkh8A3'
                           b'H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"E-H2udL7vQADRbeDID2ApJ8NKyQx-c7TUpCe7Oxriax8"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        ctsn = tever.vcState(vcpre=creder.said)
        assert ctsn.raw == (b'{"v":"KERI10JSON000135_","i":"EU6Ihd0np3JU0p6HOiXkVMGpARyBjqZNeIIvKh_HYAPA",'
                            b'"s":"0","d":"E1BchG9O1F4wCljhb62mfHVEe0VhLEw9ZH1iCyllH9zk","ri":"E_dyu0_yRdu'
                            b'OU-KjhNvgCCmvBwoCPjdXozcvfglcrUvU","ra":{},"a":{"s":2,"d":"Ea05BQyfxAffAqq5n'
                            b'5QR_eIHnCPyetHcz7vsIQqYI1T8"},"dt":"2021-01-01T00:00:00.000000+00:00","et":"'
                            b'iss"}')

        rpy = bobHab.reply(route="/tsn/credential/" + bobHab.pre, data=ctsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-mre", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'EGqcQtozQ2FoVNJ5ytNQ6VWaVlCLgPr7lslb_7oiz9aI'
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
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
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
        assert saider[0].qb64b == b'EGqcQtozQ2FoVNJ5ytNQ6VWaVlCLgPr7lslb_7oiz9aI'

        vci = viring.nsKey([issuer.regk, creder.said])
        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=vci, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        parsing.Parser().parse(ims=tmsgs, tvy=bamTvy, rvy=bamRvy)

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(creder.said, bobHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(creder.said, bobHab.pre))
        assert saider.qb64b == b'E1BchG9O1F4wCljhb62mfHVEe0VhLEw9ZH1iCyllH9zk'
