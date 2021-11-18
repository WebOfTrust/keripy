from keri.app import habbing, keeping
from keri.core import routing, parsing, coring
from keri.core.eventing import Kevery

from keri.db import basing
from keri.vc import proving
from keri.vdr import viring, issuing, eventing


def test_tsn_message_out_of_order(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[], temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc"

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamDB, rtr=bamRtr)
        bamKvy = Kevery(db=bamDB, lax=False, local=False, rvy=bamRvy)
        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == ((b'{"v":"KERI10JSON000158_","i":"ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc",'
                            b'"s":"0","d":"EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M","ii":"Eta8KLf1zrE'
                            b'5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","dt":"2021-01-01T00:00:00.000000+00:00","'
                            b'et":"vcp","a":{"s":1,"d":"EbFIqGFsIJnlkf6h9AT_AU_Uyiqtko__BEkxP_n2IvXk"},"bt'
                            b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}'))

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'ENRhplnqsNRO94MRu3mYM3VthB7kmuZGoS5tLvRy-uFI'

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
        assert saider.qb64b == b'EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M'


def test_tsn_message_missing_anchor(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[], temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc"

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamDB, rtr=bamRtr)
        bamKvy = Kevery(db=bamDB, lax=False, local=False, rvy=bamRvy)

        tever = issuer.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc",'
                           b'"s":"0","d":"EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M","ii":"Eta8KLf1zrE'
                           b'5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"EbFIqGFsIJnlkf6h9AT_AU_Uyiqtko__BEkxP_n2IvXk"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = bobHab.reply(route="/tsn/registry/" + bobHab.pre, data=tsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'ENRhplnqsNRO94MRu3mYM3VthB7kmuZGoS5tLvRy-uFI'
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue['q']['pre'] == bobHab.pre

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, bobHab.pre))
        assert saider[0].qb64b == b'ENRhplnqsNRO94MRu3mYM3VthB7kmuZGoS5tLvRy-uFI'

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
        assert saider.qb64b == b'EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M'


def test_tsn_from_witness(mockHelpingNowUTC):
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)

        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[wesHab.pre], temp=True)
        assert bobHab.pre == "E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "EBBbecdi5jrcJR-R0bgwhHCtcj-WBbqvaXyKJbZaeKsY"

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesDB, lax=False, local=False)

        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
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
        wesRvy = routing.Revery(db=bamDB, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesDB, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"EBBbecdi5jrcJR-R0bgwhHCtcj-WBbqvaXyKJbZaeKsY",'
                           b'"s":"0","d":"EKpzPCVpoHZQliTIvZhLaJKn5-6fbN0wJ_y7jKfsJ2ac","ii":"E4BsxCYUtUx'
                           b'3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"Eo4BSkczfAJtaVXOde_n0OtRfEJn6llRMW2GONnafkvM"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamDB, rtr=bamRtr)
        bamKvy = Kevery(db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-mae", issuer.regk, wesHab.pre))
        assert saider[0].qb64b == b'Ehcsr9i4WlTUy1mp-HU_Fqrrkyj61MYR2UfyZI0c6syI'
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue['q']['pre'] == bobHab.pre

        wesIcp = wesHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(wesIcp), kvy=bamKvy)
        assert wesHab.pre in bamDB.kevers

        msgs = bytearray()
        for msg in wesDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)
        assert bobHab.pre in bamDB.kevers

        bamTvy.processEscrows()

        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        saider = bamReger.txnsb.escrowdb.get(keys=("registry-ooo", issuer.regk, wesHab.pre))
        assert saider[0].qb64b == b'Ehcsr9i4WlTUy1mp-HU_Fqrrkyj61MYR2UfyZI0c6syI'

        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=bamTvy, rvy=bamRvy)

        assert issuer.regk in bamReger.tevers

        bamTvy.processEscrows()

        # check to make sure the tsn escrow state is clear
        assert bamReger.txnsb.escrowdb.get(keys=(issuer.regk, wesHab.pre)) == []
        # check to make sure the tsn has been saved
        saider = bamReger.txnsb.saiderdb.get(keys=(issuer.regk, wesHab.pre))
        assert saider.qb64b == b'EKpzPCVpoHZQliTIvZhLaJKn5-6fbN0wJ_y7jKfsJ2ac'


def test_tsn_from_no_one(mockHelpingNowUTC):
    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)

        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[], temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc"

        # Create Bob's icp, pass to Wes.
        wesKvy = Kevery(db=wesDB, lax=False, local=False)

        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
            parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)

        assert bobHab.pre in wesHab.kevers

        tmsgs = bytearray()
        cloner = reger.clonePreIter(pre=issuer.regk, fn=0)  # create iterator at 0
        for msg in cloner:
            tmsgs.extend(msg)

        wesReger = viring.Registry(name="wes", temp=True)
        wesRtr = routing.Router()
        wesRvy = routing.Revery(db=bamDB, rtr=wesRtr)
        wesTvy = eventing.Tevery(reger=wesReger, db=wesDB, lax=False, local=False, rvy=wesRvy)
        wesTvy.registerReplyRoutes(router=wesRtr)
        parsing.Parser().parse(ims=bytearray(tmsgs), tvy=wesTvy, rvy=wesRvy)

        assert issuer.regk in wesReger.tevers

        tever = wesReger.tevers[issuer.regk]
        tsn = tever.state()

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc",'
                           b'"s":"0","d":"EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M","ii":"Eta8KLf1zrE'
                           b'5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"EbFIqGFsIJnlkf6h9AT_AU_Uyiqtko__BEkxP_n2IvXk"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        rpy = wesHab.reply(route="/tsn/registry/" + wesHab.pre, data=tsn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamDB, rtr=bamRtr)
        bamKvy = Kevery(db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)

        msgs = bytearray()
        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)
        assert bobHab.pre in bamDB.kevers

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
    with basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[], temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        reger = viring.Registry(name=bobHab.name, temp=True)
        issuer = issuing.Issuer(hab=bobHab, name=bobHab.name, reger=reger, noBackers=True, )

        assert issuer.regk == "ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc"
        assert len(issuer.cues) == 2

        # pass key event log to Bam
        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamDB, rtr=bamRtr)
        bamKvy = Kevery(db=bamDB, lax=False, local=False, rvy=bamRvy)

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

        assert tsn.raw == (b'{"v":"KERI10JSON000158_","i":"ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc",'
                           b'"s":"0","d":"EE5c5Cr5u4xU8lfTWLwYtd5R_8kcB64uoMqG5F_jND6M","ii":"Eta8KLf1zrE'
                           b'5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","dt":"2021-01-01T00:00:00.000000+00:00","'
                           b'et":"vcp","a":{"s":1,"d":"EbFIqGFsIJnlkf6h9AT_AU_Uyiqtko__BEkxP_n2IvXk"},"bt'
                           b'":"0","br":[],"ba":[],"b":[],"c":["NB"]}')

        ctsn = tever.vcState(vcpre=creder.said)
        assert ctsn.raw == (
            b'{"v":"KERI10JSON000135_","i":"EZc4FuRsgMJ3nagRMmz7kSCsh2VCHj9yI0fpaUOZf3Zs","s":"0",'
            b'"d":"EG6VAER9fTbirNC313PrMVdlJeaFjia4xBxYvhfmTQIw","ri":"ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc",'
            b'"ra":{},"a":{"s":2,"d":"ElcdRh_66cR79tYDs7Q2OjjOjiAf_SZp6lWERgG1aSs8"},'
            b'"dt":"2021-01-01T00:00:00.000000+00:00","et":"iss"}')

        rpy = bobHab.reply(route="/tsn/credential/" + bobHab.pre, data=ctsn.ked)

        bamReger = viring.Registry(name="bam", temp=True)
        bamTvy = eventing.Tevery(reger=bamReger, db=bamDB, lax=False, local=False, rvy=bamRvy)
        bamTvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(rpy), tvy=bamTvy, rvy=bamRvy)

        saider = bamReger.txnsb.escrowdb.get(keys=("credential-mre", creder.said, bobHab.pre))
        assert saider[0].qb64b == b'E--rpyw2A5OATjluDezNIcgeMvLTSYALvMqVKnop-lJo'
        assert len(bamTvy.cues) == 1
        cue = bamTvy.cues.popleft()
        assert cue["kin"] == "telquery"
        assert cue['q']['ri'] == issuer.regk

        # Gather up Bob's key event log
        msgs = bytearray()
        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
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
        assert saider[0].qb64b == b'E--rpyw2A5OATjluDezNIcgeMvLTSYALvMqVKnop-lJo'

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
        assert saider.qb64b == b'EG6VAER9fTbirNC313PrMVdlJeaFjia4xBxYvhfmTQIw'
