# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""
import pytest

import os
import uuid

from hio.base import doing

from keri.kering import (ConfigurationError, MissingEntryError,
                         Vrsn_1_0, Kinds, Roles, Schemes)

from keri.help import helping

from keri.core import (Kevery, Salter, Seqner, Number,
                       Diger, Dater, Parser, SerderKERI,
                       Tiers, MtrDex, NumDex)

from keri.app import (Configer, ConfigerDoer, Habery,
                      Hab, HaberyDoer, Keeper, KeeperDoer,
                      openHab, openHby, Algos)

from keri.db import Baser, BaserDoer

TEST_VERSION = Vrsn_1_0


def test_make_load_hab_with_habery_v1():
    """
    Test creation methods for Hab instances with Habery
    """
    with pytest.raises(TypeError):  # missing required dependencies
        _ = Hab()  # defaults

    name = "sue"
    suePre = 'ELF1S0jZkyQx8YtHaPLu-qyFmrkcykAiEW8twS-KPSO1'  # with temp=True

    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:  # default is temp=True on openHab
        hab = hby.makeHab(name=name, version=Vrsn_1_0, kind=Kinds.json)
        assert isinstance(hab, Hab)
        assert hab.pre in hby.habs
        assert id(hby.habByName(hab.name)) == id(hab)

        assert hab.name == name
        assert hab.pre == suePre
        assert hab.temp
        assert hab.accepted
        assert hab.inited

        assert hab.pre in hby.kevers
        assert hab.pre in hby.prefixes

        hab.db = hby.db  # injected
        hab.ks = hby.ks  # injected
        hab.cf = hby.cf  # injected
        hab.mgr = hby.mgr  # injected
        hab.rtr = hby.rtr  # injected
        hab.rvy = hby.rvy  # injected
        hab.kvy = hby.kvy  # injected
        hab.psr = hby.psr  # injected

    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    # create not temp and then reload from not temp
    base = f"hold-v1-{uuid.uuid4().hex}"
    suePre = 'EAxe215BJ4Iy9r0mfoMEGVmHW8A4Avk3RYBC1A1_DZam'  # with temp=False
    bobPre = 'ENya5E5pvc6MVCe75huDK0QQhE4_64J55vCn4aKdXhR9'  # with temp=False

    with openHby(base=base, temp=False, salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:  # default is temp=True

        assert hby.cf.path.endswith(os.path.join("keri", "cf", base, "test.json"))
        assert hby.db.path.endswith(os.path.join("keri", "db", base, "test"))
        assert hby.ks.path.endswith(os.path.join("keri", "ks", base, "test"))

        sueHab = hby.makeHab(name='Sue', version=Vrsn_1_0, kind=Kinds.json)
        assert isinstance(sueHab, Hab)
        assert sueHab.pre in hby.habs
        assert id(hby.habByName(sueHab.name)) == id(sueHab)

        assert sueHab.name == "Sue"
        assert sueHab.pre == suePre
        assert not sueHab.temp
        assert sueHab.accepted
        assert sueHab.inited
        assert sueHab.pre in hby.kevers
        assert sueHab.pre in hby.prefixes

        bobHab = hby.makeHab(name='Bob', version=Vrsn_1_0, kind=Kinds.json)
        assert isinstance(bobHab, Hab)
        assert bobHab.pre in hby.habs
        assert id(hby.habByName(bobHab.name)) == id(bobHab)

        assert bobHab.name == "Bob"
        assert bobHab.pre == bobPre
        assert not bobHab.temp
        assert bobHab.accepted
        assert bobHab.inited
        assert bobHab.pre in hby.kevers
        assert bobHab.pre in hby.prefixes

        assert len(hby.habs) == 2

    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert os.path.exists(hby.cf.path)
    assert os.path.exists(hby.db.path)
    assert os.path.exists(hby.ks.path)

    # test load from database
    with openHby(base=base, temp=False, version=TEST_VERSION) as hby:  # default is temp=True
        assert hby.cf.path.endswith(os.path.join("keri", "cf", base, "test.json"))
        assert hby.db.path.endswith(os.path.join("keri", "db", base, "test"))
        assert hby.ks.path.endswith(os.path.join("keri", "ks", base, "test"))

        assert hby.inited
        assert len(hby.habs) == 2

        assert suePre in hby.kevers
        assert suePre in hby.prefixes
        assert suePre in hby.habs
        sueHab = hby.habByName("Sue")
        assert sueHab.name == "Sue"
        assert sueHab.pre == suePre
        assert sueHab.accepted
        assert sueHab.inited

        assert bobPre in hby.kevers
        assert bobPre in hby.prefixes
        assert bobPre in hby.habs
        bobHab = hby.habByName("Bob")
        assert bobHab.name == "Bob"
        assert bobHab.pre == bobPre
        assert bobHab.accepted
        assert bobHab.inited

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    """End Test"""

def test_hab_rotate_with_witness_v1():
    """
    Reload from disk and rotate hab with witness
    """
    name = f"phil-test-v1-{uuid.uuid4().hex}"

    with openHby(name=name, base="test", temp=False, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name=name, icount=1, wits=["BANkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"], version=Vrsn_1_0, kind=Kinds.json)
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said

    with openHby(name=name, base="test", temp=False, version=TEST_VERSION) as hby:
        hab = hby.habByName(name)
        assert hab.pre == opre
        assert hab.prefixes is hab.db.prefixes
        assert hab.kevers is hab.db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate(ncount=3, framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

def test_habery_reinitialization_v1():
    """Test Reinitializing Habery and its Habs
    """
    name = f"bob-test-v1-{uuid.uuid4().hex}"
    base = f"test-v1-{uuid.uuid4().hex}"
    salt = Salter(raw=b'0123456789abcdef').qb64

    with openHby(name=name, base=base, temp=False, clear=True, salt=salt, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name=name, icount=1, version=Vrsn_1_0, kind=Kinds.json)
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said

    with openHby(name=name, base=base, temp=False, salt=salt, version=TEST_VERSION) as hby:

        assert opre in hby.db.kevers  # read through cache
        assert opre in hby.db.prefixes

        hab = hby.habByName(name)
        assert hab.pre == opre
        assert hab.prefixes is hab.db.prefixes
        assert hab.kevers is hab.db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.said

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.kever.serder.said != odig
        assert hab.kever.serder.said == ndig

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    """End Test"""

def test_get_own_event_v1():
    """Test Hab.getOwnEvent: happy path sn=0 and sn=1, delegated duple, error path missing event."""
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name="test", version=Vrsn_1_0, kind=Kinds.json)
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        # Happy path: inception at sn=0
        serder, sigs, duple = hab.getOwnEvent(sn=0)
        assert serder.sad["t"] == "icp"
        assert serder.sad["s"] == "0"
        assert serder.sad["i"] == hab.pre
        assert len(sigs) >= 1
        assert duple is None

        # Happy path: rotation at sn=1
        hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        serder, sigs, duple = hab.getOwnEvent(sn=1)
        assert serder.sad["t"] == "rot"
        assert serder.sad["s"] == "1"
        assert serder.sad["i"] == hab.pre
        assert len(sigs) >= 1
        assert duple is None  # rotation has no authorizer seal

    # Happy path: delegated hab with authorizer seal (duple is not None)
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:
        delHab = hby.makeHab(name="delegator", version=Vrsn_1_0, kind=Kinds.json)
        delHab.interact(data=[], framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)  # anchoring event at sn=1
        anchorSner = Number(num=delHab.kever.sn, code=NumDex.Huge)
        anchorSaider = Diger(qb64b=delHab.kever.serder.saidb)

        subHab = hby.makeHab(name="delegate", delpre=delHab.pre, version=Vrsn_1_0, kind=Kinds.json)
        hby.db.aess.pin(keys=(subHab.pre, subHab.kever.serder.saidb), val=(anchorSner, anchorSaider))

        serder, sigs, duple = subHab.getOwnEvent(sn=0)
        assert serder.sad["t"] == "dip"
        assert serder.sad["i"] == subHab.pre
        assert duple is not None
        sner, saider = duple
        assert sner.sn == delHab.kever.sn
        assert saider.qb64 == delHab.kever.serder.said

    # Error path: missing event at sn (no event at sn=1 for inception-only hab)
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name="other", version=Vrsn_1_0, kind=Kinds.json)
        with pytest.raises(MissingEntryError) as exc_info:
            hab.getOwnEvent(sn=1)
        assert hab.pre in str(exc_info.value)
        assert "1" in str(exc_info.value)

def test_msg_own_event_v1():
    """Test Hab.msgOwnEvent: sn=0 vs msgOwnInception, sn=1 after rotate."""
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name="test", version=Vrsn_1_0, kind=Kinds.json)
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        # msgOwnEvent(sn=0) equals msgOwnInception()
        msg0 = hab.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        msg_icp = hab.msgOwnInception(framed=True, gvrsn=TEST_VERSION)
        assert msg0 == msg_icp
        assert len(msg0) > 0
        assert msg0.startswith(b'{"v":"KERI10JSON')
        assert SerderKERI(raw=bytes(msg0)).kind == Kinds.json

        # msgOwnEvent(sn=1) after rotate
        hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        msg1 = hab.msgOwnEvent(sn=1, framed=True, gvrsn=TEST_VERSION)
        assert len(msg1) > 0
        serder = SerderKERI(raw=bytes(msg1))
        assert serder.kind == Kinds.json
        assert serder.sad["t"] == "rot"
        assert serder.sad["s"] == "1"

def test_msg_other_event_v1():
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name="test", version=Vrsn_1_0, kind=Kinds.json)
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)

        msg = hab.msgOtherEvent(hab.pre, sn=1, framed=True, gvrsn=TEST_VERSION)
        assert msg == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EGnFNzw2UJKpQZYJj_xhcFYW'
                       b'E7prFWFBbghgcMuJ4VeM","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2Q'
                       b'V8dDjI3","s":"1","p":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDj'
                       b'I3","kt":"1","k":["DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP"'
                       b'],"nt":"1","n":["EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax"],'
                       b'"bt":"0","br":[],"ba":[],"a":[]}-AABAAC2DAJCt6KLh442NsGVLE0pYKvL'
                       b'-3MVh-kWcBWWqpVmXbhlQ3oGHD5h4jUY7Trw2jFvsQyC4A_1kJpmNP1AgXcM')
        assert SerderKERI(raw=bytes(msg)).kind == Kinds.json

        msg = hab.msgOtherEvent(hab.pre, sn=2, framed=True, gvrsn=TEST_VERSION)
        assert msg == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EJCaUsmfvR35xZxpenqEWCtX'
                       b'sXnD_efjlvvRd1hEvu5d","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2Q'
                       b'V8dDjI3","s":"2","p":"EGnFNzw2UJKpQZYJj_xhcFYWE7prFWFBbghgcMuJ4V'
                       b'eM","kt":"1","k":["DPjsUEx6Nqby9-yUO1DtExQ81CRYdvpwQZufBRzBM5yk"'
                       b'],"nt":"1","n":["EIraDaPWlGBU9DnwCaNQ2XVaX8zQQFhnkj8Ir4R5R-Yh"],'
                       b'"bt":"0","br":[],"ba":[],"a":[]}-AABAADGsMs4ifEPuBH9vApQTnJyGCXm'
                       b'p8Sc4CcESKA-q5O0O5CmpCbSrA29UpqZnfvUagrwm8w3M1a1WJKy64OQYXIG')
        assert SerderKERI(raw=bytes(msg)).kind == Kinds.json

def test_postman_endsfor_v1():
    with openHby(name="test", temp=True, salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as hby, \
            openHby(name="wes", temp=True, salt=Salter(raw=b'wess-the-witness').qb64, version=TEST_VERSION) as wesHby, \
            openHab(name="agent", temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (agentHby, agentHab):

        wesHab = wesHby.makeHab(name='wes', isith="1", icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not wesHab.kever.prefixer.transferable
        # create non-local kevery for Wes to process nonlocal msgs
        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)

        wits = [wesHab.pre]
        hab = hby.makeHab(name='cam', isith="1", icount=1, toad=1, wits=wits, version=Vrsn_1_0, kind=Kinds.json)
        assert hab.kever.prefixer.transferable
        assert len(hab.iserder.berfers) == len(wits)
        for werfer in hab.iserder.berfers:
            assert werfer.qb64 in wits
        assert hab.kever.wits == wits
        assert hab.kever.toader.num == 1
        assert hab.kever.sn == 0

        kvy = Kevery(db=hab.db, lax=False, local=False)
        icpMsg = hab.msgOwnInception(framed=True, gvrsn=TEST_VERSION)
        rctMsgs = []  # list of receipts from each witness
        Parser(version=TEST_VERSION).parse(ims=bytearray(icpMsg), kvy=wesKvy, local=True)
        assert wesKvy.kevers[hab.pre].sn == 0  # accepted event
        assert len(wesKvy.cues) >= 1  # assunmes includes queued receipt cue
        # better to find cue in cues and confirm exactly
        rctMsg = wesHab.processCues(wesKvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)  # process cue returns rct msg
        assert len(rctMsg) == 626
        rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kvy, local=True)
        assert wesHab.pre in kvy.kevers

        agentIcpMsg = agentHab.msgOwnInception(framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(agentIcpMsg), kvy=kvy, local=True)
        assert agentHab.pre in kvy.kevers

        msgs = bytearray()
        msgs.extend(wesHab.makeEndRole(eid=wesHab.pre,
                                       role=Roles.controller,
                                       stamp=helping.nowIso8601(),
                                       version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(wesHab.makeLocScheme(url='http://127.0.0.1:8888',
                                         scheme=Schemes.http,
                                         stamp=helping.nowIso8601(),
                                         version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        wesHab.psr.parse(ims=bytearray(msgs))

        # Set up
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(),
                                    version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(hab.makeLocScheme(url='http://127.0.0.1:7777',
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(),
                                      version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        hab.psr.parse(ims=msgs)

        msgs = bytearray()
        msgs.extend(agentHab.makeEndRole(eid=agentHab.pre,
                                         role=Roles.controller,
                                         stamp=helping.nowIso8601(),
                                         version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(agentHab.makeLocScheme(url='http://127.0.0.1:6666',
                                           scheme=Schemes.http,
                                           stamp=helping.nowIso8601(),
                                           version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(hab.makeEndRole(eid=agentHab.pre,
                                    role=Roles.agent,
                                    stamp=helping.nowIso8601(),
                                    version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(hab.makeEndRole(eid=agentHab.pre,
                                    role=Roles.mailbox,
                                    stamp=helping.nowIso8601(),
                                    version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        agentHab.psr.parse(ims=bytearray(msgs))
        hab.psr.parse(ims=bytearray(msgs))

        ends = hab.endsFor(hab.pre)
        assert ends == {
            'agent': {
                'EBErgFZoM3PBQNTpTuK9bax_U8HLJq1Re2RM1cdifaTJ': {'http': 'http://127.0.0.1:6666'}},
            'controller': {
                'EGadHcyW9IfVIPrFUAa_I0z4dF8QzQAvUvfaUTJk8Jre': {'http': 'http://127.0.0.1:7777'}},
            'mailbox': {
                'EBErgFZoM3PBQNTpTuK9bax_U8HLJq1Re2RM1cdifaTJ': {'http': 'http://127.0.0.1:6666'}},
            'witness': {
                'BN8t3n1lxcV0SWGJIIF46fpSUqA7Mqre5KJNN3nbx3mr': {'http': 'http://127.0.0.1:8888'}}
        }

def test_cues_v1():
    """
    Test BaseHab.processCuesIter and GroupHab.processCuesIter cue handlers.

    Covers all implemented kins:
        receipt, replay, reply, witness, query,
        notice, noticeBadCloneFN, keyStateSaved, stream, invalid,
        remoteMemberedSig (GroupHab only)
    """
    with openHby(name="cam", temp=True,
                         salt=Salter(raw=b'camcamcamcamcamc').qb64, version=TEST_VERSION) as camHby, \
         openHby(name="wes", temp=True,
                         salt=Salter(raw=b'wesweswesweswesx').qb64, version=TEST_VERSION) as wesHby, \
         openHby(name="bob", temp=True,
                         salt=Salter(raw=b'bobbobbobbobbobb').qb64, version=TEST_VERSION) as bobHby:

        # shared habs
        wesHab = wesHby.makeHab(name='wes', isith="1", icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not wesHab.kever.prefixer.transferable

        camHab = camHby.makeHab(name='cam', isith="1", icount=1,
                                toad=1, wits=[wesHab.pre], version=Vrsn_1_0, kind=Kinds.json)
        bobHab = bobHby.makeHab(name='bob', isith="1", icount=1, version=Vrsn_1_0, kind=Kinds.json)

        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)
        camKvy = Kevery(db=camHab.db, lax=False, local=False)

        # parse cam's inception into wes so wes has cam's key state
        icpMsg = camHab.msgOwnInception(framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icpMsg),
                                                kvy=wesKvy, local=True)
        assert camHab.pre in wesKvy.kevers
        assert wesHab.pre in wesKvy.kevers[camHab.pre].wits

        # receipt
        assert any(c["kin"] == "receipt" for c in wesKvy.cues)
        rctMsg = wesHab.processCues(wesKvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(rctMsg) > 0
        Parser(version=TEST_VERSION).parse(ims=bytearray(rctMsg),
                                                kvy=camKvy, local=False)
        assert wesHab.pre in camKvy.kevers

        # replay
        kvy = Kevery(db=camHab.db, lax=False, local=True)
        replay_payload = bytearray(b"fake-replay-msgs")
        kvy.cues.push(dict(kin="replay", msgs=replay_payload))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == replay_payload

        # reply
        kvy.cues.push(dict(kin="reply",
                           route="/end/role/add",
                           data=dict(cid=camHab.pre,
                                     role=Roles.controller,
                                     eid=camHab.pre)))
        rpyMsg = camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(rpyMsg) > 0
        rpySerder = SerderKERI(raw=bytes(rpyMsg))
        assert rpySerder.kind == Kinds.json
        assert rpySerder.pvrsn == TEST_VERSION
        assert "i" not in rpySerder.ked

        # witness
        # drain incidental cues from parsing above, then push witness cue
        while wesKvy.cues:
            wesKvy.cues.pull()
        wesKvy.cues.push(dict(kin="witness", serder=camHab.iserder))
        assert len(wesHab.processCues(wesKvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)) > 0

        # query
        kvy.cues.push(dict(kin="query", pre=bobHab.pre, src=camHab.pre))
        qryMsg = camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(qryMsg) > 0
        qrySerder = SerderKERI(raw=bytes(qryMsg))
        assert qrySerder.kind == Kinds.json
        assert qrySerder.pvrsn == TEST_VERSION
        assert "i" not in qrySerder.ked
        assert qrySerder.ked["q"]["i"] == bobHab.pre

        # notice
        kvy.cues.push(dict(kin="notice", serder=camHab.iserder))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == b""
        assert not kvy.cues

        # noticeBadCloneFN
        kvy.cues.push(dict(kin="noticeBadCloneFN",
                           serder=camHab.iserder,
                           fn=7,
                           firner=Seqner(sn=5),
                           dater=Dater()))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == b""
        assert not kvy.cues

        # keyStateSaved
        ksn = {"i": camHab.pre, "s": "0", "d": camHab.kever.serder.said}
        kvy.cues.push(dict(kin="keyStateSaved", ksn=ksn))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == b""
        assert not kvy.cues

        # stream
        kvy.cues.push(dict(kin="stream",
                           serder=camHab.iserder,
                           pre=bobHab.pre,
                           src=camHab.pre,
                           topics={"/receipt": 0, "/replay": 0}))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == b""
        assert not kvy.cues

        # invalid
        kvy.cues.push(dict(kin="invalid", serder=camHab.iserder))
        assert camHab.processCues(kvy.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0) == b""
        assert not kvy.cues

def test_habery_reconfigure_v1(mockHelpingNowUTC):
    """
    Test   .reconfigure method using .cf for config file

     conf
    {
      dt: "isodatetime",
      curls: ["tcp://localhost:5620/"],
      iurls: ["ftp://localhost:5621/?name=eve"],
    }

    """
    # use same salter but with different path from name for each
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    # salter = Salter(raw=raw)
    # salt = salter.qb64
    # assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    salt = Salter(raw=b'0123456789abcdef').qb64

    cname = "tam"  # controller name
    cbase = "main"  # controller base shared
    pname = "nel"  # peer name
    pbase = "head"  # peer base shared

    with (openHby(name='wes', base=cbase, salt=salt, version=TEST_VERSION) as wesHby,
          openHby(name='wok', base=cbase, salt=salt, version=TEST_VERSION) as wokHby,
          openHby(name=cname, base=cbase, salt=salt, version=TEST_VERSION) as tamHby,
          openHby(name='wat', base=cbase, salt=salt, version=TEST_VERSION) as watHby,
          openHby(name=pname, base=pbase, salt=salt, version=TEST_VERSION) as nelHby):
        # witnesses first so can setup inception event for tam
        wsith = '1'

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith=wsith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not wesHab.kever.prefixer.transferable

        # setup Wok's habitat nontrans
        wokHab = wokHby.makeHab(name="wok", isith=wsith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not wokHab.kever.prefixer.transferable

        # setup Tam's config
        curls = ["tcp://localhost:5620/"]
        iurls = [f"tcp://localhost:5621/?role={Roles.peer}&name={pname}"]
        assert tamHby.cf.get() == {}
        conf = dict(dt=helping.nowIso8601(), tam=dict(dt=helping.nowIso8601(), curls=curls), iurls=iurls)
        tamHby.cf.put(conf)

        assert tamHby.cf.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                   'tam': {
                                       'dt': '2021-01-01T00:00:00.000000+00:00',
                                       'curls': ['tcp://localhost:5620/']
                                   },
                                   'iurls': ['tcp://localhost:5621/?role=peer&name=nel']}

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre]
        tsith = '1'  # hex str of threshold int
        tamHab = tamHby.makeHab(name=cname, isith=tsith, icount=3, toad=2, wits=wits, version=Vrsn_1_0, kind=Kinds.json)
        assert tamHab.kever.prefixer.transferable
        assert len(tamHab.iserder.berfers) == len(wits)
        for werfer in tamHab.iserder.berfers:
            assert werfer.qb64 in wits
        assert tamHab.kever.wits == wits
        assert tamHab.kever.toader.num == 2
        assert tamHab.kever.sn == 0
        assert tamHab.kever.tholder.thold == 1 == int(tsith, 16)
        # create non-local kevery for Tam to process non-local msgs

        # check tamHab.cf config setup
        ender = tamHab.db.ends.get(keys=(tamHab.pre, "controller", tamHab.pre))
        assert ender.allowed
        assert not ender.name
        locer = tamHab.db.locs.get(keys=(tamHab.pre, Schemes.tcp))
        assert locer.url == 'tcp://localhost:5620/'

        # setup Wat's habitat nontrans
        watHab = watHby.makeHab(name="wat", isith=wsith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not watHab.kever.prefixer.transferable

        # setup Nel's config
        curls = ["tcp://localhost:5621/"]
        iurls = [f"tcp://localhost:5620/?role={Roles.peer}&name={cname}"]
        assert nelHby.cf.get() == {}
        conf = dict(dt=helping.nowIso8601(), nel=dict(dt=helping.nowIso8601(), curls=curls), iurls=iurls)
        nelHby.cf.put(conf)

        assert nelHby.cf.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                   'nel': {
                                       'dt': '2021-01-01T00:00:00.000000+00:00',
                                       'curls': ['tcp://localhost:5621/'],
                                   },
                                   'iurls': ['tcp://localhost:5620/?role=peer&name=tam']}

        # setup Nel's habitat nontrans
        nelHab = nelHby.makeHab(name=pname, isith=wsith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not nelHab.kever.prefixer.transferable
        # create non-local parer for Nel to process non-local msgs

        assert nelHab.pre == 'BBWmLeVPY4obmPkyBGCsmysDmhbe017t6gS7v6B_ogV9'
        assert nelHab.kever.prefixer.code == MtrDex.Ed25519N
        assert nelHab.kever.verfers[0].qb64 == nelHab.pre

        # check nelHab.cf config setup
        ender = nelHab.db.ends.get(keys=(nelHab.pre, "controller", nelHab.pre))
        assert ender.allowed
        assert not ender.name
        locer = nelHab.db.locs.get(keys=(nelHab.pre, Schemes.tcp))
        assert locer.url == 'tcp://localhost:5621/'

    assert not os.path.exists(nelHby.cf.path)
    assert not os.path.exists(nelHby.db.path)
    assert not os.path.exists(nelHby.ks.path)
    assert not os.path.exists(watHby.cf.path)
    assert not os.path.exists(watHby.db.path)
    assert not os.path.exists(watHby.ks.path)
    assert not os.path.exists(wokHby.cf.path)
    assert not os.path.exists(wokHby.db.path)
    assert not os.path.exists(wokHby.ks.path)
    assert not os.path.exists(wesHby.cf.path)
    assert not os.path.exists(wesHby.db.path)
    assert not os.path.exists(wesHby.ks.path)
    assert not os.path.exists(tamHby.cf.path)
    assert not os.path.exists(tamHby.db.path)
    assert not os.path.exists(tamHby.ks.path)
    """Done Test"""


if __name__ == "__main__":
    test_make_load_hab_with_habery_v1()
    test_hab_rotate_with_witness_v1()
    test_habery_reinitialization_v1()
    test_get_own_event_v1()
    test_msg_own_event_v1()
    test_msg_other_event_v1()
    test_postman_endsfor_v1()
    test_cues_v1()
    test_habery_reconfigure_v1()
