# -*- encoding: utf-8 -*-
"""
tests.app.indirecting module

"""
import json
import platform
import time

import falcon
from falcon import testing
import hio
import pytest

from hio.core import http
from hio.base import doing
from hio.help import decking

from keri.kering import Schemes, Vrsn_1_0, Vrsn_2_0, Kinds, Ilks, Roles
from keri.core import SerderKERI, Salter, Kevery, Parser
from keri.db import basing
from keri.app import (MailboxIterable, QryRpyMailboxIterable,
                      QueryEnd, Mailboxer, Receiptor,
                      setupWitness, createHttpServer, openHab, openHby,
                      ReceiptEnd, CESR_CONTENT_TYPE, CESR_DESTINATION_HEADER)
from keri.app.httping import CESR_ATTACHMENT_HEADER

from tests.common import CUE_KWA, KWA

from tests.common import KWA


def test_mailbox_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    mbx = Mailboxer(temp=True)
    mb = MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 1, "/multisig": 0},
                                     retry=1000)

    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    val = next(mbi)
    assert val == b''

    # Store a message for the iter
    msg = dict(i=pre, t="rct")
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store messages for the iter, each next returns all available messages
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    mbx.storeMsg(topic=f"{pre}/multisig", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\nid: 0\nevent: /multisi'
                   b'g\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6d'
                   b'W_GT068", "t": "rct"}\n\n')

    # First stored challenge message will not be found because topics indicates already seen
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /challenge\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx'
                   b'68GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store a message that does not match any topics
    mbx.storeMsg(topic=f"{pre}/replay", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_mailbox_multiple_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    msg = dict(words=["abc", "def"])
    mbx = Mailboxer(temp=True)
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))

    mb = MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 0, "/multisig": 0},
                                     retry=1000)
    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    # First stored challenge message will not be found because topics indicates already seen
    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /challenge\nretry: 1000\ndata: {"words": ["abc", "def'
                   b'"]}\n\nid: 1\nevent: /challenge\nretry: 1000\ndata: {"words": ["a'
                   b'bc", "def"]}\n\n')

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_qrymailbox_iter():
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        assert hab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
        icp = hab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
        icpSrdr = SerderKERI(raw=icp)
        qry = hab.query(pre=hab.pre, src=hab.pre, route="/mbx", **KWA)
        srdr = SerderKERI(raw=qry)

        cues = decking.Deck()
        mbx = Mailboxer(temp=True)
        mb = QryRpyMailboxIterable(mbx=mbx, cues=cues, said=srdr.said, retry=1000)

        mbi = iter(mb)
        assert mb.iter is None

        #  No cued query response, empty iter
        val = next(mbi)
        assert val == b''
        assert mb.iter is None

        # A cue with the wrong said still returns nothing and recues the cue
        cues.append(dict(kin="stream", serder=icpSrdr))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 1
        assert mb.iter is None
        cues.popleft()

        cues.append(dict(kin="stream", pre=hab.pre, serder=srdr,
                         topics={"/receipt": 0, "/challenge": 1, "/multisig": 0}))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 0
        assert mb.iter is not None

        # And now it behaves just like a standard MailboxIterable
        val = next(mbi)
        assert val == b'retry: 1000\n\n'

        # Store a message for the iter
        msg = dict(i=hab.pre, t="rct")
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        val = next(mbi)
        assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: '
                       b'{"i": "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3", '
                       b'"t": "rct"}\n\n')

        mb.iter.TimeoutMBX = 0  # Force the iter to timeout
        with pytest.raises(StopIteration):
            next(mbi)


def test_qrymailbox_iter_v2():
    topics = {"/receipt": 0, "/challenge": 1, "/multisig": 0}

    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef',
                 version=Vrsn_2_0, kind=Kinds.json) as (hby, hab):
        assert hab.pre == 'EChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M'
        icp = hab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0)
        icpSrdr = SerderKERI(raw=icp)
        qry = hab.query(pre=hab.pre, src=hab.pre, route="mbx", query={"topics": topics},
                        version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        srdr = SerderKERI(raw=qry)
        assert srdr.pvrsn == Vrsn_2_0
        assert srdr.gvrsn == Vrsn_2_0
        assert srdr.kind == Kinds.json
        assert srdr.ked["t"] == Ilks.qry
        assert srdr.ked["i"] == hab.pre
        assert srdr.ked["r"] == "mbx"
        assert srdr.ked["q"]["i"] == hab.pre
        assert srdr.ked["q"]["src"] == hab.pre
        assert srdr.ked["q"]["topics"] == topics
        
        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby.cf.put(cf)
        kvy = Kevery(db=hby.db, cf=hby.cf, enableKram=True, lax=False, local=False)
        assert kvy.kramer.enabled is True
        Parser(version=Vrsn_2_0).parse(ims=bytearray(qry), kvy=kvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, srdr.said))
        assert cache is not None
        assert cache.mdt == srdr.stamp
        assert cache.d == 1000

        cues = decking.Deck()
        mbx = Mailboxer(temp=True)
        mb = QryRpyMailboxIterable(mbx=mbx, cues=cues, said=srdr.said, retry=1000)

        mbi = iter(mb)
        assert mb.iter is None

        #  No cued query response, empty iter
        val = next(mbi)
        assert val == b''
        assert mb.iter is None

        # A cue with the wrong said still returns nothing and recues the cue
        cues.append(dict(kin="stream", serder=icpSrdr))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 1
        assert mb.iter is None
        cues.popleft()

        cues.append(dict(kin="stream", pre=hab.pre, serder=srdr, topics=topics))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 0
        assert mb.iter is not None

        # And now it behaves just like a standard MailboxIterable
        val = next(mbi)
        assert val == b'retry: 1000\n\n'

        # Store a message for the iter
        msg = dict(i=hab.pre, t="rct")
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        val = next(mbi)
        assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: '
                       b'{"i": "EChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M", '
                       b'"t": "rct"}\n\n')

        mb.iter.TimeoutMBX = 0  # Force the iter to timeout
        with pytest.raises(StopIteration):
            next(mbi)


def test_wit_query_ends(seeder, witnessPorter):
    with openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, version=Vrsn_1_0) as wesHby, \
            openHby(name="pal", salt=Salter(raw=b'0123456789abcdef').qb64, version=Vrsn_1_0) as palHby:
        witnessPorts, witnessUrls = witnessPorter("wes")
        wesDoers = setupWitness(alias="wes", hby=wesHby,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"], **KWA)
        # Pull the reger out of the Doers so the reger is reused and does not trigger an LMDB error on reuse
        wesReger = next(doer.baser for doer in wesDoers if isinstance(doer, basing.BaserDoer))
        witDoer = Receiptor(hby=palHby)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab],
                           protocols=[Schemes.http], witnessUrls=witnessUrls, **KWA)

        app = falcon.App()
        query_endpoint = QueryEnd(wesHab, reger=wesReger)
        app.add_route("/query", query_endpoint)

        wesClient = testing.TestClient(app)

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            witDoer=witDoer,
            wesClient=wesClient
        )
        testDo = QueryTestDoer(**opts)
        doers = wesDoers + [witDoer, testDo]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        while not testDo.done:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()


class QueryTestDoer(doing.Doer):
    def __init__(self, **opts):
        self.options = opts
        super(QueryTestDoer, self).__init__(**opts)

    def recur(self, tyme=0.0, deeds=None, **kwa):
        wesHab = self.options["wesHab"]
        palHby = self.options["palHby"]
        witDoer = self.options["witDoer"]
        wesClient = self.options["wesClient"]

        palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True, **KWA)

        assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

        witDoer.msgs.append(dict(pre=palHab.pre))
        while not witDoer.cues:
            yield self.tock

        msg = next(wesHab.db.clonePreIter(pre=palHab.pre, version=palHab.kever.serder.pvrsn))


        # Test valid KEL query with 'pre'
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"
        assert bytearray(res.content) == bytearray(msg)

        # Test KEL query without 'pre'
        res = wesClient.simulate_get("/query", params={"typ": "kel"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "'pre' query param is required" in res.text

        # Test KEL query with 'sn' parameter
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 0})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test KEL query with non-existant 'sn' parameter
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 5})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "non-existant event at seq-num 5" in res.text

        # Test valid TEL query with 'reg'
        res = wesClient.simulate_get("/query", params={"typ": "tel", "reg": "mock_reg"})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test valid TEL query with 'vcid'
        res = wesClient.simulate_get("/query", params={"typ": "tel", "vcid": "mock_vcid"})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test TEL query missing both 'reg' and 'vcid'
        res = wesClient.simulate_get("/query", params={"typ": "tel"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "Either 'reg' or 'vcid' query param is required for TEL query" in res.text

        # Test invalid 'typ' parameter
        res = wesClient.simulate_get("/query", params={"typ": "invalid"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "unkown query type" in res.text

        return True


class MockServerTls:
    def __init__(self,  certify, keypath, certpath, cafilepath, port):
        pass


class MockHttpServer:
    def __init__(self, host, port, app, servant=None):
        self.servant = servant


def test_createHttpServer(monkeypatch):
    host = "0.0.0.0"
    if platform.system() == "Windows":
        host = "127.0.0.1"
    port = 5632
    app = falcon.App()
    server = createHttpServer(host, port, app)
    assert isinstance(server, http.Server)

    monkeypatch.setattr(hio.core.tcp, 'ServerTls', MockServerTls)
    monkeypatch.setattr(hio.core.http, 'Server', MockHttpServer)

    server = createHttpServer(host, port, app, keypath='keypath', certpath='certpath', cafilepath='cafilepath')

    assert isinstance(server, MockHttpServer)
    assert isinstance(server.servant, MockServerTls)


def test_receipt_end_returns_bytes_for_v1_receipt():
    with openHby(name="receipt-wit", version=Vrsn_1_0) as witHby, \
            openHby(name="receipt-cam", version=Vrsn_1_0) as camHby:
        wit = witHby.makeHab(name="wit", transferable=False, **KWA)
        cam = camHby.makeHab(name="cam", transferable=True, wits=[wit.pre],
                             toad=1, icount=1, ncount=1,
                             isith="1", nsith="1", **KWA)

        serder, _, _ = cam.getOwnEvent(sn=0)
        msg = cam.msgOwnEvent(sn=0, framed=True, gvrsn=serder.pvrsn)

        ims = bytearray(msg)
        serder = SerderKERI(raw=ims)
        del ims[:serder.size]

        app = falcon.App()
        app.add_route("/receipts", ReceiptEnd(hab=wit))
        client = testing.TestClient(app)

        res = client.simulate_post("/receipts",
                                   body=serder.raw,
                                   headers={
                                       "Content-Type": CESR_CONTENT_TYPE,
                                       CESR_ATTACHMENT_HEADER: bytes(ims).decode("utf-8"),
                                       CESR_DESTINATION_HEADER: wit.pre,
                                   })

        assert res.status_code == 200
        assert isinstance(res.content, bytes)
        rserder = SerderKERI(raw=res.content)
        assert rserder.pvrsn == Vrsn_1_0
        assert rserder.ked["t"] == Ilks.rct


def test_mailbox_query_honors_explicit_v1_kwargs():
    with openHby(name="mailbox-query", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", **KWA)

        msg = hab.query(pre=hab.pre,
                        src=hab.pre,
                        route="mbx",
                        query=dict(topics={"/receipt": 0}),
                        **KWA)

        serder = SerderKERI(raw=msg)
        assert serder.pvrsn == Vrsn_1_0
        assert serder.kind == Kinds.json
        assert serder.ked["q"]["topics"] == {"/receipt": 0}


def test_follow_on_events_honor_explicit_v1_kwargs():
    with openHby(name="v1-follow-ons", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", **KWA)

        rot = hab.rotate(framed=True, **CUE_KWA)
        rserder = SerderKERI(raw=rot)
        assert rserder.pvrsn == Vrsn_1_0
        assert rserder.kind == Kinds.json

        ixn = hab.interact(framed=True, **CUE_KWA)
        iserder = SerderKERI(raw=ixn)
        assert iserder.pvrsn == Vrsn_1_0
        assert iserder.kind == Kinds.json


def test_end_role_reply_defaults_to_hab_version_for_v1_hab():
    with openHby(name="v1-end-role", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", **KWA)

        msg = hab.makeEndRole(eid=hab.pre, role=Roles.mailbox)
        serder = SerderKERI(raw=msg)
        assert serder.pvrsn == Vrsn_1_0
        assert serder.kind == Kinds.json

        hab.psr.parse(ims=bytearray(msg))
        loaded = hab.loadEndRole(cid=hab.pre, eid=hab.pre, role=Roles.mailbox)
        assert loaded



def test_query_end_reuses_injected_reger():
    """QueryEnd must use an injected reger instead of opening a second one,
    preventing LMDB double-open on the same TEL store.  See #1367.
    """
    from keri.app.indirecting import QueryEnd
    from unittest.mock import MagicMock

    mock_hab = MagicMock()
    mock_reger = MagicMock()

    qe = QueryEnd(hab=mock_hab, reger=mock_reger)
    assert qe.reger is mock_reger


def test_poller_keeps_supplied_msgs_deck():
    """Poller must keep a caller-supplied msgs deck instead of discarding it.
    See #1500.
    """
    from keri.app.indirecting import Poller
    from unittest.mock import MagicMock

    mock_hab = MagicMock()
    msgs = decking.Deck()

    poller = Poller(hab=mock_hab, witness="wit", topics=["/receipt"], msgs=msgs)
    assert poller.msgs is msgs

    poller = Poller(hab=mock_hab, witness="wit", topics=["/receipt"])
    assert isinstance(poller.msgs, decking.Deck)


if __name__ == "__main__":
    test_mailbox_iter()
    test_qrymailbox_iter()
    test_wit_query_ends()
