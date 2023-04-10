# -*- encoding: utf-8 -*-
"""
tests.app.kiwiing module

"""
import json
import os

import falcon
from falcon import testing
from hio.base import doing

from keri import kering
from keri.app import habbing, kiwiing, grouping, indirecting, directing, booting, notifying
from keri.core import scheming, coring, eventing, parsing
from keri.db import basing
from keri.vc import proving
from keri.vdr import credentialing, verifying
from tests.app import test_grouping

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def loadApp(hby, rgy, verifier, notifier):
    app = falcon.App()

    counselor = grouping.Counselor(hby=hby)
    registrar = credentialing.Registrar(hby=hby, rgy=rgy, counselor=counselor)
    credentialer = credentialing.Credentialer(hby=hby, rgy=rgy, registrar=registrar, verifier=verifier)
    mbx = indirecting.MailboxDirector(hby=hby, topics=["/receipt", "/replay", "/credential", "/multisig"],
                                      verifier=verifier)
    servery = booting.Servery(port=1234)
    doers = kiwiing.loadEnds(hby=hby,
                             rgy=rgy,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             verifier=verifier,
                             app=app, path="/",
                             registrar=registrar,
                             credentialer=credentialer,
                             servery=servery,
                             bootConfig=dict(),
                             counselor=counselor)
    doers.extend([counselor, registrar, credentialer, mbx])
    return app, doers


def loadSchema(db):
    filepath = os.path.join(TEST_DIR, "schema.json")
    with open(filepath) as f:
        sed = json.load(f)
        _, sad = coring.Saider.saidify(sed, label=coring.Saids.dollar)

        schemer = scheming.Schemer(sed=sed)
        assert schemer.said == 'EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs'
        db.schema.pin(keys=(schemer.said,), val=schemer)


def createMbxEndRole(hab, cid, eid, url):
    keys = (cid, kering.Roles.mailbox, eid)

    ender = basing.EndpointRecord(allowed=True)  # create new record
    hab.db.ends.pin(keys=keys, val=ender)
    httplocer = basing.LocationRecord(url=url)  # create new record
    lockeys = (eid, kering.Schemes.http)
    hab.db.locs.pin(keys=lockeys, val=httplocer)  # overwrite


class TestDoer(doing.DoDoer):

    def __init__(self, wanHby, hby1, hab1, hby2, hab2, hby3, hab3, recp):
        self.hab1 = hab1
        self.hab2 = hab2
        self.hab3 = hab3
        self.recp = recp

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wanHab = wanHby.habByName("wan")
        # Verify the group identifier was incepted properly and matches the identifiers
        assert wanHab.pre == 'BOigXdxpp1r43JhO--czUTwrCXzoWrIwW8i41KWDlr8s'
        assert hab1.mhab.pre == 'EH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba'
        assert hab2.mhab.pre == 'EJPlLivjjHWkkSpvUTT7iewTlG_TolGIpUbAxsK8Dslu'
        assert hab3.mhab.pre == 'ECKuCwnnPA3z212QjiWewHv2jQwArMu7HPRBUSXOSqKv'
        gid = 'EERn_laF0qwP8zTBGL86LbF84J0Yh2IvQSRskH3BZZiy'
        assert hab1.pre == hab2.pre == hab3.pre == gid
        assert hab1.name == "test_group1"
        assert hab2.name == "test_group2"
        assert hab3.name == "test_group3"

        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        ricp = recp.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ricp), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(ricp), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(ricp), kvy=kev3)

        # Set up mailbox end role for each participant using wan
        for hab in [hab1, hab2, hab3]:
            createMbxEndRole(hab1, hab.mhab.pre, wanHab.pre, "http://127.0.0.1:5642/")
            createMbxEndRole(hab2, hab.mhab.pre, wanHab.pre, "http://127.0.0.1:5642/")
            createMbxEndRole(hab3, hab.mhab.pre, wanHab.pre, "http://127.0.0.1:5642/")

        createMbxEndRole(hab1, recp.pre, wanHab.pre, "http://127.0.0.1:5642/")
        createMbxEndRole(hab2, recp.pre, wanHab.pre, "http://127.0.0.1:5642/")
        createMbxEndRole(hab3, recp.pre, wanHab.pre, "http://127.0.0.1:5642/")

        # Create Regery for each participant
        self.rgy1 = credentialing.Regery(hby=hby1, name="test_1", temp=True)
        self.rgy2 = credentialing.Regery(hby=hby2, name="test_2", temp=True)
        self.rgy3 = credentialing.Regery(hby=hby3, name="test_3", temp=True)

        self.notifier1 = notifying.Notifier(hby=hby1)
        self.verifier1 = verifying.Verifier(hby=hby1, reger=self.rgy1.reger)
        self.notifier2 = notifying.Notifier(hby=hby2)
        self.verifier2 = verifying.Verifier(hby=hby2, reger=self.rgy2.reger)
        self.notifier3 = notifying.Notifier(hby=hby3)
        self.verifier3 = verifying.Verifier(hby=hby3, reger=self.rgy3.reger)

        # Load schema in database for each participant
        loadSchema(hby1.db)
        loadSchema(hby2.db)
        loadSchema(hby3.db)

        # Create falcon app loaded with kiwiing ends for each participant
        self.app1, doers1 = loadApp(hby1, self.rgy1, self.verifier1, self.notifier1)
        self.app2, doers2 = loadApp(hby2, self.rgy2, self.verifier2, self.notifier2)
        self.app3, doers3 = loadApp(hby3, self.rgy3, self.verifier3, self.notifier3)
        doers = wanDoers + doers1 + doers2 + doers3 + [doing.doify(self.escrowDo)]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(TestDoer, self).__init__(doers=doers)

    def escrowDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            # have each regery process escrows to get the now anchored TEL event committed
            self.rgy1.processEscrows()
            self.rgy2.processEscrows()
            self.rgy3.processEscrows()

            self.verifier1.processEscrows()
            self.verifier2.processEscrows()
            self.verifier3.processEscrows()

            yield tock

    def testDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        client1 = testing.TestClient(self.app1)
        client2 = testing.TestClient(self.app2)
        client3 = testing.TestClient(self.app3)

        # Post to /registries to create a Registry for the multisig identifier
        regd = dict(alias=self.hab1.name,
                    name="vLEI",
                    nonce="AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s",
                    baks=[],
                    estOnly=False,
                    noBackers=True,
                    toad=0)
        b = json.dumps(regd).encode("utf-8")
        response = client1.simulate_post("/registries", body=b)
        assert response.status == falcon.HTTP_202
        regd["alias"] = self.hab2.name
        b = json.dumps(regd).encode("utf-8")
        response = client2.simulate_post("/registries", body=b)
        assert response.status == falcon.HTTP_202
        regd["alias"] = self.hab3.name
        b = json.dumps(regd).encode("utf-8")
        response = client3.simulate_post("/registries", body=b)
        assert response.status == falcon.HTTP_202

        registry = self.rgy1.registryByName("vLEI")
        while registry.regk not in self.rgy1.tevers:
            yield tock

        registry = self.rgy2.registryByName("vLEI")
        while registry.regk not in self.rgy3.tevers:
            yield tock

        registry = self.rgy3.registryByName("vLEI")
        while registry.regk not in self.rgy3.tevers:
            yield tock

        issd = dict(credentialData=dict(LEI="5493001KJTIIGC8Y1R17"), recipient=self.recp.pre, registry="vLEI",
                    schema="EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs", source={})
        b = json.dumps(issd).encode("utf-8")
        response = client1.simulate_post(f"/groups/{self.hab1.name}/credentials", body=b)
        assert response.status == falcon.HTTP_200
        credential = response.json
        assert credential["a"]["LEI"] == "5493001KJTIIGC8Y1R17"

        issd = dict(credential=credential)
        b = json.dumps(issd).encode("utf-8")
        response = client2.simulate_put(f"/groups/{self.hab2.name}/credentials", body=b)
        assert response.status == falcon.HTTP_200
        response = client3.simulate_put(f"/groups/{self.hab3.name}/credentials", body=b)
        assert response.status == falcon.HTTP_200

        creder = proving.Creder(ked=credential)
        while not self.rgy1.reger.saved.get(creder.said):
            yield tock


        # Wait for the credential endpoint to notify the completion of the credential issuance

        while len(self.notifier1.getNotes()) < 1 or len(self.notifier2.getNotes()) < 1 \
                or len(self.notifier3.getNotes()) < 1:
            yield tock

        notes1 = self.notifier1.getNotes()
        assert notes1[0].pad['a']['r'] == "/multisig/iss/complete"
        notes2 = self.notifier2.getNotes()
        assert notes2[0].pad['a']['r'] == "/multisig/iss/complete"
        notes3 = self.notifier3.getNotes()
        assert notes3[0].pad['a']['r'] == "/multisig/iss/complete"

        self.remove(self.toRemove)

        return True


def test_multisig_issue_agent():
    salt = coring.Salter(raw=b'wann-the-witness').qb64
    with test_grouping.openMultiSig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
            habbing.openHby(name="wan", salt=salt, temp=True) as wanHby, \
            habbing.openHab(name="recp", transferable=True) as (_, recp):

        testDoer = TestDoer(wanHby, hby1, hab1, hby2, hab2, hby3, hab3, recp)

        # Run all participants
        directing.runController(doers=[testDoer], expire=60.0)

        assert testDoer.done is True
