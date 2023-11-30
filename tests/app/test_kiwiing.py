# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""

import json
import os

import falcon
from falcon import testing
from hio.base import doing

import keri.app.oobiing
from keri import kering
from keri.app import (habbing, kiwiing, grouping, booting, notifying,
                      signing, connecting)
from keri.core import eventing, parsing, coring, scheming, serdering
from keri.core.eventing import SealEvent
from keri.db import basing, dbing
from keri.vc import proving
from keri.vdr import credentialing, verifying


def test_credential_handlers(mockHelpingNowUTC, seeder):
    with habbing.openHab(name="test", transferable=True) as (hby, hab), \
            habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
        seeder.seedSchema(hby.db)
        seeder.seedSchema(recpHby.db)

        app = falcon.App()

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(name=hab.name, prefix=hab.pre)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        icp = recp.makeOwnEvent(sn=0)
        kvy = eventing.Kevery(db=hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=kvy)

        notifier = notifying.Notifier(hby=hby)
        counselor = grouping.Counselor(hby=hby)
        registrar = credentialing.Registrar(hby=hby, rgy=regery, counselor=counselor)
        credentialer = credentialing.Credentialer(hby=hby, rgy=regery, registrar=registrar, verifier=verifier)

        _ = kiwiing.loadEnds(hby=hby,
                             rgy=regery,
                             verifier=verifier,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             counselor=counselor,
                             registrar=registrar,
                             credentialer=credentialer,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             app=app, path="/")

        client = testing.TestClient(app)

        result = client.simulate_post(path="/registries", body=b'{}')
        assert result.status == falcon.HTTP_400  # Bad request, missing name

        result = client.simulate_post(path="/registries", body=b'{"name": "test"}')
        assert result.status == falcon.HTTP_400  # Bad Request, missing alias

        result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test123"}')
        assert result.status == falcon.HTTP_404  # Bad Request, invalid alias

        # Test all the parameters
        result = client.simulate_post(path="/registries",
                                      body=b'{"name": "test-full", "alias": "test",'
                                           b' "noBackers": true, "baks": [], "toad": 0, "estOnly": false}')
        assert result.status == falcon.HTTP_202
        regery.processEscrows()

        result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test"}')
        assert result.status == falcon.HTTP_202
        regery.processEscrows()

        result = client.simulate_get(path="/registries")
        assert result.status == falcon.HTTP_200
        assert len(result.json) == 3

        schema = "ENTAoj2oNBFpaniRswwPcca9W1ElEeH2V7ahw68HV4G5"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry="test",
            schema=schema,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data, source={}, rules={}
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credentials/test", body=b)
        assert result.status == falcon.HTTP_200
        creder = serdering.SerderACDC(sad=result.json) # proving.Creder(ked=result.json)
        regery.processEscrows()
        credentialer.processEscrows()
        verifier.processEscrows()

        assert regery.reger.creds.get(creder.saidb).raw == creder.raw

        # Try to revoke a credential that doesn't exist and get the appropriate error
        result = client.simulate_delete(path="/credentials/test",
                                        query_string=("registry=test&"
                                                      "said=ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs"))
        assert result.status == falcon.HTTP_NOT_FOUND

        # Now revoke the actual credential
        result = client.simulate_delete(path="/credentials/test",
                                        query_string=("registry=test&"
                                                      f"said={creder.said}"))
        assert result.status == falcon.HTTP_202
        regery.processEscrows()
        credentialer.processEscrows()

        result = client.simulate_get(path="/credentials/test123", params=dict(type="issued", registry="test"))
        assert result.status == falcon.HTTP_400  # Bad Request, invalid alias

        result = client.simulate_get(path="/credentials/test", params=dict(type="issued", registry="test"))
        assert result.status == falcon.HTTP_200
        assert len(result.json) == 1
        sad = result.json[0]["sad"]
        assert sad["d"] == creder.said
        state = result.json[0]["status"]
        assert state["et"] == coring.Ilks.rev


def test_identifier_ends():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        assert hab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'

        app = falcon.App()

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        notifier = notifying.Notifier(hby=hby)
        counselor = grouping.Counselor(hby=hby)
        registrar = credentialing.Registrar(hby=hby, rgy=regery, counselor=counselor)
        credentialer = credentialing.Credentialer(hby=hby, rgy=regery, registrar=registrar, verifier=verifier)

        doers = kiwiing.loadEnds(hby=hby,
                                 rgy=regery,
                                 verifier=verifier,
                                 notifier=notifier,
                                 signaler=notifier.signaler,
                                 app=app, path="/",
                                 registrar=registrar,
                                 credentialer=credentialer,
                                 servery=booting.Servery(port=1234),
                                 bootConfig=dict(),
                                 counselor=counselor)
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        client = testing.TestClient(app)

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [{'DnD': False,
                                'estOnly': False,
                                'isith': '1',
                                'metadata': {},
                                'name': 'test',
                                'next_keys': ['EJhRr10e5p7LVB6JwLDIcgqsISktnfe5m60O_I2zZO6N'],
                                'nsith': '1',
                                'prefix': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                                'public_keys': ['DGmIfLmgErg4zFHfPwaDckLNxsLqc5iS_P0QbLjbWR0I'],
                                'receipts': 0,
                                'seq_no': 0,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(isith='1', count=1)
        result = client.simulate_put(path="/ids/test/rot", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'v': 'KERI10JSON000160_',
                               't': 'rot',
                               'd': 'EGnFNzw2UJKpQZYJj_xhcFYWE7prFWFBbghgcMuJ4VeM',
                               'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               's': '1',
                               'p': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               'kt': '1',
                               'k': ['DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP'],
                               'nt': '1',
                               'n': ['EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax'],
                               'bt': '0',
                               'br': [],
                               'ba': [],
                               'a': []}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [{'DnD': False,
                                'estOnly': False,
                                'isith': '1',
                                'metadata': {},
                                'name': 'test',
                                'next_keys': ['EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax'],
                                'nsith': '1',
                                'prefix': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                                'public_keys': ['DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP'],
                                'receipts': 0,
                                'seq_no': 1,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'v': 'KERI10JSON00012b_',
                               't': 'icp',
                               'd': 'EFreoTWR_zDOyPd3QeNvwDHYrgFYnurZST68-cMCoBMT',
                               'i': 'EFreoTWR_zDOyPd3QeNvwDHYrgFYnurZST68-cMCoBMT',
                               's': '0',
                               'kt': '1',
                               'k': ['DOUxFFi_t9quipRvAzIsoC_uoQXhpTIe62Y0fJffpEj1'],
                               'nt': '1',
                               'n': ['ENpmBFOoWlPjRBFtN4aq7tZ0cdKWSOPJLoa-w3-90JEk'],
                               'bt': '0',
                               'b': [],
                               'c': [],
                               'a': []}

        # Try to reuse the alias
        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_400

        # Create a delegated identifier
        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False,
                   delpre="ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc")
        result = client.simulate_post(path="/ids/test3", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'v': 'KERI10JSON00015f_',
                               't': 'dip',
                               'd': 'EOhHlK7KtTcSH16YPwTq34Y4FaV7fyHmbybdc8aMgA98',
                               'i': 'EOhHlK7KtTcSH16YPwTq34Y4FaV7fyHmbybdc8aMgA98',
                               's': '0',
                               'kt': '1',
                               'k': ['DMIk0jr4_B7cnWUNuB7lWLlMQvNJM6uPQ2pxEq1N4OMI'],
                               'nt': '1',
                               'n': ['EDtSbRLbBc-NEn-sCqTNBCUJXZq6HT6zQPTtmL0DkENV'],
                               'bt': '0',
                               'b': [],
                               'c': [],
                               'a': [],
                               'di': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc'}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200
        assert len(result.json) == 3
        assert result.json[2] == {'DnD': False,
                                  'anchored': False,
                                  'delegated': True,
                                  'delegator': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                  'estOnly': False,
                                  'isith': '1',
                                  'metadata': {},
                                  'name': 'test3',
                                  'next_keys': ['EDtSbRLbBc-NEn-sCqTNBCUJXZq6HT6zQPTtmL0DkENV'],
                                  'nsith': '1',
                                  'prefix': 'EOhHlK7KtTcSH16YPwTq34Y4FaV7fyHmbybdc8aMgA98',
                                  'public_keys': ['DMIk0jr4_B7cnWUNuB7lWLlMQvNJM6uPQ2pxEq1N4OMI'],
                                  'receipts': 0,
                                  'seq_no': 0,
                                  'toad': 0,
                                  'witnesses': []}

        req = dict(data=[{"i": 1, "s": 0, "d": 2}])
        result = client.simulate_put(path="/ids/test/ixn", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'v': 'KERI10JSON0000de_',
                               't': 'ixn',
                               'd': 'EK6W1L2q1iHn9HcyfmMvXRbMQHK_ZNnT9HGiR09OZkbP',
                               'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               's': '2',
                               'p': 'EGnFNzw2UJKpQZYJj_xhcFYWE7prFWFBbghgcMuJ4VeM',
                               'a': [{'i': 1, 's': 0, 'd': 2}]}

        req = dict(id="ignored", name="Wile", company="ACME", email="wile-coyote@acme.com")
        result = client.simulate_put("/ids/bad/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_404  # Unknown alias
        result = client.simulate_post("/ids/bad/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_404  # Unknown alias

        # Update contact data for identifier
        result = client.simulate_put("/ids/test/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res = dict(req)
        res["id"] = 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
        assert result.json == res

        # Test single GET with metadata
        result = client.simulate_get("/ids/test")
        assert result.status == falcon.HTTP_200
        assert result.json == {'DnD': False,
                               'estOnly': False,
                               'isith': '1',
                               'metadata': {'company': 'ACME',
                                            'email': 'wile-coyote@acme.com',
                                            'name': 'Wile'},
                               'name': 'test',
                               'next_keys': ['EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax'],
                               'nsith': '1',
                               'prefix': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               'public_keys': ['DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP'],
                               'receipts': 0,
                               'seq_no': 2,
                               'toad': 0,
                               'witnesses': []}

        # Test list GET method with metadata
        result = client.simulate_get("/ids")
        assert result.status == falcon.HTTP_200
        assert result.json[0] == {'DnD': False,
                                  'estOnly': False,
                                  'isith': '1',
                                  'metadata': {'company': 'ACME',
                                               'email': 'wile-coyote@acme.com',
                                               'name': 'Wile'},
                                  'name': 'test',
                                  'next_keys': ['EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax'],
                                  'nsith': '1',
                                  'prefix': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                                  'public_keys': ['DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP'],
                                  'receipts': 0,
                                  'seq_no': 2,
                                  'toad': 0,
                                  'witnesses': []}

        # Change the alias for the identifier
        req = dict(alias="another_test")
        result = client.simulate_put("/ids/test/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res["id"] = "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        result = client.simulate_get("/ids")
        assert result.status == falcon.HTTP_200
        assert result.json[0] == {'DnD': False,
                                  'estOnly': False,
                                  'isith': '1',
                                  'metadata': {'company': 'ACME',
                                               'email': 'wile-coyote@acme.com',
                                               'name': 'Wile'},
                                  'name': 'another_test',
                                  'next_keys': ['EOh7LXjpAqsP6YNGOMVFjn02yCpXfGVsHbSYIQ5Ul7Ax'],
                                  'nsith': '1',
                                  'prefix': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                                  'public_keys': ['DGgN_X4ZJvgAMQpD3CqI5bidKkgkCLc_yk-Pk1culnXP'],
                                  'receipts': 0,
                                  'seq_no': 2,
                                  'toad': 0,
                                  'witnesses': []}

        # Verify the old ID is no longer valid and the new one now works
        result = client.simulate_get("/ids/test")
        assert result.status == falcon.HTTP_404
        result = client.simulate_get("/ids/another_test")
        assert result.status == falcon.HTTP_200

        # Replace all metadata with a post
        req = dict(id="ignored", name="Alfred Lanning", company="USR Corp")
        result = client.simulate_post("/ids/another_test/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res = dict(req)
        res["id"] = "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"
        assert result.json == res

        # Alias can be changed with POST too
        req = dict(alias="final_test")
        result = client.simulate_post("/ids/another_test/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res["id"] = "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        # Bad post doesn't work either
        result = client.simulate_post("/ids/test/metadata", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_404

        # Verify the old ID is no longer valid and the new one now works
        result = client.simulate_get("/ids/another_test")
        assert result.status == falcon.HTTP_404
        result = client.simulate_get("/ids/final_test")
        assert result.status == falcon.HTTP_200


def test_oobi_ends(seeder):
    with habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        wesHab = wesHby.makeHab(name="wes", transferable=False)

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[wesHab.pre])

        assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

        notifier = notifying.Notifier(hby=palHby)
        oobiery = keri.app.oobiing.Oobiery(hby=palHby)
        app = falcon.App()
        regery = credentialing.Regery(hby=palHby, name=palHab.name, temp=True)
        _ = kiwiing.loadEnds(hby=palHby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             counselor=None,
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict())
        client = testing.TestClient(app)

        result = client.simulate_get(path="/oobi/test?role=witness")
        assert result.status == falcon.HTTP_400  # Bad alias, does not exist

        result = client.simulate_get(path="/oobi/pal?role=watcher")
        assert result.status == falcon.HTTP_404  # Bad role, watcher not supported yet

        result = client.simulate_get(path="/oobi/pal?role=witness")
        assert result.status == falcon.HTTP_404  # Missing OOBI endpoints for witness

        result = client.simulate_get(path="/oobi/pal?role=controller")
        assert result.status == falcon.HTTP_404  # Missing OOBI controller endpoints

        # Add controller endpoints
        url = "http://127.0.0.1:9999/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/controller"
        palHab.db.locs.put(keys=(palHab.pre, kering.Schemes.http), val=basing.LocationRecord(url=url))
        result = client.simulate_get(path="/oobi/pal?role=controller")
        assert result.status == falcon.HTTP_200  # Missing OOBI controller endpoints
        assert result.json == {
            'oobis': ['http://127.0.0.1:9999/oobi/EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y/controller'],
            'role': 'controller'}

        # Seed with witness endpoints
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http, kering.Schemes.tcp])

        result = client.simulate_get(path="/oobi/pal?role=witness")
        assert result.status == falcon.HTTP_200
        assert result.json == {'oobis': [
            'http://127.0.0.1:5644/oobi/EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y/witness'
            '/BN8t3n1lxcV0SWGJIIF46fpSUqA7Mqre5KJNN3nbx3mr'],
            'role': 'witness'}

        # Post without a URL or RPY
        data = dict()
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_400

        # Post an RPY
        data = dict(rpy={})
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_501

        data = dict(url="http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/")
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_202
        assert oobiery.hby.db.oobis.cntAll() == 1
        (url,), item = next(oobiery.hby.db.oobis.getItemIter())
        assert item is not None
        assert url == 'http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'
        oobiery.hby.db.oobis.rem(keys=(url,))

        # Post an RPY
        data = dict(oobialias="sal", rpy={})
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_501

        # POST without an oobialias
        data = dict(url="http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/")
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_202
        assert oobiery.hby.db.oobis.cntAll() == 1
        (url,), item = next(oobiery.hby.db.oobis.getItemIter())
        assert item is not None
        assert url == 'http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'
        assert item.oobialias is None
        oobiery.hby.db.oobis.rem(keys=(url,))

        data = dict(oobialias="sal", url="http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A"
                                         "/witness/")
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi", body=b)
        assert result.status == falcon.HTTP_202
        assert oobiery.hby.db.oobis.cntAll() == 1
        (url,), item = next(oobiery.hby.db.oobis.getItemIter())
        assert item is not None
        assert url == 'http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'
        assert item.oobialias == 'sal'


def test_challenge_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])

        assert palHab.pre == "EDtH1M06Na4Yf2_AoF-R8aY2izx3aVWsmmRNoLrWA-Gh"

        app = falcon.App()
        notifier = notifying.Notifier(hby=palHby)
        regery = credentialing.Regery(hby=palHby, name=palHab.name, temp=True)
        _ = kiwiing.loadEnds(hby=palHby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        result = client.simulate_get(path="/challenge?strength=256")
        assert result.status == falcon.HTTP_200
        assert "words" in result.json
        words = result.json["words"]
        assert len(words) == 24

        result = client.simulate_get(path="/challenge")
        assert result.status == falcon.HTTP_200
        assert "words" in result.json
        words = result.json["words"]
        assert len(words) == 12

        data = dict(
        )
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/joe", body=b)
        assert result.status == falcon.HTTP_400  # Bad allias
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_400  # Missing words

        data["words"] = words
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_400  # Missing recipient

        data["recipient"] = "Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU"
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_202

        # assert len(.reps) == 1
        # rep = repd.reps.popleft()
        # assert rep["topic"] == "challenge"
        # assert rep["dest"] == "Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU"
        # assert rep["rep"].ked['r'] == '/challenge/response'


def test_contact_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="ken", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as kenHby:

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])
        kvy = eventing.Kevery(db=palHab.db, local=False, lax=True)
        assert palHab.pre == "EDtH1M06Na4Yf2_AoF-R8aY2izx3aVWsmmRNoLrWA-Gh"

        msgs = bytearray()
        aids = []
        for i in range(5):
            hab = kenHby.makeHab(name=f"ken{i}", icount=1, ncount=1, wits=[])
            aids.append(hab.pre)
            msgs.extend(hab.makeOwnInception())

        hab = kenHby.makeHab(name="bad", icount=1, ncount=1, wits=[])
        msgs.extend(hab.makeOwnInception())
        parsing.Parser().parse(ims=msgs, kvy=kvy)

        for aid in aids:
            assert aid in palHab.kevers

        regery = credentialing.Regery(hby=kenHby, name=hab.name, temp=True)
        notifier = notifying.Notifier(hby=palHby)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=palHby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        response = client.simulate_get("/contacts")
        assert response.status == falcon.HTTP_200
        assert response.json == []

        data = dict(
            name="test"
        )
        b = json.dumps(data).encode("utf-8")
        # POST to an identifier that is not in the Kever
        response = client.simulate_post(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/{palHab.name}", body=b)
        assert response.status == falcon.HTTP_404

        # POST to a local identifier
        response = client.simulate_post(f"/contacts/{palHab.pre}", body=b)
        assert response.status == falcon.HTTP_400

        for i in range(5):
            data = dict(
                id=aid[i],
                first=f"Ken{i}",
                last=f"Burns{i}",
                company="GLEIF"
            )
            b = json.dumps(data).encode("utf-8")
            # POST to an identifier that is not in the Kever
            response = client.simulate_post(f"/contacts/{aids[i]}", body=b)
            assert response.status == falcon.HTTP_200

        response = client.simulate_get(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{hab.pre}")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[3]}")
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'GLEIF',
                                 'first': 'Ken3',
                                 'id': 'EAjKmvW6flpWJfdYYZ2Lu4pllPWKFjCBz0dcX-S86Nvg',
                                 'last': 'Burns3'}

        response = client.simulate_get(f"/contacts")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 5
        data = {d["id"]: d for d in response.json}
        for aid in aids:
            assert aid in data

        data = dict(id=hab.pre, company="ProSapien")
        b = json.dumps(data).encode("utf-8")

        response = client.simulate_put(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo", body=b)
        assert response.status == falcon.HTTP_404

        response = client.simulate_put(f"/contacts/{palHab.pre}", body=b)
        assert response.status == falcon.HTTP_400

        response = client.simulate_put(f"/contacts/{aids[2]}", body=b)
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'ProSapien',
                                 'first': 'Ken2',
                                 'id': 'ELTQ3tF3n7QS8LDpKMdJyCMhVyMdvNPTiisnqW5ZQP3C',
                                 'last': 'Burns2'}
        response = client.simulate_put(f"/contacts/{aids[4]}", body=b)
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'ProSapien',
                                 'first': 'Ken4',
                                 'id': 'EGwcSt3uvK5-oHI7hVU7dKMvWt0vRfMW2demzBBMDnBG',
                                 'last': 'Burns4'}

        response = client.simulate_get("/contacts", query_string="group=company")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 2

        gleif = response.json["GLEIF"]
        data = {d["id"]: d for d in gleif}
        assert aids[0] in data
        assert aids[1] in data
        assert aids[3] in data

        pros = response.json["ProSapien"]
        data = {d["id"]: d for d in pros}
        assert aids[2] in data
        assert aids[4] in data

        # Begins with search on company name
        response = client.simulate_get("/contacts", query_string="group=company&filter_value=Pro")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1

        pros = response.json["ProSapien"]
        data = {d["id"]: d for d in pros}
        assert aids[2] in data
        assert aids[4] in data

        response = client.simulate_get("/contacts", query_string="filter_field=last")
        assert response.status == falcon.HTTP_400

        response = client.simulate_get("/contacts", query_string="filter_field=last&filter_value=Burns3")
        assert response.status == falcon.HTTP_200
        assert response.json == [{'challenges': [],
                                  'company': 'GLEIF',
                                  'first': 'Ken3',
                                  'id': 'EAjKmvW6flpWJfdYYZ2Lu4pllPWKFjCBz0dcX-S86Nvg',
                                  'last': 'Burns3',
                                  'wellKnowns': []}]

        # Begins with search on last name
        response = client.simulate_get("/contacts",
                                       query_string="filter_field=last&filter_value=Burns")
        assert response.status == falcon.HTTP_200
        assert response.json == [{'challenges': [],
                                  'company': 'GLEIF',
                                  'first': 'Ken3',
                                  'id': 'EAjKmvW6flpWJfdYYZ2Lu4pllPWKFjCBz0dcX-S86Nvg',
                                  'last': 'Burns3',
                                  'wellKnowns': []},
                                 {'challenges': [],
                                  'company': 'GLEIF',
                                  'first': 'Ken1',
                                  'id': 'EER-n23rDM2RQB8Kw4KRrm8SFpoid4Jnelhauo6KxQpz',
                                  'last': 'Burns1',
                                  'wellKnowns': []},
                                 {'challenges': [],
                                  'company': 'ProSapien',
                                  'first': 'Ken4',
                                  'id': 'EGwcSt3uvK5-oHI7hVU7dKMvWt0vRfMW2demzBBMDnBG',
                                  'last': 'Burns4',
                                  'wellKnowns': []},
                                 {'challenges': [],
                                  'company': 'ProSapien',
                                  'first': 'Ken2',
                                  'id': 'ELTQ3tF3n7QS8LDpKMdJyCMhVyMdvNPTiisnqW5ZQP3C',
                                  'last': 'Burns2',
                                  'wellKnowns': []},
                                 {'challenges': [],
                                  'company': 'GLEIF',
                                  'first': 'Ken0',
                                  'id': 'EPo8Wy1xpTa6ri25M4IlmWBBzs5y8v4Qn3Z8xP4kEjcK',
                                  'last': 'Burns0',
                                  'wellKnowns': []}]

        response = client.simulate_delete(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert response.status == falcon.HTTP_404

        response = client.simulate_delete(f"/contacts/{aids[3]}")
        assert response.status == falcon.HTTP_202

        response = client.simulate_get("/contacts", query_string="filter_field=last&filter_value=Burns3")
        assert response.status == falcon.HTTP_200
        assert response.json == []

        data = bytearray(os.urandom(50))
        headers = {"Content-Type": "image/png", "Content-Length": "50"}
        response = client.simulate_post(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/img", body=data,
                                        headers=headers)
        assert response.status == falcon.HTTP_404

        data = bytearray(os.urandom(1000001))
        headers = {"Content-Type": "image/png", "Content-Length": "1000001"}
        response = client.simulate_post(f"/contacts/{aids[0]}/img", body=data, headers=headers)
        assert response.status == falcon.HTTP_400

        data = bytearray(os.urandom(10000))
        headers = {"Content-Type": "image/png", "Content-Length": "10000"}
        response = client.simulate_post(f"/contacts/{aids[0]}/img", body=data, headers=headers)
        assert response.status == falcon.HTTP_202

        response = client.simulate_get(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/img")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[2]}/img")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[0]}/img")
        assert response.status == falcon.HTTP_200
        assert response.content == data
        headers = response.headers
        assert headers["Content-Type"] == "image/png"
        assert headers["Content-Length"] == "10000"


def test_keystate_end():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        assert hab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'

        app = falcon.App()

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        notifier = notifying.Notifier(hby=hby)
        counselor = grouping.Counselor(hby=hby)

        _ = kiwiing.loadEnds(hby=hby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             app=app, path="/",
                             counselor=counselor)
        client = testing.TestClient(app)

        result = client.simulate_get(path="/keystate/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert result.status == falcon.HTTP_404

        result = client.simulate_get(path=f"/keystate/{hab.pre}")
        assert result.status == falcon.HTTP_200
        state = result.json["state"]
        assert state["i"] == hab.pre
        assert state["et"] == "icp"
        assert state["k"] == ['DGmIfLmgErg4zFHfPwaDckLNxsLqc5iS_P0QbLjbWR0I']
        assert state["n"] == ['EJhRr10e5p7LVB6JwLDIcgqsISktnfe5m60O_I2zZO6N']

        kel = result.json["kel"]
        assert len(kel) == 1

        # Ask for event with a bad public key
        result = client.simulate_get(path=f"/keystate/pubkey/{state['n'][0]}")
        assert result.status == falcon.HTTP_404

        # Ask for event with a known public key
        result = client.simulate_get(path=f"/keystate/pubkey/{state['k'][0]}")
        assert result.status == falcon.HTTP_200
        assert result.json == {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                               'k': ['DGmIfLmgErg4zFHfPwaDckLNxsLqc5iS_P0QbLjbWR0I'],
                               'kt': '1',
                               'n': ['EJhRr10e5p7LVB6JwLDIcgqsISktnfe5m60O_I2zZO6N'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON00012b_'}


def test_schema_ends():
    with habbing.openHby(name="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as hby:
        app = falcon.App()
        notifier = notifying.Notifier(hby=hby)
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        _ = kiwiing.loadEnds(hby=hby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(type="object", properties=dict(a=dict(type="string"))))
        sce = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        hby.db.schema.pin(sce.said, sce)

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(type="object", properties=dict(b=dict(type="number"), )))
        sce = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        hby.db.schema.pin(sce.said, sce)

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(type="object", properties=dict(c=dict(type="string", format="date-time"))))
        sce = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        hby.db.schema.pin(sce.said, sce)

        response = client.simulate_get("/schema")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 3
        assert response.json[0]["$id"] == 'EHoMjhY-5V5jdSXr0yHEYWxSH8MeFfNEqnmhXbClTepe'
        schema0id = 'EHoMjhY-5V5jdSXr0yHEYWxSH8MeFfNEqnmhXbClTepe'
        assert response.json[1]["$id"] == 'ELrCCNUmu7t9OS5XX6MYwuyLHY13IWuJoFVPfBkjkGAd'
        assert response.json[2]["$id"] == 'ENW0ZoANRhLAHczo7BwgzBlkDMZWFU2QilCCIbg98PK6'

        assert response.json[2]["properties"] == {'b': {'type': 'number'}}
        assert response.json[0]["properties"] == {'c': {'format': 'date-time', 'type': 'string'}}
        assert response.json[1]["properties"] == {'a': {'type': 'string'}}

        badschemaid = 'EH1MjhY-5V5jdSXr0yHEYWxSH8MeFfNEqnmhXbClTepe'
        response = client.simulate_get(f"/schema/{badschemaid}")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/schema/{schema0id}")
        assert response.status == falcon.HTTP_200
        assert response.json["$id"] == schema0id
        assert response.json["properties"] == {'c': {'format': 'date-time', 'type': 'string'}}


def test_escrow_end(mockHelpingNowUTC):
    with habbing.openHby(name="bob", temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name="bob", temp=True)

        notifier = notifying.Notifier(hby=hby)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=hby,
                             rgy=rgy,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        response = client.simulate_get("/escrows")
        assert response.status == falcon.HTTP_200
        assert response.json == {'likely-duplicitous-events': [],
                                 'out-of-order-events': [],
                                 'partially-signed-events': [],
                                 'partially-witnessed-events': []}

        response = client.simulate_get("/escrows?escrow=partially-signed-events")
        assert response.status == falcon.HTTP_200
        assert response.json == {'partially-signed-events': []}

        response = client.simulate_get("/escrows?escrow=unknown-escrow")
        assert response.status == falcon.HTTP_200
        assert response.json == {}

        response = client.simulate_get(
            "/escrows?escrow=partially-witnessed-events&pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert response.json == {'partially-witnessed-events': []}

        bob = hby.makeHab(name="bob")
        icp = bob.kever.serder
        sigs = []

        key = dbing.dgKey(bob.pre, icp.said)  # digest key
        for sig in hby.db.getSigsIter(key):
            sigs.append(coring.Siger(qb64b=bytes(sig)))
        bob.kever.escrowPSEvent(serder=icp, sigers=sigs)
        # regenerated down below
        escrowedEvt = {'ked': {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH',
                               'i': 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH',
                               'k': ['DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU'],
                               'kt': '1',
                               'n': ['EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON00012b_'},
                       'receipts': {},
                       'signatures': [{'index': 0,
                                       'signature':
                                           'AAArkDBeflIAo4kBsKnc754XHJvdLnf04iq-noTFEJkbv2MeI'
                                           'GZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0-nlhHEE'}],
                       'stored': True,
                       'timestamp': '2021-01-01T00:00:00.000000+00:00',
                       'witness_signatures': [],
                       'witnesses': []}

        response = client.simulate_get("/escrows?pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert response.json == {'likely-duplicitous-events': [],
                                 'out-of-order-events': [],
                                 'partially-signed-events': [],
                                 'partially-witnessed-events': []}

        response = client.simulate_get("/escrows")
        assert response.status == falcon.HTTP_200
        data = dict(response.json)
        assert "partially-signed-events" in data
        evt = data["partially-signed-events"]
        del data["partially-signed-events"]
        assert data == {'likely-duplicitous-events': [],
                        'out-of-order-events': [],
                        'partially-witnessed-events': []}
        assert evt == [escrowedEvt]

        response = client.simulate_get(f"/escrows?escrow=partially-signed-events&pre={bob.pre}")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['partially-signed-events']) == 1

        response = client.simulate_get(f"/escrows?escrow=partially-signed-events"
                                       f"&pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['partially-signed-events']) == 0

        snkey = dbing.snKey(bob.pre, bob.kever.sn)
        hby.db.delPses(snkey)
        bob.kever.escrowPWEvent(serder=icp, sigers=sigs, wigers=None)

        response = client.simulate_get("/escrows?escrow=partially-witnessed-events")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        evt = response.json['partially-witnessed-events']
        assert evt == [escrowedEvt]

        response = client.simulate_get(f"/escrows?escrow=partially-witnessed-events&pre={bob.pre}")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['partially-witnessed-events']) == 1

        response = client.simulate_get(f"/escrows?escrow=partially-witnessed-events"
                                       f"&pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['partially-witnessed-events']) == 0

        hby.db.delPwes(snkey)

        kvy = eventing.Kevery(db=bob.db)
        kvy.escrowOOEvent(serder=icp, sigers=sigs)
        response = client.simulate_get("/escrows?escrow=out-of-order-events")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        evt = response.json['out-of-order-events']
        assert evt == [escrowedEvt]

        response = client.simulate_get(f"/escrows?escrow=out-of-order-events&pre={bob.pre}")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['out-of-order-events']) == 1

        response = client.simulate_get(f"/escrows?escrow=out-of-order-events"
                                       f"&pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['out-of-order-events']) == 0

        hby.db.delPde(key)

        kvy.escrowLDEvent(serder=icp, sigers=sigs)
        response = client.simulate_get("/escrows?escrow=likely-duplicitous-events")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        evt = response.json['likely-duplicitous-events']
        assert evt == [escrowedEvt]

        response = client.simulate_get(f"/escrows?escrow=likely-duplicitous-events&pre={bob.pre}")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['likely-duplicitous-events']) == 1

        response = client.simulate_get(f"/escrows?escrow=likely-duplicitous-events"
                                       f"&pre=ECgrcJTdVr1TNnmmDrT8Pol9w_0BhsTxlQkWtjyrT060")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 1
        assert len(response.json['likely-duplicitous-events']) == 0


def test_presentation_ends(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="ken", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as kenHby:
        seeder.seedSchema(palHby.db)
        seeder.seedSchema(kenHby.db)
        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])
        kvy = eventing.Kevery(db=palHab.db, local=False, lax=True)
        assert palHab.pre == "EDtH1M06Na4Yf2_AoF-R8aY2izx3aVWsmmRNoLrWA-Gh"

        msgs = bytearray()
        aids = []
        hab = kenHby.makeHab(name=f"ken", icount=1, ncount=1, wits=[])
        aids.append(hab.pre)
        msgs.extend(hab.makeOwnInception())
        parsing.Parser().parse(ims=msgs, kvy=kvy)

        for aid in aids:
            assert aid in palHab.kevers

        org = connecting.Organizer(hby=palHby)
        org.set(hab.pre, field="alias", val="ken")

        palReg = credentialing.Regery(hby=palHby, name="han", temp=True)
        notifier = notifying.Notifier(hby=palHby)
        app = falcon.App()
        ends = kiwiing.loadEnds(hby=palHby,
                                rgy=palReg,
                                verifier=None,
                                notifier=notifier,
                                signaler=notifier.signaler,
                                app=app, path="/",
                                registrar=None,
                                credentialer=None,
                                servery=booting.Servery(port=1234),
                                bootConfig=dict(),
                                counselor=None)
        presentEnd = None
        for end in ends:
            if isinstance(end, kiwiing.PresentationEnd):
                presentEnd = end
        assert presentEnd is not None

        client = testing.TestClient(app)

        # Create a credential that we will present
        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
        credSubject = dict(
            LEI="254900OPPU84GM83MG36",
        )

        issuer = palReg.makeRegistry(prefix=palHab.pre, name="han")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        palHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=palHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=palHab.kever.serder.said))
        palReg.processEscrows()

        verifier = verifying.Verifier(hby=palHby, reger=palReg.reger)

        creder = proving.credential(issuer=palHab.pre,
                                    schema=schema,
                                    recipient=palHab.pre,
                                    data=credSubject,
                                    status=issuer.regk,
                                    )
        assert creder.said == "ENF8t9hfbZtM86yxqQLuipzJTTWmUl4tm2jSTDu9-egd"

        msg = signing.ratify(palHab, serder=creder)

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        palHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=palHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=palHab.kever.serder.said))
        palReg.processEscrows()

        parsing.Parser().parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert palReg.reger.creds.get(key) is not None

        # Valid request asking for just the exn
        body = dict(
            said=creder.said,
            recipient=hab.pre,
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_202
        assert len(presentEnd.postman.evts) == 1
        presentEnd.postman.evts.popleft()

        # Valid request using alias for recipient
        body = dict(
            said=creder.said,
            recipient="ken",
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_202
        assert len(presentEnd.postman.evts) == 1
        presentEnd.postman.evts.popleft()

        # now ask to include the credential and associated data
        body = dict(
            said=creder.said,
            recipient=hab.pre,
            include=True
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_202
        assert len(presentEnd.postman.evts) == 10

        # Bad alias
        body = dict(
            said=creder.said,
            recipient=hab.pre,
            include=True
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/jim/presentations", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "Invalid alias jim for credential presentation"

        # No SAID in body
        body = dict(
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "said is required, none provided"

        # No recipient in body
        body = dict(
            said=creder.said,
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "recipient is required, none provided"

        # SAID for a non-existant credential
        body = dict(
            said="ABC",
            recipient=hab.pre,
            include=True
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/presentations", body=raw)
        assert response.status == falcon.HTTP_404
        assert response.text == "credential ABC not found"

        presentEnd.postman.evts.clear()

        # Valid request using alias for recipient
        body = dict(
            schema=creder.said,
            recipient="ken",
            issuer=palHab.pre,
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/requests", body=raw)
        assert response.status == falcon.HTTP_202
        assert len(presentEnd.postman.evts) == 1
        presentEnd.postman.evts.popleft()

        # Valid request using alias for recipient
        body = dict(
            schema=creder.said,
            recipient="ken",
            issuer=palHab.pre,
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/jim/requests", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "Invalid alias jim for credential request"

        # Valid request using alias for recipient
        body = dict(
            schema=creder.said,
            issuer=palHab.pre,
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/requests", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "recp is required, none provided"

        # Valid request using alias for recipient
        body = dict(
            issuer=palHab.pre,
            recipient="ken",
        )
        raw = json.dumps(body).encode("utf-8")
        response = client.simulate_post("/credentials/pal/requests", body=raw)
        assert response.status == falcon.HTTP_400
        assert response.text == "schema is required, none provided"


def test_aied_ends():
    bran = "1B88Kq7afAZHlxsNIBE5y"
    with habbing.openHby(name="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64, bran=bran) as hby:
        app = falcon.App()
        notifier = notifying.Notifier(hby=hby)
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        _ = kiwiing.loadEnds(hby=hby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        response = client.simulate_get("/codes")
        assert response.status == falcon.HTTP_200
        assert "passcode" in response.json
        aeid = response.json["passcode"]
        assert len(aeid) == booting.DEFAULT_PASSCODE_SIZE

        #  Change passcode
        nbran = "pouh228IgK9RhloUnkydZ"
        body = dict(current=bran, passcode=nbran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_202

        # Try to use the old passcode again
        body = dict(current=bran, passcode=nbran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_401

        # Change back to the original passcode
        body = dict(current=nbran, passcode=bran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_202

        # Try to use an invalid passcode
        body = dict(current=bran, passcode="ABCDEF")
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_400


if __name__ == "__main__":
    test_aied_ends()
