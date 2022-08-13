# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json
import os

import falcon
from falcon import testing
from hio.base import doing

from keri import kering
from keri.app import habbing, storing, kiwiing, grouping, booting, notifying
from keri.app.kiwiing import MultisigEventEnd
from keri.core import eventing, parsing, coring, scheming
from keri.core.eventing import SealEvent
from keri.db import basing, dbing
from keri.end import ending
from keri.vc import proving
from keri.vdr import credentialing, verifying
from tests.app import test_grouping


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
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        icp = recp.makeOwnEvent(sn=0)
        kvy = eventing.Kevery(db=hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=kvy)

        notifier = notifying.Notifier(hby=hby)
        repd = storing.Respondant(hby=hby)
        counselor = grouping.Counselor(hby=hby)
        registrar = credentialing.Registrar(hby=hby, rgy=regery, counselor=counselor)
        credentialer = credentialing.Credentialer(hby=hby, rgy=regery, registrar=registrar, verifier=verifier)

        _ = kiwiing.loadEnds(hby=hby,
                             rep=repd,
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

        schema = "E1MCiPag0EWlqeJGzDA9xxr1bUSUR4fZXtqHDrwdXgbk"
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
        creder = proving.Creder(ked=result.json)
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


def test_multisig_incept():
    prefix = "ends_test"
    salt = b'0123456789abcdef'
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=True) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=True) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=True) as (hby3, hab3):
        kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        assert hab1.pre == "E1plfvtsnS6XwiHOxF6n3fUTs-ylvJsxIUCd2Ji4hNqc"
        assert hab2.pre == "EmYIWxzWUtSfQNBodo5RT8hNjoFlzcXZXTQXQM500tyE"
        assert hab3.pre == "EPrbmW_c_3Dp4Q6rddi5X7RHp_Xkjp21RcMG2FEWr_HI"

        counselor = grouping.Counselor(hby=hby1)
        notifier = notifying.Notifier(hby=hby1)
        icpEnd = kiwiing.MultisigInceptEnd(hby=hby1, counselor=counselor, notifier=notifier)
        app = falcon.App()
        app.add_route("/multisig/{alias}/icp", icpEnd)

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/icp", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group inception request, 'aids' is required'"

        # aids must include a local identifier
        body = dict(group="test", aids=[hab2.pre, hab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/icp", body=b)
        assert result.status == falcon.HTTP_400
        assert result.text == ('Invalid multisig group inception request, aid list must contain a local '
                               "identifier'")

        # can not reuse a hab alias
        body = dict(aids=[hab1.pre, hab2.pre, hab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path=f"/multisig/{prefix}_1/icp", body=b)
        assert result.status == falcon.HTTP_400
        assert result.text == "Identifier alias ends_test_1 is already in use"

        body = dict(
            aids=[hab1.pre, hab2.pre, hab3.pre],
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            toad=2,
            isith='2',
            nsith='2'

        )
        b = json.dumps(body).encode("utf-8")

        # Use Falcon test all to submit the request to issue a credential
        client = testing.TestClient(app)
        result = client.simulate_post(path="/multisig/multisig/icp", body=b)
        assert result.status == falcon.HTTP_200
        assert len(icpEnd.postman.evts) == 2

        # Incept POST endpoint initiates multisig inception by sending the ICP to all other participants
        evt = icpEnd.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        srdr = evt["serder"]
        assert srdr.ked['t'] == coring.Ilks.exn
        assert srdr.ked['r'] == '/multisig/icp'
        payload = json.dumps(srdr.ked["a"]).encode("utf-8")
        assert payload == (b'{"aids": ["E1plfvtsnS6XwiHOxF6n3fUTs-ylvJsxIUCd2Ji4hNqc", "EmYIWxzWUtSfQNBod'
                           b'o5RT8hNjoFlzcXZXTQXQM500tyE", "EPrbmW_c_3Dp4Q6rddi5X7RHp_Xkjp21RcMG2FEWr_HI"'
                           b'], "ked": {"v": "KERI10JSON000273_", "t": "icp", "d": "EaPj6HOFtnnvbNKlFLwb3'
                           b'lVTOZBvRxdSGlEpZVLFLU6U", "i": "EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEpZVLFLU6U'
                           b'", "s": "0", "kt": "2", "k": ["DZahe53x0zi5u3BEGPEdnYHePZ1uU1tE317OOSUNRqqg"'
                           b', "DUrtOqQyjGz_CkXkgPblFlQFvmjD3eQ_ivdGR6bPjUaU", "D_3nA6zRH1IYiA5oL6ClYeUm2'
                           b'vA--AN4_7T5UspmFqZY"], "nt": "2", "n": ["Em9F-auLKTY-KStSxCI4m4VlnIJlcaruPjP'
                           b'oQGk_FFT4", "Eo1ouQV2441h2Hg8cPD3D0YJg5eCzRKFFN3Dc-QYwPas", "Epxv4r1j0khdLvL'
                           b'_y0gTrTsCKd3Kv_iKAiBtF-mDlzLg"], "bt": "2", "b": ["BGKVzj4ve0VSd8z_AmvhLg4lq'
                           b'cC_9WYX90k03q-R_Ydo", "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw", "Bgoq6'
                           b'8HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"], "c": [], "a": []}}')

        evt = icpEnd.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab3.pre
        assert evt["serder"] == srdr

        # Create new end and app to represent Hab2's agent
        counselor = grouping.Counselor(hby=hby2)
        notifier = notifying.Notifier(hby=hby2)
        icpEnd = kiwiing.MultisigInceptEnd(hby=hby2, counselor=counselor, notifier=notifier)
        app = falcon.App()
        app.add_route("/multisig/{alias}/icp", icpEnd)

        client = testing.TestClient(app)

        # Perform a PUT to join a group identifier inception
        result = client.simulate_put(path="/multisig/multisig2/icp", body=b)
        assert result.status == falcon.HTTP_200
        assert len(icpEnd.counselor.postman.evts) == 2
        evt = icpEnd.counselor.postman.evts.popleft()
        assert evt["src"] == hab2.pre
        assert evt["dest"] == hab1.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000273_","t":"icp","d":"EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEp'
                                     b'ZVLFLU6U","i":"EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEpZVLFLU6U","s":"0","kt":"2'
                                     b'","k":["DZahe53x0zi5u3BEGPEdnYHePZ1uU1tE317OOSUNRqqg","DUrtOqQyjGz_CkXkgPblF'
                                     b'lQFvmjD3eQ_ivdGR6bPjUaU","D_3nA6zRH1IYiA5oL6ClYeUm2vA--AN4_7T5UspmFqZY"],"nt'
                                     b'":"2","n":["Em9F-auLKTY-KStSxCI4m4VlnIJlcaruPjPoQGk_FFT4","Eo1ouQV2441h2Hg8c'
                                     b'PD3D0YJg5eCzRKFFN3Dc-QYwPas","Epxv4r1j0khdLvL_y0gTrTsCKd3Kv_iKAiBtF-mDlzLg"]'
                                     b',"bt":"2","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZ'
                                     b'oapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh'
                                     b'9c"],"c":[],"a":[]}')
        assert evt["attachment"] == (b'-AABAB_ic5fv_CzcSzvhuM4ngRuzRhjlJRFVuRuZ8xr6dyhcoQJ7EmuBM90aSci3wC-dE1JItuW2HkhM'
                                     b'k2cBE2oOAVBA')
        evt = icpEnd.counselor.postman.evts.popleft()
        assert evt["src"] == hab2.pre
        assert evt["dest"] == hab3.pre

        # Test weight threshold specification for isith and nsith
        body = dict(
            aids=[hab1.pre, hab2.pre, hab3.pre],
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            toad=2,
            isith="1/3,1/3,1/3",
            nsith="1/3,1/3,1/3"

        )
        b = json.dumps(body).encode("utf-8")

        # Use Falcon test all to submit the request to issue a credential
        client = testing.TestClient(app)
        result = client.simulate_post(path="/multisig/multisig/icp", body=b)
        assert result.status == falcon.HTTP_200
        assert len(icpEnd.postman.evts) == 2


def test_multisig_rotation():
    prefix = "test"
    with test_grouping.openMutlsig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (hby3, ghab3)):
        assert ghab1.pre == ghab2.pre == ghab3.pre == "Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU"

        app = falcon.App()

        # Start with hby1 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        notifier = notifying.Notifier(hby=hby1)
        rotEnd = MultisigEventEnd(hby=hby1, counselor=counselor, notifier=notifier)
        app.add_route("/multisig/{alias}/rot", rotEnd, suffix="rot")

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/rot", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group rotation request, 'aids' is required"

        # aids must include a local identifier
        body = dict(group="test", aids=[ghab2.pre, ghab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/rot", body=b)
        assert result.status == falcon.HTTP_404
        assert result.text == "Invalid multisig group rotation request alias {alias} not found"

        body = dict(
            aids=[ghab1.phab.pre, ghab2.phab.pre, ghab3.phab.pre],
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            toad=2,
            isith='2',
            nsith='2'

        )
        b = json.dumps(body).encode("utf-8")

        # initiate a multisig rotation with a POST
        client = testing.TestClient(app)
        result = client.simulate_post(path=f"/multisig/{prefix}_group1/rot", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for local witnessing
        assert hby1.db.glwe.get(keys=(ghab1.pre,)) is not None

        # sends local rotation event to other participants to start the rotation
        assert len(rotEnd.postman.evts) == 2
        evt = rotEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab2.phab.pre
        assert evt["topic"] == "multisig"
        evt = rotEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab3.phab.pre
        assert evt["topic"] == "multisig"
        payload = evt["serder"].ked["a"]
        assert set(payload['adds']) == {'BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo',
                                        'Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c',
                                        'BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw'}

        assert payload['aids'] == ['E07_pVCaF6sp9qv-_ufgnqfzySdauT1izcndWMwZzy6c',
                                   'E83mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068',
                                   'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI']
        assert payload['cuts'] == []
        assert payload['sith'] == '2'
        assert payload['toad'] == 2
        assert payload['data'] is None

        app = falcon.App()
        # Now join rotation with hby2 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby2)
        notifier = notifying.Notifier(hby=hby2)
        rotEnd = MultisigEventEnd(hby=hby2, counselor=counselor, notifier=notifier)
        app.add_route("/multisig/{alias}/rot", rotEnd, suffix="rot")
        client = testing.TestClient(app)
        result = client.simulate_put(path=f"/multisig/{prefix}_group2/rot", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for local witnessing
        glwe = hby2.db.glwe.get(keys=(ghab2.pre,))
        assert glwe is not None
        # no notifications set if joining
        assert len(rotEnd.postman.evts) == 0


def test_multisig_interaction():
    prefix = "test"
    with test_grouping.openMutlsig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (hby3, ghab3)):
        assert ghab1.pre == ghab2.pre == ghab3.pre == "Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU"

        app = falcon.App()

        # Start with hby1 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        notifier = notifying.Notifier(hby=hby1)
        evtEnd = MultisigEventEnd(hby=hby1, counselor=counselor, notifier=notifier)
        app.add_route("/multisig/{alias}/ixn", evtEnd, suffix="ixn")

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/ixn", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group rotation request, 'aids' is required"

        # aids must include a local identifier
        body = dict(group="test", aids=[ghab2.pre, ghab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/ixn", body=b)
        assert result.status == falcon.HTTP_404
        assert result.text == "Invalid multisig group rotation request alias {alias} not found"

        body = dict(
            aids=[ghab1.phab.pre, ghab2.phab.pre, ghab3.phab.pre],
            data=dict(i=ghab3.phab.pre, s=0)
        )
        b = json.dumps(body).encode("utf-8")

        # initiate a multisig rotation with a POST
        client = testing.TestClient(app)
        result = client.simulate_post(path=f"/multisig/{prefix}_group1/ixn", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for all signatures
        assert hby1.db.gpse.get(keys=(ghab1.pre,)) is not None

        # sends local rotation event to other participants to start the rotation
        assert len(evtEnd.postman.evts) == 2
        evt = evtEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab2.phab.pre
        assert evt["topic"] == "multisig"
        evt = evtEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab3.phab.pre
        assert evt["topic"] == "multisig"
        payload = evt["serder"].ked["a"]
        assert payload == {'aids': ['E07_pVCaF6sp9qv-_ufgnqfzySdauT1izcndWMwZzy6c',
                                    'E83mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068',
                                    'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI'],
                           'data': {'i': 'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI', 's': 0},
                           'gid': 'Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU'}

        app = falcon.App()
        # Now join rotation with hby2 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        notifier = notifying.Notifier(hby=hby1)
        evtEnd = MultisigEventEnd(hby=hby2, counselor=counselor, notifier=notifier)
        app.add_route("/multisig/{alias}/ixn", evtEnd, suffix="ixn")
        client = testing.TestClient(app)
        result = client.simulate_put(path=f"/multisig/{prefix}_group2/ixn", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for all signatures
        assert hby2.db.gpse.get(keys=(ghab2.pre,)) is not None
        # no notifications set if joining
        assert len(evtEnd.postman.evts) == 0


def test_identifier_ends():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        assert hab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        app = falcon.App()

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        notifier = notifying.Notifier(hby=hby)
        repd = storing.Respondant(hby=hby)
        counselor = grouping.Counselor(hby=hby)
        registrar = credentialing.Registrar(hby=hby, rgy=regery, counselor=counselor)
        credentialer = credentialing.Credentialer(hby=hby, rgy=regery, registrar=registrar, verifier=verifier)

        doers = kiwiing.loadEnds(hby=hby,
                                 rep=repd,
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

        assert result.json == [{'isith': '1',
                                'name': 'test',
                                'next_keys': ['EsBMmyevdbrDojd73T6UmBvSktf7f-i-Yu0LjsuRr7y4'],
                                'nsith': '1',
                                'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'public_keys': ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg'],
                                'receipts': 0,
                                'seq_no': 0,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(isith='1', count=1)
        result = client.simulate_put(path="/ids/test/rot", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'a': [],
                               'ba': [],
                               'br': [],
                               'bt': '0',
                               'd': 'EawlnQ8c4obp5urfda9tBLdeWQuYN7caxxIZYXjABFRY',
                               'i': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'k': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                               'kt': '1',
                               'n': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                               'nt': '1',
                               'p': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               's': '1',
                               't': 'rot',
                               'v': 'KERI10JSON000160_'}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [{'isith': '1',
                                'name': 'test',
                                'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                                'nsith': '1',
                                'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                                'receipts': 0,
                                'seq_no': 1,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EWJA1LHU3Du10uW9B0pM8e7xIQ_3CP3qp9a-D713MlxM',
                               'i': 'EWJA1LHU3Du10uW9B0pM8e7xIQ_3CP3qp9a-D713MlxM',
                               'k': ['D5TEUWL-32q6KlG8DMiygL-6hBeGlMh7rZjR8l9-kSPU'],
                               'kt': '1',
                               'n': ['EurslVC_9AbgETqNkP8xXewQyUxeICfbSy5hrFX5Dh3s'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON00012b_'}

        # Try to reuse the alias
        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_400

        # Create a delegated identifier
        req = dict(transferable=True, wits=[], toad=0, isith='1', count=1, nsith='1', ncount=1, estOnly=False,
                   delpre="ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc")
        result = client.simulate_post(path="/ids/test3", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                               'di': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'i': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                               'k': ['DwiTSOvj8HtydZQ24HuVYuUxC80kzq49DanESrU3g4wg'],
                               'kt': '1',
                               'n': ['ERQq0RyQ3nN97chiuWJSjxS3fdtPbDWZ9MmRzdQtLIk4'],
                               'nt': '1',
                               's': '0',
                               't': 'dip',
                               'v': 'KERI10JSON00015f_'}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200
        assert len(result.json) == 3
        assert result.json[2] == {'anchored': False,
                                  'delegated': True,
                                  'delegator': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                  'isith': '1',
                                  'name': 'test3',
                                  'next_keys': ['ERQq0RyQ3nN97chiuWJSjxS3fdtPbDWZ9MmRzdQtLIk4'],
                                  'nsith': '1',
                                  'prefix': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                                  'public_keys': ['DwiTSOvj8HtydZQ24HuVYuUxC80kzq49DanESrU3g4wg'],
                                  'receipts': 0,
                                  'seq_no': 0,
                                  'toad': 0,
                                  'witnesses': []}

        req = dict(data=[{"i": 1, "s": 0, "d": 2}])
        result = client.simulate_put(path="/ids/test/ixn", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'a': [{'d': 2, 'i': 1, 's': 0}],
                               'd': 'EMNnpGzsaDEsYMhGsAlGX3VX0DE78rGzuEdj4l_HY49A',
                               'i': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'p': 'EawlnQ8c4obp5urfda9tBLdeWQuYN7caxxIZYXjABFRY',
                               's': '2',
                               't': 'ixn',
                               'v': 'KERI10JSON0000de_'}

        req = dict(id="ignored", name="Wile", company="ACME")
        result = client.simulate_put("/ids/bad", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_404  # Unknown alias

        # Update contact data for identifier
        result = client.simulate_put("/ids/test", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res = dict(req)
        res["id"] = "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"
        assert result.json == res

        # Test single GET with metadata
        result = client.simulate_get("/ids/test")
        assert result.status == falcon.HTTP_200
        assert result.json == {'isith': '1',
                               'metadata': {'company': 'ACME', 'name': 'Wile'},
                               'name': 'test',
                               'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                               'nsith': '1',
                               'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                               'receipts': 0,
                               'seq_no': 2,
                               'toad': 0,
                               'witnesses': []}

        # Test list GET method with metadata
        result = client.simulate_get("/ids")
        assert result.status == falcon.HTTP_200
        assert result.json[0] == {'isith': '1',
                                  'metadata': {'company': 'ACME', 'name': 'Wile'},
                                  'name': 'test',
                                  'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                                  'nsith': '1',
                                  'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                  'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                                  'receipts': 0,
                                  'seq_no': 2,
                                  'toad': 0,
                                  'witnesses': []}


def test_oobi_ends(seeder):
    with habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        wesHab = wesHby.makeHab(name="wes", transferable=False)

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[wesHab.pre])

        assert palHab.pre == "E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A"

        notifier = notifying.Notifier(hby=palHby)
        oobiery = ending.Oobiery(hby=palHby)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=None,
                             rgy=None,
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
        assert result.json == {'oobis': [
            'http://127.0.0.1:9999/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A'
            '/controller'],
            'role': 'controller'}

        # Seed with witness endpoints
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http, kering.Schemes.tcp])

        result = client.simulate_get(path="/oobi/pal?role=witness")
        assert result.status == falcon.HTTP_200
        assert result.json == {'oobis': [('http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A'
                                          '/witness/'
                                          'B3y3efWXFxXRJYYkggXjp-lJSoDsyqt7kok03edvHeas')],
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
        (url,),  item = next(oobiery.hby.db.oobis.getItemIter())
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
        (url,),  item = next(oobiery.hby.db.oobis.getItemIter())
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
        (url,),  item = next(oobiery.hby.db.oobis.getItemIter())
        assert item is not None
        assert url == 'http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'
        assert item.oobialias == 'sal'


def test_challenge_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])

        assert palHab.pre == "Eg-r6DSx1C4aReh2pwQsejJS-uPc6qb8OQ0qm30bKxcU"

        app = falcon.App()
        notifier = notifying.Notifier(hby=palHby)
        repd = storing.Respondant(hby=palHby)
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=repd,
                             rgy=None,
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

        assert len(repd.reps) == 1
        rep = repd.reps.popleft()
        assert rep["topic"] == "challenge"
        assert rep["dest"] == "Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU"
        assert rep["rep"].ked['r'] == '/challenge/response'


def test_contact_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="ken", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as kenHby:

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])
        kvy = eventing.Kevery(db=palHab.db, local=False, lax=True)
        assert palHab.pre == "Eg-r6DSx1C4aReh2pwQsejJS-uPc6qb8OQ0qm30bKxcU"

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

        notifier = notifying.Notifier(hby=palHby)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=None,
                             rgy=None,
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
                                 'id': 'EbmbYwDptKJwtvhvwp_832eepyfFgqBiUe_PWbPgq0kA',
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
                                 'id': 'EF2EBiBL7RJ84ilErw8PyMEbABX_wJIL2VHNqLOdq5cw',
                                 'last': 'Burns2'}
        response = client.simulate_put(f"/contacts/{aids[4]}", body=b)
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'ProSapien',
                                 'first': 'Ken4',
                                 'id': 'EWgyARhlWPWWC3DD1kr-hKKR3EK10FUSpY78IGWrmf7M',
                                 'last': 'Burns4'}

        response = client.simulate_get("/contacts", query_string="group=company")
        assert response.status == falcon.HTTP_200

        gleif = response.json["GLEIF"]
        data = {d["id"]: d for d in gleif}
        assert aids[0] in data
        assert aids[1] in data
        assert aids[3] in data

        pros = response.json["ProSapien"]
        data = {d["id"]: d for d in pros}
        assert aids[2] in data
        assert aids[4] in data

        response = client.simulate_get("/contacts", query_string="filter_field=last")
        assert response.status == falcon.HTTP_400

        response = client.simulate_get("/contacts", query_string="filter_field=last&filter_value=Burns3")
        assert response.status == falcon.HTTP_200
        assert response.json == [{'company': 'GLEIF',
                                  'first': 'Ken3',
                                  'id': 'EbmbYwDptKJwtvhvwp_832eepyfFgqBiUe_PWbPgq0kA',
                                  'last': 'Burns3'}]

        response = client.simulate_get("/contacts",
                                       query_string="filter_field=last&filter_value=Burns3&filter_value=Burns1")
        assert response.status == falcon.HTTP_200
        assert response.json == [{'company': 'GLEIF',
                                  'first': 'Ken3',
                                  'id': 'EbmbYwDptKJwtvhvwp_832eepyfFgqBiUe_PWbPgq0kA',
                                  'last': 'Burns3'},
                                 {'company': 'GLEIF',
                                  'first': 'Ken1',
                                  'id': 'Esba3nH2TssmC3ePHxQFZkbFqOxNFxKlCOfrXEnEUl0M',
                                  'last': 'Burns1'}]

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
        assert hab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        app = falcon.App()

        notifier = notifying.Notifier(hby=hby)
        counselor = grouping.Counselor(hby=hby)

        _ = kiwiing.loadEnds(hby=hby,
                             rep=None,
                             rgy=None,
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

        result = client.simulate_get(path=f"/keystate/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert result.status == falcon.HTTP_404

        result = client.simulate_get(path=f"/keystate/{hab.pre}")
        assert result.status == falcon.HTTP_200
        state = result.json["state"]
        assert state["i"] == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"
        assert state["et"] == "icp"
        assert state["k"] == ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg']
        assert state["n"] == ['EsBMmyevdbrDojd73T6UmBvSktf7f-i-Yu0LjsuRr7y4']

        kel = result.json["kel"]
        assert len(kel) == 1


def test_schema_ends():
    with habbing.openHby(name="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as hby:
        app = falcon.App()
        notifier = notifying.Notifier(hby=hby)
        _ = kiwiing.loadEnds(hby=hby,
                             rep=None,
                             rgy=None,
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
        assert response.json[0]["$id"] == "E1bRmgA1GEsAdzOjsHCDMGWQMxlYVTZCKUIIhuD3w8ro"
        assert response.json[1]["$id"] == "EegyOFj7lXmN1JevTIcRhbFIfwx4V80SqeaFdsKVN6l4"
        assert response.json[2]["$id"] == "EusII1Sa7u305LldfoxjC7IsdjXcha4mgVU98GSOQYB0"

        assert response.json[0]["properties"] == {'b': {'type': 'number'}}
        assert response.json[1]["properties"] == {'c': {'format': 'date-time', 'type': 'string'}}
        assert response.json[2]["properties"] == {'a': {'type': 'string'}}

        response = client.simulate_get("/schema/EzzRmgA1GEsAdzOjsHCDMGWQMxlYVTZCKUIIhuD3w8ro")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get("/schema/EegyOFj7lXmN1JevTIcRhbFIfwx4V80SqeaFdsKVN6l4")
        assert response.status == falcon.HTTP_200
        assert response.json["$id"] == "EegyOFj7lXmN1JevTIcRhbFIfwx4V80SqeaFdsKVN6l4"
        assert response.json["properties"] == {'c': {'format': 'date-time', 'type': 'string'}}


def test_escrow_end(mockHelpingNowUTC):
    with habbing.openHby(name="bob", temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name="bob", temp=True)

        notifier = notifying.Notifier(hby=hby)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=hby,
                             rep=None,
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
        escrowedEvt = {'ked': {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd':
                                   'E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0',
                               'i':
                                   'E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0',
                               'k': [
                                   'DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ'],
                               'kt': '1',
                               'n': [
                                   'EOmBSdblll8qB4324PEmETrFN-DhElyZ0BcBH1q1qukw'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON00012b_'},
                       'receipts': {},
                       'signatures': [{'index': 0,
                                       'signature':
                                           'AAotHSmS5LuCg2LXwlandbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3'
                                           'tjcc8ySvYcpiBg'}],
                       'stored': True,
                       'timestamp': '2021-01-01T00:00:00.000000+00:00',
                       'witness_signatures': []}
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
