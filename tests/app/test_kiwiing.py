# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon
from falcon import testing, media
from hio.base import doing
from hio.help import decking

from keri.app import habbing, storing, grouping, kiwiing
from keri.core import eventing, parsing
from keri.vc import proving
from keri.vdr import viring, issuing, verifying


def test_credential_handlers(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True) as (hby, hab), \
            habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
        app = falcon.App()

        ims = bytearray()
        reger = viring.Registry(name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=reger)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)
        gdoer = grouping.MultiSigGroupDoer(hby=hby, ims=ims)
        issuerCues = decking.Deck()

        icp = recp.makeOwnEvent(sn=0)
        kvy = eventing.Kevery(db=hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=kvy)

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        assert cue["kin"] == "kevt"
        cue = issuer.cues.popleft()
        assert cue["kin"] == "send"

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hby=hby)

        _ = kiwiing.loadEnds(hby=hby,
                             rep=repd,
                             verifier=verifier,
                             gdoer=gdoer,
                             issuers=issuers,
                             issuerCues=issuerCues,
                             app=app, path="/", mbx=None)

        client = testing.TestClient(app)

        result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test"}')
        assert result.status == falcon.HTTP_202

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            alias="test",
            registry=issuer.regk,
            schema=schema,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credentials", body=b)
        assert result.status == falcon.HTTP_200

        tevt = (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EYp0zprvOVGALuENur3xFYR3'
                b'f97-prCMjl9RXnKJ7HxI","i":"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC3'
                b'24D_MUs","s":"0","ri":"EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482K'
                b'PDs","dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAA'
                b'AAAAAAAAgEmg5GkO_0R3PG3qlDNYtTpTFVZWbUoHwmAXkpP0cXI2c')
        kevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"Emg5GkO_0R3PG3qlDNYtTpTF'
                b'VZWbUoHwmAXkpP0cXI2c","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpB'
                b'GF9Z1Pc","s":"2","p":"EhUlcH33N486ITfJu3kG5evVLoivVaR8Wp6ut8rP21'
                b'gs","a":[{"i":"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs","s"'
                b':"0","d":"EYp0zprvOVGALuENur3xFYR3f97-prCMjl9RXnKJ7HxI"}]}-AABAA'
                b'10QegNBAIM_NSA2Tj_u7jEWS5a2S1CX9qWl_TY2r5NnyV7buK3r_aHmtUUcRRrlj'
                b'xhOAvAECR9x-SAHgtZApCg')
        cred = (b'{"v":"ACDC10JSON00019b_","d":"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs",'
                b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"ECtWlHS2Wbx5M2Rg6nm6'
                b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"E-ZnCrHoereORJlfqYCLRju-Bh78JXuyZjYtwUx2'
                b'juTU","i":"EqwblUykZNwSsBd4g8pHeRZhlkPj64MhoGDspLCh2qnI","dt":"2021-01-01T00'
                b':00:00.000000+00:00","LEI":"1234567890abcdefg","ri":"EjPXk1a_MtWR3a0qrZiJ34c'
                b'971FxiHyCZSRo6482KPDs"},"p":[]}')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == kevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == tevt

        creder = proving.Credentialer(raw=cred)
        assert reger.creds.get(b'ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs').raw == creder.raw

        # Try to revoke a credential that doesn't exist and get the appropriate error
        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs", "said": '
                                           b'"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs"}')
        assert result.status == falcon.HTTP_NOT_FOUND

        print(creder.saider.qb64)
        # Now revoke the actual credential
        result = client.simulate_delete(path="/credentials",
                                        query_string=("alias=test&"
                                                      "registry=EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs&"
                                                      "said=ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs"))
        assert result.status == falcon.HTTP_202

        rev = (b'{"v":"KERI10JSON000120_","t":"rev","d":"ErO_5RRABj5WhZMvtorj9Lj0'
               b'3FScWkyvLaWWRhNIn050","i":"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC3'
               b'24D_MUs","s":"1","ri":"EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482K'
               b'PDs","p":"EYp0zprvOVGALuENur3xFYR3f97-prCMjl9RXnKJ7HxI","dt":"20'
               b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEzsh'
               b'nUr86BE4aIQLgOP8S7Y-WtvEHaxu0rIZPYliC4ug')
        rkevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EzshnUr86BE4aIQLgOP8S7Y-'
                 b'WtvEHaxu0rIZPYliC4ug","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpB'
                 b'GF9Z1Pc","s":"3","p":"Emg5GkO_0R3PG3qlDNYtTpTFVZWbUoHwmAXkpP0cXI'
                 b'2c","a":[{"i":"ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs","s"'
                 b':"1","d":"ErO_5RRABj5WhZMvtorj9Lj03FScWkyvLaWWRhNIn050"}]}-AABAA'
                 b'5ZC0m0ttngqIVwmgb6tmkQ1D0DuvglMzQUmF8rtz3hpRDoYMUqjelKjiHmZ5F24N'
                 b'ykAO4WBSqM5FWPd0hqdTDQ')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rkevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rev


# def test_credential_handlers_singlesig(mockHelpingNowUTC):
#     with test_grouping.openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
#             habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
#         app = falcon.App()
#
#         ims = bytearray()
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#         issuerCues = decking.Deck()
#
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/", mbx=None)
#
#         client = testing.TestClient(app)
#
#         result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test"}')
#         assert result.status == falcon.HTTP_202
#
#         schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
#         LEI = "1234567890abcdefg"
#
#         data = dict(LEI=LEI)
#         body = dict(
#             alias="test_1",
#             registry="test",
#             schema=schema,
#             recipient=recp.pre,
#             type="GLEIFvLEICredential",
#             credentialData=data
#         )
#         b = json.dumps(body).encode("utf-8")
#         result = client.simulate_post(path="/credentials", body=b)
#         assert result.status == falcon.HTTP_200
#         assert len(issuer.cues) == 1
#
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "multisig"
#         assert cue["op"] == grouping.Ops.ixn
#         assert cue["data"] == [
#             {'d': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              'i': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              's': '0'}
#         ]
#
#         result = client.simulate_delete(path="/credentials",
#                                         query_string=("alias=test&"
#                                                       "registry=E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38&"
#                                                       "said=EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0"))
#         assert result.status == falcon.HTTP_NOT_FOUND
#         assert result.text == "credential not found"


# def test_issue_credential_full_multisig():
#     with test_grouping.openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
#             habbing.openHab(name="recp", transferable=True) as recp:
#         # Verify the group identifier was incepted properly and matches the identifiers
#         assert hab1.pre == "El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8"
#         assert hab2.pre == "ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw"
#         assert hab3.pre == "EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA"
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.db.gids.get(hab1.pre)
#         assert group1.gid == gid
#         group2 = hab2.db.gids.get(hab2.pre)
#         assert group2.gid == gid
#         group3 = hab3.db.gids.get(hab3.pre)
#         assert group3.gid == gid
#
#         # Now create the Falcon app and the Kiwi Server
#         # with one of the Group participants Habitats
#         app = falcon.App()
#
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         witq = agenting.WitnessInquisitor(hby=hby1, reger=verifier.reger, klas=agenting.HttpWitnesser)
#         issuerCues = decking.Deck()
#
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "multisig"
#         assert cue["data"] == [
#             {'d': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              'i': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              's': '0'}
#         ]
#
#         ims = bytearray()
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/", mbx=None)
#
#         # Create the credential to be issued
#         schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
#         LEI = "1234567890abcdefg"
#
#         data = dict(LEI=LEI)
#         body = dict(
#             registry=issuer.regk,
#             schema=schema,
#             source=hab1.pre,
#             recipient=recp.pre,
#             type="GLEIFvLEICredential",
#             credentialData=data
#         )
#         b = json.dumps(body).encode("utf-8")
#
#         # Use Falcon test all to submit the request to issue a credential
#         client = testing.TestClient(app)
#         result = client.simulate_post(path="/credentials", body=b)
#         assert result.status == falcon.HTTP_200
#
#         creder = proving.Credentialer(ked=result.json, kind=coring.Serials.json)
#
#         # The Issuer will have cue'd up a multisig request to be processed
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#
#         assert cue["kin"] == "multisig"
#         data = cue["data"]
#         assert len(data) == 1
#         assert data[0]['s'] == '0'
#         assert data[0]['i'] == creder.saider.qb64
#         assert 'd' in data[0]


# def test_multisig_ends():
#     prefix = "ends_test"
#     salt = b'0123456789abcdef'
#     with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=True) as (hby1, hab1), \
#             habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=True) as (hby2, hab2), \
#             habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=True) as (hby3, hab3):
#         # Keverys so we can process each other's inception messages.
#         kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
#         kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
#         kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)
#
#         icp1 = hab1.makeOwnEvent(sn=0)
#         parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
#         icp2 = hab2.makeOwnEvent(sn=0)
#         parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
#         icp3 = hab3.makeOwnEvent(sn=0)
#         parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)
#
#         assert hab1.pre == "ExfT1Zv-yjDdoffhH-8mf3xO57PJvDMRF4-6VZqgnFms"
#         assert hab2.pre == "E66PuB1r9qFEFgDYXleqtaAzMGuiUTuM3foK_DFZRWJo"
#         assert hab3.pre == "EESncQr9Gt38GEnJK96CN5nHpsjC5wmTAEkOC_E3_dlA"
#
#         app = falcon.App()
#
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         witq = agenting.WitnessInquisitor(hby=hby1, reger=verifier.reger, klas=agenting.HttpWitnesser)
#         issuerCues = decking.Deck()
#
#         ims = bytearray()
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/",
#                              mbx=None)
#
#         req = dict(
#             sith=3,
#             aids=[hab1.pre, hab2.pre, hab3.pre]
#         )
#         body = json.dumps(req).encode("utf-8")
#         client = testing.TestClient(app)
#         result = client.simulate_post(path="/multisig", body=body)
#         assert result.status == falcon.HTTP_202
#         msg = gdoer.msgs.popleft()
#         assert msg == {
#             'aids': ['ExfT1Zv-yjDdoffhH-8mf3xO57PJvDMRF4-6VZqgnFms', 'E66PuB1r9qFEFgDYXleqtaAzMGuiUTuM3foK_DFZRWJo',
#                      'EESncQr9Gt38GEnJK96CN5nHpsjC5wmTAEkOC_E3_dlA'], 'toad': None, 'witnesses': [], 'isith': None,
#             'nsith': None, 'op': 'icp'}
#
#         assert len(repd.reps) == 3
#
#     with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3):
#         # Verify the group identifier was incepted properly and matches the identifiers
#         assert hab1.pre == "El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8"
#         assert hab2.pre == "ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw"
#         assert hab3.pre == "EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA"
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.db.gids.get(hab1.pre)
#         assert group1.gid == gid
#         group2 = hab2.db.gids.get(hab2.pre)
#         assert group2.gid == gid
#         group3 = hab3.db.gids.get(hab3.pre)
#         assert group3.gid == gid
#
#         # Now create the Falcon app and the Kiwi Server
#         # with one of the Group participants Habitats
#         app = falcon.App()
#
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         witq = agenting.WitnessInquisitor(hby=hby1, reger=verifier.reger, klas=agenting.HttpWitnesser)
#         issuerCues = decking.Deck()
#
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "multisig"
#         assert cue["data"] == [
#             {'d': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              'i': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              's': '0'}
#         ]
#
#         ims = bytearray()
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/",
#                              mbx=None)
#
#         client = testing.TestClient(app)
#         result = client.simulate_get(path="/multisig")
#         assert result.status == falcon.HTTP_200
#         assert result.json == ([{'prefix': 'Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow', 'seq_no': 0,
#                                  'aids': ['El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8',
#                                           'ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw',
#                                           'EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA'], 'delegated': False,
#                                  'delegator': None, 'witnesses': [],
#                                  'public_keys': ['D1tpzhwcKFWZV9v9d2Emnn6U_HL2bxwyK37Dv4oV3Q0w',
#                                                  'Dx_yShohMR4yD2m3WGBzRCvvVmdeii_hcDZ3qZ_TGfqQ',
#                                                  'DcGxDJAzB24GJ3mD6v3RDTo8XBSk7WbWD7TKst3rCJSY'], 'toad': 0,
#                                  'isith': '2', 'receipts': 0}])
#
#         result = client.simulate_put(path="/multisig", body=b'{"sith": 3}')
#         assert result.status == falcon.HTTP_202
#         msg = gdoer.msgs.popleft()
#         assert msg == (
#             {'sith': 3, 'toad': None, 'data': None, 'witnesses': [], 'witness_cuts': [], 'witness_adds': [],
#              'op': 'rot'})


def test_identifier_ends():
    with habbing.openHab(name="test", transferable=True) as (hby, hab):
        assert hab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        app = falcon.App()

        reger = viring.Registry(name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=reger)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hby=hby)

        endDoers = kiwiing.loadEnds(hby=hby,
                                    rep=repd,
                                    verifier=verifier,
                                    gdoer=None,
                                    issuers=None,
                                    issuerCues=None,
                                    app=app, path="/",
                                    mbx=None)
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=endDoers)
        doist.enter()

        client = testing.TestClient(app)

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [
            {'name': 'test', 'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc', 'seq_no': 1, 'delegated': False,
             'delegator': None, 'witnesses': [], 'public_keys': ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg'],
             'toad': 0, 'isith': '1', 'receipts': 0}]

        req = dict(isith=1, count=1)
        result = client.simulate_put(path="/ids/test", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.text == "Successful rotate to event number 2"

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [
            {'name': 'test', 'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc', 'seq_no': 2, 'delegated': False,
             'delegator': None, 'witnesses': [], 'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
             'toad': 0, 'isith': '1', 'receipts': 0}]
