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

        tevt = (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EkkObJoLZkhWlH5rNMAGNwXz'
                b'u9NrJ5VymB8S8faa91ok","i":"EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_'
                b'b9sw8NQ","s":"0","ri":"EUmNxM911ZUMWSdndXCq8kSJq6ILtWt7oZBn27iOQ'
                b'yyo","dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAA'
                b'AAAAAAAAgEc-gQ4RwkHHO0AWmnDD5A2tMIzNv_F9W1rYxCrjbcG7c')
        kevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"Ec-gQ4RwkHHO0AWmnDD5A2tM'
                b'IzNv_F9W1rYxCrjbcG7c","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqy'
                b'KTlh0nc","s":"2","p":"EUEfHVjhRI0f5WmNPF6PxLJigCxQn73ijikUzO9p42'
                b'f8","a":[{"i":"EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_b9sw8NQ","s"'
                b':"0","d":"EkkObJoLZkhWlH5rNMAGNwXzu9NrJ5VymB8S8faa91ok"}]}-AABAA'
                b'dzceG1ISVULhZWVUOA_jFwp-aC8uTJQuAaG9Fl--jXdm8pUC1KFHIDoMGjoNiCzS'
                b'jn4PlTyX_5QKgWeQkTYmCQ')
        cred = (
            b'{"v":"ACDC10JSON00019b_","d":"EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_b9sw8NQ",'
            b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc",'
            b'"a":{"d":"EX68IGyVlJbavp7mMFUqDUtZ6M0QVhAI-hZvwEoEZzaM",'
            b'"i":"Eo-yqSHYEN7C1T7fQLiRCkB_yObnXLpMNXaqBe4-uwBc","dt":"2021-01-01T00:00:00.000000+00:00",'
            b'"LEI":"1234567890abcdefg","ri":"EUmNxM911ZUMWSdndXCq8kSJq6ILtWt7oZBn27iOQyyo"},"p":[]}')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == kevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == tevt

        creder = proving.Credentialer(raw=cred)
        assert reger.creds.get(b'EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_b9sw8NQ').raw == creder.raw

        # Try to revoke a credential that doesn't exist and get the appropriate error
        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "EUmNxM911ZUMWSdndXCq8kSJq6ILtWt7oZBn27iOQyyo", "said": '
                                           b'"EhFUqi_LAldgF0I6XmN9JGjc7Wh7ld1yCRiUxtMDVvow"}')
        assert result.status == falcon.HTTP_NOT_FOUND

        print(creder.saider.qb64)
        # Now revoke the actual credential
        result = client.simulate_delete(path="/credentials",
                                        query_string=("alias=test&"
                                                      "registry=EUmNxM911ZUMWSdndXCq8kSJq6ILtWt7oZBn27iOQyyo&"
                                                      "said=EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_b9sw8NQ"))
        assert result.status == falcon.HTTP_202

        rev = (b'{"v":"KERI10JSON000120_","t":"rev","d":"EAeIinuz-droPXota2YFXZ16'
               b'm4-Gyq-yjo56Av0ckoMg","i":"EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_'
               b'b9sw8NQ","s":"1","ri":"EUmNxM911ZUMWSdndXCq8kSJq6ILtWt7oZBn27iOQ'
               b'yyo","p":"EkkObJoLZkhWlH5rNMAGNwXzu9NrJ5VymB8S8faa91ok","dt":"20'
               b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEmAa'
               b'D4PJNioOn-jUo96EuN0rz7GalszG_pz90EKR_1qc')
        rkevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EmAaD4PJNioOn-jUo96EuN0r'
                 b'z7GalszG_pz90EKR_1qc","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqy'
                 b'KTlh0nc","s":"3","p":"Ec-gQ4RwkHHO0AWmnDD5A2tMIzNv_F9W1rYxCrjbcG'
                 b'7c","a":[{"i":"EeBiAoXWrs5fCo0km-8GlPHctMkoSAcQ7DWP_b9sw8NQ","s"'
                 b':"1","d":"EAeIinuz-droPXota2YFXZ16m4-Gyq-yjo56Av0ckoMg"}]}-AABAA'
                 b'0gBlBfu1q-vKDi2nn318dJ8Cmbrzg5We80Sg4OgkkBzUvNMSb3xu7NreG5vMRJSb'
                 b'NQMc9FB2t-efuWbg1YuTAA')

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
        assert hab.pre == "EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc"

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
            {'name': 'test', 'prefix': 'EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc', 'seq_no': 1, 'delegated': False,
             'delegator': None, 'witnesses': [], 'public_keys': ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg'],
             'toad': 0, 'isith': '1', 'receipts': 0}]

        req = dict(isith=1, count=1)
        result = client.simulate_put(path="/ids/test", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.text == "Successful rotate to event number 2"

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [
            {'name': 'test', 'prefix': 'EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc', 'seq_no': 2, 'delegated': False,
             'delegator': None, 'witnesses': [], 'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
             'toad': 0, 'isith': '1', 'receipts': 0}]
