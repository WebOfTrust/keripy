# -*- encoding: utf-8 -*-
"""
tests.vdr.issuing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core.coring import Serder
from keri.db import basing
from keri.vc import proving
from keri.vdr import viring
from keri.vdr.issuing import Issuer


def test_issuer(mockHelpingNowUTC):
    # help.ogler.resetLevel(level=logging.DEBUG)

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hby, hab = buildHab(db, kpr)
        # setup issuer with defaults for allowBackers, backers and estOnly
        issuer = Issuer(hab=hab, name="bob", reger=reg, temp=True)
        kevt, tevt = events(issuer)
        assert kevt == (
             b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EHuiZ2zC5kfJlBV9wRh9pZxa'
             b'QbJwmAhieX2odN-KuJYM","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
             b'GI0Br6A","s":"1","p":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br'
             b'6A","a":[{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
             b':"0","d":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI"}]}-AABAA'
             b'Ojwa_pLjlTnFDR_p0Bc5PsgW65gi0xFr1JIh49-RxBbpN28ReEPeTP_PlmAt_j-z'
             b'93KrJkwRS9zD2rLH1cKoBA')
        assert tevt == (
            b'{"v":"KERI10JSON0000dc_","t":"vcp","d":"EWKCDqk4W2wseV-VnW-KpzvM'
            b'pe2Y08bChQQPhmwgZdTI","i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPh'
            b'mwgZdTI","ii":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s"'
            b':"0","c":[],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAAQEHuiZ2zC'
            b'5kfJlBV9wRh9pZxaQbJwmAhieX2odN-KuJYM')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI'

        res = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        tsn = issuer.tevers[issuer.regk].state()
        assert res is True
        kevt, tevt = events(issuer)
        assert kevt == (
            b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EaK53gpNuE4qiQFxIvxcrreE'
            b'pu2_lEt0lz3GxvCHLIaw","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
            b'GI0Br6A","s":"2","p":"EHuiZ2zC5kfJlBV9wRh9pZxaQbJwmAhieX2odN-KuJ'
            b'YM","a":[{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
            b':"1","d":"EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4"}]}-AABAA'
            b'9ylhjYwYK9dBk1XUkP-n75WgCIzps3GfJ6nPQHK3-43GFSZXzi0l0HwwvzFpy75V'
            b'GbAhw7L-9n8tJ78P4cGhAw')
        assert tevt == (
            b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EyN9LfEwJS4_YDDIdLqe6P_D'
            b'knpF5AdojA0zTF9yo6J4","i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPh'
            b'mwgZdTI","p":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s":'
            b'"1","bt":"1","br":[],"ba":["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNp'
            b'WnZU_YEU"]}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEaK53gpNuE4qiQFxIvxcrreEp'
            b'u2_lEt0lz3GxvCHLIaw')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4'

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON000160_","t":"bis","d":"E9LBqA1-92yyBhzAVvflg5tf'
                        b'_pBI4v0bWDcj_TX3ma1E","i":"EQPbbAIPxTwrjnaycNJn5B0pVa_qiYVCmOYgV'
                        b'2VI9yGI","ii":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
                        b':"0","ra":{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s'
                        b'":1,"d":"EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4"},"dt":"20'
                        b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEv6k'
                        b'TfdcCDLXoHIWJskfhNY-ugUJUzStnEWl-S2DuMM0')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"Ev6kTfdcCDLXoHIWJskfhNY-'
                        b'ugUJUzStnEWl-S2DuMM0","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
                        b'GI0Br6A","s":"3","p":"EaK53gpNuE4qiQFxIvxcrreEpu2_lEt0lz3GxvCHLI'
                        b'aw","a":[{"i":"EQPbbAIPxTwrjnaycNJn5B0pVa_qiYVCmOYgV2VI9yGI","s"'
                        b':"0","d":"E9LBqA1-92yyBhzAVvflg5tf_pBI4v0bWDcj_TX3ma1E"}]}-AABAA'
                        b'1sdM4fSuuDtpZPnTmvE7NTci_bxkC2hQr_8zeu_7kgrUyosnkMx4_T4GBWlDhwzR'
                        b'7LQ32X_dPz81J9nRS5_wDg')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'E9LBqA1-92yyBhzAVvflg5tf_pBI4v0bWDcj_TX3ma1E'

        tsn = issuer.tevers[issuer.regk].vcState(vcpre=ser.pre)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON00015f_","t":"brv","d":"ECs2aL_9Od-cLh_4BYgqWjD9'
                        b'oki7NlhvfWUheOGMcFHg","i":"EQPbbAIPxTwrjnaycNJn5B0pVa_qiYVCmOYgV'
                        b'2VI9yGI","s":"1","p":"E9LBqA1-92yyBhzAVvflg5tf_pBI4v0bWDcj_TX3ma'
                        b'1E","ra":{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
                        b':1,"d":"EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4"},"dt":"202'
                        b'1-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAABAE_Vea'
                        b'au6PP2idV-HqF-RqfTgZ4A4i_HVON_-jEgW6cU0')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"E_Veaau6PP2idV-HqF-RqfTg'
                        b'Z4A4i_HVON_-jEgW6cU0","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
                        b'GI0Br6A","s":"4","p":"Ev6kTfdcCDLXoHIWJskfhNY-ugUJUzStnEWl-S2DuM'
                        b'M0","a":[{"i":"EQPbbAIPxTwrjnaycNJn5B0pVa_qiYVCmOYgV2VI9yGI","s"'
                        b':"1","d":"ECs2aL_9Od-cLh_4BYgqWjD9oki7NlhvfWUheOGMcFHg"}]}-AABAA'
                        b'qTPSn0wsf6LTmdbTXvnaxNdvsydNd4IR-G-Ne6YUSBPT7_DEEAElGgzI2zNO2dtj'
                        b'yr5DeV9fwXnAPwV77e7wDQ')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'ECs2aL_9Od-cLh_4BYgqWjD9oki7NlhvfWUheOGMcFHg'

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
            hby, hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            issuer = Issuer(hab=hab, name="bob", noBackers=True, reger=reg, temp=True)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"
            assert ser.ked["t"] == "vcp"
            assert ser.ked["c"] == ["NB"]
            assert ser.ked["b"] == []
            assert ser.ked["bt"] == "0"

            ser = Serder(raw=kevt)
            assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"
            assert seal["s"] == "0"
            assert seal["d"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"

            with pytest.raises(ValueError):
                issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
            hby, hab = buildHab(db, kpr)
            issuer = Issuer(hab=hab, name="bob", noBackers=True, reger=reg, temp=True)
            events(issuer)

            creder = credential(hab=hab, regk=issuer.regk)

            issuer.issue(creder=creder)
            kevt, tevt = events(issuer)
            ser = Serder(raw=tevt)
            assert ser.pre == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
            assert ser.ked["ri"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"
            assert ser.ked["t"] == "iss"

            ser = Serder(raw=kevt)
            assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
            assert seal["s"] == "0"
            assert seal["d"] == 'EXushvyjVgQgBOiWETWY_ci528w5yWBwPdy35eB-D6yU'

            issuer.revoke(creder=creder)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
            assert ser.ked["t"] == "rev"
            assert ser.ked["ri"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"

            ser = Serder(raw=kevt)
            assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
            assert seal["s"] == "1"
            assert seal["d"] == 'EY6zcYqOwQCCyAMZ2XPDFWlkKGkzVO8OnanLGnGv3Pr4'

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hby, hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.ked["bt"] == "1"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert seal["s"] == "0"

        issuer.rotate(adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                            "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert ser.ked["t"] == "vrt"
        assert ser.ked["ba"] == ["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                 "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert seal["s"] == "1"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert ser.ked["t"] == "brv"
        seal = ser.ked["ra"]
        # ensure the ra seal digest matches the vrt event digest
        assert seal["d"] == vrtser.saider.qb64

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert seal["s"] == "1"

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hby, hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, reger=reg, noBackers=True, estOnly=True, temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ["NB"]
        assert ser.ked["bt"] == "0"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        assert ser.ked["k"] == ["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"]
        assert ser.ked["n"] == ['E-JoB6yM-Q9xRnC5Kn1_Pq68_O3um8FKQsZGzWAA1J4A']

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EoU5YLpjnfkWtPepbLoWQnkpT_st_MyPszLj_PxPJbiw"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hby, hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True,
                        temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.saider.qb64 == 'EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI'
        ser = Serder(raw=kevt)
        assert ser.ked["t"] == "rot"

        issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                    "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert ser.ked["t"] == "vrt"
        assert issuer.backers == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU",
                                  "B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                  "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'EN1kFSB7XmRMp2TUFocy4NrJqqyUq38u_D8RfIo1bt0M'

        # rotate to no backers
        issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        ser = Serder(raw=tevt)
        assert ser.pre == "Ewr0AFofqVDZH6QXUJJuZVs263zRunNRVGTOdJj0hHL8"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'E24XmL_Cie-NK_uPYKaZ0_HwAmwtNYLhnaHm9XbmLzdc'

    """ End Test """


def buildHab(db, ks, name="test"):
    """Utility to setup Habery and Hab for testing purposes
    Returns:
       tuple (Habery, Hab):
    """
    secrets = [
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])
    # setup hab
    hby = habbing.Habery(name=name, temp=True, ks=ks, db=db)
    hab = hby.makeHab(name=name, secrecies=secrecies)
    # hab = habbing.Habitat(ks=ks, db=db, secrecies=secrecies, temp=True)
    return (hby, hab)


def credential(hab, regk):
    """
    Generate test credential from with Habitat as issuer

    Parameters:
        hab (Habitat): issuer environment
        regk (str) qb64 of registry

    """
    credSubject = dict(
        d="",
        i="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
        LEI="254900OPPU84GM83MG36",
    )

    creder = proving.credential(issuer=hab.pre,
                                schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                subject=credSubject,
                                status=regk)

    return creder


def events(issuer):
    assert len(issuer.cues) == 2
    cue = issuer.cues.popleft()
    assert cue["kin"] == "kevt"
    kevt = cue["msg"]
    cue = issuer.cues.popleft()
    assert cue["kin"] == "send"
    tevt = cue["msg"]

    return kevt, tevt


if __name__ == "__main__":
    pytest.main(['-vv', 'test_issuing.py::test_issuer'])
    # test_issuer()
