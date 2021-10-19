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
        hab = buildHab(db, kpr)
        # setup issuer with defaults for allowBackers, backers and estOnly
        issuer = Issuer(hab=hab, name="bob", reger=reg, temp=True)
        kevt, tevt = events(issuer)
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"1","t":"ixn",'
            b'"p":"Eg3wsIOW3RdCqhcG4xZ4uZhTA_qTE24DoLeyjFBB8rks",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0",'
            b'"d":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'
            b'"}]}-AABAAVDMZ3Zfu5Vhw4vIBBbh4oh7l6XACLfOFpS7VN_Tn0vrBlZuHxktv1D9S0Q_e-YbP-PXBjiAnkupzaQ50saSfAA')
        assert tevt == (
            b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"0",'
            b'"b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAAQElQxdAkGEMsdDn_GFiYPU1eVgQ3z1MvVPEoAGP3THI3A')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

        res = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        assert res is True
        kevt, tevt = events(issuer)
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"2","t":"ixn",'
            b'"p":"ElQxdAkGEMsdDn_GFiYPU1eVgQ3z1MvVPEoAGP3THI3A",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"1",'
            b'"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0"}]}-AABAAb-kk2ijQRZkVmmvWpRcyDLRZad3YOKOvev0yZq'
            b'-ay5QyW9J574kIUxOwgFbC-DUkRIKdPPHkBWZdPSjw6IT-Cg')
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"p":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg","s":"1","t":"vrt","bt":"1","br":[],'
            b'"ba":["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU'
            b'"]}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEf12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0'

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON00012d_","i":"EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2F'
                        b'X4GUeOLNHQ","ii":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
                        b'"s":"0","t":"bis","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDG'
                        b'eLWHb9vSY","s":1,"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqb'
                        b'I0"},"dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAA'
                        b'AAAAAAAAwEx7i6wv4YzDRTO9_iHkTQSXrvLYldSd_UEjNfqia3Pqc')
        assert kevt == (b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"3","t":"ixn","p":"Ef12IRHtb_gVo5ClaHHNV90b43adA'
                        b'0f8vRs3jeU-AstY","a":[{"i":"EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2FX4'
                        b'GUeOLNHQ","s":"0","d":"ENNTabgWbaNqOKLqEZdQCjxbafwwSoXNzAsE1Enq-'
                        b'kdk"}]}-AABAAS9RaaKhprhdUWCncJ7t1kUJbRjtmYowfuycasun1dBxc-jqAldB'
                        b'ZY_6m5mL9DkqKYnUvnyLufx-iLQMZhgfnAQ')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'ENNTabgWbaNqOKLqEZdQCjxbafwwSoXNzAsE1Enq-kdk'

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON00012c_","i":"EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2F'
                        b'X4GUeOLNHQ","s":"1","t":"brv","p":"ENNTabgWbaNqOKLqEZdQCjxbafwwS'
                        b'oXNzAsE1Enq-kdk","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGe'
                        b'LWHb9vSY","s":1,"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI'
                        b'0"},"dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAA'
                        b'AAAAAABAEwRLQcXWTn2AJtgSznMSH4q62f4QEHw1ab9NfsThia0Q')
        assert kevt == (b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"4","t":"ixn","p":"Ex7i6wv4YzDRTO9_iHkTQSXrvLYld'
                        b'Sd_UEjNfqia3Pqc","a":[{"i":"EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2FX4'
                        b'GUeOLNHQ","s":"1","d":"ELkzsQE3_TD2qe7xdyc1XkAJs4UoHeHnOExK4aPDZ'
                        b'ngo"}]}-AABAA7dtqz8VJf0-O9NQjTODNCOsNxbX8prjZlNUynoh-IZ8ReOS60_m'
                        b'_UiMl6vLzFVOXjGKJM0X5ehBrNgFfusfsAw')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'ELkzsQE3_TD2qe7xdyc1XkAJs4UoHeHnOExK4aPDZngo'

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
            hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            issuer = Issuer(hab=hab, name="bob", noBackers=True, reger=reg, temp=True)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
            assert ser.ked["t"] == "vcp"
            assert ser.ked["c"] == ["NB"]
            assert ser.ked["b"] == []
            assert ser.ked["bt"] == "0"

            ser = Serder(raw=kevt)
            assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
            assert seal["s"] == "0"
            assert seal["d"] == "ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4"

            with pytest.raises(ValueError):
                issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
            hab = buildHab(db, kpr)
            issuer = Issuer(hab=hab, name="bob", noBackers=True, reger=reg, temp=True)
            events(issuer)

            creder = credential(hab=hab, regk=issuer.regk)

            issuer.issue(creder=creder)
            kevt, tevt = events(issuer)
            ser = Serder(raw=tevt)
            assert ser.pre == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
            assert ser.ked["ri"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
            assert ser.ked["t"] == "iss"

            ser = Serder(raw=kevt)
            assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
            assert seal["s"] == "0"
            assert seal["d"] == 'E7530zxhPK3yFd39cnb8sWTWiyR9eDkZRGdgjmSgV5VM'

            issuer.revoke(creder=creder)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
            assert ser.ked["t"] == "rev"
            assert ser.ked["ri"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"

            ser = Serder(raw=kevt)
            assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
            assert seal["s"] == "1"
            assert seal["d"] == 'E_4NkYeNImN0uRLszsqNZbrtNo3na7qPjbHiuJxYV0uM'

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.ked["bt"] == "1"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert seal["s"] == "0"

        issuer.rotate(adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                            "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vrt"
        assert ser.ked["ba"] == ["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                 "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert seal["s"] == "1"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert ser.ked["t"] == "brv"
        seal = ser.ked["ra"]
        # ensure the ra seal digest matches the vrt event digest
        assert seal["d"] == vrtser.diger.qb64

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert seal["s"] == "1"

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, reger=reg, noBackers=True, estOnly=True, temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ["NB"]
        assert ser.ked["bt"] == "0"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert ser.ked["k"] == ["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"]
        assert ser.ked["n"] == "ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EIrM2s0pcRE0KXFtytuuLugELkF7f0uCeD1y9fqRuumc"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True,
                        temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.diger.qb64 == 'EevCI-l5dfYW63xg1bQ52ldLQa3li8FBo-znWxNEzv7E'
        ser = Serder(raw=kevt)
        assert ser.ked["t"] == "rot"

        issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                    "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vrt"
        assert issuer.backers == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU",
                                  "B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                  "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'ECQbOOZdBxpw5RTH4VvPXDSH_o2uYdPWSoWolW5tobgA'

        # rotate to no backers
        issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        ser = Serder(raw=tevt)
        assert ser.pre == "EPrcGi4z6FyyhqRCm3bYU07XUpuJgwcKT2EKME1MvZN0"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'EnUD_KZu-dGpFSEWZOlFdQSydioYY78qIDPfzA7Fhr-Q'

    """ End Test """


def buildHab(db, kpr):
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
    hab = habbing.Habitat(ks=kpr, db=db, secrecies=secrecies, temp=True)
    return hab


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
