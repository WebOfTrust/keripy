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
            b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EyvWVkV1ktMFvJxKwsSbTxaq'
            b'JC9ppB0l37IHuSG03uEU","i":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0di'
            b'SV_sdGw","s":"1","p":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sd'
            b'Gw","a":[{"i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s"'
            b':"0","d":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg"}]}-AABAA'
            b'D7drxQaaOMhJtPt3DI3NgX3syAYNhAwVHKy0gsooCoZDstumF60PBPv9XQQ9T7-p'
            b'dvU4MnDwCs0k-UhoNHYmBQ')
        assert tevt == (
            b'{"v":"KERI10JSON0000dc_","t":"vcp","d":"EuUK4Q1-XrmsPZW44_HwGmRz'
            b'WGzWkYbc0NZNkA6zVVqg","i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNk'
            b'A6zVVqg","ii":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw","s"'
            b':"0","c":[],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAAQEyvWVkV1'
            b'ktMFvJxKwsSbTxaqJC9ppB0l37IHuSG03uEU')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg'

        res = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        tsn = issuer.tevers[issuer.regk].state()
        assert res is True
        kevt, tevt = events(issuer)
        assert kevt == (
            b'{"v":"KERI10JSON00013a_","t":"ixn","d":"ElQ-JFNVR4I_wumyv-S6YGv7'
            b'6eGuXjx2coApDSyCEInM","i":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0di'
            b'SV_sdGw","s":"2","p":"EyvWVkV1ktMFvJxKwsSbTxaqJC9ppB0l37IHuSG03u'
            b'EU","a":[{"i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s"'
            b':"1","d":"EEOByNw2UfZgk7kqNF_JE8jUXDVde4V_KnODfZBmap1U"}]}-AABAA'
            b'q3hIjRYRHDBQ1ies2l-ZhH1WhO0aJqYVKz3tFJ62Hkt2si6xtD6UUjftGk0KF3iW'
            b'05oyNhzukT7gaXJMmsm2AA')
        assert tevt == (
            b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EEOByNw2UfZgk7kqNF_JE8jU'
            b'XDVde4V_KnODfZBmap1U","i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNk'
            b'A6zVVqg","p":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s":'
            b'"1","bt":"1","br":[],"ba":["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNp'
            b'WnZU_YEU"]}-GAB0AAAAAAAAAAAAAAAAAAAAAAgElQ-JFNVR4I_wumyv-S6YGv76'
            b'eGuXjx2coApDSyCEInM')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EEOByNw2UfZgk7kqNF_JE8jUXDVde4V_KnODfZBmap1U'

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON000160_","t":"bis","d":"E06RacBCSX5uWKlxEV8gNdZn'
                        b'stY4itTHiBsHuqX3_7Vs","i":"EG5LDGAwp9rrJUwAfsyv1dOvcMG9hhO0qHVNh'
                        b'iFLWrc8","ii":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s"'
                        b':"0","ra":{"i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s'
                        b'":1,"d":"EEOByNw2UfZgk7kqNF_JE8jUXDVde4V_KnODfZBmap1U"},"dt":"20'
                        b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEDCs'
                        b'gExJ5uJWUTXmJFhWfZO4V1P1AOMssALIzbRbqlYo')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EDCsgExJ5uJWUTXmJFhWfZO4'
                        b'V1P1AOMssALIzbRbqlYo","i":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0di'
                        b'SV_sdGw","s":"3","p":"ElQ-JFNVR4I_wumyv-S6YGv76eGuXjx2coApDSyCEI'
                        b'nM","a":[{"i":"EG5LDGAwp9rrJUwAfsyv1dOvcMG9hhO0qHVNhiFLWrc8","s"'
                        b':"0","d":"E06RacBCSX5uWKlxEV8gNdZnstY4itTHiBsHuqX3_7Vs"}]}-AABAA'
                        b'jBPcdsLd_XpdZkJJZMuz7wRWBPBWrLAVLbI7VgvPA7pfV1kOStk9DJBtZu0RJ_wp'
                        b'FPDkjm2ukCXH2NfPeegrBA')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'E06RacBCSX5uWKlxEV8gNdZnstY4itTHiBsHuqX3_7Vs'

        tsn = issuer.tevers[issuer.regk].vcState(vcpre=ser.pre)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON00015f_","t":"brv","d":"EHRzc-eDDcC1q4OOQSGiXE24'
                        b'zuD-HyiNtYD4P5rU_GmE","i":"EG5LDGAwp9rrJUwAfsyv1dOvcMG9hhO0qHVNh'
                        b'iFLWrc8","s":"1","p":"E06RacBCSX5uWKlxEV8gNdZnstY4itTHiBsHuqX3_7'
                        b'Vs","ra":{"i":"EuUK4Q1-XrmsPZW44_HwGmRzWGzWkYbc0NZNkA6zVVqg","s"'
                        b':1,"d":"EEOByNw2UfZgk7kqNF_JE8jUXDVde4V_KnODfZBmap1U"},"dt":"202'
                        b'1-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAABAExKi8'
                        b'KGtM_0MnBZBnz-UhOl9pbXmQq7B6qSjLJzUn7Qw')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"ExKi8KGtM_0MnBZBnz-UhOl9'
                        b'pbXmQq7B6qSjLJzUn7Qw","i":"EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0di'
                        b'SV_sdGw","s":"4","p":"EDCsgExJ5uJWUTXmJFhWfZO4V1P1AOMssALIzbRbql'
                        b'Yo","a":[{"i":"EG5LDGAwp9rrJUwAfsyv1dOvcMG9hhO0qHVNhiFLWrc8","s"'
                        b':"1","d":"EHRzc-eDDcC1q4OOQSGiXE24zuD-HyiNtYD4P5rU_GmE"}]}-AABAA'
                        b'F2gXCAriZ5P1E0zrrmkVVuz_PBnQjQ9mIiMaXFCxeq__9ryit9wwmb8_i3fu5vjB'
                        b'foc1MmyqJl9jIEqbCJXuDw')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EHRzc-eDDcC1q4OOQSGiXE24zuD-HyiNtYD4P5rU_GmE'

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
            hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            issuer = Issuer(hab=hab, name="bob", noBackers=True, reger=reg, temp=True)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"
            assert ser.ked["t"] == "vcp"
            assert ser.ked["c"] == ["NB"]
            assert ser.ked["b"] == []
            assert ser.ked["bt"] == "0"

            ser = Serder(raw=kevt)
            assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"
            assert seal["s"] == "0"
            assert seal["d"] == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"

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
            assert ser.pre == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
            assert ser.ked["ri"] == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"
            assert ser.ked["t"] == "iss"

            ser = Serder(raw=kevt)
            assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
            assert seal["s"] == "0"
            assert seal["d"] == 'EYJoiPXenloR_Au2j9pR4fSxb3XICzlepPLalDks_kjs'

            issuer.revoke(creder=creder)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
            assert ser.ked["t"] == "rev"
            assert ser.ked["ri"] == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"

            ser = Serder(raw=kevt)
            assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
            assert seal["s"] == "1"
            assert seal["d"] == 'ER_MTXfX6ROo5HPIZibWH0wVNZacBz1ztNRdhUakF5LU'

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.ked["bt"] == "1"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert seal["s"] == "0"

        issuer.rotate(adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                            "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert ser.ked["t"] == "vrt"
        assert ser.ked["ba"] == ["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                 "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert seal["s"] == "1"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert ser.ked["t"] == "brv"
        seal = ser.ked["ra"]
        # ensure the ra seal digest matches the vrt event digest
        assert seal["d"] == vrtser.saider.qb64

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert seal["s"] == "1"

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, reger=reg, noBackers=True, estOnly=True, temp=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EkOHsPmFEtpOByvqk1r7FYBbi54kTeWNo97phizdlEnk"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ["NB"]
        assert ser.ked["bt"] == "0"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"
        assert ser.ked["k"] == ["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"]
        assert ser.ked["n"] == "ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EYej8jti_qR78oxlS4EEnJkS1N7EC_pBs11S7OwhJAhk"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
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
        assert ser.pre == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.saider.qb64 == 'E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY'
        ser = Serder(raw=kevt)
        assert ser.ked["t"] == "rot"

        issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                    "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert ser.ked["t"] == "vrt"
        assert issuer.backers == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU",
                                  "B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                  "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'EO4rxeZq_ZyfiYYaTKPi6LnwQ_EpLveZVT1d21a1Vlmw'

        # rotate to no backers
        issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "E7-tHhxEGQXtCOBKtKBAgaIjxUwAVp1JUuRiHZo3DAYY"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        ser = Serder(raw=tevt)
        assert ser.pre == "EH_SXUzNXYdBVP6ulTxNslyNlOWN0ws3oF_eCdNfq5nQ"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "EhtDTO-ax8fziNSVsgTkQ9JRPsN4LAft2v0diSV_sdGw"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'EAUQwLvElrZD_j0e4Q6ovn50tzRrFknV7Rxbx5D1H_YE'

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
