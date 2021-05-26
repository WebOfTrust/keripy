import logging

import pytest

from keri.base import keeping, directing
from keri.core.coring import Serder
from keri.db import dbing
from keri.vdr import viring
from keri.vdr.issuing import Issuer

from keri import help  # logger support


def test_issuer():
    # help.ogler.resetLevel(level=logging.DEBUG)
    with dbing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # setup issuer with defaults for allowBackers, backers and estOnly
        issuer = Issuer(hab=hab, name="bob", reger=reg)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"0",'
            b'"b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAAQElQxdAkGEMsdDn_GFiYPU1eVgQ3z1MvVPEoAGP3THI3A')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"1","t":"ixn",'
            b'"p":"Eg3wsIOW3RdCqhcG4xZ4uZhTA_qTE24DoLeyjFBB8rks",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0",'
            b'"d":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'
            b'"}]}-AABAAVDMZ3Zfu5Vhw4vIBBbh4oh7l6XACLfOFpS7VN_Tn0vrBlZuHxktv1D9S0Q_e-YbP-PXBjiAnkupzaQ50saSfAA')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

        tevt, kevt = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"p":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg","s":"1","t":"vrt","bt":"1","br":[],'
            b'"ba":["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU'
            b'"]}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEf12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"2","t":"ixn",'
            b'"p":"ElQxdAkGEMsdDn_GFiYPU1eVgQ3z1MvVPEoAGP3THI3A",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"1",'
            b'"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0"}]}-AABAAb-kk2ijQRZkVmmvWpRcyDLRZad3YOKOvev0yZq'
            b'-ay5QyW9J574kIUxOwgFbC-DUkRIKdPPHkBWZdPSjw6IT-Cg')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0'

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == bytearray(b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","ii":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0","t":"bis","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0"}}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEqShtJnn-xjtbY8Tesz_0V6jPlPPUomUThNgFbFmW4C4')
        assert kevt == bytearray(b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"3","t":"ixn","p":"Ef12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","d":"EEK-dBgrpgJOh322FaVLOEnZDhKS785Jx9YCz2_zbCHA"}]}-AABAADp5I4829RH3lt_BMons2A5Rz3HImJCzKx9AM1-IjeeM7kT8wPgkHfDWN88quV-YK0QJWyK4uBV-OmA9U-Mj3Ag')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "EEK-dBgrpgJOh322FaVLOEnZDhKS785Jx9YCz2_zbCHA"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == bytearray(b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv","p":"ERUVLLWRCZ3JwZ0pPaDMyMkZhVkxPRW5aRGhLUzc4NUo","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,"d":"EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0"}}-GAB0AAAAAAAAAAAAAAAAAAAAABAEGrumf0GeUHoUckTwkKpsZth72W8xa7yCzpgrZ9ttDUc')
        assert kevt == bytearray(b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"4","t":"ixn","p":"EqShtJnn-xjtbY8Tesz_0V6jPlPPUomUThNgFbFmW4C4","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","d":"EHR9ChXcp6P49dbi94FeZZKMfbcPLp3iahPgWXMfn5sk"}]}-AABAAfl7kaEycAdQmbLIQMedCjbUak5j5iT9M0HgVRNdOKdvGUH6abOgwTZWtwVo-ZPEqB1VZs7ZrT0pC3scKLMI2AQ')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "EHR9ChXcp6P49dbi94FeZZKMfbcPLp3iahPgWXMfn5sk"

        # issuer, not allowed to issue backers
        issuer = Issuer(hab=hab, name="test", noBackers=True)
        ser = Serder(raw=issuer.incept)
        assert ser.pre == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ["NB"]
        assert ser.ked["b"] == []
        assert ser.ked["bt"] == "0"

        ser = Serder(raw=issuer.ianchor)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
        assert seal["s"] == "0"
        assert seal["d"] == "ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["ri"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert seal["s"] == "0"
        assert seal["d"] == "EXTVuADWAm9XOG6XKMyKRs8FO2dYPFo12rinap96BUjU"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "rev"
        assert ser.ked["ri"] == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert seal["s"] == "1"
        assert seal["d"] == "Epb9TpQOCneEKGg9Ogc-xztVcYlc8iVbwzcXLtcr-Bfg"

    with dbing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        ser = Serder(raw=issuer.incept)
        print(ser.pre)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.ked["bt"] == "1"

        ser = Serder(raw=issuer.ianchor)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert seal["s"] == "0"

        tevt, kevt = issuer.rotate(adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                         "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
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

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "brv"
        seal = ser.ked["ra"]
        # ensure the ra seal digest matches the vrt event digest
        assert seal["d"] == vrtser.diger.qb64

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert seal["s"] == "1"

    with dbing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, reger=reg, noBackers=True, estOnly=True)
        ser = Serder(raw=issuer.incept)
        assert ser.pre == "Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ["NB"]
        assert ser.ked["bt"] == "0"

        ser = Serder(raw=issuer.ianchor)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert ser.ked["k"] == ["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"]
        assert ser.ked["n"] == "ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc"

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with dbing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, reger=reg, baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True)
        ser = Serder(raw=issuer.incept)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.diger.qb64 == 'EevCI-l5dfYW63xg1bQ52ldLQa3li8FBo-znWxNEzv7E'
        ser = Serder(raw=issuer.ianchor)
        assert ser.ked["t"] == "rot"

        tevt, kevt = issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                                 "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
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

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'ECQbOOZdBxpw5RTH4VvPXDSH_o2uYdPWSoWolW5tobgA'

        # rotate to no backers
        tevt, kevt = issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        ser = Serder(raw=tevt)
        assert ser.pre == "EaU321874i434f59ab7cMH6YlN52PJ395nrLS_6tLq6c"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'EnUD_KZu-dGpFSEWZOlFdQSydioYY78qIDPfzA7Fhr-Q'

    """ End Test """


def buildHab(db, kpr):
    kevers = dict()
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
    hab = directing.Habitat(ks=kpr, db=db, kevers=kevers, secrecies=secrecies, temp=True)
    return hab


if __name__ == "__main__":
    test_issuer()
