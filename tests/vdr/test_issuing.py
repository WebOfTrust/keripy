import pytest

from keri.base import keeping, directing
from keri.core.coring import Serder
from keri.db import dbing
from keri.vdr.issuing import Issuer


def test_issuer():
    with dbing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hab = buildHab(db, kpr)

        # setup issuer with defaults for allowBackers, backers and estOnly
        issuer = Issuer(hab=hab, name="test")
        assert issuer.incept == bytearray(
            b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"0",'
            b'"b":['
            b']}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAQElQxdAkGEMsdDn_'
            b'GFiYPU1eVgQ3z1MvVPEoAGP3THI3A')
        assert issuer.ianchor == bytearray(
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"1","t":"ixn",'
            b'"p":"Eg3wsIOW3RdCqhcG4xZ4uZhTA_qTE24DoLeyjFBB8rks",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0",'
            b'"d":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'
            b'"}]}-AABAAVDMZ3Zfu5Vhw4vIBBbh4oh7l6XACLfOFpS7VN_Tn0vrBlZuHxktv1D9S0Q_e-YbP-PXBjiAnkupzaQ50saSfAA')
        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

        tevt, kevt = issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (bytearray(
            b'{"v":"KERI10JSON0000d8_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"p":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg","s":"1","t":"vrt","bt":"1","br":[],'
            b'"ba":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAgEDbiEyQmi'
            b'-5ojLeMKJ5qTP0_hI2jwXCVEGL_L4Fsz1ws'))
        assert kevt == (bytearray(
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"2","t":"ixn",'
            b'"p":"ElQxdAkGEMsdDn_GFiYPU1eVgQ3z1MvVPEoAGP3THI3A",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"1",'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'
            b'"}]}-AABAAGICq27nb3bODX_ngwCSNHPtrpXauO8a6PRy7WvVf1emhc7DOmHU37A98FmU-BHHvDWGJE0vMWHjX34gMMaVmCw'))
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (bytearray(
            b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"ii":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0","t":"bis",'
            b'"ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAwEr2WTm676JbMe'
            b'OkJaZBCpt4TZOHbv4NzkIqJkGUDSZKk'))
        assert kevt == (bytearray(
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"3","t":"ixn",'
            b'"p":"EDbiEyQmi-5ojLeMKJ5qTP0_hI2jwXCVEGL_L4Fsz1ws",'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0",'
            b'"d":"E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw"}]}-AABAAdfJRx_1Xnjx7bbGwqT57HLkNZG40fUQ-9tbyTs7QzUpV'
            b'-mLx3mKAtY-XCsyCgMCwc7OjdiERp-JgpX-mODjeCw'))
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw'

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (bytearray(
            b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv",'
            b'"p":"E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw",'
            b'"ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABAEJs'
            b'-WG2wPvLXBQVVbhr8pEY2i0BZgBEE2rbPNFFvSzRA'))
        assert kevt == (bytearray(
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"4","t":"ixn",'
            b'"p":"Er2WTm676JbMeOkJaZBCpt4TZOHbv4NzkIqJkGUDSZKk",'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1",'
            b'"d":"Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c"}]}-AABAAje9hJDX4_PnD3h2tfTS8lEfLOqXjLp'
            b'-S8qCdyvHbHOnY07KpLC6flXopcLitQiRlvxCTIHGoy1FtxMRhlm47BA'))
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c'

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
        assert seal["d"] == "EnoxdX7INt30KUqLJkhobxGpGbEIk1ehQ6cKUtXKFjDc"

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        ser = Serder(raw=issuer.incept)
        assert ser.pre == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["b"] == ["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"]
        assert ser.ked["bt"] == "1"

        ser = Serder(raw=issuer.ianchor)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
        assert seal["s"] == "0"

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
        assert ser.ked["t"] == "vrt"
        assert ser.ked["ba"] == ["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                 "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"]

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
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


        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, name="test", noBackers=True, estOnly=True)
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

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"], estOnly=True)
        ser = Serder(raw=issuer.incept)
        assert ser.pre == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
        assert ser.ked["b"] == ["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"]
        assert ser.diger.qb64 == 'EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc'
        ser = Serder(raw=issuer.ianchor)
        assert ser.ked["t"] == "rot"

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'

        # rotate to no backers
        tevt, kevt = issuer.rotate(cuts=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        ser = Serder(raw=tevt)
        assert ser.pre == "EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        ser = Serder(raw=tevt)
        assert ser.pre == "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
        assert ser.ked["t"] == "rot"
        assert vrtser.diger.qb64 == 'ETtfhi2rdeM4yqMuBb1fLXMjZlG_n_I3N00JMfaIBUns'

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
