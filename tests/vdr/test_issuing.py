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
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"0",'
            b'"b":['
            b']}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAQEoDaZfC2yqtP'
            b'wKJBrhAGzP20SOslMZ-eQ7hAbl3w4JP0')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"1","t":"ixn",'
            b'"p":"Eg3wsIOW3RdCqhcG4xZ4uZhTA_qTE24DoLeyjFBB8rks","a":["EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"0","EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg"]}-AABAAw3jupSvehfh'
            b'-Ow0v_E3Er49HUvwQp0Qa0P9KYNdaf9ihtzZU0bJtrbIW1z6eMoR3B52SDSxw9gfMmqlZRZfaBQ')
        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

        tevt, kevt = issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"p":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg","s":"1","t":"vrt","bt":"1","br":[],'
            b'"ba":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAgE798R6gQT07IP'
            b'vbLgNS5lmna6z4yZCU6B17AMhnRFrSI')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"2","t":"ixn",'
            b'"p":"EoDaZfC2yqtPwKJBrhAGzP20SOslMZ-eQ7hAbl3w4JP0",'
            b'"a":[{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"1",'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo"}]}-AABAACWbbcb2aGRWqFPFGDpYDjTf6LnsJHduP3rMl6LwNYo3W'
            b'-emSCfNSI5OcWu6REkTQfUuuWSAUjNblbsGukApFBw')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"ii":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":"0","t":"bis",'
            b'"ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAwE403h7Xmpxy'
            b'9k2uMVsHePwYpP37Sc5tEOcj3JiCvRyu4')
        assert kevt == (
            b'{"v":"KERI10JSON000109_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"3","t":"ixn",'
            b'"p":"E798R6gQT07IPvbLgNS5lmna6z4yZCU6B17AMhnRFrSI","a":[[{'
            b'"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0",'
            b'"d":"E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw'
            b'"}]]}-AABAA9z6vN6lUjX7UvrIkGad_LsZzeiHc82oGMwlShI2FE3MiadXq0344K1EJUK27ly9V3wODxGD-zBnpF-VJ5iwJCA')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw'

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv",'
            b'"p":"E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw",'
            b'"ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY","s":1,'
            b'"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABAEdJQZEBogJR'
            b'-F6VJ1MQNtcfiCt7jsSTEAdzaJGLhD0LQ')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"4","t":"ixn",'
            b'"p":"E403h7Xmpxy9k2uMVsHePwYpP37Sc5tEOcj3JiCvRyu4",'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1",'
            b'"d":"Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c'
            b'"}]}-AABAAwbhGtmBHVAdtwXF7_8lk4jbQXipEzJhQggj745Ms4IxVbVYklx_xFJQ-yj_SZvI7SeQD8YLo2sxv5aUx9sSTBg')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c'

        # issuer, not allowed to issue backers
        issuer = Issuer(hab=hab, name="test", noBackers=True)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000ad_","i":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":["NB"],"bt":"0",'
            b'"b":[]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABQEFUEapoe'
            b'-CsY8NDg5jCGglTMmmrGPjVHl0eHU6L08gjk')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"5","t":"ixn",'
            b'"p":"EdJQZEBogJR-F6VJ1MQNtcfiCt7jsSTEAdzaJGLhD0LQ","a":["Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw",'
            b'"0","ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4'
            b'"]}-AABAAktxU34VfV1A8ireInH26LQV1Bv24b52GjDzR5qqmeBl5DO6UAtU_S16VioEukblsC2oI2S7M6X2B-hiS7hyFBA')
        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000092_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","t":"iss",'
            b'"ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw'
            b'"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABgE0'
            b'TJu0XyIA5rxhhuD7ObZOqH8SPzPcrJ3Ma_7fdz_Lyk')
        assert kevt == (
            b'{"v":"KERI10JSON000109_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"6","t":"ixn",'
            b'"p":"EFUEapoe-CsY8NDg5jCGglTMmmrGPjVHl0eHU6L08gjk","a":[[{'
            b'"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0",'
            b'"d":"EXTVuADWAm9XOG6XKMyKRs8FO2dYPFo12rinap96BUjU"}]]}-AABAAdtac6LRtK8DEU0D9dtFMyYoWVO-MDaudgvwtonclSiX'
            b'-AVdwg1cbQvctV2qg3Hku7iWhtMXLhUMIxtkXOQcFCw')

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000091_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"rev",'
            b'"p":"EXTVuADWAm9XOG6XKMyKRs8FO2dYPFo12rinap96BUjU'
            b'"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABwEj'
            b'TI0_0BeTzBRu6mxu6elbatQy7m4wLZZ3OQ0Za_JQPQ')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"7","t":"ixn",'
            b'"p":"E0TJu0XyIA5rxhhuD7ObZOqH8SPzPcrJ3Ma_7fdz_Lyk",'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1",'
            b'"d":"EgaGSsEExjY_19HbFsfWjtrj_nmtYmDU23qaod0KSr2o"}]}-AABAAJys4R8ZmjvHn_TXEo_Jia1pYrPRxO2rAvJP-PNd'
            b'-RuOYBDHzz_IEC4HzEFBqiVAQ0cyb81rjxBJe3dfDNe_0AQ')
        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000d7_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"1",'
            b'"b":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAACAE97PqVDN3Eub'
            b'-8beXPqMIFoGDsbDlrG3hLZcD3t3oTP8')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"8","t":"ixn",'
            b'"p":"EjTI0_0BeTzBRu6mxu6elbatQy7m4wLZZ3OQ0Za_JQPQ","a":["EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"0","EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc"]}-AABAA1SfCnDphf70AM8YT-ODhvzUNA'
            b'-wd22p0JrWDxP_DzBr2dBxVR8OeTtFW5UtnFC7oC9xMxDacdscRR8iv3_hqAA')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"ii":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"0","t":"bis",'
            b'"ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":0,'
            b'"d":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAACQ'
            b'EBqtQ1HSKIARANXaF5igRuKfFXS4g-ThQYB2t25Snvzk')
        assert kevt == (
            b'{"v":"KERI10JSON000109_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"9","t":"ixn",'
            b'"p":"E97PqVDN3Eub-8beXPqMIFoGDsbDlrG3hLZcD3t3oTP8","a":[[{'
            b'"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0",'
            b'"d":"Eu9JBjmUh10w5FLNORAdHuICsQ0VJ7WLoxvAA56fQr0w"}]]}-AABAAvO05fpZQJiBHFPhbm'
            b'-x_KZFPYGZ9dOmwHno3Ke_Z_F73xLImhOAOC1xSjtcr-dbM1raZCC2sJlJyVG-QAQzgAA')

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)

        assert tevt == (
            b'{"v":"KERI10JSON000107_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"p":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc","s":"1","t":"vrt","bt":"3","br":[],'
            b'"ba":["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",'
            b'"ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAACgE_6_PjcDv7Iy2ai58YD'
            b'-kqGRYoMkogS34hk1KHaADGwE')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"a","t":"ixn",'
            b'"p":"EBqtQ1HSKIARANXaF5igRuKfFXS4g-ThQYB2t25Snvzk",'
            b'"a":[{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"1",'
            b'"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'
            b'"}]}-AABAANSt79BZYas02eh8IHPF_S6OdmPgbuRu3UzhTtgZWMmI9Xyy_gePe2O8VsZbUby3wVQpNQ6mAtCyEkw3FcgVMAw')

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv",'
            b'"p":"Eu9JBjmUh10w5FLNORAdHuICsQ0VJ7WLoxvAA56fQr0w",'
            b'"ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":1,'
            b'"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAACw'
            b'EtoZgKPmL14JPnd6J9LZDWS5fFcvnuEHZuAinL94rcAo')
        assert kevt == (
            b'{"v":"KERI10JSON000107_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"b","t":"ixn",'
            b'"p":"E_6_PjcDv7Iy2ai58YD-kqGRYoMkogS34hk1KHaADGwE",'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1",'
            b'"d":"E9lcc71zkJXoc5E7qcCKOjZrhsNqqenXhTJMShSVek04"}]}-AABAAqnlAjMxr1HJgm2-YwyirUfi7qX2YUnTA0'
            b'-_6LJl7ablTakJojDf5kii3mh9qI47SAnNd1lqSanhBFdnRYjjqAQ')

        # ensure the ra seal digest matches the vrt event digest
        assert vrtser.diger.qb64 == 'EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, name="test", noBackers=True, estOnly=True)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000ad_","i":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":["NB"],"bt":"0",'
            b'"b":[]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAADAELkfceguD'
            b'-go9iMe3qAiTSp_mj3e6Web4hxLwqzNjWAY')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON000183_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"c","t":"rot",'
            b'"p":"EtoZgKPmL14JPnd6J9LZDWS5fFcvnuEHZuAinL94rcAo","kt":"1",'
            b'"k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],'
            b'"n":"ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc","bt":"0","br":[],"ba":[],'
            b'"a":["Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw","0",'
            b'"ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4'
            b'"]}-AABAA5PjAzS_L1J0dCkYd4UzvR5Zt8Dr9YsDn7JS8o7991bni76IdxUlNPox6GOmwIQUVxa-kMo_DgCCqoc_EAeyPCw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON00008d_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"0","t":"iss",'
            b'"ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw'
            b'"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAADQ'
            b'Eh0INKJjqiv3WfiDDP4t3thc8bFyp6DYjweF8vCbhiPY')
        assert kevt == (
            b'{"v":"KERI10JSON00018e_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"d","t":"rot",'
            b'"p":"ELkfceguD-go9iMe3qAiTSp_mj3e6Web4hxLwqzNjWAY","kt":"1",'
            b'"k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],'
            b'"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","br":[],"ba":[],'
            b'"a":[[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"0",'
            b'"d":"EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-mAL8-E-JoY'
            b'"}]]}-AABAAQSpvf0nfdhy3KZVE5aIyIItZ8g_pZVQgf2DXLkzUNddeesMyBkwhOmlG4sg3I9quvtfgBWMKoQ0pR-_xo5IfCQ')

        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-mAL8-E-JoY'

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON00008c_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1","t":"rev",'
            b'"p":"EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-mAL8-E-JoY'
            b'"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAADg'
            b'EEA_q_p08SOR37yAtBvkID03Rwxu0hhcuoCPM4ZLbzrY')
        assert kevt == (
            b'{"v":"KERI10JSON00018c_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"e","t":"rot",'
            b'"p":"Eh0INKJjqiv3WfiDDP4t3thc8bFyp6DYjweF8vCbhiPY","kt":"1",'
            b'"k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],'
            b'"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1",'
            b'"d":"EVFiCQMPCoXtMpK-yoLWIVfwifQkLSH1Dj4RtzyOCVuo"}]}-AABAAQD2mn0v72pQtuTRVkzOGUM3IfpYN2AsbPxFfW3M'
            b'-0zXeE0pZxiD8E4uVUdw0XeJKErLvhTBN13WsmjZr8wMPDQ')

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"], estOnly=True)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000d7_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"1",'
            b'"b":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAADwEPoJTokYK9xvWA1-7r9OFFDjGbL'
            b'-BUYSkS0O-ljg0G8c')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON000183_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"f","t":"rot",'
            b'"p":"EEA_q_p08SOR37yAtBvkID03Rwxu0hhcuoCPM4ZLbzrY","kt":"1",'
            b'"k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],'
            b'"n":"EDs-qIrh79lTtoIz4K9q_vu7-avDc79YkNCfK49HpwQg","bt":"0","br":[],"ba":[],'
            b'"a":["EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","0",'
            b'"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc"]}-AABAA4JsJMDJJRR'
            b'-YIGeRX6n9xKWI0MXq0Cudm1EOFAvr9P24r7UaCQDrcETeJQXjZFkyNsSgVf6J_BfWx6MzQrffBw')
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc'

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)
        assert tevt == (
            b'{"v":"KERI10JSON000107_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"p":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc","s":"1","t":"vrt","bt":"3","br":[],'
            b'"ba":["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",'
            b'"ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY'
            b'"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAEAEiUSUaowV'
            b'-DfgrBuETPogb9gQ5VusNv1ktmEXosvJaEE')
        assert kevt == (
            b'{"v":"KERI10JSON000192_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"10","t":"rot",'
            b'"p":"EPoJTokYK9xvWA1-7r9OFFDjGbL-BUYSkS0O-ljg0G8c","kt":"1",'
            b'"k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],'
            b'"n":"EvbWtNrsw7dfaWRiDMXcF6P90KM1gdfPhg7FWTIwD39c","bt":"0","br":[],"ba":[],'
            b'"a":[{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"1",'
            b'"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'
            b'"}]}-AABAApKJyhDdBqeeU6BhOFMNEao9Iz8LguBFOOnAO2__4crjG9FgiL8Yk7ccDW5gbhhmfOYH-6_QYOiWmot409bOYAw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON000100_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z",'
            b'"ii":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"0","t":"bis",'
            b'"ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":1,'
            b'"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAEQE'
            b'KAUstCcX2wl_HDg9WS_dXBA3Ap0fNA-fKs-K43l1TtA')
        assert kevt == (
            b'{"v":"KERI10JSON00018f_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"11","t":"rot",'
            b'"p":"EiUSUaowV-DfgrBuETPogb9gQ5VusNv1ktmEXosvJaEE","kt":"1",'
            b'"k":["DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4"],'
            b'"n":"EpusdZwamtwTwqtwOenXWKQ0FpX9yWnq0XHlOEgQmss0","bt":"0","br":[],"ba":[],'
            b'"a":[[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"0",'
            b'"d":"EXklP9Aj6ZXeC4Ox-TFExo_pk5u-ocMacfq82evq0rVo'
            b'"}]]}-AABAAFaWmgYXLuAzasX4rQqv7zN9bJD7NPlYYBChWETjHsXxHgu4WTOPlQnH6l_IiXmqYu2Zn3XePm_rybzcC3fWCBg')
        assert vrtser.diger.qb64 == 'EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'

        # rotate to no backers
        tevt, kevt = issuer.rotate(cuts=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
            b'"p":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA","s":"2","t":"vrt","bt":"0",'
            b'"br":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"],'
            b'"ba":['
            b']}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAEgEO_e2'
            b'fScvSgM02vBlys1o4cYdLYewpBJPjMEqAZcJ05Y')
        assert kevt == (
            b'{"v":"KERI10JSON000192_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"12","t":"rot",'
            b'"p":"EKAUstCcX2wl_HDg9WS_dXBA3Ap0fNA-fKs-K43l1TtA","kt":"1",'
            b'"k":["DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],'
            b'"n":"ER0SqaQnpyIxxtL_UFvE8wpooAjKNiq36zhpwwbfuZow","bt":"0","br":[],"ba":[],'
            b'"a":[{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"2",'
            b'"d":"ETtfhi2rdeM4yqMuBb1fLXMjZlG_n_I3N00JMfaIBUns"}]}-AABAAleLK5gMaFERO1Ry_s10ccoKU_qBV5J'
            b'-vyaNdQ0HJjQN5X1kgBTfGY9NM56sbvTOmr64C9b0e0mDbfuwGQa9EAg')
        vrtser = Serder(raw=tevt)

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON0000ff_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1","t":"brv",'
            b'"p":"EXklP9Aj6ZXeC4Ox-TFExo_pk5u-ocMacfq82evq0rVo",'
            b'"ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":2,'
            b'"d":"ETtfhi2rdeM4yqMuBb1fLXMjZlG_n_I3N00JMfaIBUns'
            b'"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAEwE6-b'
            b'-eyNq_g1QUtPhKMPRB6apTvB25LhH4Ovlvi_6408')
        assert kevt == (
            b'{"v":"KERI10JSON00018d_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"13","t":"rot",'
            b'"p":"EO_e2fScvSgM02vBlys1o4cYdLYewpBJPjMEqAZcJ05Y","kt":"1",'
            b'"k":["DiDeeYNZLsQncGJZ6DR54gAy-HySmzzgl61KFMZ4iR0U"],'
            b'"n":"E9IUWbvzBjn0ubo_lpKsjCb6ajDS1V23iLHrJFHZ2rVk","bt":"0","br":[],"ba":[],'
            b'"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1",'
            b'"d":"EI_uyS9EE7t3s_TD5PpqqpLXb3PfPt8K0J7VnNLF50-o"}]}-AABAAv5KH40d_2dWQ81'
            b'-gmy1htSLvpTgZWq_IQLNkd5milXqvhBVQtMMhAt0b1LEqN24em5EhCU15IdHXdMievcqeCA')
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
