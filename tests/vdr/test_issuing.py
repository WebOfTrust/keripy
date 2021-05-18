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
        assert issuer.incept == (b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkD'
                                b'GeLWHb9vSY","ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",'
                                b'"s":"0","t":"vcp","c":[],"bt":"0","b":[]}-eABEaKJ0FoLxO1TYmyuprg'
                                b'uKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAQEoDaZfC2yqtPwKJ'
                                b'BrhAGzP20SOslMZ-eQ7hAbl3w4JP0')
        assert issuer.ianchor == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                                b'k5aMtSrMtY","s":"1","t":"ixn","p":"Eg3wsIOW3RdCqhcG4xZ4uZhTA_qTE'
                                b'24DoLeyjFBB8rks","a":["EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9'
                                b'vSY","0","EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg"]}-AABAAw'
                                b'3jupSvehfh-Ow0v_E3Er49HUvwQp0Qa0P9KYNdaf9ihtzZU0bJtrbIW1z6eMoR3B'
                                b'52SDSxw9gfMmqlZRZfaBQ')
        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

        tevt, kevt = issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (b'{"v":"KERI10JSON0000d8_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkD'
                        b'GeLWHb9vSY","p":"EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg","'
                        b's":"1","t":"vrt","bt":"1","br":[],"ba":["EqoNZAX5Lu8RuHzwwyn5tCZ'
                        b'Te-mDBq5zusCrRo5TDugs"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5'
                        b'aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAAgEoDJpf8xcmVXj3chkgVpVXvFgAaHyohm'
                        b'v-Bkgjsf5yf4')
        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"2","t":"ixn","p":"EoDaZfC2yqtPwKJBrhAGzP20SOslM'
                        b'Z-eQ7hAbl3w4JP0","a":["EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9'
                        b'vSY","1","Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo"]}-AABAAG'
                        b'XF1gyvCxtP3GaL-MenYOYSAqf0_BzzyRknY6mhCohXK5cIA0CrJfkPandYmDvGxo'
                        b'63K0BPxCR3ey6PbjabkBg')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xuo'

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","ii":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
                        b'"s":"0","t":"bis","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDG'
                        b'eLWHb9vSY","s":1,"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9x'
                        b'uo"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAA'
                        b'AAAAAAAAAAAAwEJDkcdO3kE_gFLxSZA53HsEr9DK3gI1j6qEcwsZjzcZo')
        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"3","t":"ixn","p":"EoDJpf8xcmVXj3chkgVpVXvFgAaHy'
                        b'ohmv-Bkgjsf5yf4","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","0","E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw"]}-AABAAN'
                        b'bk_fVhHJVPZpwLA2Bmj9ZvD6T885Krwd8RJn2AGgQHVux7fsr-ZW4BXtFT7DW9Cj'
                        b'jXkxP8gBSmIQt9gHPljBA')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'E_RmCtCYGKOUj9-r2HbZlTOTzrViYvlthhlhZFElyjzw'

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","s":"1","t":"brv","p":"E_RmCtCYGKOUj9-r2HbZlTOTzrViY'
                        b'vlthhlhZFElyjzw","ra":{"i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGe'
                        b'LWHb9vSY","s":1,"d":"Ex1ZICku_jaiYzNIjfw1Q46T_srpyz7YJwpqS1xA9xu'
                        b'o"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAA'
                        b'AAAAAAAAAABAEUQewfkI5B3VEU1w0BPpikSBdchw52PW4MrMcgizKVpc')

        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"4","t":"ixn","p":"EJDkcdO3kE_gFLxSZA53HsEr9DK3g'
                        b'I1j6qEcwsZjzcZo","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","1","Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c"]}-AABAA3'
                        b'3POBHT4hao0mAXiOAsji3ft-NLbGRAVJ1kh1VBu9eTddSO6mUYwZpQCDgQc2SwqS'
                        b'C7VuegB_UVHbRtQcNiLCA')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'Ei1-r5vju2kh44KY09nd1KzeB1mq5_a33CwlYFs0tH3c'

        # issuer, not allowed to issue backers
        issuer = Issuer(hab=hab, name="test", allowBackers=False)
        assert issuer.incept == (b'{"v":"KERI10JSON0000ad_","i":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEG'
                                b'I0egFyLehw","ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",'
                                b'"s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}-eABEaKJ0FoLxO1TYmy'
                                b'uprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAABQEAUius1E3mN'
                                b'za_tVygjmKAd5tIz9JVAP8PTLaEHwnx7w')
        assert issuer.ianchor == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                                b'k5aMtSrMtY","s":"5","t":"ixn","p":"EUQewfkI5B3VEU1w0BPpikSBdchw5'
                                b'2PW4MrMcgizKVpc","a":["Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyL'
                                b'ehw","0","ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4"]}-AABAAN'
                                b'Tokkv5aZ_MPLauMFsgzASyFs5qMb4-fo7HIofmpRa-XMfDS9vccchXXZb47774Be'
                                b'YR6Nljg9m_ehk3b8NnTCg')
        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000092_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","s":"0","t":"iss","ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23'
                        b'QKdJEGI0egFyLehw"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrM'
                        b'tY0AAAAAAAAAAAAAAAAAAAAABgErPUCiDOsokTzqSx3ktSFx6P6bhfWLps3PbvbY'
                        b'ZIdjMw')
        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"6","t":"ixn","p":"EAUius1E3mNza_tVygjmKAd5tIz9J'
                        b'VAP8PTLaEHwnx7w","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","0","EXTVuADWAm9XOG6XKMyKRs8FO2dYPFo12rinap96BUjU"]}-AABAAf'
                        b'tQ5Ccj6aiZCVArCRlcBPhUKnO0m5q75dRgs316rxbsbEdXC3lB2AC4TWCMB0EVv5'
                        b'rzGRu6Gnw6134VpkkrPCw')


        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000091_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","s":"1","t":"rev","p":"EXTVuADWAm9XOG6XKMyKRs8FO2dYP'
                        b'Fo12rinap96BUjU"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMt'
                        b'Y0AAAAAAAAAAAAAAAAAAAAABwEpzwTULkTXErmB12S-vR4Ysi22kFCtqaV9_uoP2'
                        b'zBWNE')
        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"7","t":"ixn","p":"ErPUCiDOsokTzqSx3ktSFx6P6bhfW'
                        b'Lps3PbvbYZIdjMw","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","1","EgaGSsEExjY_19HbFsfWjtrj_nmtYmDU23qaod0KSr2o"]}-AABAAM'
                        b'w_8vSj-GBc1dMDTeNZg1sRhqOOBIROUDXAEvY5nICWhgp1RP-XYOYaVlJpLOLN6M'
                        b'nm6JU_z3rvsq475D4WsBQ')
        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert issuer.incept == (b'{"v":"KERI10JSON0000d7_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78'
                                b'p90WN3sG3I","ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",'
                                b'"s":"0","t":"vcp","c":[],"bt":"1","b":["EqoNZAX5Lu8RuHzwwyn5tCZT'
                                b'e-mDBq5zusCrRo5TDugs"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5a'
                                b'MtSrMtY0AAAAAAAAAAAAAAAAAAAAACAERI1IUUGtVVKDEqLw59qPJzIIwRFVU1sN'
                                b'n__B8Z6GgXk')
        assert issuer.ianchor == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                                b'k5aMtSrMtY","s":"8","t":"ixn","p":"EpzwTULkTXErmB12S-vR4Ysi22kFC'
                                b'tqaV9_uoP2zBWNE","a":["EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3s'
                                b'G3I","0","EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc"]}-AABAAZ'
                                b'Zo51JRK2aU0zppx12N584195BP-UjAtCly9_Z1dfuoUQz5yV4m_NJSt-w86t9VsH'
                                b'UMDtI20EbRtenypM3NyDw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","ii":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I",'
                        b'"s":"0","t":"bis","ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p'
                        b'90WN3sG3I","s":0,"d":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJ'
                        b'Wc"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAA'
                        b'AAAAAAAAAAACQETPkpmuLwJY4SXHPw0kjrKG5CYTTkf-OMxTgDnBFx7_k')
        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"9","t":"ixn","p":"ERI1IUUGtVVKDEqLw59qPJzIIwRFV'
                        b'U1sNn__B8Z6GgXk","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","0","Eu9JBjmUh10w5FLNORAdHuICsQ0VJ7WLoxvAA56fQr0w"]}-AABAAY'
                        b'Dm3lQah_ZQhX9wJmgHY6eWTtFozD2HLA004TIm-w2LIdqS-tw6pHSNgYQKBvNt0T'
                        b'4t2Y1pL0rsDBTGAEaw_Cg')

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)

        assert tevt == (b'{"v":"KERI10JSON000107_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78'
                        b'p90WN3sG3I","p":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc","'
                        b's":"1","t":"vrt","bt":"3","br":[],"ba":["EtEBUSHpJDMfzHdDt3QCtrA'
                        b'-iVlP-0DT03AdqeeDa7vs","ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2bozi'
                        b'ikcY"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAA'
                        b'AAAAAAAAAAAAACgE58EtRRxJROE7qmMnHV6fnP8FeFTBkX8eMlZbMNDFY6w')

        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"a","t":"ixn","p":"ETPkpmuLwJY4SXHPw0kjrKG5CYTTk'
                        b'f-OMxTgDnBFx7_k","a":["EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3s'
                        b'G3I","1","EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA"]}-AABAAp'
                        b'fZ6LoLMi4L_nabHRQZgW59NT3xt6IYrZ5D4lc7gUoalP-VraZ-TIThFSJSKsZER7'
                        b'W0Ev1FD6Zn5pb1JTAgKAg')

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z-i0d8","s":"1","t":"brv","p":"Eu9JBjmUh10w5FLNORAdHuICsQ0VJ'
                        b'7WLoxvAA56fQr0w","ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p9'
                        b'0WN3sG3I","s":1,"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_Yhu'
                        b'A"}}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAA'
                        b'AAAAAAAAAACwE71WIaYxok1t0xzC9OYyX1TYjsKG1o9LCnj_o_gsGH4M')

        assert kevt == (b'{"v":"KERI10JSON0000f9_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"b","t":"ixn","p":"E58EtRRxJROE7qmMnHV6fnP8FeFTB'
                        b'kX8eMlZbMNDFY6w","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i'
                        b'0d8","1","E9lcc71zkJXoc5E7qcCKOjZrhsNqqenXhTJMShSVek04"]}-AABAAq'
                        b'1GKbPLjSoNJLTiAbSP6EM0j2d3IOzw9LTbGGrXw3GVT6P6P-S9y8kPdmIXszP5PB'
                        b'CDJehu8GsgvxLR2f_alCg')

        # ensure the ra seal digest matches the vrt event digest
        assert vrtser.diger.qb64 == 'EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, name="test", allowBackers=False, estOnly=True)
        assert issuer.incept == (b'{"v":"KERI10JSON0000ad_","i":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEG'
                                b'I0egFyLehw","ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",'
                                b'"s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}-eABEaKJ0FoLxO1TYmy'
                                b'uprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAAAAAAADAEE4ISn-pS8v'
                                b'oter-KsYyHlMb8pxiG_Uazvjw-cNRlm8s')

        assert issuer.ianchor == (b'{"v":"KERI10JSON000183_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                                b'k5aMtSrMtY","s":"c","t":"rot","p":"E71WIaYxok1t0xzC9OYyX1TYjsKG1'
                                b'o9LCnj_o_gsGH4M","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j'
                                b'9kaxLhV3x8AQ"],"n":"ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc'
                                b'","bt":"0","br":[],"ba":[],"a":["Ezm53Qww2LTJ1yksEL06Wtt-5D23QKd'
                                b'JEGI0egFyLehw","0","ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4'
                                b'"]}-AABAATpTzNLJAV5CLD8znuTh2w73ZwqlsrOJIXa-XK2uY7QhnFHAD16yoDma'
                                b'BhdNFEKhFhqFLWnwUVe8myYkVnh8YCQ')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (b'{"v":"KERI10JSON00008d_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z","s":"0","t":"iss","ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJE'
                        b'GI0egFyLehw"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AA'
                        b'AAAAAAAAAAAAAAAAAAADQEDrLbf5h3GE06g3v-Ox2fFoolQyrvKW_sTrIxtQxuZAU')
        assert kevt == (b'{"v":"KERI10JSON00017e_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"d","t":"rot","p":"EE4ISn-pS8voter-KsYyHlMb8pxiG'
                        b'_Uazvjw-cNRlm8s","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_Z'
                        b'OoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU'
                        b'","bt":"0","br":[],"ba":[],"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH'
                        b'3ULvaU6Z","0","EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-mAL8-E-JoY"]}-A'
                        b'ABAANcQvSou7f1vUanuNPB0QWSsv0_NUupscqNl4sY7HijmH0eUDxiz9ryWa-UdQ'
                        b'nzHLI-gY7ITVB5JgXJMtxKkxBw')

        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == 'EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-mAL8-E-JoY'

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (b'{"v":"KERI10JSON00008c_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z","s":"1","t":"rev","p":"EnZpkCQXGps7J8hO5BbFrVG7KSaEd1J3u-'
                        b'mAL8-E-JoY"}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAA'
                        b'AAAAAAAAAAAAAAAAAADgE9-23oNfUrdBvXi-x89tgF8cO6mLCW5rGdQZ-C6agszE')

        assert kevt == (b'{"v":"KERI10JSON00017e_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"e","t":"rot","p":"EDrLbf5h3GE06g3v-Ox2fFoolQyrv'
                        b'KW_sTrIxtQxuZAU","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfA'
                        b'kt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
                        b'","bt":"0","br":[],"ba":[],"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH'
                        b'3ULvaU6Z","1","EVFiCQMPCoXtMpK-yoLWIVfwifQkLSH1Dj4RtzyOCVuo"]}-A'
                        b'ABAArUM8moanrzuFmxW48V4XE06zRkvnRHmtQtxt-q8ZqDoZeU0fTvJu_qQC0Qrb'
                        b'KVfVBNQ8ajphcJDdRP82d5aWAQ')

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"], estOnly=True)
        assert issuer.incept == (b'{"v":"KERI10JSON0000d7_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78'
                                b'p90WN3sG3I","ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",'
                                b'"s":"0","t":"vcp","c":[],"bt":"1","b":["EqoNZAX5Lu8RuHzwwyn5tCZT'
                                b'e-mDBq5zusCrRo5TDugs"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5a'
                                b'MtSrMtY0AAAAAAAAAAAAAAAAAAAAADwEvDmjSZQmSLqNzTJDq9rdDd7X-ffGPt6z'
                                b'uD2n51EFRLw')

        assert issuer.ianchor == (b'{"v":"KERI10JSON000183_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                                b'k5aMtSrMtY","s":"f","t":"rot","p":"E9-23oNfUrdBvXi-x89tgF8cO6mLC'
                                b'W5rGdQZ-C6agszE","kt":"1","k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAt'
                                b'bLA0Ljx-Grh8"],"n":"EDs-qIrh79lTtoIz4K9q_vu7-avDc79YkNCfK49HpwQg'
                                b'","bt":"0","br":[],"ba":[],"a":["EZRowynuVBviCH0ZfUx24mkMWn-jGRB'
                                b'm78p90WN3sG3I","0","EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc'
                                b'"]}-AABAAmTxyOx_38hK74779sN9vPXxcRHV49li9vt0RvAKlfuCBKG2hwWyy0P-'
                                b'9tFF_2VMvAfrWChEsjWPm9lsPeWIwBw')
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == 'EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc'

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)
        assert tevt == (b'{"v":"KERI10JSON000107_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78'
                        b'p90WN3sG3I","p":"EMMt2bfrg5ACOrCLQRuU21qWMBxDPwzIhOANvHKAGJWc","'
                        b's":"1","t":"vrt","bt":"3","br":[],"ba":["EtEBUSHpJDMfzHdDt3QCtrA'
                        b'-iVlP-0DT03AdqeeDa7vs","ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2bozi'
                        b'ikcY"]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAA'
                        b'AAAAAAAAAAAAAEAEKKopp_VUWhCpagBvKuWMfuSwRe5gcmh4LO4kJB1rItE')
        assert kevt == (b'{"v":"KERI10JSON000184_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"10","t":"rot","p":"EvDmjSZQmSLqNzTJDq9rdDd7X-ff'
                        b'GPt6zuD2n51EFRLw","kt":"1","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r3'
                        b'8yo7kgDuyGkQM"],"n":"EvbWtNrsw7dfaWRiDMXcF6P90KM1gdfPhg7FWTIwD39'
                        b'c","bt":"0","br":[],"ba":[],"a":["EZRowynuVBviCH0ZfUx24mkMWn-jGR'
                        b'Bm78p90WN3sG3I","1","EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_Yhu'
                        b'A"]}-AABAAonXgmX0PD7e94oqW9yhkm9ydZjwivpNWEPPLIQkOzzvfqGlI79io4x'
                        b'FF8-8K8UWok5dfb9j9fhrqR-e9p23bBw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (b'{"v":"KERI10JSON000100_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z","ii":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3sG3I","s":"'
                        b'0","t":"bis","ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3'
                        b'sG3I","s":1,"d":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA"}}'
                        b'-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAA'
                        b'AAAAAAEQEoRSZSkIHCJjvW9KDO26tFW4VQkhZXVXuYm8OrfxUfh8')
        assert kevt == (b'{"v":"KERI10JSON00017f_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"11","t":"rot","p":"EKKopp_VUWhCpagBvKuWMfuSwRe5'
                        b'gcmh4LO4kJB1rItE","kt":"1","k":["DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwI'
                        b'J-3OjdYmMwxf4"],"n":"EpusdZwamtwTwqtwOenXWKQ0FpX9yWnq0XHlOEgQmss'
                        b'0","bt":"0","br":[],"ba":[],"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZ'
                        b'H3ULvaU6Z","0","EXklP9Aj6ZXeC4Ox-TFExo_pk5u-ocMacfq82evq0rVo"]}-'
                        b'AABAAIcH6E9px8Tcz2kbJd8vmOvcvnb4Pe2QYL5Y6hkbIPsymR7awzvThHx8qkXB'
                        b'G51sJIgUExNoyaAOnkp20psoeAQ')
        assert vrtser.diger.qb64 == 'EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA'

        # rotate to no backers
        tevt, kevt = issuer.rotate(cuts=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (b'{"v":"KERI10JSON0000d8_","i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78'
                        b'p90WN3sG3I","p":"EKwtenOwTRhQCzIiBWTPWPCWB6PQ9sF0pnPrsCS_YhuA","'
                        b's":"2","t":"vrt","bt":"0","br":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5'
                        b'zusCrRo5TDugs"],"ba":[]}-eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5'
                        b'aMtSrMtY0AAAAAAAAAAAAAAAAAAAAAEgEX0HvF8uLvwvQcbnMq1JaMqoPSiJ0RqZ'
                        b'dhyM7gWfYS4g')
        assert kevt == (b'{"v":"KERI10JSON000184_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"12","t":"rot","p":"EoRSZSkIHCJjvW9KDO26tFW4VQkh'
                        b'ZXVXuYm8OrfxUfh8","kt":"1","k":["DT1nEDepd6CSAMCE7NY_jlLdG6_mKUl'
                        b'KS_mW-2HJY1hg"],"n":"ER0SqaQnpyIxxtL_UFvE8wpooAjKNiq36zhpwwbfuZo'
                        b'w","bt":"0","br":[],"ba":[],"a":["EZRowynuVBviCH0ZfUx24mkMWn-jGR'
                        b'Bm78p90WN3sG3I","2","ETtfhi2rdeM4yqMuBb1fLXMjZlG_n_I3N00JMfaIBUn'
                        b's"]}-AABAARKOiQnD9BSRUqFg63Q3lUjyMAJ-cZiVVCHO4POe0iEAXdIRp4Ylzdt'
                        b'PJzVTRpuJC2YecICPXkEehBbnQhXwHBg')
        vrtser = Serder(raw=tevt)

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (b'{"v":"KERI10JSON0000ff_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3UL'
                        b'vaU6Z","s":"1","t":"brv","p":"EXklP9Aj6ZXeC4Ox-TFExo_pk5u-ocMacf'
                        b'q82evq0rVo","ra":{"i":"EZRowynuVBviCH0ZfUx24mkMWn-jGRBm78p90WN3s'
                        b'G3I","s":2,"d":"ETtfhi2rdeM4yqMuBb1fLXMjZlG_n_I3N00JMfaIBUns"}}-'
                        b'eABEaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY0AAAAAAAAAAAAAAAA'
                        b'AAAAAEwE97hmLY8BYtFhPxzmN0ZweLfeU_hU7RVgD8e6BvZA92U')
        assert kevt == (b'{"v":"KERI10JSON00017f_","i":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wu'
                        b'k5aMtSrMtY","s":"13","t":"rot","p":"EX0HvF8uLvwvQcbnMq1JaMqoPSiJ'
                        b'0RqZdhyM7gWfYS4g","kt":"1","k":["DiDeeYNZLsQncGJZ6DR54gAy-HySmzz'
                        b'gl61KFMZ4iR0U"],"n":"E9IUWbvzBjn0ubo_lpKsjCb6ajDS1V23iLHrJFHZ2rV'
                        b'k","bt":"0","br":[],"ba":[],"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZ'
                        b'H3ULvaU6Z","1","EI_uyS9EE7t3s_TD5PpqqpLXb3PfPt8K0J7VnNLF50-o"]}-'
                        b'AABAAdKHkxbgf1PgVw8dfg4taD8igLLzGlZkifbMcVL3cLOciDn6Ovi39Xsk36Y8'
                        b'a3xHh8WJkIfOaONYscc_bz-jJBw')
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
