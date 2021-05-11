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
            b'{"v":"KERI10JSON0000a9_","i":"EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k",'
            b'"ii":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"0","t":"vcp","c":[],"bt":"0",'
            b'"b":[]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAAQEDxdQFijZVIxI9HBh4WXSqIutA9nURy986dxhIHH6SeY')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"1","t":"ixn",'
            b'"p":"EWrLpSwDwrVz5zeTvyunFitxwnFRnvCVSLKOHMsce2XA","a":["EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k",'
            b'"0","E8ZAv8TRo12im4Ve8BbMEDc6TSgdA5Bk-UE6bjn-B_4U'
            b'"]}-AABAAQm8Mjyfu0_1raHPdcDKBverkwbXZwSST3NpN9cai_XFXo0KDm4TIxa2wDPtfc6TDRysQxAbqq4VoZ4WzPXQHAQ')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == "E8ZAv8TRo12im4Ve8BbMEDc6TSgdA5Bk-UE6bjn-B_4U"

        tevt, kevt = issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k",'
            b'"p":"E8ZAv8TRo12im4Ve8BbMEDc6TSgdA5Bk-UE6bjn-B_4U","s":"1","t":"vrt","bt":"1","br":[],'
            b'"ba":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAAgEL0faoqzmgefFGElqqo6L7uCMQVtKFwTNDErS4IXzwe4')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"2","t":"ixn",'
            b'"p":"EDxdQFijZVIxI9HBh4WXSqIutA9nURy986dxhIHH6SeY","a":["EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k",'
            b'"1","Ew7qo4pvPCY1V7tnjD44t2DALO_nFeoBJXCfGDgf8JRo'
            b'"]}-AABAA1vdHXecUOeWVYW_6HMsfejutCtvBVbrBMS5KAs5fXg1FPkcWsGkkoZIkOSDoFbTW74uk0xjoHIWt_lAo-NqkDg')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "Ew7qo4pvPCY1V7tnjD44t2DALO_nFeoBJXCfGDgf8JRo"

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"ii":"EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k","s":"0","t":"bis",'
            b'"ra":{"i":"EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k","s":1,'
            b'"d":"Ew7qo4pvPCY1V7tnjD44t2DALO_nFeoBJXCfGDgf8JRo"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAAwEidtej07_APQ3IPNYwmZ_P2gUPotR4Z7w_v0s1xqT9lU')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"3","t":"ixn",'
            b'"p":"EL0faoqzmgefFGElqqo6L7uCMQVtKFwTNDErS4IXzwe4","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"0","Et4KVC-FR7JcUDdjyexxEhxoZFDizrk3fXBuPZ_9exFk'
            b'"]}-AABAATLrI_q1pApJoZnnOQXi86tOPcdUs0TzKWs6tVIyHzdFzaYyMFKxjUjXYXSsHcXWQQUQUvWNlbv0g_H9vLNbzAw')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "Et4KVC-FR7JcUDdjyexxEhxoZFDizrk3fXBuPZ_9exFk"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv",'
            b'"p":"Et4KVC-FR7JcUDdjyexxEhxoZFDizrk3fXBuPZ_9exFk",'
            b'"ra":{"i":"EQm5xam50g9di3k-qpqq8DkxD--Eapo-1JwCbauzF99k","s":1,'
            b'"d":"Ew7qo4pvPCY1V7tnjD44t2DALO_nFeoBJXCfGDgf8JRo"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAABAEUcbtZ_ELtswfE3EHJAhnweej_e4jCpWgfz61mFJG5AY')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"4","t":"ixn",'
            b'"p":"Eidtej07_APQ3IPNYwmZ_P2gUPotR4Z7w_v0s1xqT9lU","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"1","EsnQ8lmJKeX04-rXuNREtT9YQCH3xHHT9_0hlnBkiTXE"]}-AABAA3fc99I6dfXeUprO2wDYMjlUUNsmVVG-jwNDT9AiK'
            b'-BIDIq8RuQaCcghdEoiYZAVcPLzFAZNOtNwMIEHOgLKlDQ')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "EsnQ8lmJKeX04-rXuNREtT9YQCH3xHHT9_0hlnBkiTXE"

        # issuer, not allowed to issue backers
        issuer = Issuer(hab=hab, name="test", allowBackers=False)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000ad_","i":"EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc",'
            b'"ii":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"0","t":"vcp","c":["NB"],"bt":"0",'
            b'"b":[]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAABQEiiFkqt9ojWAIPPlhzU1V8Jos3K9DVScySk4UgRIN7Uc')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"5","t":"ixn",'
            b'"p":"EUcbtZ_ELtswfE3EHJAhnweej_e4jCpWgfz61mFJG5AY","a":["EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc",'
            b'"0","E5G_fNyV7ZnmpNDcihRGvABYF_qJocTcrkwQ2I1p-G3Q'
            b'"]}-AABAAipfXUJhHXy7PiZdYKJcFD063yNM4ybAJW2L4FC_Rxe7TL2wVP_PnQrMAyG5BJLlz52fx11ii50T8MwirKOAfDg')

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000092_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","t":"iss",'
            b'"ri":"EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc"}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAABgEeGLr_q3EGQwhT3wdXN3AeEO91gJ3tR94lJjPDMr6vnw')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"6","t":"ixn",'
            b'"p":"EiiFkqt9ojWAIPPlhzU1V8Jos3K9DVScySk4UgRIN7Uc","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"0","EZKyDISOdQeWwSZOcJ0tgrXU3Ve7Zpk_NEMtWcu5yRs8"]}-AABAAl9SNGk8XPsWDqqY6PScHdiJF5IGHlPQMTL_2trL-6NPz'
            b'-GRd6eLBnfkJ24FBTFVhMQa1EpuYpopHF2hVheI2AQ')

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000091_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"rev",'
            b'"p":"EZKyDISOdQeWwSZOcJ0tgrXU3Ve7Zpk_NEMtWcu5yRs8"}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAABwEZMMja4DZF-s1v8KBCJgpURCMWg9eyZshUwhCXV2-PHc')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"7","t":"ixn",'
            b'"p":"EeGLr_q3EGQwhT3wdXN3AeEO91gJ3tR94lJjPDMr6vnw","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"1","E6nlcS8KZ0wWBaiNd-sKHKn6z9FPY3GUqjGwo-TwiDBw'
            b'"]}-AABAAKFFq486pIOZdCZbzWSKA80dIXEHTMJSA9m4omgb3JMRdSKXPNKki7bbZ5eZPPfNtZV6WxdcotpZPUWZix_TCDg')

        # issuer, allowed backers, initial set of backers
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000d7_","i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"ii":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"0","t":"vcp","c":[],"bt":"1",'
            b'"b":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAACAE8PBXqykTBFSi-8mpfxLTZfPpvJjtGk5wt9gVuKrUxlo')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"8","t":"ixn",'
            b'"p":"EZMMja4DZF-s1v8KBCJgpURCMWg9eyZshUwhCXV2-PHc","a":["EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"0","E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4"]}-AABAA8B5uQ8kAdeMFPO6F2gGqMVcIlHKe'
            b'-YODgyoxIgV7CYIo3D0X76hVEyN8_LAhkFQsTUqHxVU1Hs5vcgPjpjRVDA')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000105_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"ii":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":"0","t":"bis",'
            b'"ra":{"i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":0,'
            b'"d":"E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAACQE1EPhqAXfejA9TxVkPivU3jjGKnojkjl1Z27213JIf5Q')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"9","t":"ixn",'
            b'"p":"E8PBXqykTBFSi-8mpfxLTZfPpvJjtGk5wt9gVuKrUxlo","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"0","E56bo_Hkp6cuYvmKBzB8r4Pd5DUqZgpCRklv0vMi4_ro"]}-AABAAPutryRAZzz49uIhJ8QVgDQyu7FhIn2joGkKj5Lb4vamj'
            b'-fy9Owt21lzWSdt8JwF4BBVItZc22DuwThE00Z17Bw')

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)

        assert tevt == (
            b'{"v":"KERI10JSON000107_","i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"p":"E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4","s":"1","t":"vrt","bt":"3","br":[],'
            b'"ba":["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",'
            b'"ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAACgEXPuxfNlH6X7k_eLi9tdr1VxxnO33lWypepQReiTYhiw')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"a","t":"ixn",'
            b'"p":"E1EPhqAXfejA9TxVkPivU3jjGKnojkjl1Z27213JIf5Q","a":["EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"1","EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ'
            b'"]}-AABAAkW9YLJMBAh7uv0AMj0w1bYlbrAOKINq8gaA6XitniVba19aMiE1F_Ixt2lSp8c08ZzaD6jTurkSwywFOiuFkDA')

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8")
        assert tevt == (
            b'{"v":"KERI10JSON000104_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","t":"brv",'
            b'"p":"E56bo_Hkp6cuYvmKBzB8r4Pd5DUqZgpCRklv0vMi4_ro",'
            b'"ra":{"i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":1,'
            b'"d":"EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAACwEUwv5lqIkzT2ggiNEhqI2G1iSONQ0JiSJSR73yVL7koU')
        assert kevt == (
            b'{"v":"KERI10JSON0000f9_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"b","t":"ixn",'
            b'"p":"EXPuxfNlH6X7k_eLi9tdr1VxxnO33lWypepQReiTYhiw","a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",'
            b'"1","Ecz7AZHxRfyssgAbKisdYTx9uAnTOHK8rZl1HgwU0CMg"]}-AABAAFx6wyqcClR6QS4'
            b'-AGQ9n1XzFZJyk42s1A9C27cYanSOhEBRhkTFXJi3-jh7SNB0QKtmSFIHs6dgENSfrFrpFAQ')

        # ensure the ra seal digest matches the vrt event digest
        assert vrtser.diger.qb64 == "EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ"

        # issuer, no backers allowed, establishment events only
        issuer = Issuer(hab=hab, name="test", allowBackers=False, estOnly=True)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000ad_","i":"EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc",'
            b'"ii":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"0","t":"vcp","c":["NB"],"bt":"0",'
            b'"b":[]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAADAEYbYjRpELXLRSPZ5FMwAMFeiLCXfFSAaO5dVP0hjDe_8')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON000183_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"c","t":"rot",'
            b'"p":"EUwv5lqIkzT2ggiNEhqI2G1iSONQ0JiSJSR73yVL7koU","kt":"1",'
            b'"k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],'
            b'"n":"ELqHYQwWR0h2vP1_cxTsutU0wKJ_NrwBVKJCgPgWGgwc","wt":"0","wr":[],"wa":[],'
            b'"a":["EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc","0",'
            b'"E5G_fNyV7ZnmpNDcihRGvABYF_qJocTcrkwQ2I1p-G3Q'
            b'"]}-AABAALsZTUshZv6w2WgeDENJZsW2i039X5vL0up76PLlXxF37FKqMwXjnJc6AoTl1qKvAQFdHslJweubxIyhOAdxKAw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON00008d_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"0","t":"iss",'
            b'"ri":"EzW6ql1cAZMMu9zx-0233Z0pRUQkP6vfDGyFUkWyFZTc"}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAADQEQP6IDCpP6GgdmpiQngNcDxx027lfMy01VK9V26Bg2Yk')
        assert kevt == (
            b'{"v":"KERI10JSON00017e_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"d","t":"rot",'
            b'"p":"EYbYjRpELXLRSPZ5FMwAMFeiLCXfFSAaO5dVP0hjDe_8","kt":"1",'
            b'"k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],'
            b'"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","wr":[],"wa":[],'
            b'"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","0",'
            b'"EtKUY74jmqU1pDw_v2V2_0Pf8rHc01X3AZ6Ie9iVk7bc'
            b'"]}-AABAAaLuoLtrtTDcLzvZlCfwYD4IeWqNmb2HzKqqk2rdL8OHc7v2K_viaaUAJBMV9mII4mS-GDVeQpNWF_8e8_6bOCA')
        ser = Serder(raw=tevt)
        assert ser.diger.qb64 == "EtKUY74jmqU1pDw_v2V2_0Pf8rHc01X3AZ6Ie9iVk7bc"

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON00008c_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1","t":"rev",'
            b'"p":"EtKUY74jmqU1pDw_v2V2_0Pf8rHc01X3AZ6Ie9iVk7bc"}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAADgE6K-BKGDmTqX189sNUueYLwRfn1L8AZf36T5lp6crEIY')
        assert kevt == (
            b'{"v":"KERI10JSON00017e_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"e","t":"rot",'
            b'"p":"EQP6IDCpP6GgdmpiQngNcDxx027lfMy01VK9V26Bg2Yk","kt":"1",'
            b'"k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],'
            b'"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],'
            b'"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","1",'
            b'"EHpVp6dow2ZiVqq_8vp9RxQCKC4BJIY8QVIirqsxojfE'
            b'"]}-AABAAXumAu115kpjA7QPJD12DgaMexxDUQAjNd0IBKEaVz8BWC4yvCLi1h0O31tZVvO-54QNCZgMo8CQPsMkZp9QqCA')

        with pytest.raises(ValueError):
            issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        # issuer, backers allowed, initial backer, establishment events only
        issuer = Issuer(hab=hab, name="test", baks=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"], estOnly=True)
        assert issuer.incept == (
            b'{"v":"KERI10JSON0000d7_","i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"ii":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"0","t":"vcp","c":[],"bt":"1",'
            b'"b":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAADwEw7BAi9QM_NQWmE3uExDG8-2vv4np3t41ulcY2NIbWiQ')
        assert issuer.ianchor == (
            b'{"v":"KERI10JSON000183_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"f","t":"rot",'
            b'"p":"E6K-BKGDmTqX189sNUueYLwRfn1L8AZf36T5lp6crEIY","kt":"1",'
            b'"k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],'
            b'"n":"EDs-qIrh79lTtoIz4K9q_vu7-avDc79YkNCfK49HpwQg","wt":"0","wr":[],"wa":[],'
            b'"a":["EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","0",'
            b'"E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4"]}-AABAARHm-78IQYUdjh0Y6ULUJDAlP9MHm_paGxCqLn'
            b'-946SkAVicxGznV2iakGll1cDBSYLeh-ZUwABKnmb_VOBvMCw')
        ser = Serder(raw=issuer.incept)
        assert ser.diger.qb64 == "E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4"

        tevt, kevt = issuer.rotate(adds=["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",
                                         "ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"])
        vrtser = Serder(raw=tevt)
        assert tevt == (
            b'{"v":"KERI10JSON000107_","i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"p":"E2Coarhq0Kuf783I6o3lV-R8ZEtJX4z7ImUcHXcL_ZG4","s":"1","t":"vrt","bt":"3","br":[],'
            b'"ba":["EtEBUSHpJDMfzHdDt3QCtrA-iVlP-0DT03AdqeeDa7vs",'
            b'"ERVZTggTUOPmLcWBESrxcI-VsB48FerF6sz2boziikcY"]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAEAEEaChrt0rTHOh7ruCmS21-MNwse69UBtkfAG4jZbp3PU')
        assert kevt == (
            b'{"v":"KERI10JSON000184_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"10","t":"rot",'
            b'"p":"Ew7BAi9QM_NQWmE3uExDG8-2vv4np3t41ulcY2NIbWiQ","kt":"1",'
            b'"k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],'
            b'"n":"EvbWtNrsw7dfaWRiDMXcF6P90KM1gdfPhg7FWTIwD39c","wt":"0","wr":[],"wa":[],'
            b'"a":["EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","1",'
            b'"EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ"]}-AABAAVlE'
            b'-koeuyJTSQ8QZLi9qKeShpXBsx36Jrbi39CCGss9s2NNJFlxMwgV2ruGMLsE-kZf2t7QMM59dX6pA3RXHBw')

        tevt, kevt = issuer.issue(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON000100_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z",'
            b'"ii":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":"0","t":"bis",'
            b'"ra":{"i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":1,'
            b'"d":"EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAEQENBjlE-A2Bw8RvMUlEKKgMnqdOmUXX_fh13q70kap3dU')
        assert kevt == (
            b'{"v":"KERI10JSON00017f_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"11","t":"rot",'
            b'"p":"EEaChrt0rTHOh7ruCmS21-MNwse69UBtkfAG4jZbp3PU","kt":"1",'
            b'"k":["DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4"],'
            b'"n":"EpusdZwamtwTwqtwOenXWKQ0FpX9yWnq0XHlOEgQmss0","wt":"0","wr":[],"wa":[],'
            b'"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","0",'
            b'"EhfUPKVqq2L8aStMHg6xECarNnMkV3lGV7SZUG70auWo"]}-AABAATwnY8DSMefcwO4PZ3YaHXqmT'
            b'-9onKrgN8v6Y3bjoZGnsRjoBzweG0GtbO-XHxG1g3vz68Ks3Vij2jHRWe-v6Bw')
        assert vrtser.diger.qb64 == "EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ"

        # rotate to no backers
        tevt, kevt = issuer.rotate(cuts=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])
        assert tevt == (
            b'{"v":"KERI10JSON0000d8_","i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ",'
            b'"p":"EKaQVivdNmHRa_3cjdqv_2PLAu9CU0ppXb2GuJ7j0UTQ","s":"2","t":"vrt","bt":"0",'
            b'"br":["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"],'
            b'"ba":[]}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAEgEke_p'
            b'-lOclUAeAubTU0T9ko4RO-40uzymdbzfcENy8yk')
        assert kevt == (
            b'{"v":"KERI10JSON000184_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"12","t":"rot",'
            b'"p":"ENBjlE-A2Bw8RvMUlEKKgMnqdOmUXX_fh13q70kap3dU","kt":"1",'
            b'"k":["DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],'
            b'"n":"ER0SqaQnpyIxxtL_UFvE8wpooAjKNiq36zhpwwbfuZow","wt":"0","wr":[],"wa":[],'
            b'"a":["EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","2",'
            b'"EWC-_ZzRRQkXR94q6FtT4--xZy6NTqZlqzKT1W3Zfp5s"]}-AABAAJgygsjOQCWbQR'
            b'-rgHW01WxlAKemgCSWT8YD0GK1XeXWEPkPeZeLu2MyMEzAKgmrOhqb3vs1uEB2HOzODoUn2Cw')
        vrtser = Serder(raw=tevt)

        tevt, kevt = issuer.revoke(vcdig="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z")
        assert tevt == (
            b'{"v":"KERI10JSON0000ff_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","s":"1","t":"brv",'
            b'"p":"EhfUPKVqq2L8aStMHg6xECarNnMkV3lGV7SZUG70auWo",'
            b'"ra":{"i":"EVnmskszWLvlEVJtRSDb00ah4SWBpzDpNy8NMbBZPccQ","s":2,'
            b'"d":"EWC-_ZzRRQkXR94q6FtT4--xZy6NTqZlqzKT1W3Zfp5s"}}-eABEIGo5cJoRC7xHsvuNUcd6T5zMSmte11'
            b'-oNiu7KGbdD7g0AAAAAAAAAAAAAAAAAAAAAEwE0pvXKShpXC_BvHBcG4licI1WaCqa-18ZOU0CGBEoXnQ')
        assert kevt == (
            b'{"v":"KERI10JSON00017f_","i":"EIGo5cJoRC7xHsvuNUcd6T5zMSmte11-oNiu7KGbdD7g","s":"13","t":"rot",'
            b'"p":"Eke_p-lOclUAeAubTU0T9ko4RO-40uzymdbzfcENy8yk","kt":"1",'
            b'"k":["DiDeeYNZLsQncGJZ6DR54gAy-HySmzzgl61KFMZ4iR0U"],'
            b'"n":"E9IUWbvzBjn0ubo_lpKsjCb6ajDS1V23iLHrJFHZ2rVk","wt":"0","wr":[],"wa":[],'
            b'"a":["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z","1",'
            b'"EjrzNKh2IeMZ2xGU_ZniakCqDk-J3wabITvA3yYFXYUI"]}-AABAAHZODU22gqpI7O_aigpgkGTnfhYmy-ZLt1r3xwei'
            b'-Ez76mokHrvcEVw8IeqhVnv7_x6gr1MGvtqfe-UbFbccQCg')
        assert vrtser.diger.qb64 == "EWC-_ZzRRQkXR94q6FtT4--xZy6NTqZlqzKT1W3Zfp5s"

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
