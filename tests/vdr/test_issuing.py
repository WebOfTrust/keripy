# -*- encoding: utf-8 -*-
"""
tests.vdr.issuing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core.coring import Serder
from keri.db import basing
from keri.vc import proving
from keri.vdr import credentialing


def test_issuer(mockHelpingNowUTC):
    # help.ogler.resetLevel(level=logging.DEBUG)

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)
        # setup issuer with defaults for allowBackers, backers and estOnly
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False)
        kevt, tevt = events(issuer)
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EHuiZ2zC5kfJlBV9wRh9pZxa'
                        b'QbJwmAhieX2odN-KuJYM","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
                        b'GI0Br6A","s":"1","p":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br'
                        b'6A","a":[{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
                        b':"0","d":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI"}]}-AABAA'
                        b'Ojwa_pLjlTnFDR_p0Bc5PsgW65gi0xFr1JIh49-RxBbpN28ReEPeTP_PlmAt_j-z'
                        b'93KrJkwRS9zD2rLH1cKoBA')
        assert tevt == (b'{"v":"KERI10JSON0000dc_","t":"vcp","d":"EWKCDqk4W2wseV-VnW-KpzvM'
                        b'pe2Y08bChQQPhmwgZdTI","i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPh'
                        b'mwgZdTI","ii":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s"'
                        b':"0","c":[],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAAQEHuiZ2zC'
                        b'5kfJlBV9wRh9pZxaQbJwmAhieX2odN-KuJYM')

        # ensure the digest in the seal from the key event matches the transacript event digest
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI'

        res = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
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
        assert tevt == (b'{"v":"KERI10JSON000160_","t":"bis","d":"ExvhloEw3f3WmD9wfdLcIEZQ'
                        b'uHQDa3tdRgG0H_jk8nK0","i":"ECZKX5Hnk2wREdIbSFJc5fydNndm4yOTXErl6'
                        b'BDL_KLw","ii":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
                        b':"0","ra":{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s'
                        b'":1,"d":"EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4"},"dt":"20'
                        b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEbDV'
                        b'9yKEEDP_FAhEJZKKRFVe4feirwi0Q7JBqByzskSY')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EbDV9yKEEDP_FAhEJZKKRFVe'
                        b'4feirwi0Q7JBqByzskSY","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
                        b'GI0Br6A","s":"3","p":"EaK53gpNuE4qiQFxIvxcrreEpu2_lEt0lz3GxvCHLI'
                        b'aw","a":[{"i":"ECZKX5Hnk2wREdIbSFJc5fydNndm4yOTXErl6BDL_KLw","s"'
                        b':"0","d":"ExvhloEw3f3WmD9wfdLcIEZQuHQDa3tdRgG0H_jk8nK0"}]}-AABAA'
                        b'ShRehCKPuq0HJyPfQq-HU6IM0XAx6Ykp_fAowZB50YLpBTZ_H1PNdNztngx9WoW-'
                        b'9x5SRT7Iza9PqcNE6CwGCg')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'ExvhloEw3f3WmD9wfdLcIEZQuHQDa3tdRgG0H_jk8nK0'

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        assert tevt == (b'{"v":"KERI10JSON00015f_","t":"brv","d":"ES2qunCG9p2u7D5cfIvVjaqo'
                        b'JYmsrxATDEhHOKd5JGM8","i":"ECZKX5Hnk2wREdIbSFJc5fydNndm4yOTXErl6'
                        b'BDL_KLw","s":"1","p":"ExvhloEw3f3WmD9wfdLcIEZQuHQDa3tdRgG0H_jk8n'
                        b'K0","ra":{"i":"EWKCDqk4W2wseV-VnW-KpzvMpe2Y08bChQQPhmwgZdTI","s"'
                        b':1,"d":"EyN9LfEwJS4_YDDIdLqe6P_DknpF5AdojA0zTF9yo6J4"},"dt":"202'
                        b'1-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAABAEFFc5'
                        b'mMhCGnefFuF6ckA5aAwvOli797SXcP_TGGm5_NQ')
        assert kevt == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EFFc5mMhCGnefFuF6ckA5aAw'
                        b'vOli797SXcP_TGGm5_NQ","i":"Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dR'
                        b'GI0Br6A","s":"4","p":"EbDV9yKEEDP_FAhEJZKKRFVe4feirwi0Q7JBqByzsk'
                        b'SY","a":[{"i":"ECZKX5Hnk2wREdIbSFJc5fydNndm4yOTXErl6BDL_KLw","s"'
                        b':"1","d":"ES2qunCG9p2u7D5cfIvVjaqoJYmsrxATDEhHOKd5JGM8"}]}-AABAA'
                        b'fu_T5g92zR8GzlGWYWGZxA6CyTfwPg3_urjLQWVgQc1EojfrM8Jj9XKwQDtDy_Lf'
                        b'Boqkj91CgWwSzkpowSS8Dw')
        ser = Serder(raw=tevt)
        assert ser.saider.qb64 == 'ES2qunCG9p2u7D5cfIvVjaqoJYmsrxATDEhHOKd5JGM8'

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            regery = credentialing.Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
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

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            regery = credentialing.Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
            events(issuer)

            creder = credential(hab=hab, regk=issuer.regk)

            issuer.issue(creder=creder)
            kevt, tevt = events(issuer)
            ser = Serder(raw=tevt)
            assert ser.pre == "EG06x1w8Txctcgy4JsxIZGuStZcgqVGFRPsjIMfjQ6rw"
            assert ser.ked["ri"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"
            assert ser.ked["t"] == "iss"

            ser = Serder(raw=kevt)
            assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EG06x1w8Txctcgy4JsxIZGuStZcgqVGFRPsjIMfjQ6rw"
            assert seal["s"] == "0"
            assert seal["d"] == 'E6A0phPEii7xlO3OAQxSWZWlExQ_JhQbwN8ypzZb4fnc'

            issuer.revoke(creder=creder)
            kevt, tevt = events(issuer)

            ser = Serder(raw=tevt)
            assert ser.pre == "EG06x1w8Txctcgy4JsxIZGuStZcgqVGFRPsjIMfjQ6rw"
            assert ser.ked["t"] == "rev"
            assert ser.ked["ri"] == "E_WBd2MgZlm36iyhmzMjNFWd_Xv6WsrybkGCjD_Es5JY"

            ser = Serder(raw=kevt)
            assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
            assert ser.ked["t"] == "ixn"
            seal = ser.ked["a"][0]
            assert seal["i"] == "EG06x1w8Txctcgy4JsxIZGuStZcgqVGFRPsjIMfjQ6rw"
            assert seal["s"] == "1"
            assert seal["d"] == 'E0Q23OwV42YbjyuMZx01TAiLnp8Fu3hk55og5d2cl_k0'

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
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
        assert ser.pre == "ES0fuTsBtNjGB_WXFuv5ek15cbIgLMoO2nnSspcElJY0"
        assert ser.ked["t"] == "bis"
        seal = ser.ked["ra"]
        assert seal["i"] == "EnDHbU-5I_3HMw8vXxLpoyXOKRcBTtoJb5QEfEovYnVI"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "ES0fuTsBtNjGB_WXFuv5ek15cbIgLMoO2nnSspcElJY0"
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
        assert ser.pre == "ES0fuTsBtNjGB_WXFuv5ek15cbIgLMoO2nnSspcElJY0"
        assert ser.ked["t"] == "brv"
        seal = ser.ked["ra"]
        # ensure the ra seal digest matches the vrt event digest
        assert seal["d"] == vrtser.saider.qb64

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "ixn"
        seal = ser.ked["a"][0]
        assert seal["i"] == "ES0fuTsBtNjGB_WXFuv5ek15cbIgLMoO2nnSspcElJY0"
        assert seal["s"] == "1"

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True, estOnly=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EvzIA_4sgDPwnalcHpx3dijcprEahTLw3UFMdKn0RLSU"
        assert ser.ked["t"] == "vcp"
        assert ser.ked["c"] == ['NB', 'EO']
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
        assert ser.pre == "EJ219cLgOqq9OV6xMf0_uPO0V59OGzDtLgPjJGssRg5A"
        assert ser.ked["t"] == "iss"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EJ219cLgOqq9OV6xMf0_uPO0V59OGzDtLgPjJGssRg5A"
        assert ser.ked["t"] == "rev"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EG4T9IdrcIY77TvjhxELoIvinHnrIjhB8RdODwzTg-Z8"
        assert ser.ked["b"] == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"]
        assert ser.saider.qb64 == 'EG4T9IdrcIY77TvjhxELoIvinHnrIjhB8RdODwzTg-Z8'
        ser = Serder(raw=kevt)
        assert ser.ked["t"] == "rot"

        issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                    "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        kevt, tevt = events(issuer)

        vrtser = Serder(raw=tevt)
        ser = Serder(raw=tevt)
        assert ser.pre == "EG4T9IdrcIY77TvjhxELoIvinHnrIjhB8RdODwzTg-Z8"
        assert ser.ked["t"] == "vrt"
        assert issuer.baks == ["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU",
                               "B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                               "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"]

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"

        creder = credential(hab=hab, regk=issuer.regk)
        issuer.issue(creder=creder)
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EdZGnuk-GIdKhMHkl8fDukqOBAcVi3kP-RlMkgs3uU9k"
        assert ser.ked["t"] == "bis"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'E3bLmEsHHqzwNNygqzeMCtl97Isi7sZ0ZwaljJqpNvWM'

        # rotate to no backers
        issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        kevt, tevt = events(issuer)

        ser = Serder(raw=tevt)
        assert ser.pre == "EG4T9IdrcIY77TvjhxELoIvinHnrIjhB8RdODwzTg-Z8"
        assert ser.ked["t"] == "vrt"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        vrtser = Serder(raw=tevt)

        issuer.revoke(creder=creder)
        kevt, tevt = events(issuer)
        ser = Serder(raw=tevt)
        assert ser.pre == "EdZGnuk-GIdKhMHkl8fDukqOBAcVi3kP-RlMkgs3uU9k"
        assert ser.ked["t"] == "brv"

        ser = Serder(raw=kevt)
        assert ser.pre == "Evzy4LumzatnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A"
        assert ser.ked["t"] == "rot"
        assert vrtser.saider.qb64 == 'EGW5iTVCk_w_EBVUpaDQbxjlBor8jKN5PPjvgZa7a-Kw'

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
