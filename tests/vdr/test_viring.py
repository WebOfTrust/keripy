# -*- encoding: utf-8 -*-
"""
tests.vdr.viring module

"""

import json
import os

import lmdb
import pytest

from keri import kering
from keri.app.keeping import KERIKeeperMapSizeKey
from keri.core import coring
from keri.core.coring import Diger, versify, Kinds
from keri.core.serdering import SerderACDC
from keri.db.dbing import openLMDB, dgKey, snKey, KERIBaserMapSizeKey, KERIRegerMapSizeKey, LMDBer
from keri.vdr.viring import Reger


def test_issuer():
    """
    Test Issuer Class
    """
    issuer = Reger()

    assert isinstance(issuer, Reger)
    assert issuer.name == "main"
    assert issuer.temp is False
    assert isinstance(issuer.env, lmdb.Environment)
    assert issuer.path.endswith("keri/reg/main")
    assert issuer.env.path() == issuer.path
    assert os.path.exists(issuer.path)

    assert isinstance(issuer.tvts, lmdb._Database)

    issuer.close(clear=True)
    assert not os.path.exists(issuer.path)
    assert not issuer.opened

    # test not opened on init
    issuer = Reger(reopen=False)
    assert isinstance(issuer, Reger)
    assert issuer.name == "main"
    assert issuer.temp is False
    assert issuer.opened is False
    assert issuer.path is None
    assert issuer.env is None

    issuer.reopen()
    assert issuer.opened
    assert issuer.path is not None
    assert isinstance(issuer.env, lmdb.Environment)
    assert issuer.path.endswith("keri/reg/main")
    assert issuer.env.path() == issuer.path
    assert os.path.exists(issuer.path)

    issuer.close(clear=True)
    assert not os.path.exists(issuer.path)
    assert not issuer.opened

    assert isinstance(issuer.tvts, lmdb._Database)

    with openLMDB(cls=Reger) as issuer:
        assert isinstance(issuer, Reger)
        assert issuer.name == "test"
        assert issuer.temp is True
        assert isinstance(issuer.env, lmdb.Environment)
        assert issuer.path.startswith("/tmp/keri_reg_")
        assert issuer.path.endswith("_test/keri/reg/test")
        assert issuer.env.path() == issuer.path
        assert os.path.exists(issuer.path)

        assert isinstance(issuer.tvts, lmdb._Database)

    assert not os.path.exists(issuer.path)

    regb = "EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0".encode("utf-8")
    rarb = "BBjzaUuRMwh1ivT5BQrqNhbvx82lB-ofrHVHjL3WADbA".encode("utf-8")

    #  test with registry inception (vcp) event
    regk = regb
    sn = 0
    vs = versify(kind=Kinds.json, size=20)

    vcp = dict(v=vs, i=regk.decode("utf-8"),
               s="{:x}".format(sn), b=[rarb.decode("utf-8")],
               t="vcp")

    vcpb = json.dumps(vcp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert vcpb == (b'{"v":"KERI10JSON000014_","i":"EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0",'
                    b'"s":"0","b":["BBjzaUuRMwh1ivT5BQrqNhbvx82lB-ofrHVHjL3WADbA"],"t":"vcp"}')
    vdig = Diger(ser=vcpb)

    with openLMDB(cls=Reger) as issuer:
        key = dgKey(regk, vdig.qb64b)

        assert issuer.getTvt(key) is None
        assert issuer.delTvt(key) is False
        assert issuer.putTvt(key, val=vcpb) is True
        assert issuer.getTvt(key) == vcpb
        assert issuer.putTvt(key, val=vcpb) is False
        assert issuer.setTvt(key, val=vcpb) is True
        assert issuer.getTvt(key) == vcpb
        assert issuer.delTvt(key) is True
        assert issuer.getTvt(key) is None

        telKey = snKey(regk, sn)
        assert issuer.getTel(telKey) is None
        assert issuer.delTel(telKey) is False
        assert issuer.putTel(telKey, val=vdig.qb64b)
        assert issuer.getTel(telKey) == vdig.qb64b
        assert issuer.putTel(telKey, val=vdig.qb64b) is False
        assert issuer.setTel(telKey, val=vdig.qb64b) is True
        assert issuer.getTel(telKey) == vdig.qb64b
        assert issuer.delTel(telKey) is True
        assert issuer.getTel(telKey) is None

        # not sure how these are generated in the first place
        coupl01 = ("BPVuWC4Hc0izqPKn2LIwhp72SHJSRgfaL1RhtuiavIy4AAfiKvopJ0O2afOmxb5A6JtdY7Wkl_1uNx1Z8xQkg_"
                   "gMzf-vTfEHDylFdgn2e_u_ppaFajIdvEvONX6dcSYzlfBQ").encode("utf-8")
        coupl02 = ("BW1gbapuOJ4TJKwLfKZs5cXEIs9k8EtBqxR1psVxnD7IABrSkjrgPGXdhBiOy6LUZpiqtsHkKHhfLGj_LhT1n6"
                   "EqCIdDjrihzrdM1bm0ZNJDwbDGXoeeZujd7ZYsOsBPzRCw").encode("utf-8")
        coupl03 = ("BklrMm7GlYzNrPQunLJHFn_1wWjlUslGkXfs0KyoNOEAAC_6PB5Zre_E_7YLkM9OtRo-uYmwRyFmOH3Xo4JDiP"
                   "jioY7Ycna6ouhSSH0QcKsEjce10HCXIW_XtmEYr9SrB5BA").encode("utf-8")
        coups = [coupl01, coupl02, coupl03]

        key = dgKey(regk, vdig.qb64b)
        assert issuer.getTibs(key) == []
        assert issuer.cntTibs(key) == 0
        assert issuer.delTibs(key) is False
        assert issuer.putTibs(key, vals=[coupl01]) is True
        assert issuer.getTibs(key) == [coupl01]
        assert issuer.cntTibs(key) == 1
        assert issuer.putTibs(key, vals=[coupl01]) is True  # add duplicate
        assert issuer.cntTibs(key) == 1
        assert issuer.addTib(key, coupl01) is False
        assert issuer.addTib(key, coupl02) is True
        assert issuer.cntTibs(key) == 2
        assert issuer.putTibs(key, vals=[coupl02, coupl03]) is True
        assert issuer.cntTibs(key) == 3
        assert issuer.delTibs(key) is True
        assert issuer.getTibs(key) == []
        for c in coups:
            assert issuer.addTib(key, c) is True
        assert issuer.cntTibs(key) == 3
        assert issuer.getTibs(key) == [coupl01, coupl02, coupl03]
        for c in issuer.getTibsIter(key):
            assert issuer.delTibs(key, c) is True
        assert issuer.getTibs(key) == []

        tweKey = snKey(regk, sn)
        assert issuer.getTwe(tweKey) is None
        assert issuer.delTwe(tweKey) is False
        assert issuer.putTwe(tweKey, val=vdig.qb64b)
        assert issuer.getTwe(tweKey) == vdig.qb64b
        assert issuer.putTwe(tweKey, val=vdig.qb64b) is False
        assert issuer.setTwe(tweKey, val=vdig.qb64b) is True
        assert issuer.getTwe(tweKey) == vdig.qb64b
        assert issuer.delTwe(tweKey) is True
        assert issuer.getTwe(tweKey) is None

        ooKey = snKey(regk, sn)
        assert issuer.getOot(ooKey) is None
        assert issuer.delOot(ooKey) is False
        assert issuer.putOot(ooKey, val=vdig.qb64b)
        assert issuer.getOot(ooKey) == vdig.qb64b
        assert issuer.putOot(ooKey, val=vdig.qb64b) is False
        assert issuer.setOot(ooKey, val=vdig.qb64b) is True
        assert issuer.getOot(ooKey) == vdig.qb64b
        assert issuer.delOot(ooKey) is True
        assert issuer.getOot(ooKey) is None

        anc01 = ("0AAAAAAAAAAAAAAAAAAAAABA"
                 "Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4").encode("utf-8")

        key = dgKey(regk, vdig.qb64b)
        assert issuer.getAnc(key) is None
        assert issuer.delAnc(key) is False
        assert issuer.putAnc(key, val=anc01)
        assert issuer.getAnc(key) == anc01
        assert issuer.putAnc(key, val=anc01) is False
        assert issuer.setAnc(key, val=anc01) is True
        assert issuer.getAnc(key) == anc01
        assert issuer.delAnc(key) is True
        assert issuer.getAnc(key) is None

        #  test with verifiable credential issuance (iss) event
        vcdig = b'EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc'
        sn = 0
        vs = versify(kind=Kinds.json, size=20)

        vcp = dict(v=vs, i=vcdig.decode("utf-8"),
                   s="{:x}".format(sn),
                   t="iss")

        issb = json.dumps(vcp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert issb == (b'{"v":"KERI10JSON000014_",'
                        b'"i":"EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc",'
                        b''b'"s":"0","t":"iss"}')
        idig = Diger(ser=issb)

        key = dgKey(vcdig, idig.qb64b)
        assert issuer.getTvt(key) is None
        assert issuer.delTvt(key) is False
        assert issuer.putTvt(key, val=issb) is True
        assert issuer.getTvt(key) == issb
        assert issuer.putTvt(key, val=issb) is False
        assert issuer.setTvt(key, val=issb) is True
        assert issuer.getTvt(key) == issb
        assert issuer.delTvt(key) is True
        assert issuer.getTvt(key) is None

        telKey = snKey(vcdig, sn)
        assert issuer.getTel(telKey) is None
        assert issuer.delTel(telKey) is False
        assert issuer.putTel(telKey, val=idig.qb64b)
        assert issuer.getTel(telKey) == idig.qb64b
        assert issuer.putTel(telKey, val=idig.qb64b) is False
        assert issuer.setTel(telKey, val=idig.qb64b) is True
        assert issuer.getTel(telKey) == idig.qb64b
        assert issuer.delTel(telKey) is True
        assert issuer.getTel(telKey) is None

        rev = dict(v=vs, i=vcdig.decode("utf-8"),
                   s="{:x}".format(sn + 1),
                   t="rev")

        revb = json.dumps(rev, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert revb == b'{"v":"KERI10JSON000014_","i":"EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","s":"1","t":"rev"}'
        rdig = Diger(raw=revb)

        assert issuer.putTel(snKey(vcdig, sn), val=idig.qb64b) is True
        assert issuer.putTel(snKey(vcdig, sn + 1), val=rdig.qb64b) is True
        assert issuer.putTel(snKey(vcdig, sn + 2), val=idig.qb64b) is True
        assert issuer.putTel(snKey(vcdig, sn + 3), val=rdig.qb64b) is True

        result = [(sn, dig) for _, sn, dig in issuer.getTelItemPreIter(vcdig)]
        assert result == [(0, idig.qb64b), (1, rdig.qb64b), (2, idig.qb64b), (3, rdig.qb64b)]

        bak1 = b'BA1Q98kT0HRn9R62lY-LufjjKdbCeL1mqu9arTgOmbqI'
        bak2 = b'DAEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU'
        bak3 = b'DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw'
        bak4 = b'BBeAn9JkFuEOOwDhfkhnxtGsRQkMh2AH1oGB9QHAvl1U'
        bak5 = b'BChy5f2BIJbAYdgoy00OcOEZwEyxCGCUDlzbGkbz1RAI'
        baks = [bak1, bak2, bak3, bak4]

        # test .baks insertion order dup methods.  dup vals are insertion order
        assert issuer.getBaks(key) == []
        assert issuer.cntBaks(key) == 0
        assert issuer.delBaks(key) is False
        assert issuer.putBaks(key, baks) is True
        assert issuer.getBaks(key) == baks
        assert issuer.cntBaks(key) == len(baks) == 4
        assert issuer.putBaks(key, vals=[bak1]) is False
        assert issuer.getBaks(key) == baks
        assert issuer.addBak(key, bak1) is False
        assert issuer.addBak(key, bak5) is True
        assert issuer.getBaks(key) == [bak1, bak2, bak3, bak4, bak5]
        assert [val for val in issuer.getBaksIter(key)] == [bak1, bak2, bak3, bak4, bak5]
        assert issuer.delBaks(key) is True
        assert issuer.getBaks(key) == []

    """End Test"""


def test_clone():
    regk = "EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0".encode("utf-8")
    rarb = "BAjzaUuRMwh1ivT5BQrqNhbvx82lB-ofrHVHjL3WADbA".encode("utf-8")
    rarb2 = "BBVuWC4Hc0izqPKn2LIwhp72SHJSRgfaL1RhtuiavIy4".encode("utf-8")

    #  test with registry inception (vcp) event
    sn = 0
    vs = versify(kind=Kinds.json, size=20)

    vcp = dict(v=vs, i=regk.decode("utf-8"),
               s="{:x}".format(sn), b=[rarb.decode("utf-8")],
               t="vcp")

    vcpb = json.dumps(vcp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    vdig = Diger(ser=vcpb)
    anc01 = "0AAAAAAAAAAAAAAAAAAAAABAEzpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4".encode("utf-8")
    tib01 = ("BPVuWC4Hc0izqPKn2LIwhp72SHJSRgfaL1RhtuiavIy4AAfiKvopJ0O2afOmxb5A6JtdY7Wkl_1uNx1Z8xQkg_"
             "gMzf-vTfEHDylFdgn2e_u_ppaFajIdvEvONX6dcSYzlfBQ").encode("utf-8")

    rot1 = dict(v=vs, i=regk.decode("utf-8"),
                s="{:x}".format(sn + 1), ba=[rarb2.decode("utf-8")],
                t="rot")
    rot1b = json.dumps(rot1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    r1dig = Diger(ser=rot1b)
    anc02 = "0AAAAAAAAAAAAAAAAAAAAABBEzpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4".encode("utf-8")
    tib02 = ("BW1gbapuOJ4TJKwLfKZs5cXEIs9k8EtBqxR1psVxnD7IABrSkjrgPGXdhBiOy6LUZpiqtsHkKHhfLGj_LhT1n6"
             "EqCIdDjrihzrdM1bm0ZNJDwbDGXoeeZujd7ZYsOsBPzRCw").encode("utf-8")

    rot2 = dict(v=vs, i=regk.decode("utf-8"),
                s="{:x}".format(sn + 2), br=[rarb.decode("utf-8")],
                t="rot")
    rot2b = json.dumps(rot2, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    r2dig = Diger(ser=rot2b)
    anc03 = "0AAAAAAAAAAAAAAAAAAAAABCEzpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4".encode("utf-8")
    tib03 = ("BklrMm7GlYzNrPQunLJHFn_1wWjlUslGkXfs0KyoNOEAAC_6PB5Zre_E_7YLkM9OtRo-uYmwRyFmOH3Xo4JDiP"
             "jioY7Ycna6ouhSSH0QcKsEjce10HCXIW_XtmEYr9SrB5BA").encode("utf-8")

    with openLMDB(cls=Reger) as issuer:
        dgkey = dgKey(regk, vdig.qb64b)
        snkey = snKey(regk, sn)
        assert issuer.putTvt(dgkey, val=vcpb) is True
        assert issuer.putTel(snkey, val=vdig.qb64b)
        assert issuer.putAnc(dgkey, val=anc01) is True
        assert issuer.putTibs(dgkey, vals=[tib01]) is True

        dgkey = dgKey(regk, r1dig.qb64b)
        snkey = snKey(regk, sn + 1)
        assert issuer.putTvt(dgkey, val=rot1b) is True
        assert issuer.putTel(snkey, val=r1dig.qb64b)
        assert issuer.putAnc(dgkey, val=anc02) is True
        assert issuer.putTibs(dgkey, vals=[tib02]) is True

        dgkey = dgKey(regk, r2dig.qb64b)
        snkey = snKey(regk, sn + 2)
        assert issuer.putTvt(dgkey, val=rot2b) is True
        assert issuer.putTel(snkey, val=r2dig.qb64b)
        assert issuer.putAnc(dgkey, val=anc03) is True
        assert issuer.putTibs(dgkey, vals=[tib03]) is True

        msgs = bytearray()  # outgoing messages
        for msg in issuer.clonePreIter(regk):
            msgs.extend(msg)

        assert msgs == (b'{"v":"KERI10JSON000014_","i":"EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEU'
          b'k-ODnif3O0","s":"0","b":["BAjzaUuRMwh1ivT5BQrqNhbvx82lB-ofrHVHjL'
          b'3WADbA"],"t":"vcp"}-VA0-BABBPVuWC4Hc0izqPKn2LIwhp72SHJSRgfaL1Rht'
          b'uiavIy4AAfiKvopJ0O2afOmxb5A6JtdY7Wkl_1uNx1Z8xQkg_gMzf-vTfEHDylFd'
          b'gn2e_u_ppaFajIdvEvONX6dcSYzlfBQ-GAB0AAAAAAAAAAAAAAAAAAAAABAEzpq0'
          b'6UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4{"v":"KERI10JSON000014_",'
          b'"i":"EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0","s":"1","ba":'
          b'["BBVuWC4Hc0izqPKn2LIwhp72SHJSRgfaL1RhtuiavIy4"],"t":"rot"}-VA0-'
          b'BABBW1gbapuOJ4TJKwLfKZs5cXEIs9k8EtBqxR1psVxnD7IABrSkjrgPGXdhBiOy'
          b'6LUZpiqtsHkKHhfLGj_LhT1n6EqCIdDjrihzrdM1bm0ZNJDwbDGXoeeZujd7ZYsO'
          b'sBPzRCw-GAB0AAAAAAAAAAAAAAAAAAAAABBEzpq06UecHwzy-K9FpNoRxCJp2wIG'
          b'M9u2Edk-PLMZ1H4{"v":"KERI10JSON000014_","i":"EAWdT7a7fZwRz0jiZ0D'
          b'JxZEM3vsNbLDPEUk-ODnif3O0","s":"2","br":["BAjzaUuRMwh1ivT5BQrqNh'
          b'bvx82lB-ofrHVHjL3WADbA"],"t":"rot"}-VA0-BABBklrMm7GlYzNrPQunLJHF'
          b'n_1wWjlUslGkXfs0KyoNOEAAC_6PB5Zre_E_7YLkM9OtRo-uYmwRyFmOH3Xo4JDi'
          b'PjioY7Ycna6ouhSSH0QcKsEjce10HCXIW_XtmEYr9SrB5BA-GAB0AAAAAAAAAAAA'
          b'AAAAAAAAABCEzpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4')

def test_clearEscrows():
    with openLMDB(cls=Reger) as db:
        regk = "EAWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0".encode("utf-8")
        sn = 0
        ooKey = snKey(regk, sn)
        vs = versify(kind=coring.Kinds.json, size=20)
        rarb = "BBjzaUuRMwh1ivT5BQrqNhbvx82lB-ofrHVHjL3WADbA".encode("utf-8")
        vcp = dict(v=vs, i=regk.decode("utf-8"),
                   s="{:x}".format(sn), b=[rarb.decode("utf-8")],
                   t="vcp")

        vcpb = json.dumps(vcp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        vdig = Diger(ser=vcpb)

        db.putOot(ooKey, val=vdig.qb64b)
        db.putTwe(ooKey, val=vdig.qb64b)
        db.putTae(ooKey, val=vdig.qb64b)

        pre = 'k'
        db.mre.put(keys=(pre, ), val=coring.Dater())
        db.mce.put(keys=(pre, ), val=coring.Dater())
        db.mse.put(keys=(pre, ), val=coring.Dater())

        creder = SerderACDC(makify=True, proto=kering.Protocols.acdc, verify=False)
        db.cmse.put(("a", "b"), val=creder)

        prefixer = coring.Prefixer(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        db.tpwe.add(("a", "b"), (prefixer, seqner, saider))
        db.tmse.add(("a", "b"), (prefixer, seqner, saider))
        db.tede.add(("a", "b"), (prefixer, seqner, saider))

        dater = coring.Dater()
        broker_saider = coring.Saider(qb64="EBD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        aid = "ECD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I"
        for typ in ["registry-mae", "registry-ooo", "credential-mre", "credential-mae", "credential-ooo"]:
            db.txnsb.escrowdb.put(keys=(typ, pre, aid), vals=[broker_saider])
            db.txnsb.daterdb.put(keys=(broker_saider.qb64,), val=dater)

        assert db.getOot(ooKey) == vdig.qb64b
        assert db.getTwe(ooKey) == vdig.qb64b
        assert db.getTae(ooKey) == vdig.qb64b
        assert db.mre.get((pre, )) is not None
        assert db.mce.get((pre, )) is not None
        assert db.mse.get((pre, )) is not None
        assert db.cmse.cntAll() == 1
        assert db.tpwe.cntAll() == 1
        assert db.tmse.cntAll() == 1
        assert db.tede.cntAll() == 1

        for typ in ["registry-mae", "registry-ooo", "credential-mre", "credential-mae", "credential-ooo"]:
            assert db.txnsb.escrowdb.get(keys=(typ, pre, aid)) != []

        db.clearEscrows()

        assert db.getOot(ooKey) is None
        assert db.getTwe(ooKey) is None
        assert db.getTae(ooKey) is None
        assert db.mre.get((pre, )) is None
        assert db.mce.get((pre, )) is None
        assert db.mse.get((pre, )) is None
        assert db.cmse.cntAll() == 0
        assert db.tpwe.cntAll() == 0
        assert db.tmse.cntAll() == 0
        assert db.tede.cntAll() == 0

        # Verify Broker escrows were cleared
        for typ in ["registry-mae", "registry-ooo", "credential-mre", "credential-mae", "credential-ooo"]:
            assert db.txnsb.escrowdb.get(keys=(typ, pre, aid)) == []
        assert db.txnsb.daterdb.get(keys=(broker_saider.qb64,)) is None

def test_mailbox_db_size_set_from_env_var():
    # Clear environment before test
    if KERIBaserMapSizeKey in os.environ:
        os.environ.pop(KERIBaserMapSizeKey)
    if KERIRegerMapSizeKey in os.environ:
        os.environ.pop(KERIRegerMapSizeKey)

    new_map_size = 10737418240
    # Default map size works
    reger = Reger()
    assert reger.env.info()['map_size'] != new_map_size, "Expected map size to be the default 10MB"
    assert reger.env.info()['map_size'] == LMDBer.MapSize, "Expected map size to be the default 10MB"

    # Specific map size works
    os.environ[KERIRegerMapSizeKey] = f"{new_map_size}"

    reger = Reger()
    assert reger.env.info()['map_size'] == new_map_size, "Expected map size to be set from environment variable to 10GB"
    os.environ.pop(KERIRegerMapSizeKey)

    # generic map size works
    baser_map_size = 10737418240
    os.environ[KERIRegerMapSizeKey] = f"{baser_map_size}"

    reger = Reger()
    assert reger.env.info()['map_size'] == new_map_size, "Expected map size to be set from environment variable to 10GB"

    # Bad map size throws
    os.environ[KERIRegerMapSizeKey] = f"bad_map_size"
    with pytest.raises(ValueError) as excinfo:
        Reger()
    assert "invalid literal for int" in str(excinfo.value), "Expected ValueError when map size is not an integer"
    os.environ.pop(KERIRegerMapSizeKey)

if __name__ == "__main__":
    test_issuer()
    test_clone()
