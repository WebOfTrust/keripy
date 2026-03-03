# -*- encoding: utf-8 -*-
"""
tests.vdr.viring module

"""

import json
import os
import platform
import tempfile

import lmdb

from keri.core import indexing
from keri.core.coring import Diger, Number, Prefixer, Saider, Seqner, versify, Kinds
from keri.db import subing
from keri.db.dbing import openLMDB, dgKey, snKey
from keri.vdr.viring import Reger


def test_issuer():
    """
    Test Issuer Class
    """
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    issuer = Reger()

    assert isinstance(issuer, Reger)
    assert issuer.name == "main"
    assert issuer.temp is False
    assert isinstance(issuer.env, lmdb.Environment)
    assert issuer.path.endswith(os.path.join("keri", "reg", "main"))
    assert issuer.env.path() == issuer.path
    assert os.path.exists(issuer.path)

    assert isinstance(issuer.tvts, subing.Suber)

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
    assert issuer.path.endswith(os.path.join("keri", "reg", "main"))
    assert issuer.env.path() == issuer.path
    assert os.path.exists(issuer.path)

    issuer.close(clear=True)
    assert not os.path.exists(issuer.path)
    assert not issuer.opened

    assert isinstance(issuer.tvts, subing.Suber)

    with openLMDB(cls=Reger) as issuer:
        assert isinstance(issuer, Reger)
        assert issuer.name == "test"
        assert issuer.temp is True
        assert isinstance(issuer.env, lmdb.Environment)
        assert issuer.path.startswith(os.path.join(tempDirPath, "keri_reg_"))
        assert issuer.path.endswith(os.path.join("_test", "keri", "reg", "test"))
        assert issuer.env.path() == issuer.path
        assert os.path.exists(issuer.path)

        assert isinstance(issuer.tvts, subing.Suber)

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

        assert issuer.tvts.get(keys=key) is None
        assert issuer.tvts.rem(keys=key) is False
        assert issuer.tvts.put(keys=key, val=vcpb) is True
        assert issuer.tvts.get(keys=key) == vcpb.decode("utf-8")
        assert issuer.tvts.put(keys=key, val=vcpb) is False
        assert issuer.tvts.pin(keys=key, val=vcpb) is True
        assert issuer.tvts.get(keys=key) == vcpb.decode("utf-8")
        assert issuer.tvts.rem(keys=key) is True
        assert issuer.tvts.get(keys=key) is None

        telKey = snKey(regk, sn)
        assert issuer.tels.get(keys=telKey) is None
        assert issuer.tels.rem(keys=telKey) is False
        assert issuer.tels.put(keys=telKey, val=vdig.qb64b)
        assert issuer.tels.get(keys=telKey) == vdig.qb64
        assert issuer.tels.put(keys=telKey, val=vdig.qb64b) is False
        assert issuer.tels.pin(keys=telKey, val=vdig.qb64b) is True
        assert issuer.tels.get(keys=telKey) == vdig.qb64
        assert issuer.tels.rem(keys=telKey) is True
        assert issuer.tels.get(keys=telKey) is None

        # Tibs store Siger instances; use valid Siger bytes and distinct indices
        valid_tib_bytes = (b'AAAUr5RHYiDH8RU0ig-2Dp5h7rVKx89StH5M3CL60-cWEbgG-XmtW31pZlFicYgSPduJZUnD838_'
                          b'QLbASSQLAZcC')
        s0 = indexing.Siger(qb64b=valid_tib_bytes)
        s1 = indexing.Siger(raw=s0.raw, code=s0.code, index=1)
        s2 = indexing.Siger(raw=s0.raw, code=s0.code, index=2)
        sigers = [s0, s1, s2]

        key = dgKey(regk, vdig.qb64b)
        assert issuer.tibs.get(keys=(regk, vdig.qb64b)) == []
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 0
        assert issuer.tibs.rem(keys=(regk, vdig.qb64b)) is False
        assert issuer.tibs.pin(keys=(regk, vdig.qb64b), vals=[s0]) is True
        assert [s.qb64b for s in issuer.tibs.get(keys=key)] == [s0.qb64b]
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 1
        assert issuer.tibs.pin(keys=(regk, vdig.qb64b), vals=[s0]) is True  # add duplicate
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 1
        assert issuer.tibs.add(keys=(regk, vdig.qb64b), val=s0) is False
        assert issuer.tibs.add(keys=(regk, vdig.qb64b), val=s1) is True
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 2
        assert issuer.tibs.pin(keys=(regk, vdig.qb64b), vals=[s1, s2]) is True
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 2
        assert issuer.tibs.rem(keys=(regk, vdig.qb64b)) is True
        assert issuer.tibs.get(keys=(regk, vdig.qb64b)) == []
        for sig in sigers:
            assert issuer.tibs.add(keys=(regk, vdig.qb64b), val=sig) is True
        assert issuer.tibs.cnt(keys=(regk, vdig.qb64b)) == 3
        assert set(s.qb64b for s in issuer.tibs.get(keys=(regk, vdig.qb64b))) == {s0.qb64b, s1.qb64b, s2.qb64b}
        for c in issuer.tibs.getIter(keys=(regk, vdig.qb64b)):
            assert issuer.tibs.rem(keys=(regk, vdig.qb64b), val=c) is True
        assert issuer.tibs.get(keys=(regk, vdig.qb64b)) == []

        assert issuer.twes.getOn(keys=regk, on=sn) == []
        assert issuer.twes.remOn(keys=regk, on=sn) is False
        assert issuer.twes.putOn(keys=regk, on=sn, vals=vdig.qb64b)
        assert issuer.twes.getOn(keys=regk, on=sn)[0].encode("utf-8") == vdig.qb64b
        assert issuer.twes.putOn(keys=regk, on=sn, vals=vdig.qb64b) is False
        assert issuer.twes.pinOn(keys=regk, on=sn, vals=vdig.qb64b) is True
        assert issuer.twes.getOn(keys=regk, on=sn)[0].encode("utf-8") == vdig.qb64b
        assert issuer.twes.remOn(keys=regk, on=sn) is True
        assert issuer.twes.getOn(keys=regk, on=sn) == []

        assert issuer.oots.getOn(keys=regk, on=sn) == []
        assert issuer.oots.remOn(keys=regk, on=sn) is False
        assert issuer.oots.putOn(keys=regk, on=sn, vals=vdig.qb64b)
        assert issuer.oots.getOn(keys=regk, on=sn)[0].encode("utf-8") == vdig.qb64b
        assert issuer.oots.putOn(keys=regk, on=sn, vals=vdig.qb64b) is False
        assert issuer.oots.pinOn(keys=regk, on=sn, vals=vdig.qb64b) is True
        assert issuer.oots.getOn(keys=regk, on=sn)[0].encode("utf-8") == vdig.qb64b
        assert issuer.oots.remOn(keys=regk, on=sn) is True
        assert issuer.oots.getOn(keys=regk, on=sn) == []

        key = dgKey(regk, vdig.qb64b)
        number = Number(num=0)
        diger = Diger(qb64=vdig.qb64)
        anc_couple = number.qb64b + diger.qb64b
        assert issuer.ancs.get(keys=key) is None
        assert issuer.ancs.rem(keys=key) is False
        assert issuer.ancs.put(keys=key, val=(number, diger))
        rnum, rdig = issuer.ancs.get(keys=key)
        assert rnum.qb64b + rdig.qb64b == anc_couple
        assert issuer.ancs.put(keys=key, val=(number, diger)) is False
        assert issuer.ancs.pin(keys=key, val=(number, diger)) is True
        rnum, rdig = issuer.ancs.get(keys=key)
        assert rnum.qb64b + rdig.qb64b == anc_couple
        assert issuer.ancs.rem(keys=key) is True
        assert issuer.ancs.get(keys=key) is None

        prefixer = Prefixer(qb64b=rarb)
        saider = Saider(qb64=vdig.qb64)
        trituple = (prefixer.qb64b, number.qb64b, saider.qb64b)
        assert issuer.cancs.get(keys=key) is None
        assert issuer.cancs.rem(keys=key) is False
        assert issuer.cancs.put(keys=key, val=(prefixer, number, saider)) is True
        rpfx, rnum, rsaid = issuer.cancs.get(keys=key)
        assert (rpfx.qb64b, rnum.qb64b, rsaid.qb64b) == trituple
        assert issuer.cancs.put(keys=key, val=(prefixer, number, saider)) is False
        assert issuer.cancs.pin(keys=key, val=(prefixer, number, saider)) is True
        rpfx, rnum, rsaid = issuer.cancs.get(keys=key)
        assert (rpfx.qb64b, rnum.qb64b, rsaid.qb64b) == trituple
        assert issuer.cancs.rem(keys=key) is True
        assert issuer.cancs.get(keys=key) is None

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
        assert issuer.tvts.get(keys=key) is None
        assert issuer.tvts.rem(keys=key) is False
        assert issuer.tvts.put(keys=key, val=issb) is True
        assert issuer.tvts.get(keys=key) == issb.decode("utf-8")
        assert issuer.tvts.put(keys=key, val=issb) is False
        assert issuer.tvts.pin(keys=key, val=issb) is True
        assert issuer.tvts.get(keys=key) == issb.decode("utf-8")
        assert issuer.tvts.rem(keys=key) is True
        assert issuer.tvts.get(keys=key) is None

        telKey = snKey(vcdig, sn)
        assert issuer.tels.get(keys=telKey) is None
        assert issuer.tels.rem(keys=telKey) is False
        assert issuer.tels.put(keys=telKey, val=idig.qb64b)
        assert issuer.tels.get(keys=telKey) == idig.qb64
        assert issuer.tels.put(keys=telKey, val=idig.qb64b) is False
        assert issuer.tels.pin(keys=telKey, val=idig.qb64b) is True
        assert issuer.tels.get(keys=telKey) == idig.qb64
        assert issuer.tels.rem(keys=telKey) is True
        assert issuer.tels.get(keys=telKey) is None

        rev = dict(v=vs, i=vcdig.decode("utf-8"),
                   s="{:x}".format(sn + 1),
                   t="rev")

        revb = json.dumps(rev, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert revb == b'{"v":"KERI10JSON000014_","i":"EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","s":"1","t":"rev"}'
        rdig = Diger(raw=revb)

        assert issuer.tels.put(keys=snKey(vcdig, sn), val=idig.qb64b) is True
        assert issuer.tels.put(keys=snKey(vcdig, sn + 1), val=rdig.qb64b) is True
        assert issuer.tels.put(keys=snKey(vcdig, sn + 2), val=idig.qb64b) is True
        assert issuer.tels.put(keys=snKey(vcdig, sn + 3), val=rdig.qb64b) is True

        result = [(sn, dig) for _, sn, dig in issuer.tels.getOnItemIterAll(keys=vcdig)]
        assert result == [(0, idig.qb64), (1, rdig.qb64), (2, idig.qb64), (3, rdig.qb64)]

        bak1 = b'BA1Q98kT0HRn9R62lY-LufjjKdbCeL1mqu9arTgOmbqI'
        bak2 = b'DAEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU'
        bak3 = b'DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw'
        bak4 = b'BBeAn9JkFuEOOwDhfkhnxtGsRQkMh2AH1oGB9QHAvl1U'
        bak5 = b'BChy5f2BIJbAYdgoy00OcOEZwEyxCGCUDlzbGkbz1RAI'
        baks = [bak1, bak2, bak3, bak4]
        deserializedBaks = [bak.decode("utf-8") for bak in baks]
        # test .baks insertion order dup methods.  dup vals are insertion order
        assert issuer.baks.get(key) == []
        assert issuer.baks.cnt(key) == 0
        assert issuer.baks.rem(key) is False
        assert issuer.baks.put(key, baks) is True
        assert issuer.baks.get(key) == deserializedBaks
        assert issuer.baks.cnt(key) == len(baks) == 4
        assert issuer.baks.put(key, vals=[bak1]) is False
        assert issuer.baks.get(key) == deserializedBaks
        assert issuer.baks.add(key, bak1) is False
        assert issuer.baks.add(key, bak5) is True
        assert issuer.baks.get(key) == deserializedBaks + [bak5.decode("utf-8")]
        assert [val for val in issuer.baks.getIter(key)] == deserializedBaks + [bak5.decode("utf-8")]
        assert issuer.baks.rem(key) is True
        assert issuer.baks.get(key) == []

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
    number01 = Number(num=0)
    diger01 = Diger(qb64=vdig.qb64)
    anc01_couple = (Seqner(sn=number01.sn).qb64b +
                    Saider(qb64=diger01.qb64).qb64b)
    # Valid Siger bytes (tibs must be Siger for CesrDupSuber)
    tib01 = (b'AAAUr5RHYiDH8RU0ig-2Dp5h7rVKx89StH5M3CL60-cWEbgG-XmtW31pZlFicYgSPduJZUnD838_'
             b'QLbASSQLAZcC')
    tib02 = (b'AAAUr5RHYiDH8RU0ig-2Dp5h7rVKx89StH5M3CL60-cWEbgG-XmtW31pZlFicYgSPduJZUnD838_'
             b'QLbASSQLAZcC')
    tib03 = (b'AAAUr5RHYiDH8RU0ig-2Dp5h7rVKx89StH5M3CL60-cWEbgG-XmtW31pZlFicYgSPduJZUnD838_'
             b'QLbASSQLAZcC')

    rot1 = dict(v=vs, i=regk.decode("utf-8"),
                s="{:x}".format(sn + 1), ba=[rarb2.decode("utf-8")],
                t="rot")
    rot1b = json.dumps(rot1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    r1dig = Diger(ser=rot1b)
    number02 = Number(num=1)
    diger02 = Diger(qb64=r1dig.qb64)
    anc02_couple = (Seqner(sn=number02.sn).qb64b +
                    Saider(qb64=diger02.qb64).qb64b)

    rot2 = dict(v=vs, i=regk.decode("utf-8"),
                s="{:x}".format(sn + 2), br=[rarb.decode("utf-8")],
                t="rot")
    rot2b = json.dumps(rot2, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    r2dig = Diger(ser=rot2b)
    number03 = Number(num=2)
    diger03 = Diger(qb64=r2dig.qb64)
    anc03_couple = (Seqner(sn=number03.sn).qb64b +
                    Saider(qb64=diger03.qb64).qb64b)

    with openLMDB(cls=Reger) as issuer:
        dgkey = dgKey(regk, vdig.qb64b)
        snkey = snKey(regk, sn)
        assert issuer.tvts.put(keys=dgkey, val=vcpb) is True
        assert issuer.tels.put(keys=snkey, val=vdig.qb64b)
        assert issuer.ancs.put(keys=dgkey, val=(number01, diger01)) is True
        assert issuer.tibs.pin(keys=(regk, vdig.qb64b), vals=[indexing.Siger(qb64b=tib01)]) is True

        dgkey = dgKey(regk, r1dig.qb64b)
        snkey = snKey(regk, sn + 1)
        assert issuer.tvts.put(keys=dgkey, val=rot1b) is True
        assert issuer.tels.put(keys=snkey, val=r1dig.qb64b)
        assert issuer.ancs.put(keys=dgkey, val=(number02, diger02)) is True
        assert issuer.tibs.pin(keys=(regk, r1dig.qb64b), vals=[indexing.Siger(qb64b=tib02)]) is True

        dgkey = dgKey(regk, r2dig.qb64b)
        snkey = snKey(regk, sn + 2)
        assert issuer.tvts.put(keys=dgkey, val=rot2b) is True
        assert issuer.tels.put(keys=snkey, val=r2dig.qb64b)
        assert issuer.ancs.put(keys=dgkey, val=(number03, diger03)) is True
        assert issuer.tibs.pin(keys=(regk, r2dig.qb64b), vals=[indexing.Siger(qb64b=tib03)]) is True

        msgs = bytearray()  # outgoing messages
        for msg in issuer.clonePreIter(regk):
            msgs.extend(msg)

        valid_tib = (b'AAAUr5RHYiDH8RU0ig-2Dp5h7rVKx89StH5M3CL60-cWEbgG-XmtW31pZlFicYgSPduJZUnD838_'
                     b'QLbASSQLAZcC')
        out = bytes(msgs)

        # Verify ordering of replayed events
        assert out.find(vcpb) != -1
        assert out.find(rot1b) != -1
        assert out.find(rot2b) != -1
        assert out.find(vcpb) < out.find(rot1b) < out.find(rot2b)

        # Verify each event includes one indexed signature and one anchor couple
        assert out.count(valid_tib) == 3
        assert out.count(anc01_couple) == 1
        assert out.count(anc02_couple) == 1
        assert out.count(anc03_couple) == 1
        assert out.find(anc01_couple) < out.find(anc02_couple) < out.find(anc03_couple)


if __name__ == "__main__":
    test_issuer()
    test_clone()
