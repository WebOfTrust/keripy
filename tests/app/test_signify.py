# -*- encoding: utf-8 -*-
"""
tests.app.habbing remote module

"""
import pytest

from keri.kering import KeriError, Ilks, Kinds

from keri.core import Salter, Diger, Tiers, MtrDex, incept, rotate

from keri.app import SaltyCreator, openHby



def test_remote_salty_hab():
    name = "test"
    tier = Tiers.low
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=raw, tier=tier)

    with openHby(name="remoteSalty") as remote, \
            openHby(name="local", salt=salter.qb64, temp=True, tier=tier) as local:
        # create a single Local Hab and compare the results with the Signify Hab

        creator = SaltyCreator(salt=salter.qb64, stem="test", tier=tier)
        pidx = 1
        ridx = 0
        kidx = 0

        lhab = local.makeHab(name=name)
        assert lhab.pre == "EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi"

        # create current key
        sith = 1  # one signer

        #  original signing keypair transferable default
        skp0 = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        # skp0 = salter.signer(path=path, temp=True, tier=tier)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519
        keys = [skp0.verfer.qb64]
        assert keys == ['DPNKzAuOw9utnR6L1_bS0spnsPFbc609WdzUvJrfUh-h']

        # create next key
        #  next signing keypair transferable is default
        skp1 = creator.create(pidx=pidx, ridx=ridx+1, kidx=kidx+1, temp=True).pop()
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519

        # compute nxt digest
        # transferable so nxt is not empty
        ndiger = Diger(ser=skp1.verfer.qb64b)
        nxt = [ndiger.qb64]
        assert nxt == ['EAbq5OnIog2j1Rm5dtFuFuSIBbKKxlV1ILwrRI5yPgtX']

        toad = 0  # no witnesses

        icp = incept(keys, isith=sith, ndigs=nxt, toad=toad, code=MtrDex.Blake3_256,
                     kind=Kinds.json)
        assert icp.raw == lhab.kever.serder.raw
        tsig0 = skp0.sign(icp.raw, index=0)
        assert tsig0.qb64b == (b'AACXScoPrHhORzgowfiTZ2qrDrvy0wjavZg0QgPk1bxc1ifdREd5RSEtk9RCXIDm25Mj5J7hs32E'
                               b'ddCg5kSj3igC')

        hab = remote.makeSignifyHab(name, serder=icp, sigers=[tsig0],
                                    stem="test", pidx=pidx, tier=tier, temp=True)
        assert hab.pre == lhab.pre  # we have recreated the local hab with the remote hab

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre  # we have recreated the local hab with the remote hab
        assert kever.sn == 0
        assert kever.serder.said == lhab.kever.serder.said
        assert kever.ilk == Ilks.icp
        assert [verfer.qb64 for verfer in kever.verfers] == keys
        assert [diger.qb64 for diger in kever.ndigers] == nxt

        habord = remote.db.habs.get(hab.pre)
        assert habord.hid == "EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi"
        assert habord.sid == "EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi"

        lhab.rotate(framed=True)

        ridx = ridx + 1
        kidx = kidx + 1
        # Regenerate skp1 signer from data in Habord as we will on Signify client
        skp1 = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        keys1 = [skp1.verfer.qb64]
        skp2 = creator.create(pidx=pidx, ridx=ridx+1, kidx=kidx+1, temp=True).pop()
        assert skp2.code == MtrDex.Ed25519_Seed
        assert skp2.verfer.code == MtrDex.Ed25519
        ndiger1 = Diger(ser=skp2.verfer.qb64b)
        nxt1 = [ndiger1.qb64]
        assert nxt1 == ['EKNg5bhKpDTv_DixBKYfOHHl1omtvQ06UD3Nf40JUsQ-']

        rot = rotate(pre=hab.pre, keys=keys1, dig=icp.said, sn=1, isith=sith, ndigs=nxt1, toad=toad,
                     kind=Kinds.json)
        assert rot.raw == lhab.kever.serder.raw

        tsig1 = skp1.sign(rot.raw, index=0)
        assert tsig1.qb64b == (b'AADb9p1d3jhNhm_UQhgiZx5zxrIfj5h4QVo0S6D0F4NhjcZ_Z_5r1Fi7l7r1iHHZQQoxx4Ov6MFg'
                               b'uSwk1R8zAPYN')

        msg = hab.rotate(serder=rot, sigers=[tsig1], framed=True)
        assert msg == (b'{"v":"KERICAACAAJSONAAFp.","t":"rot","d":"ENljpHtLsIT8EVSKWkTKJUl_xkK-'
                       b'-Q0c4jgfeCzuA8X4","i":"EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi",'
                       b'"s":"1","p":"EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi","kt":"1","'
                       b'k":["DN8nxDNnlY-qCNdb294nZQs29PXDsmbphujYJGQCLL0Y"],"nt":"1","n":["EK'
                       b'Ng5bhKpDTv_DixBKYfOHHl1omtvQ06UD3Nf40JUsQ-"],"bt":"0","br":[],"ba":['
                       b'],"c":[],"a":[]}-KAWAADb9p1d3jhNhm_UQhgiZx5zxrIfj5h4QVo0S6D0F4NhjcZ_'
                       b'Z_5r1Fi7l7r1iHHZQQoxx4Ov6MFguSwk1R8zAPYN')

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre
        assert kever.sn == 1
        assert kever.serder.said == lhab.kever.serder.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert [diger.qb64 for diger in kever.ndigers] == nxt1

        habord = remote.db.habs.get(hab.pre)
        assert habord.hid == "EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi"
        assert habord.sid == "EG9OKSeOlbwwjcOp6U5eYtHeF4lsCcM_Oia-idKlnYQi"

        with pytest.raises(KeriError):
            hab.sign(ser=rot.raw)

            # create something to sign
        ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

        lsigs = lhab.sign(ser=ser, indices=[0])
        assert lsigs[0].qb64b == (b'AABaTxcQvCatFXQJK2uYuss7JC2SLgisX70Tm0DyWAOxRPC1nYuMrbV2UWCa5zYQTIzu4I7SqfbD'
                                  b'XKgvxjjpJfkP')

        # Regenerate signer from data in Habord as we will on Signify client
        rskp = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        # Sign with regenerated signer
        rsig = rskp.sign(ser=ser, index=0)
        assert rsig.qb64b == lsigs[0].qb64b
