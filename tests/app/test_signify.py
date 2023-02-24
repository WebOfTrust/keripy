# -*- encoding: utf-8 -*-
"""
tests.app.habbing remote module

"""
import pytest

from keri import kering
from keri.app import habbing
from keri.app.keeping import SaltyCreator
from keri.core import coring, eventing


def test_remote_salty_hab():
    name = "test"
    tier = coring.Tiers.low
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw, tier=tier)

    with habbing.openHby(name="remoteSalty") as remote, \
            habbing.openHby(name="local", salt=salter.qb64, temp=True, tier=tier) as local:
        # create a single Local Hab and compare the results with the Signify Hab

        creator = SaltyCreator(salt=salter.qb64, stem="test", tier=tier)
        pidx = 1
        ridx = 0
        kidx = 0

        lhab = local.makeHab(name=name)
        assert lhab.pre == "ENysLhDtYrGZ2WXCVDEnN2lExe_XhwYRXzBQdrITAGwU"

        # create current key
        sith = 1  # one signer

        #  original signing keypair transferable default
        skp0 = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        # skp0 = salter.signer(path=path, temp=True, tier=tier)
        assert skp0.code == coring.MtrDex.Ed25519_Seed
        assert skp0.verfer.code == coring.MtrDex.Ed25519
        keys = [skp0.verfer.qb64]
        assert keys == ["DGZ3jJ4nLnJQdKPHDWQIFbR_n6QY9eKhKGgpxV_rjl3H"]

        # create next key
        #  next signing keypair transferable is default
        skp1 = creator.create(pidx=pidx, ridx=ridx+1, kidx=kidx+1, temp=True).pop()
        assert skp1.code == coring.MtrDex.Ed25519_Seed
        assert skp1.verfer.code == coring.MtrDex.Ed25519

        # compute nxt digest
        # transferable so nxt is not empty
        ndiger = coring.Diger(ser=skp1.verfer.qb64b)
        nxt = [ndiger.qb64]
        assert nxt == ['EHJC7vkeIxZinEE-fn2S6gGTW2IDc6tvq6ZOBEL2YgKD']

        toad = 0  # no witnesses

        icp = eventing.incept(keys, isith=sith, ndigs=nxt, toad=toad, code=coring.MtrDex.Blake3_256)
        assert icp.raw == lhab.kever.serder.raw
        tsig0 = skp0.sign(icp.raw, index=0)
        assert tsig0.qb64b == (b'AABr33UBXfd03Q8KtU_FoBV6LpKmuv1govsWf3e7-VLLJnX3ECBtkDl-v3nJhak4-nfUVBF4gLpr'
                               b'LX_EulliZjIB')

        hab = remote.makeSignifyHab(name, serder=icp, sigers=[tsig0], stem="test", pidx=pidx, tier=tier, temp=True)
        assert hab.pre == lhab.pre  # we have recreated the local hab with the remote hab

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre  # we have recreated the local hab with the remote hab
        assert kever.sn == 0
        assert kever.serder.saider.qb64 == lhab.kever.serder.saider.qb64
        assert kever.ilk == coring.Ilks.icp
        assert [verfer.qb64 for verfer in kever.verfers] == keys
        assert [diger.qb64 for diger in kever.digers] == nxt

        habord = remote.db.habs.get(name)
        assert habord.hid == "ENysLhDtYrGZ2WXCVDEnN2lExe_XhwYRXzBQdrITAGwU"
        assert habord.stem == "test"
        assert habord.pidx == 1
        assert habord.tier == tier
        assert habord.temp is True

        lhab.rotate()

        ridx = ridx + 1
        kidx = kidx + 1
        # Regenerate skp1 signer from data in Habord as we will on Signify client
        skp1 = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        keys1 = [skp1.verfer.qb64]
        skp2 = creator.create(pidx=pidx, ridx=ridx+1, kidx=kidx+1, temp=True).pop()
        assert skp2.code == coring.MtrDex.Ed25519_Seed
        assert skp2.verfer.code == coring.MtrDex.Ed25519
        ndiger1 = coring.Diger(ser=skp2.verfer.qb64b)
        nxt1 = [ndiger1.qb64]
        assert nxt1 == ['EPMMF13g1NoN-mzDKAJOrHzIPi-hpDp3tHkzc2t97d6e']

        rot = eventing.rotate(pre=hab.pre, keys=keys1, dig=icp.saider.qb64, sn=1, isith=sith, ndigs=nxt1, toad=toad)
        assert rot.raw == lhab.kever.serder.raw

        tsig1 = skp1.sign(rot.raw, index=0)
        assert tsig1.qb64b == (b'AADaWvPu97xTMXMTFoCuCOKRrI9Vr6xSg9qjZQNu2S5C0J5WmEzBSVQdtyafm7P4Fd6TOhbPs-b9'
                               b'PkNXsOz7r_4A')

        msg = hab.rotate(serder=rot, sigers=[tsig1])
        assert msg == (b'{"v":"KERI10JSON000160_","t":"rot","d":"ENhoV9KycOjzJjBGrGOQo04U'
                       b'N-AwY2UpNg-hMNUXVAhn","i":"ENysLhDtYrGZ2WXCVDEnN2lExe_XhwYRXzBQd'
                       b'rITAGwU","s":"1","p":"ENysLhDtYrGZ2WXCVDEnN2lExe_XhwYRXzBQdrITAG'
                       b'wU","kt":"1","k":["DDAr4NGnAmxSEQAZpuH0VM4OxQHnxWB1zIURHlydCyW3"'
                       b'],"nt":"1","n":["EPMMF13g1NoN-mzDKAJOrHzIPi-hpDp3tHkzc2t97d6e"],'
                       b'"bt":"0","br":[],"ba":[],"a":[]}-AABAADaWvPu97xTMXMTFoCuCOKRrI9V'
                       b'r6xSg9qjZQNu2S5C0J5WmEzBSVQdtyafm7P4Fd6TOhbPs-b9PkNXsOz7r_4A')

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre
        assert kever.sn == 1
        assert kever.serder.saider.qb64 == lhab.kever.serder.saider.qb64
        assert kever.ilk == coring.Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert [diger.qb64 for diger in kever.digers] == nxt1

        habord = remote.db.habs.get(name)
        assert habord.hid == "ENysLhDtYrGZ2WXCVDEnN2lExe_XhwYRXzBQdrITAGwU"
        assert habord.stem == "test"
        assert habord.pidx == 1
        assert habord.tier == tier
        assert habord.temp is True

        with pytest.raises(kering.KeriError):
            hab.sign(ser=rot.raw)

            # create something to sign
        ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

        lsigs = lhab.sign(ser=ser, indices=[0])
        assert lsigs[0].qb64b == (b'AABosC3hRCZo09eEmyc2SPPK2q5OocvEzR2M8n6WROrCJVwoSyK6dE1IKKRXnBcAsYOlWIxUBWbc'
                                  b'd-ivo14z6s8N')

        # Regenerate signer from data in Habord as we will on Signify client
        rskp = creator.create(pidx=pidx, ridx=ridx, kidx=kidx, temp=True).pop()
        # Sign with regenerated signer
        rsig = rskp.sign(ser=ser, index=0)
        assert rsig.qb64b == lsigs[0].qb64b
