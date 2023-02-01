# -*- encoding: utf-8 -*-
"""
tests.app.habbing remote module

"""
import pytest

from keri import kering
from keri.app import habbing
from keri.core import coring, eventing


def test_remote_salty_hab():
    name = "test"
    tier = coring.Tiers.low
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw, tier=tier)

    with habbing.openHby(name="remoteSalty") as remote, \
            habbing.openHby(name="local", salt=salter.qb64, temp=True, tier=tier) as local:
        # create a single Local Hab and compare the results with the Signify Hab
        lhab = local.makeHab(name=name)
        assert lhab.pre == "EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N"

        # create current key
        sith = 1  # one signer

        #  original signing keypair transferable default
        skp0 = salter.signer(path="test00", temp=True, tier=tier)
        assert skp0.code == coring.MtrDex.Ed25519_Seed
        assert skp0.verfer.code == coring.MtrDex.Ed25519
        keys = [skp0.verfer.qb64]

        # create next key
        #  next signing keypair transferable is default
        skp1 = salter.signer(path="test11", temp=True, tier=tier)
        assert skp1.code == coring.MtrDex.Ed25519_Seed
        assert skp1.verfer.code == coring.MtrDex.Ed25519
        # compute nxt digest
        # transferable so nxt is not empty
        ndiger = coring.Diger(ser=skp1.verfer.qb64b)
        nxt = [ndiger.qb64]
        assert nxt == ['EAbq5OnIog2j1Rm5dtFuFuSIBbKKxlV1ILwrRI5yPgtX']

        toad = 0  # no witnesses

        icp = eventing.incept(keys, isith=sith, ndigs=nxt, toad=toad, code=coring.MtrDex.Blake3_256)
        assert icp.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATi'
                           b'yZCcDH7N","i":"EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N","s":"0","kt":"1'
                           b'","k":["DPNKzAuOw9utnR6L1_bS0spnsPFbc609WdzUvJrfUh-h"],"nt":"1","n":["EAbq5O'
                           b'nIog2j1Rm5dtFuFuSIBbKKxlV1ILwrRI5yPgtX"],"bt":"0","b":[],"c":[],"a":[]}')
        tsig0 = skp0.sign(icp.raw, index=0)
        assert tsig0.qb64b == (b'AAB0ewd_rP91-GX9d943r48qWXThuHpHbqMwJT92jFJWbbynC-QGXVRPaSX5DGAI4Bqyviw4zsz-'
                               b'uEAxo9HwEucF')

        hab = remote.makeSignifyHab(name, serder=icp, sigers=[tsig0], ipath="test00", npath="test11", tier=tier,
                                    temp=True)
        assert hab.pre == lhab.pre  # we have recreated the local hab with the remote hab

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre  # we have recreated the local hab with the remote hab
        assert kever.sn == 0
        assert kever.serder.saider.qb64 == lhab.kever.serder.saider.qb64
        assert kever.ilk == coring.Ilks.icp
        assert [verfer.qb64 for verfer in kever.verfers] == keys
        assert [diger.qb64 for diger in kever.digers] == nxt

        habord = remote.db.habs.get(name)
        assert habord.hid == "EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N"
        assert habord.ipath == "test00"
        assert habord.npath == "test11"
        assert habord.tier == tier
        assert habord.temp is True

        lhab.rotate()

        # Regenerate skp1 signer from data in Habord as we will on Signify client
        skp1 = salter.signer(path=habord.npath, temp=habord.temp, tier=habord.tier)
        keys1 = [skp1.verfer.qb64]
        skp2 = salter.signer(path="test22", temp=True, tier=tier)
        assert skp2.code == coring.MtrDex.Ed25519_Seed
        assert skp2.verfer.code == coring.MtrDex.Ed25519
        ndiger1 = coring.Diger(ser=skp2.verfer.qb64b)
        nxt1 = [ndiger1.qb64]
        assert nxt1 == ['EKNg5bhKpDTv_DixBKYfOHHl1omtvQ06UD3Nf40JUsQ-']

        rot = eventing.rotate(pre=hab.pre, keys=keys1, dig=icp.saider.qb64, sn=1, isith=sith, ndigs=nxt1, toad=toad)
        assert rot.raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EEZTwrSQdE6QXDNHGMVDf8ZcfA-us9tavFOR'
                           b'rBaorrtf","i":"EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N","s":"1","p":"EH'
                           b'eU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N","kt":"1","k":["DN8nxDNnlY-qCNdb2'
                           b'94nZQs29PXDsmbphujYJGQCLL0Y"],"nt":"1","n":["EKNg5bhKpDTv_DixBKYfOHHl1omtvQ0'
                           b'6UD3Nf40JUsQ-"],"bt":"0","br":[],"ba":[],"a":[]}')
        tsig1 = skp1.sign(rot.raw, index=0)
        assert tsig1.qb64b == (b'AAAGWYaw6N_4Wk2IBVOaPGb-rnuj1ys5xSHjfYnAzTRdBN8VzT9GVkBE8CLxLp0iSQ_SCRNpKQEV'
                               b'6BIwPVyJS0cA')

        msg = hab.rotate(serder=rot, sigers=[tsig1], npath="test22", temp=True)
        assert msg == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EEZTwrSQdE6QXDNHGMVDf8Zc'
                       b'fA-us9tavFORrBaorrtf","i":"EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiy'
                       b'ZCcDH7N","s":"1","p":"EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH'
                       b'7N","kt":"1","k":["DN8nxDNnlY-qCNdb294nZQs29PXDsmbphujYJGQCLL0Y"'
                       b'],"nt":"1","n":["EKNg5bhKpDTv_DixBKYfOHHl1omtvQ06UD3Nf40JUsQ-"],'
                       b'"bt":"0","br":[],"ba":[],"a":[]}-AABAAAGWYaw6N_4Wk2IBVOaPGb-rnuj'
                       b'1ys5xSHjfYnAzTRdBN8VzT9GVkBE8CLxLp0iSQ_SCRNpKQEV6BIwPVyJS0cA')

        kever = hab.kever
        assert kever.prefixer.qb64 == lhab.pre
        assert kever.sn == 1
        assert kever.serder.saider.qb64 == lhab.kever.serder.saider.qb64
        assert kever.ilk == coring.Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert [diger.qb64 for diger in kever.digers] == nxt1

        habord = remote.db.habs.get(name)
        assert habord.hid == "EHeU-ldGfJhxceV9BTq38HdFUoasoWEcYATiyZCcDH7N"
        assert habord.ipath == "test11"
        assert habord.npath == "test22"
        assert habord.tier == tier
        assert habord.temp is True

        with pytest.raises(kering.KeriError):
            hab.sign(ser=rot.raw)

            # create something to sign
        ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

        lsigs = lhab.sign(ser=ser, indices=[0])
        assert lsigs[0].qb64b == (b'AABaTxcQvCatFXQJK2uYuss7JC2SLgisX70Tm0DyWAOxRPC1nYuMrbV2UWCa5zYQTIzu4I7SqfbD'
                                  b'XKgvxjjpJfkP')

        # Regenerate signer from data in Habord as we will on Signify client
        rskp = salter.signer(path=habord.ipath, temp=habord.temp, tier=habord.tier)
        # Sign with regenerated signer
        rsig = rskp.sign(ser=ser, index=0)
        assert rsig.qb64b == lsigs[0].qb64b
