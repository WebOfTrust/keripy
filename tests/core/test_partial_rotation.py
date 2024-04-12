# -*- encoding: utf-8 -*-
"""
tests.core.test_partial_rotation module

"""
import pytest

from keri import kering

from keri import core
from keri.core import coring, eventing

from keri.db.basing import openDB



def test_partial_rotation():

    #  create signers
    raw = b"ABCDEFGH01234567"
    signers = core.Salter(raw=raw).signers(count=18, path='rot', temp=True)

    # partial rotation with numeric thresholds
    with openDB(name="controller") as db:

        ndigs = [coring.Diger(ser=signers[1].verfer.qb64b).qb64]

        # raises ValueError because nsith 2 is invalud for 1 nkey
        with pytest.raises(ValueError):
            _ = eventing.incept(keys=[signers[0].verfer.qb64],
                                nsith='2',
                                ndigs=ndigs,
                                code=coring.MtrDex.Blake3_256)

        # 5 keys for the next rotation
        ndigs = [
            coring.Diger(ser=signers[1].verfer.qb64b).qb64,
            coring.Diger(ser=signers[2].verfer.qb64b).qb64,
            coring.Diger(ser=signers[3].verfer.qb64b).qb64,
            coring.Diger(ser=signers[4].verfer.qb64b).qb64,
            coring.Diger(ser=signers[5].verfer.qb64b).qb64,
        ]

        serder = eventing.incept(keys=[signers[0].verfer.qb64],
                                 nsith='2',  # next signed event must satisfy this along with the new `kt`
                                 ndigs=ndigs,
                                 code=coring.MtrDex.Blake3_256)

        siger = signers[0].sign(serder.raw, index=0)  # return siger

        # create key event verifier state
        kever = eventing.Kever(serder=serder, sigers=[siger], db=db)

        assert kever.prefixer.qb64 == 'ELOoOFim_fwYEySZxhcg0r1XTXzFACzasBR3WvglN8Dn'

        # partial rotation so only select subset of the keys
        keys = [
            signers[2].verfer.qb64,
            signers[4].verfer.qb64,
            signers[5].verfer.qb64
        ]
        ndigs = [
            coring.Diger(ser=signers[6].verfer.qb64b).qb64,
            coring.Diger(ser=signers[7].verfer.qb64b).qb64,
            coring.Diger(ser=signers[8].verfer.qb64b).qb64,
            coring.Diger(ser=signers[9].verfer.qb64b).qb64,
            coring.Diger(ser=signers[10].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 isith='3',
                                 keys=keys,
                                 dig=kever.serder.said,
                                 nsith='4',
                                 ndigs=ndigs,
                                 sn=1)

        # sign serialization
        siger0 = signers[2].sign(rotser.raw, index=0, ondex=1)  # returns siger
        siger1 = signers[4].sign(rotser.raw, index=1, ondex=3)  # returns siger
        siger2 = signers[5].sign(rotser.raw, index=2, ondex=4)  # returns siger
        # update key event verifier state
        kever.update(serder=rotser, sigers=[siger0, siger1, siger2])

        assert kever.sn == 1
        assert kever.ntholder.sith == "4"
        keys = [verfer.qb64 for verfer in kever.verfers]
        assert keys == ['DHW697b8XAGiqr7TsztVMNwPmHX7TWmD7p0Uo4dfIYu3',
                        'DDXeNb9ODc37-ohxTqdNBSbH7v6Q4WbojSUGKC8MfWzS',
                        'DMEWpXmIznjrVMpV_Swi_F1Z5l2HrCFeowq3PuGX3LvE']

        # partial rotation that will fail because it does not have enough sigs for prior threshold (`nt`)
        keys = [
            signers[6].verfer.qb64,
            signers[7].verfer.qb64,
            signers[8].verfer.qb64
        ]
        ndigs = [
            coring.Diger(ser=signers[11].verfer.qb64b).qb64,
            coring.Diger(ser=signers[12].verfer.qb64b).qb64,
            coring.Diger(ser=signers[13].verfer.qb64b).qb64,
            coring.Diger(ser=signers[14].verfer.qb64b).qb64,
            coring.Diger(ser=signers[15].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 isith='3',
                                 keys=keys,
                                 dig=kever.serder.said,
                                 nsith='2',
                                 ndigs=ndigs,
                                 sn=2)

        # sign serialization
        siger0 = signers[6].sign(rotser.raw, index=0)  # returns siger
        siger1 = signers[7].sign(rotser.raw, index=1)  # returns siger
        siger2 = signers[8].sign(rotser.raw, index=2)  # returns siger

        # update key event verifier state
        with pytest.raises(kering.MissingSignatureError):
            kever.update(serder=rotser, sigers=[siger0, siger1, siger2])

    # partial rotation with weighted thresholds
    with openDB(name="controller") as db:

        # 5 keys for the next rotation
        ndigs = [
            coring.Diger(ser=signers[1].verfer.qb64b).qb64,
            coring.Diger(ser=signers[2].verfer.qb64b).qb64,
            coring.Diger(ser=signers[3].verfer.qb64b).qb64,
            coring.Diger(ser=signers[4].verfer.qb64b).qb64,
            coring.Diger(ser=signers[5].verfer.qb64b).qb64,
        ]

        serder = eventing.incept(keys=[signers[0].verfer.qb64],
                                 nsith=["1/2", "1/2", "1/3", "1/3", "1/3"],
                                 ndigs=ndigs,
                                 code=coring.MtrDex.Blake3_256)

        siger = signers[0].sign(serder.raw, index=0)  # return siger

        # create key event verifier state
        kever = eventing.Kever(serder=serder, sigers=[siger], db=db)

        assert kever.prefixer.qb64 == 'EPdegTY8sPauiS2mT2F1r_NzzJpOD6CnqZqz7JF4mr9F'

        # partial rotation so only select subset of the keys
        keys = [
            signers[3].verfer.qb64,
            signers[4].verfer.qb64,
            signers[5].verfer.qb64
        ]
        ndigs = [
            coring.Diger(ser=signers[11].verfer.qb64b).qb64,
            coring.Diger(ser=signers[12].verfer.qb64b).qb64,
            coring.Diger(ser=signers[13].verfer.qb64b).qb64,
            coring.Diger(ser=signers[14].verfer.qb64b).qb64,
            coring.Diger(ser=signers[15].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 isith=["1/2", "1/2", "1/3"],
                                 keys=keys,
                                 dig=kever.serder.said,
                                 nsith=["1/2", "1/2", "1/3", "1/3", "1/3"],
                                 ndigs=ndigs,
                                 sn=1)

        # sign serialization
        siger0 = signers[3].sign(rotser.raw, index=0, ondex=2)  # returns siger
        siger1 = signers[4].sign(rotser.raw, index=1, ondex=3)  # returns siger
        siger2 = signers[5].sign(rotser.raw, index=2, ondex=4)  # returns siger
        # update key event verifier state
        kever.update(serder=rotser, sigers=[siger0, siger1, siger2])

        assert kever.sn == 1
        assert kever.ntholder.sith == ["1/2", "1/2", "1/3", "1/3", "1/3"]
        keys = [verfer.qb64 for verfer in kever.verfers]
        assert keys == ['DA91Hp4_r8Lxhq-GmFedt4ke5__sZiIQMvbQxsQ1_JgO',
                        'DDXeNb9ODc37-ohxTqdNBSbH7v6Q4WbojSUGKC8MfWzS',
                        'DMEWpXmIznjrVMpV_Swi_F1Z5l2HrCFeowq3PuGX3LvE']

        # partial rotation that will fail because threshold not met for prior threshold (`nt`)
        keys = [
            signers[13].verfer.qb64,
            signers[14].verfer.qb64,
        ]
        ndigs = []
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 isith='2',
                                 keys=keys,
                                 dig=kever.serder.said,
                                 nsith='0',
                                 ndigs=ndigs,
                                 sn=2)

        # sign serialization
        siger0 = signers[13].sign(rotser.raw, index=0, ondex=2)  # returns siger
        siger1 = signers[14].sign(rotser.raw, index=1, ondex=3)  # returns siger

        # update key event verifier state
        with pytest.raises(kering.MissingSignatureError):
            kever.update(serder=rotser, sigers=[siger0, siger1])


if __name__ == "__main__":
    test_partial_rotation()
