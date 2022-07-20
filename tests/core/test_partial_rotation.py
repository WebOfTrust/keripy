# -*- encoding: utf-8 -*-
"""
tests.core.test_partial_rotation module

"""
import pytest

from keri import kering
from keri.core import coring, eventing
from keri.db.basing import openDB

secrets = [
    'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
    'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
    'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
    'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
    'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
    'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
    'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
    'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY',
    "AAD8sznuHWMw7cl6eZJQLm8PGBKvCjQzDH1Ui9ygH0Uo",
    "ANqQNn_9UjfayUJNdQobmixrH9qJF1cltKDwDMVkiLg8",
    "A1t7ix1GuZIP48r6ljsoo8jPsB9dEnnWNfhy2XNl1r-c",
    "AhzCysVY12fWXfkH1QkAOCY6oYbVwXOaUjf7YPtIfC8U",
    "A4HrsYq9XfxYK76ffoceNzj9n8tBkXrWNBIXUNdoe5ME",
    "AhpAiPtDqDcEeU_eXlJ8Bk3kJE0g0jdezyXZdBKfXslU",
    "AzN9fKZAZEIn9jMN2fZ2B35MNMQJPAZrNrJQRMi_S_8g",
    "AkNrzLqnqRx9WCpJAwTAOE5oNaDlOgOYiuM9bL4HM9R0",
    "ALjR-EE3jUF2yXW7Tq7WJSh3OFc6-BNxXJ9jGdfwA6Bs",
    "AvpsEhige2ssBrMxskK2xXpeKfed4cvcZCIdRh7fhgiI",
]


def test_partial_rotation():

    # partial rotation with numeric thresholds
    with openDB(name="controller") as db:
        signers = [coring.Signer(qb64=secret) for secret in secrets]  # faster
        assert [signer.qb64 for signer in signers] == secrets

        nkeys = [coring.Diger(ser=signers[1].verfer.qb64b).qb64]

        # raises ValueError because nsith 2 is invalud for 1 nkey
        with pytest.raises(ValueError):
            _ = eventing.incept(keys=[signers[0].verfer.qb64],
                                nsith='2',
                                nkeys=nkeys,
                                code=coring.MtrDex.Blake3_256)

        # 5 keys for the next rotation
        nkeys = [
            coring.Diger(ser=signers[1].verfer.qb64b).qb64,
            coring.Diger(ser=signers[2].verfer.qb64b).qb64,
            coring.Diger(ser=signers[3].verfer.qb64b).qb64,
            coring.Diger(ser=signers[4].verfer.qb64b).qb64,
            coring.Diger(ser=signers[5].verfer.qb64b).qb64,
        ]

        serder = eventing.incept(keys=[signers[0].verfer.qb64],
                                 nsith='2',  # next signed event must satisfy this along with the new `kt`
                                 nkeys=nkeys,
                                 code=coring.MtrDex.Blake3_256)

        siger = signers[0].sign(serder.raw, index=0)  # return siger

        # create key event verifier state
        kever = eventing.Kever(serder=serder, sigers=[siger], db=db)

        assert kever.prefixer.qb64 == "Eozz_fD_4KNiIZAggGCPcCEbV-mDbvLH_UfVMsC83yLo"

        # partial rotation so only select subset of the keys
        keys = [
            signers[2].verfer.qb64,
            signers[4].verfer.qb64,
            signers[5].verfer.qb64
        ]
        nkeys = [
            coring.Diger(ser=signers[6].verfer.qb64b).qb64,
            coring.Diger(ser=signers[7].verfer.qb64b).qb64,
            coring.Diger(ser=signers[8].verfer.qb64b).qb64,
            coring.Diger(ser=signers[9].verfer.qb64b).qb64,
            coring.Diger(ser=signers[10].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 sith='3',
                                 keys=keys,
                                 dig=kever.serder.saider.qb64,
                                 nsith='4',
                                 nkeys=nkeys,
                                 sn=1)

        # sign serialization
        siger0 = signers[2].sign(rotser.raw, index=0)  # returns siger
        siger1 = signers[4].sign(rotser.raw, index=1)  # returns siger
        siger2 = signers[5].sign(rotser.raw, index=2)  # returns siger
        # update key event verifier state
        kever.update(serder=rotser, sigers=[siger0, siger1, siger2])

        assert kever.sn == 1
        assert kever.ntholder.sith == "4"
        keys = [verfer.qb64 for verfer in kever.verfers]
        assert keys == [
            "DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8",
            "D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU",
            "D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM",
        ]

        # partial rotation that will fail because it does not have enough sigs for prior threshold (`nt`)
        keys = [
            signers[6].verfer.qb64,
            signers[7].verfer.qb64,
            signers[8].verfer.qb64
        ]
        nkeys = [
            coring.Diger(ser=signers[11].verfer.qb64b).qb64,
            coring.Diger(ser=signers[12].verfer.qb64b).qb64,
            coring.Diger(ser=signers[13].verfer.qb64b).qb64,
            coring.Diger(ser=signers[14].verfer.qb64b).qb64,
            coring.Diger(ser=signers[15].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 sith='3',
                                 keys=keys,
                                 dig=kever.serder.saider.qb64,
                                 nsith='2',
                                 nkeys=nkeys,
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
        signers = [coring.Signer(qb64=secret) for secret in secrets]  # faster
        assert [signer.qb64 for signer in signers] == secrets

        # 5 keys for the next rotation
        nkeys = [
            coring.Diger(ser=signers[1].verfer.qb64b).qb64,
            coring.Diger(ser=signers[2].verfer.qb64b).qb64,
            coring.Diger(ser=signers[3].verfer.qb64b).qb64,
            coring.Diger(ser=signers[4].verfer.qb64b).qb64,
            coring.Diger(ser=signers[5].verfer.qb64b).qb64,
        ]

        serder = eventing.incept(keys=[signers[0].verfer.qb64],
                                 nsith=["1/2", "1/2", "1/3", "1/3", "1/3"],
                                 nkeys=nkeys,
                                 code=coring.MtrDex.Blake3_256)

        siger = signers[0].sign(serder.raw, index=0)  # return siger

        # create key event verifier state
        kever = eventing.Kever(serder=serder, sigers=[siger], db=db)

        assert kever.prefixer.qb64 == "EtxZNMpv5OheTzkisPAILhrPpvqTEI52tLldrlhPSKxA"

        # partial rotation so only select subset of the keys
        keys = [
            signers[3].verfer.qb64,
            signers[4].verfer.qb64,
            signers[5].verfer.qb64
        ]
        nkeys = [
            coring.Diger(ser=signers[11].verfer.qb64b).qb64,
            coring.Diger(ser=signers[12].verfer.qb64b).qb64,
            coring.Diger(ser=signers[13].verfer.qb64b).qb64,
            coring.Diger(ser=signers[14].verfer.qb64b).qb64,
            coring.Diger(ser=signers[15].verfer.qb64b).qb64
        ]
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 sith=["1/2", "1/2", "1/3"],
                                 keys=keys,
                                 dig=kever.serder.saider.qb64,
                                 nsith=["1/2", "1/2", "1/3", "1/3", "1/3"],
                                 nkeys=nkeys,
                                 sn=1)

        # sign serialization
        siger0 = signers[3].sign(rotser.raw, index=0)  # returns siger
        siger1 = signers[4].sign(rotser.raw, index=1)  # returns siger
        siger2 = signers[5].sign(rotser.raw, index=2)  # returns siger
        # update key event verifier state
        kever.update(serder=rotser, sigers=[siger0, siger1, siger2])

        assert kever.sn == 1
        assert kever.ntholder.sith == ["1/2", "1/2", "1/3", "1/3", "1/3"]
        keys = [verfer.qb64 for verfer in kever.verfers]
        assert keys == ['DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ',
                        'D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU',
                        'D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM']

        # partial rotation that will fail because threshold not met for prior threshold (`nt`)
        keys = [
            signers[13].verfer.qb64,
            signers[14].verfer.qb64,
        ]
        nkeys = []
        rotser = eventing.rotate(pre=kever.prefixer.qb64,
                                 sith='2',
                                 keys=keys,
                                 dig=kever.serder.saider.qb64,
                                 nsith='0',
                                 nkeys=nkeys,
                                 sn=2)

        # sign serialization
        siger0 = signers[13].sign(rotser.raw, index=0)  # returns siger
        siger1 = signers[14].sign(rotser.raw, index=1)  # returns siger

        # update key event verifier state
        with pytest.raises(kering.MissingSignatureError):
            kever.update(serder=rotser, sigers=[siger0, siger1])
