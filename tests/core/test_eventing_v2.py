# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing_v2 module

"""
import os

import blake3
import pysodium
import pytest

from keri import (Version, ValidationError, UnverifiedReceiptError, InvalidCodeError,
                         Ilks, TraitDex, Vrsn_1_0, Vrsn_2_0, Ilks, Kinds,
                         versify, deversify)

from keri.app import habbing, openKS, Manager
from keri.core import (Signer, Counter, Codens, Kever, Parser,
                       SerderKERI, Salter, Diger, Matter, Cigar, Seqner,
                       Verfer, Prefixer, Number, Saider, Seqner,
                       DigDex, MtrDex, PreDex, NumDex, IdrDex, IdxSigDex,
                       Siger, SealDigest, SealRoot, SealBack, SealEvent,
                       SealSource, SealLast, BlindState, BoundState, TypeMedia,
                       StateEvent, StateEstEvent,
                       Kever, Kevery,
                       LastEstLoc, simple, ample, deWitnessCouple,
                       deReceiptCouple, deSourceCouple, deReceiptTriple,
                       deTransReceiptQuadruple, deTransReceiptQuintuple,
                       incept, rotate, interact, receipt, query, delcept,
                       deltate, state, messagize, loadEvent)

from keri.db import openDB, dgKey, snKey
from keri.help import helping, ogler

logger = ogler.getLogger()


def assertKeriV2Cesr(ked):
    proto, pvrsn, kind, _, _ = deversify(ked["v"])
    assert proto == "KERI"
    assert pvrsn == Vrsn_2_0
    assert kind == Kinds.cesr


# def test_keyevent_defaults_v2(mockHelpingNowUTC):
#     """
#     Test default key event generation now emits KERI v2 CESR events.
#     """
#     assert Version == Vrsn_2_0
#
#     signer0 = Signer(transferable=False)
#     serder0 = incept(keys=[signer0.verfer.qb64])
#     assert serder0.pvrsn == Vrsn_2_0
#     assert serder0.kind == Kinds.cesr
#     assert serder0.raw.startswith(b"-")
#
#     signer1 = Signer()
#     signer2 = Signer()
#     ndigs = [Diger(ser=signer2.verfer.qb64b).qb64]
#     serder1 = incept(keys=[signer1.verfer.qb64], ndigs=ndigs)
#     assert serder1.pvrsn == Vrsn_2_0
#     assert serder1.kind == Kinds.cesr
#
#     signer4 = Signer()
#     serder2 = rotate(pre=serder1.pre,
#                               keys=[signer2.verfer.qb64],
#                               dig=serder1.said,
#                               ndigs=[Diger(ser=signer4.verfer.qb64b).qb64])
#     assert serder2.pvrsn == Vrsn_2_0
#     assert serder2.kind == Kinds.cesr
#
#     serder3 = interact(pre=serder1.pre, dig=serder2.said, sn=2)
#     assert serder3.pvrsn == Vrsn_2_0
#     assert serder3.kind == Kinds.cesr
#
#     serder4 = receipt(pre=serder1.pre, sn=2, said=serder3.said)
#     assert serder4.pvrsn == Vrsn_2_0
#     assert serder4.kind == Kinds.cesr


def test_keyeventfuncs(mockHelpingNowUTC):
    """Test the support functionality for key event generation functions for
    version 2 KERI

    """
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    # print()
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    # Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False)  # original signing keypair non transferable
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAu0OKERICAACAAXicpELAQm4OEfqcU7n9v31V3V6NqtjZjEeTk9RRWwM6hbHRpBFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAAMAAB-JALBFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAA-JAAMAAA-JAA-JAA-JAA')

    with pytest.raises(ValidationError):
        # non-empty ndigs with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N,
                        ndigs=["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    with pytest.raises(ValidationError):
        # non-empty backers with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N,
                        wits=["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    with pytest.raises(ValidationError):
        # non-empty seals with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N,
                        data=[{"i": "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"}],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAu0OKERICAACAAXicpEMkhPJZUWSukFP1fZmkgGgAJZufMpfN7FGUWrOkcHM9HDFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAA-JAAMAAA-JAA-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == serder0.pre == 'EI4gLb3j4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str
    assert serder0.raw == (b'-FA50OKERICAACAAXicpEI4gLb3j4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHEI4gLb3j4wnW'
                            b'o2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                            b'mflpNceHo4XHMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                            b'-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert pre == serder0.pre
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'EI4gLb3j4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'-FA50OKERICAACAAXicpEI4gLb3j4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHEI4gLb3j4wnW'
                        b'o2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                        b'-JAA')

    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True, kind=Kinds.cesr,
                     version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'-FA50OKERICAACAAXicpELpQjat5fj5nawuQq1A_HrDkJK-oHiR35eRaiVB4hua6DFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                        b'-JAA')

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, kind=Kinds.cesr, version=Vrsn_2_0)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'-FA50OKERICAACAAXicpELpQjat5fj5nawuQq1A_HrDkJK-oHiR35eRaiVB4hua6DFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                        b'-JAA')

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1,
                     kind=Kinds.cesr, version=Vrsn_2_0)
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'-FBF0OKERICAACAAXrotEFv8ULsB_UwUOFMT9TkajGw-kWwToxGvqJWrZnIjXRJ-DFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAABELpQjat5fj5nawuQq1A_HrDkJK-oHiR35eRaiVB4'
                        b'hua6MAAB-JALDB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQMAAB-JALEIsKL3B6Zz5I'
                        b'CGxCQp-SoLXjwOrdlSbLJrEn21c2zVaUMAAA-JAA-JAA-JAA-JAA')

    # Rotation: Transferable not abandoned i.e. next not empty  Intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1,
                     intive=True, kind=Kinds.cesr, version=Vrsn_2_0)  # intive
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == 1
    assert serder1.ked["nt"] == 1
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == 0
    assert serder1.raw == (b'-FBF0OKERICAACAAXrotEFv8ULsB_UwUOFMT9TkajGw-kWwToxGvqJWrZnIjXRJ-DFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAABELpQjat5fj5nawuQq1A_HrDkJK-oHiR35eRaiVB4'
                        b'hua6MAAB-JALDB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQMAAB-JALEIsKL3B6Zz5I'
                        b'CGxCQp-SoLXjwOrdlSbLJrEn21c2zVaUMAAA-JAA-JAA-JAA-JAA')

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.said, sn=2, kind=Kinds.cesr,
                       version=Vrsn_2_0)
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["p"] == serder1.said
    assert serder2.raw == (b'-FAn0OKERICAACAAXixnEDPJcA23L5uq6eWm5PwcWjiFBFXlvV2xP5clIEAZiS8IDFs8BBx86uyt'
                        b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAACEFv8ULsB_UwUOFMT9TkajGw-kWwToxGvqJWrZnIj'
                        b'XRJ--JAA')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, said=serder2.said, version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.said
    assert serder3.raw == (b'-FAb0OKERICAACAAXrctEDPJcA23L5uq6eWm5PwcWjiFBFXlvV2xP5clIEAZiS8IDFs8BBx86uyt'
                           b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAA')



    serder4 = receipt(pre=pre, sn=2, said=serder2.said, version=Vrsn_2_0, kind=Kinds.cesr)

    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.said
    assert serder4.raw == (b'-FAb0OKERICAACAAXrctEDPJcA23L5uq6eWm5PwcWjiFBFXlvV2xP5clIEAZiS8IDFs8BBx86uyt'
                           b'IM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAC')



    # Receipt  transferable identifier
    serderA = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256,
                     kind=Kinds.cesr, version=Vrsn_2_0)
    assert serderA.raw == (b'-FA50OKERICAACAAXicpEI4gLb3j4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHEI4gLb3j4wnW'
                        b'o2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHMAAAMAAB-JALDFs8BBx86uytIM0D2BhsE5rrqVIT8ef8'
                        b'mflpNceHo4XHMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                        b'-JAA')
    seal = SealEvent(i=serderA.ked["i"], s=serderA.ked["s"], d=serderA.said)
    assert seal.i == serderA.ked["i"]
    assert seal.d == serderA.said

    siger = signer0.sign(ser=serderA.raw, index=0)
    msg = messagize(serder=serder4, sigers=[siger], source=seal, framed=False,
                    gvrsn=Vrsn_2_0)
    assert msg == (b'-FAb0OKERICAACAAXrctEDPJcA23L5uq6eWm5PwcWjiFBFXlvV2xP5clIEAZiS8I'
                b'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XHMAAC-CAv-XAuEI4gLb3j'
                b'4wnWo2ZtzbHRzKWs57PXl6Ls_w1VXdLdvqxHMAAAEI4gLb3j4wnWo2ZtzbHRzKWs'
                b'57PXl6Ls_w1VXdLdvqxH-KAWAABvBAdydAs5xiIDquIklFfSAKnIoT_t-cwHTmDx'
                b'Z3QtT67WjGUct1xjGV3mG4ARvfxIJE1cGAe5HLIIGW6Xik0G')

    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD)  # next signing keypair transferable is default
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nxtD = [Diger(ser=key.encode("utf-8")).qb64 for key in keysD]  # default sith is 1
    # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, ndigs=nxtD, kind=Kinds.cesr,
                      version=Vrsn_2_0)
    pre = serderD.ked["i"]
    assert pre == serderD.pre
    assert serderD.ked["i"] == 'EKybuFPAE61UWlHVWSas49NOfSHl3hKDvu-cJNfuIcj6'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'-FBE0OKERICAACAAXdipEKybuFPAE61UWlHVWSas49NOfSHl3hKDvu-cJNfuIcj6EKybuFPAE61U'
                        b'WlHVWSas49NOfSHl3hKDvu-cJNfuIcj6MAAAMAAB-JALDB4GWvru73jWZKpNgMQp8ayDRin0NG0Y'
                        b'mn_RXQP_v-PQMAAB-JALEIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7WMAAA-JAA-JAA'
                        b'-JAAEAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd')
    assert serderD.said == 'EKybuFPAE61UWlHVWSas49NOfSHl3hKDvu-cJNfuIcj6'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR)  # next signing keypair transferable is default
    assert signerR.code == MtrDex.Ed25519_Seed
    assert signerR.verfer.code == MtrDex.Ed25519
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    # default sith is 1
    nxtR = [Diger(ser=signerR.verfer.qb64b).qb64]  # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      ndigs=nxtR,
                      kind=Kinds.cbor,
                      version=Vrsn_2_0)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'\xafavsKERICAACAACBORAAEw.atcdrtadx,EECI637lfT-Xp4z_H9tuSkAgnpVY5pdIbY9ydum'
                        b'GAx_Zaix,EKybuFPAE61UWlHVWSas49NOfSHl3hKDvu-cJNfuIcj6asa4apx,EANkcl_QewzrRSK'
                        b'H2p9zUskHI462CuIMS_HQIO132Z30bkta1ak\x81x,DPLt4YqQsWZ5DPztI32mSyTJPRESONvE9'
                        b'KbETtCVYIeHbnta1an\x81x,EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaUbbta0bb'
                        b'r\x80bba\x80ac\x80aa\x80')
    assert serderR.said == 'EECI637lfT-Xp4z_H9tuSkAgnpVY5pdIbY9ydumGAx_Z'


    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    #  Secp256r1 Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False, code=MtrDex.ECDSA_256r1_Seed)  # original signing keypair non transferable
    assert signer0.code == MtrDex.ECDSA_256r1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256r1N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAw0OKERICAACAAXicpEKRmfSKU1Cnye594RRZTpgdGKedFu9141pztL3D1e9ag1AAIA3cK_P2C'
                        b'Dlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZMAAAMAAB-JAM1AAIA3cK_P2CDlh-_EMFPvyqTPI1'
                        b'POkw-dr14DANx5JEXDCZMAAA-JAAMAAA-JAA-JAA-JAA')

    with pytest.raises(ValidationError):
        # non-empty nxt with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N,
                        ndigs=['1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    with pytest.raises(ValidationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N,
                        wits=['1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    with pytest.raises(ValidationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N,
                        data=[{"i": '1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'}],
                        kind=Kinds.cesr, version=Vrsn_2_0)

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed, code=MtrDex.ECDSA_256r1_Seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.ECDSA_256r1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256r1
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAw0OKERICAACAAXicpEF3HV7LE6LeroVVK8oE1jRM10HLYhBhutLtnGBGvTyAC1AAJA3cK_P2C'
                        b'Dlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZMAAAMAAB-JAM1AAJA3cK_P2CDlh-_EMFPvyqTPI1'
                        b'POkw-dr14DANx5JEXDCZMAAA-JAAMAAA-JAA-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == 'EEvRLev2-LOUz2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibb'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str

    assert serder0.raw == (b'-FA60OKERICAACAAXicpEEvRLev2-LOUz2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibbEEvRLev2-LOU'
                        b'z2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibbMAAAMAAB-JAM1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw'
                        b'-dr14DANx5JEXDCZMAAB-JALEDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4MAAA-JAA'
                        b'-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'EEvRLev2-LOUz2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibb'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'-FA60OKERICAACAAXicpEEvRLev2-LOUz2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibbEEvRLev2-LOU'
                        b'z2Z6tlaHoL8CXKa-9xrw_P_CmA-dSibbMAAAMAAB-JAM1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw'
                        b'-dr14DANx5JEXDCZMAAB-JALEDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4MAAA-JAA'
                        b'-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'-FA70OKERICAACAAXicpEPtyeUST8zhLEDKmn4odBirfSnhgUrZC0RaKo86BOjBt1AAJA3cK_P2C'
                        b'Dlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZMAAAMAAB-JAM1AAJA3cK_P2CDlh-_EMFPvyqTPI1'
                        b'POkw-dr14DANx5JEXDCZMAAB-JALEDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4MAAA'
                        b'-JAA-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, kind=Kinds.cesr, version=Vrsn_2_0)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'-FA70OKERICAACAAXicpEPtyeUST8zhLEDKmn4odBirfSnhgUrZC0RaKo86BOjBt1AAJA3cK_P2C'
                        b'Dlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZMAAAMAAB-JAM1AAJA3cK_P2CDlh-_EMFPvyqTPI1'
                        b'POkw-dr14DANx5JEXDCZMAAB-JALEDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4MAAA'
                        b'-JAA-JAA-JAA')

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256r1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256r1
    keys2 = [Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1,
                     kind=Kinds.cesr, version=Vrsn_2_0)
    # print(f'evnt {serder1.raw}')
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'-FBH0OKERICAACAAXrotEPTdTeOFRcdw2Yifftg3oNkh-_AATRaA7lUiretGAVoJ1AAJA3cK_P2C'
                        b'Dlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZMAABEPtyeUST8zhLEDKmn4odBirfSnhgUrZC0RaK'
                        b'o86BOjBtMAAB-JAM1AAJAtrK9Q8IqgO3B4IKY4m8Dl7dp1fC77dNCsHP2aWctriaMAAB-JALEIkm'
                        b'r0Ne3wbNvTKRU-A9NLmCL-RYgu2SZuzIb3n-9xFHMAAA-JAA-JAA-JAA-JAA')

    #  Secp256k1 Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False, code=MtrDex.ECDSA_256k1_Seed)  # original signing keypair non transferable
    assert signer0.code == MtrDex.ECDSA_256k1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256k1N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAAAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAw0OKERICAACAAXicpEBvBPzqYWk_e1wY8PBFEBVH7oqUEPAOTEjpZFF2KukTX1AAAAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAAMAAB-JAM1AAAAg299p5IMvuw71HW_TlbzGq5'
                        b'cVOQ7bRbeDuhheF-DPYkMAAA-JAAMAAA-JAA-JAA-JAA')

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.ECDSA_256k1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256k1
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0, kind=Kinds.cesr, version=Vrsn_2_0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder.ked["n"] == []
    assert serder.raw == (b'-FAw0OKERICAACAAXicpEExsO-bOPQI_FV2uazK1058wmR7WRdyHhm3xu7JYeFNb1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAAMAAB-JAM1AABAg299p5IMvuw71HW_TlbzGq5'
                        b'cVOQ7bRbeDuhheF-DPYkMAAA-JAAMAAA-JAA-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == 'ENXz2YzRQF1LjEcdkwBWlej0anU9C_lAasN_YgTLaPn9'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str
    assert serder0.raw == (b'-FA60OKERICAACAAXicpENXz2YzRQF1LjEcdkwBWlej0anU9C_lAasN_YgTLaPn9ENXz2YzRQF1L'
                        b'jEcdkwBWlej0anU9C_lAasN_YgTLaPn9MAAAMAAB-JAM1AABAg299p5IMvuw71HW_TlbzGq5cVOQ'
                        b'7bRbeDuhheF-DPYkMAAB-JALEJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnOMAAA-JAA'
                        b'-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True,
                     kind=Kinds.cesr, version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'ENXz2YzRQF1LjEcdkwBWlej0anU9C_lAasN_YgTLaPn9'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'-FA60OKERICAACAAXicpENXz2YzRQF1LjEcdkwBWlej0anU9C_lAasN_YgTLaPn9ENXz2YzRQF1L'
                        b'jEcdkwBWlej0anU9C_lAasN_YgTLaPn9MAAAMAAB-JAM1AABAg299p5IMvuw71HW_TlbzGq5cVOQ'
                        b'7bRbeDuhheF-DPYkMAAB-JALEJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnOMAAA-JAA'
                        b'-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True, kind=Kinds.cesr,
                     version=Vrsn_2_0)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'-FA70OKERICAACAAXicpEMKKrTGc2-Cj3ip3zIDJukZ8Xqyrv9EHbAGgmWXaA9DZ1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAAMAAB-JAM1AABAg299p5IMvuw71HW_TlbzGq5'
                        b'cVOQ7bRbeDuhheF-DPYkMAAB-JALEJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnOMAAA'
                        b'-JAA-JAA-JAA')

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, kind=Kinds.cesr, version=Vrsn_2_0)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'-FA70OKERICAACAAXicpEMKKrTGc2-Cj3ip3zIDJukZ8Xqyrv9EHbAGgmWXaA9DZ1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAAMAAB-JAM1AABAg299p5IMvuw71HW_TlbzGq5'
                        b'cVOQ7bRbeDuhheF-DPYkMAAB-JALEJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnOMAAA'
                        b'-JAA-JAA-JAA')

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256k1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256k1
    keys2 = [Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1,
                     kind=Kinds.cesr, version=Vrsn_2_0)
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'-FBH0OKERICAACAAXrotEGz3OuXE-GXpoA9jwLGU8vS3Q8w1fabfjhai_-dDYnQa1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAABEMKKrTGc2-Cj3ip3zIDJukZ8Xqyrv9EHbAGg'
                        b'mWXaA9DZMAAB-JAM1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQKgHfa6eKyLcZpEn26MAAB-JALEDn6'
                        b'z-KqmwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07MAAA-JAA-JAA-JAA-JAA')

    # Rotation: Transferable not abandoned i.e. next not empty  Intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256k1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256k1
    keys2 = [Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1,
                     intive=True, kind=Kinds.cesr, version=Vrsn_2_0)  # intive
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == 1
    assert serder1.ked["nt"] == 1
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == 0
    assert serder1.raw == (b'-FBH0OKERICAACAAXrotEGz3OuXE-GXpoA9jwLGU8vS3Q8w1fabfjhai_-dDYnQa1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAABEMKKrTGc2-Cj3ip3zIDJukZ8Xqyrv9EHbAGg'
                        b'mWXaA9DZMAAB-JAM1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQKgHfa6eKyLcZpEn26MAAB-JALEDn6'
                        b'z-KqmwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07MAAA-JAA-JAA-JAA-JAA')

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.said, sn=2, kind=Kinds.cesr,
                       version=Vrsn_2_0)
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["p"] == serder1.said
    assert serder2.raw == (b'-FAo0OKERICAACAAXixnEKoqIn7NChzNWJrzxD-dAFt4bfrCe5gTIrNIvzt0iy7R1AABAg299p5I'
                        b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAACEGz3OuXE-GXpoA9jwLGU8vS3Q8w1fabfjhai'
                        b'_-dDYnQa-JAA')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, said=serder2.said, version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.said
    assert serder3.raw == (b'-FAc0OKERICAACAAXrctEKoqIn7NChzNWJrzxD-dAFt4bfrCe5gTIrNIvzt0iy7R1AABAg299p5I'
                           b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAA')

    serder4 = receipt(pre=pre, sn=2, said=serder2.said, version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.said
    assert serder4.raw == (b'-FAc0OKERICAACAAXrctEKoqIn7NChzNWJrzxD-dAFt4bfrCe5gTIrNIvzt0iy7R1AABAg299p5I'
                         b'Mvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYkMAAC')

    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signerD.code == MtrDex.ECDSA_256k1_Seed
    assert signerD.verfer.code == MtrDex.ECDSA_256k1
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nxtD = [Diger(ser=key.encode("utf-8")).qb64 for key in keysD]  # default sith is 1
    # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, ndigs=nxtD, kind=Kinds.cesr,
                      version=Vrsn_2_0)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'EMzVEVKepo9BgubWbkImZmyIPNkcG6zsY6ec-iMuSyTa'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'-FBF0OKERICAACAAXdipEMzVEVKepo9BgubWbkImZmyIPNkcG6zsY6ec-iMuSyTaEMzVEVKepo9B'
                        b'gubWbkImZmyIPNkcG6zsY6ec-iMuSyTaMAAAMAAB-JAM1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQK'
                        b'gHfa6eKyLcZpEn26MAAB-JALEJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnOMAAA-JAA'
                        b'-JAA-JAAEAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd')

    assert serderD.said == 'EMzVEVKepo9BgubWbkImZmyIPNkcG6zsY6ec-iMuSyTa'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signerR.code == MtrDex.ECDSA_256k1_Seed
    assert signerR.verfer.code == MtrDex.ECDSA_256k1
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    # default sith is 1
    nxtR = [Diger(ser=signerR.verfer.qb64b).qb64]  # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      ndigs=nxtR,
                      kind=Kinds.cesr,
                      version=Vrsn_2_0)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'-FBG0OKERICAACAAXdrtEFp0BtpcMSeuHLdgdP7JSdREpPI-SLaYYUmrzMKTvOs3EMzVEVKepo9B'
                        b'gubWbkImZmyIPNkcG6zsY6ec-iMuSyTaMAAEEANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO13'
                        b'2Z30MAAB-JAM1AABAh-zxZOUdAZwXBhbtZQgzD3LLPMYxF7HgsPbd2mILaPcMAAB-JALEDn6z-Kq'
                        b'mwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07MAAA-JAA-JAA-JAA-JAA')

    assert serderR.said == 'EFp0BtpcMSeuHLdgdP7JSdREpPI-SLaYYUmrzMKTvOs3'

    """ Done Test """



def test_kever(mockHelpingNowUTC):
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """

    with pytest.raises(ValueError):  # Missing required arguments
        kever = Kever()

    with openDB() as db:  # Transferable case
        # Setup inception key event dict
        raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
        salter = Salter(raw=raw)
        # create current key
        sith = 1  # one signer
        #  original signing keypair transferable default
        skp0 = salter.signer(path="A", temp=True, transferable=True)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519
        assert skp0.verfer.qb64 == 'DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        keys = [skp0.verfer.qb64]

        # create next key
        #  next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        # compute nxt digest
        # transferable so nxt is not empty
        ndiger = Diger(ser=skp1.verfer.qb64b)
        nxt = [ndiger.qb64]
        assert nxt == ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj']

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        # make with defaults with non-digestive prefix
        serder = SerderKERI(makify=True,
                                      ilk=Ilks.icp,
                                      saids = {'i': PreDex.Ed25519},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 1
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)

        serder = SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EBTCANzIfUThxmM1z1SFxQuwooGdF4QwtotRS01vZGqi'
        assert serder.pre == 'DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        aid0 = serder.pre

        # Assign first serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # no error
        assert kever.db == db
        assert kever.cues == None
        assert kever.prefixer.qb64 == aid0
        assert kever.sner.num == 0
        assert kever.sn == kever.sner.num  # sn property
        assert [verfer.qb64 for verfer in kever.verfers] == [skp0.verfer.qb64]
        assert kever.ndigs == nxt
        state = kever.db.states.get(keys=kever.prefixer.qb64)
        assert state.s == kever.sner.numh == '0'
        feqner = kever.db.fons.get(keys=(kever.prefixer.qb64, kever.serder.said))
        assert feqner.sn == kever.sn

        ksr = kever.state()  # key state record
        assert ksr == state
        assert ksr.i == kever.prefixer.qb64
        assert ksr.s == kever.sner.numh
        assert ([key for key in ksr.k] ==
                [verfer.qb64 for verfer in kever.verfers])
        assert ksr._asjson() == (b'{"vn":[1,0],"i":"DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e","s":"0","p":"'
                        b'","d":"EBTCANzIfUThxmM1z1SFxQuwooGdF4QwtotRS01vZGqi","f":"0","dt":"2021-01-0'
                        b'1T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DAUDqkmn-hqlQKD8W-FAEa5JU'
                        b'vJC2I9yarEem-AAEg3e"],"nt":"1","n":["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7'
                        b'hOrWj"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EBTCANzIfUThxmM1z1SFxQuwoo'
                        b'GdF4QwtotRS01vZGqi","br":[],"ba":[]},"di":""}')

        # test exposeds
        raw = b"raw salt to test"
        #  create signers with verfers
        signers = Salter(raw=raw).signers(count=3, path="next", temp=True)

        # create something to sign
        ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

        # test different index and ondex
        sigers = []
        digers = []
        for i, signer in enumerate(signers):
            o = len(signers) - 1 - i
            siger = signer.sign(ser=ser, index=i, ondex=o)
            diger = Diger(ser=siger.verfer.qb64b)
            sigers.append(siger)
            digers.append(diger)

        digers.reverse()

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[2, 1, 0]

        # test partial mix
        siger0 = signers[0].sign(ser=ser, index=0)  # both same
        assert siger0.code == IdxSigDex.Ed25519_Sig  # both same
        diger0 = Diger(ser=siger0.verfer.qb64b)

        siger1 = signers[1].sign(ser=ser, index=1, only=True)  # current only
        assert siger1.code == IdxSigDex.Ed25519_Crt_Sig  # current only

        siger2 = signers[2].sign(ser=ser, index=2, ondex=1)  # both different
        assert siger2.code == IdxSigDex.Ed25519_Big_Sig  # both different
        diger1 = Diger(ser=siger2.verfer.qb64b)

        sigers = [siger0, siger1, siger2]
        digers = [diger0, diger1]

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[0, 1]


        # test Bad digest
        siger0 = signers[0].sign(ser=ser, index=0)  # both same
        assert siger0.code == IdxSigDex.Ed25519_Sig  # both same
        diger0 = Diger(ser=b"Bad Digest")  # bad digest

        siger1 = signers[1].sign(ser=ser, index=1, only=True)  # current only
        assert siger1.code == IdxSigDex.Ed25519_Crt_Sig  # current only

        siger2 = signers[2].sign(ser=ser, index=2, ondex=1)  # both different
        assert siger2.code == IdxSigDex.Ed25519_Big_Sig  # both different
        diger1 = Diger(ser=siger2.verfer.qb64b, code=DigDex.Blake2b_256)

        sigers = [siger0, siger1, siger2]
        digers = [diger0, diger1]

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[1]


    with openDB() as db:  # Non-Transferable case Error nxt not empty
        # test  Error case Transferable incept event but with nontrans aid
        # Setup inception key event dict
        # create current key
        sith = 1  # one signer
        # original signing keypair non-transferable
        skp0 = salter.signer(path="A", temp=True, transferable=False)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        assert skp0.verfer.qb64 == 'BAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        keys = [skp0.verfer.qb64]

        # create next key
        # next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nxt = [Diger(ser=skp1.verfer.qb64b).qb64]  # nxt is not empty so will error

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        # make with defaults with non-transferable prefix
        serder = SerderKERI(makify=True,
                                      ilk=Ilks.icp,
                                      saids = {'i': PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 1
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)

        serder = SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EFsuiA86Q5gGuVOO3tou8KSU6LORSExIUxzWNrlnW7WP'
        assert serder.pre == skp0.verfer.qb64
        aid0 = serder.pre

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)

        # retry with valid empty nxt
        nxt = ""  # nxt is empty so no error
        sn = 0  # inception event so 0
        toad = 0  # no witnesses


        # make with defaults with non-transferable prefix
        serder = SerderKERI(makify=True,
                                      ilk=Ilks.icp,
                                      saids = {'i': PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 0
        sad['n'] = nxt  # empty nxt
        sad['bt'] = "{:x}".format(toad)

        serder = SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EHXNdcXZzJnRIdaNk30W5h4yD5sZ2Y_n3u_ReE65X9w-'
        assert serder.pre == skp0.verfer.qb64
        aid0 = serder.pre

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

    with openDB() as db:  # Non-Transferable case baks not empty
        # Setup inception key event dict
        # create current key

        # original signing keypair non-transferable
        skp0 = salter.signer(path="B", temp=True, transferable=False)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        assert skp0.verfer.qb64 == 'BEe36N1fb59sXaHIUBOlfSCf4J_H5xajMuMr5u_isjs4'
        sith = 1  # one signer
        keys = [skp0.verfer.qb64]

        # create next key
        # next signing keypair transferable is default
        skp1 = salter.signer(path="O", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest must be empty
        nxt = ""

        sn = 0  # inception event so 0
        toad = 0  # no witnesses

        # error case if baks not empty
        baks = ["BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"]

        # make with defaults with non-transferable prefix
        serder = SerderKERI(makify=True,
                                      ilk=Ilks.icp,
                                      saids = {'i': PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 0
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks

        serder = SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EKcREpfNupJ8oOqdnqDIyJVr1-GgIMBrVOtBUR9Gm6lO'
        assert serder.pre == skp0.verfer.qb64


        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)


        # retry with toad =1 and baks not empty
        toad = 1
        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)

        serder = SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EBKhptvqccp0KNBaS45bNPdTE4m19U1IvweHJW2PIEDI'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)


        # retry with valid empty baks
        baks = []
        # use some data, also invalid
        a = [dict(i="EAz8Wqqom6eeIFsng3cGQiUJ1uiNelCrR9VgFlk_8QAM")]
        sn = 0  # inception event so 0
        toad = 0  # no witnesses

        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks
        sad['a'] = a

        serder = SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EEu-cdj_9b_66XRJ5UuhgEvJxAPpn4RjyaHvRgDU3iyA'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

        # retry with valid empty baks and empty a

        a = []
        toad = 0  # no witnesses
        baks = []

        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks
        sad['a'] = a


        serder = SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EOyd2ZALXBm5k9lEpmvakO6RYPDgX1zWSFNd3MfOXL-e'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder


        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error



    """ Done Test """



def test_reload_kever(mockHelpingNowUTC):
    """
    Test reload Kever from keystate state message
    """

    with habbing.openHby(name="nat", base="test", salt=Salter(raw=b'0123456789abcdef').qb64) as natHby:
        # setup Nat's habitat using default salt multisig already incepts
        natHab = natHby.makeHab(name="nat", isith='2', icount=3,
                                version=Vrsn_2_0, kind=Kinds.cesr)
        assert natHab.name == 'nat'
        assert natHab.ks == natHby.ks
        assert natHab.db == natHby.db
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.pre in natHab.prefixes
        assert natHab.db.path.endswith(os.path.join(os.path.sep, "keri", "db", "test", "nat"))
        path = natHab.db.path  # save for later

        # Create series of events for Nat
        natHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        natHab.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        natHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        natHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        natHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        natHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.cesr)

        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.pvrsn == Vrsn_2_0
        assert natHab.kever.serder.kind == Kinds.cesr
        ldig = natHab.db.kels.getLast(keys=natHab.pre, on=natHab.kever.sn)
        ldig = ldig.encode("utf-8")
        assert ldig == natHab.kever.serder.saidb
        serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
        assert serder.said == natHab.kever.serder.said
        nstate = natHab.kever.state()

        state = natHab.db.states.get(keys=natHab.pre)  # key state record
        assert state.vn == [2, 0]
        assert state.i == natHab.pre
        assert state.d == natHab.kever.serder.said
        assert state.f == '6'
        assert state == nstate

        # now create new Kever with state
        kever = Kever(state=state, db=natHby.db)
        assert kever.sn == 6
        assert kever.fn == 6
        assert kever.serder.ked == natHab.kever.serder.ked
        assert kever.serder.said == natHab.kever.serder.said

        kstate = kever.state()
        assert kstate == state
        assert kstate.vn == [2, 0]

    assert not os.path.exists(natHby.ks.path)
    assert not os.path.exists(natHby.db.path)

    """End Test"""



def test_load_event(mockHelpingNowUTC):
    with habbing.openHby(name="tor", base="test", salt=Salter(raw=b'0123456789abcdef').qb64) as torHby, \
         habbing.openHby(name="wil", base="test", salt=Salter(raw=b'0123456789abcdef').qb64) as wilHby, \
         habbing.openHby(name="wan", base="test", salt=Salter(raw=b'0123456789abcdef').qb64) as wanHby, \
         habbing.openHby(name="tee", base="test", salt=Salter(raw=b'0123456789abcdef').qb64) as teeHby:

        wanKvy = Kevery(db=wanHby.db, lax=False, local=False)
        torKvy = Kevery(db=torHby.db, lax=False, local=False)

        wanHab = wanHby.makeHab(name="wan", transferable=False,
                                version=Vrsn_2_0, kind=Kinds.cesr)
        msg = wanHab.msgOwnEvent(sn=0, framed=True)
        Parser(version=Vrsn_2_0).parse(ims=msg, kvy=torKvy)
        assert wanHab.pre in torKvy.kevers

        wilHab = wilHby.makeHab(name="wil", transferable=False,
                                version=Vrsn_2_0, kind=Kinds.cesr)

        torHab = torHby.makeHab(name="tor", icount=1, isith='1', ncount=1, nsith='1',
                                wits=[wanHab.pre], toad=1, version=Vrsn_2_0,
                                kind=Kinds.cesr)
        assert torHab.kever.serder.pvrsn == Vrsn_2_0
        assert torHab.kever.serder.kind == Kinds.cesr
        torIcpSaid = torHab.kever.serder.said
        torIcp = torHab.msgOwnEvent(sn=0, framed=True)
        assert torHab.pre in torHab.kvy.kevers

        with pytest.raises(ValueError):
            _ = loadEvent(wanHab.db, torHab.pre, torHab.pre)

        Parser(version=Vrsn_2_0).parse(ims=bytearray(torIcp), kvy=wanHab.kvy, local=True)
        wanHab.processCues(wanHab.kvy.cues, gvrsn=Vrsn_2_0,
                           version=Vrsn_2_0, kind=Kinds.cesr)

        evt = loadEvent(wanHab.db, torHab.pre, torIcpSaid)
        assert evt["stored"] is True
        assert evt["timestamp"] == '2021-01-01T00:00:00.000000+00:00'
        assertKeriV2Cesr(evt["ked"])
        assert evt["ked"]["t"] == Ilks.icp
        assert evt["ked"]["i"] == torHab.pre
        assert evt["ked"]["d"] == torIcpSaid
        assert evt["ked"]["b"] == [wanHab.pre]
        assert evt["witnesses"] == [wanHab.pre]
        assert len(evt["signatures"]) == 1
        assert isinstance(evt["witness_signatures"], list)

        teeHab = teeHby.makeHab(name="tee", delpre=torHab.pre, icount=1, isith='1',
                                ncount=1, nsith='1', wits=[wanHab.pre], toad=1,
                                version=Vrsn_2_0, kind=Kinds.cesr)
        assert teeHab.kever.serder.pvrsn == Vrsn_2_0
        assert teeHab.kever.serder.kind == Kinds.cesr
        teeIcpSaid = teeHab.kever.serder.said

        ixn = torHab.interact(data=[dict(i=teeHab.pre, s='0', d=teeIcpSaid)],
                              framed=True, version=Vrsn_2_0, kind=Kinds.cesr)
        torIxnSaid = torHab.kever.serder.said
        Parser(version=Vrsn_2_0).parse(ims=bytearray(ixn), kvy=wanHab.kvy, local=True)
        wanHab.processCues(wanHab.kvy.cues, gvrsn=Vrsn_2_0,
                           version=Vrsn_2_0, kind=Kinds.cesr)

        evt = loadEvent(wanHab.db, torHab.pre, torIxnSaid)
        assert evt["stored"] is True
        assertKeriV2Cesr(evt["ked"])
        assert evt["ked"]["t"] == Ilks.ixn
        assert evt["ked"]["i"] == torHab.pre
        assert evt["ked"]["d"] == torIxnSaid
        assert evt["ked"]["a"] == [dict(i=teeHab.pre, s='0', d=teeIcpSaid)]
        assert len(evt["signatures"]) == 1
        assert isinstance(evt["witness_signatures"], list)

        teeHab.db.aess.pin(keys=(teeHab.pre, teeIcpSaid.encode("utf-8")),
                           val=(Number(num=torHab.kever.sn),
                                Diger(qb64=torHab.kever.serder.said)))
        teeIcp = teeHab.msgOwnEvent(sn=0, framed=True)

        rct = torHab.receipt(serder=teeHab.kever.serder, framed=True,
                             gvrsn=Vrsn_2_0, version=Vrsn_2_0,
                             kind=Kinds.cesr)
        nrct = wilHab.receipt(serder=teeHab.kever.serder, framed=True,
                              gvrsn=Vrsn_2_0, version=Vrsn_2_0,
                              kind=Kinds.cesr)

        Parser(version=Vrsn_2_0).parse(ims=bytearray(teeIcp), kvy=wanKvy, local=True)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(rct), kvy=wanHab.kvy, local=True)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(nrct), kvy=wanHab.kvy, local=True)
        wanHab.processCues(wanHab.kvy.cues, gvrsn=Vrsn_2_0,
                           version=Vrsn_2_0, kind=Kinds.cesr)
        wanHab.processCues(wanKvy.cues, gvrsn=Vrsn_2_0,
                           version=Vrsn_2_0, kind=Kinds.cesr)

        evt = loadEvent(wanHab.db, teeHab.pre, teeIcpSaid)
        assert evt["stored"] is True
        assertKeriV2Cesr(evt["ked"])
        assert evt["ked"]["t"] == Ilks.dip
        assert evt["ked"]["i"] == teeHab.pre
        assert evt["ked"]["d"] == teeIcpSaid
        assert evt["ked"]["di"] == torHab.pre
        assert evt["ked"]["b"] == [wanHab.pre]
        assert evt["witnesses"] == [wanHab.pre]
        assert len(evt["signatures"]) == 1
        assert isinstance(evt["witness_signatures"], list)
        assert evt["receipts"]["transferable"][0]["prefix"] == torHab.pre
        assert evt["receipts"]["transferable"][0]["said"] == torIcpSaid
        assert evt["receipts"]["nontransferable"][0]["prefix"] == wilHab.pre

    """End Test"""


def test_direct_mode():
    """
    Test direct mode with transferable validator event receipts

    """
    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigners = salter.signers(count=8, path='val', transferable=False, temp=True)
    assert valSigners[0].verfer.qb64 != coeSigners[0].verfer.qb64

    with (openDB(name="controller") as coeLogger,
          openDB(name="validator") as valLogger):
        #  init Keverys
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = []  # list of coe's own event log digs to verify against database
        val_event_digs = []  # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           ndigs=[Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256, version=Vrsn_2_0, kind=Kinds.cesr)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == coeSerder.pre

        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # create own Coe Kever in  Coe's Kevery
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           ndigs=[Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256, version=Vrsn_2_0, kind=Kinds.cesr)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == valSerder.pre

        val_event_digs.append(valSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = messagize(valSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # create own Val Kever in  Val's Kevery
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        Parser(version=Vrsn_2_0).parse(ims=bytearray(cmsg), kvy=valKevery)
        # valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeIcpDig = coeIcpDig.encode("utf-8")
        assert coeIcpDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeIcpDig))
        assert s.raw
        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        assert siger.qb64
        rmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert rmsg

        # process own Val receipt in Val's Kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(rmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        # Simulate send to coe of val's incept and val's receipt of coe's inception message
        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.vres.get(keys=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        ev_diger, val_prefixer, est_num, est_diger, sig = result[0]

        assert ev_diger.qb64 == fake
        assert val_prefixer.qb64 == valKever.prefixer.qb64
        assert est_num.num == valKever.sn
        assert est_diger.qb64 == valKever.serder.said
        assert sig.qb64b == siger.qb64b

        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = receipt(pre=valK.prefixer.qb64,
                           sn=valK.sn,
                           said=valK.serder.said, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = coeKevery.db.kels.getLast(keys=valpre, on=vsn)
        valIcpDig = valIcpDig.encode("utf-8")
        assert valIcpDig == valK.serder.saidb
        s = coeKevery.db.evts.get(keys=(valpre, valIcpDig))
        assert s.raw

        siger = coeSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        assert siger.qb64
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # coe process own receipt in own Kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from coe in val's receipt database
        result = valKevery.db.vrcs.get(keys=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the controller
        assert rctPrefixer.qb64 == coeKever.prefixer.qb64
        # sequence number of controller’s est event
        assert rctNum.num == coeKever.sn
        # digest of controller’s est event
        assert rctDiger.qb64 == coeKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.said,
                           ndigs=[Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           sn=csn, version=Vrsn_2_0, kind=Kinds.cesr)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # update coe's key event verifier state
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeRotDig = coeRotDig.encode("utf-8")
        assert coeRotDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeRotDig))
        assert s.raw

        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        assert siger.qb64
        # val create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # val process own receipt in own kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b


        # Next Event 2 Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.said,
                             sn=csn, version=Vrsn_2_0, kind=Kinds.cesr)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg
        # update coe's key event verifier state
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeIxnDig = coeIxnDig.encode("utf-8")
        assert coeIxnDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeIxnDig))
        assert s.raw
        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        assert siger.qb64
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # val process own receipt in own kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [v for v in coeKever.db.kels.getAllIter(keys=coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        db_digs = [v for v in valKever.db.kels.getAllIter(keys=coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [v for v in valKever.db.kels.getAllIter(keys=valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

        db_digs = [v for v in coeKever.db.kels.getAllIter(keys=valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

    """ Done Test """



def test_direct_mode_cbor_mgpk():
    """
    Test direct mode with transverable validator event receipts but using
    cbor and mspk serializations

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)

    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigners = salter.signers(count=8, path='val', transferable=False, temp=True)
    assert valSigners[0].verfer.qb64 != coeSigners[0].verfer.qb64

    with (openDB(name="controller") as coeLogger,
          openDB(name="validator") as valLogger):
        #  init Keverys
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = []  # list of coe's own event log digs to verify against database
        val_event_digs = []  # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           ndigs=[Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256,
                           kind=Kinds.cbor, version=Vrsn_2_0)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]

        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # create own Coe Kever in  Coe's Kevery
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           ndigs=[Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256,
                           kind=Kinds.mgpk, version=Vrsn_2_0)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]

        val_event_digs.append(valSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = messagize(valSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # create own Val Kever in  Val's Kevery
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        Parser(version=Vrsn_2_0).parse(ims=bytearray(cmsg), kvy=valKevery)
        # valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said,
                           kind=Kinds.mgpk, version=Vrsn_2_0)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeIcpDig = coeIcpDig.encode("utf-8")
        assert coeIcpDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeIcpDig))
        assert s.raw

        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert rmsg

        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(rmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)

        # Simulate send to coe of val's receipt of coe's inception message
        Parser(version=Vrsn_2_0).parse(ims=bytearray(vmsg), kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        # create receipt to escrow use invalid dig so not in coe's db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake,
                           kind=Kinds.mgpk, version=Vrsn_2_0)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.vres.get(keys=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        ev_diger, val_prefixer, est_num, est_diger, sig = result[0]

        assert ev_diger.qb64 == fake
        assert val_prefixer.qb64 == valKever.prefixer.qb64
        assert est_num.num == valKever.sn
        assert est_diger.qb64 == valKever.serder.said
        assert sig.qb64b == siger.qb64b

        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = receipt(pre=valK.prefixer.qb64,
                           sn=valK.sn,
                           said=valK.serder.said,
                           kind=Kinds.cbor, version=Vrsn_2_0)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = coeKevery.db.kels.getLast(keys=valpre, on=vsn)
        valIcpDig = valIcpDig.encode("utf-8")
        assert valIcpDig == valK.serder.saidb
        s = coeKevery.db.evts.get(keys=(valpre, valIcpDig))
        assert s.raw

        siger = coeSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # coe process own receipt in own Kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.db.vrcs.get(keys=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the controller
        assert rctPrefixer.qb64 == coeKever.prefixer.qb64
        # sequence number of controller est event
        assert rctNum.num == coeKever.sn
        # digest of controller's est event
        assert rctDiger.qb64 == coeKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.said,
                           ndigs=[Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           sn=csn,
                           kind=Kinds.cbor, version=Vrsn_2_0)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # update coe's key event verifier state
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said,
                           kind=Kinds.mgpk, version=Vrsn_2_0)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeRotDig = coeRotDig.encode("utf-8")
        assert coeRotDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeRotDig))
        assert s.raw

        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # val process own receipt in own kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        # Next Event Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.said,
                             sn=csn,
                             kind=Kinds.cbor, version=Vrsn_2_0)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = messagize(coeSerder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)
        assert cmsg

        # update coe's key event verifier state
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        Parser(version=Vrsn_2_0).parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said,
                           kind=Kinds.mgpk, version=Vrsn_2_0)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = valKevery.db.kels.getLast(keys=coepre, on=csn)
        coeIxnDig = coeIxnDig.encode("utf-8")
        assert coeIxnDig == coeK.serder.saidb
        s = valKevery.db.evts.get(keys=(coepre, coeIxnDig))
        assert s.raw

        siger = valSigners[vesn].sign(ser=s.raw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], source=seal, framed=True, gvrsn=Vrsn_2_0)
        assert vmsg

        # val process own receipt in own kevery so have copy in own log
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        Parser(version=Vrsn_2_0).parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.vrcs.get(keys=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        rctPrefixer, rctNum, rctDiger, rctSiger = result[0]

        # receipter is the validator
        assert rctPrefixer.qb64 == valKever.prefixer.qb64
        # sequence number of validator’s est event
        assert rctNum.num == valKever.sn
        # digest of validator’s est event
        assert rctDiger.qb64 == valKever.serder.said
        # signature matches what was produced
        assert rctSiger.qb64b == siger.qb64b

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [v for v in coeKever.db.kels.getAllIter(keys=coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        db_digs = [v for v in valKever.db.kels.getAllIter(keys=coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [v for v in valKever.db.kels.getAllIter(keys=valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

        db_digs = [v for v in coeKever.db.kels.getAllIter(keys=valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

    """ Done Test """



def test_receipt():
    """
    Test event receipt message and attached couplets
    """

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigner = salter.signers(count=1, path='val', transferable=False, temp=True)[0]
    assert valSigner.verfer.qb64 != coeSigners[0].verfer.qb64


    # create receipt signer prefixer  default code is non-transferable
    valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
    assert valPrefixer.code == MtrDex.Ed25519N
    valpre = valPrefixer.qb64
    assert valpre == 'BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4p'

    with openDB(name="controller") as coeLogger, openDB(name="validator") as valLogger:
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)
        event_digs = []  # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # create receipt msg stream
        res = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[coeSigners[esn].verfer.qb64],
                        ndigs=[Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64], version=Vrsn_2_0, kind=Kinds.cesr)

        assert sn == int(serder.ked["s"], 16) == 0
        coepre = serder.ked["i"]
        assert coepre == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # return Siger if index

        #  attach to key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        # make copy of kes so can use again for valKevery
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # create Kever using Kevery
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre
        assert coeKever.serder.raw == serder.raw

        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)  # process by Val
        assert coepre in valKevery.kevers
        valKever = valKevery.kevers[coepre]
        assert len(kes) == 0

        # create receipt from val to coe
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           said=coeKever.serder.said, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64
        res.extend(messagize(reserder, cigars=[valCigar], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=res, kvy=coeKevery)
        # coeKevery.process(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.db.rcts.get(keys=(coeKever.prefixer.qb64,coeKever.serder.said))
        prefixer, cigar = result[0]
        assert prefixer.qb64b == valPrefixer.qb64b
        assert cigar.qb64b == valCigar.qb64b
        assert len(result) == 1

        # create invalid receipt to escrow use invalid dig and sn so not in db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=2,
                           said=fake, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        # attach to receipt msg stream
        res.extend(messagize(reserder, cigars=[valCigar], framed=True, gvrsn=Vrsn_2_0))

        #  coe process the escrow receipt from val
        Parser(version=Vrsn_2_0).parse(ims=res, kvy=coeKevery)
        #  check if in escrow database
        result = coeKevery.db.ures.get(keys=(coeKever.prefixer.qb64, Number(num=2, code=NumDex.Huge).qb64))
        rsaider, sprefixer, cigar = result[0]

        assert rsaider.qb64b == fake.encode("utf-8")
        assert sprefixer.qb64b == valPrefixer.qb64b
        assert cigar.qb64b == valCigar.qb64b

        # create invalid receipt stale use valid sn so in database but invalid dig
        # so bad receipt
        fake = Diger(qb64="EAdapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI").qb64
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           said=fake, version=Vrsn_2_0, kind=Kinds.cesr)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        # attach to receipt msg stream
        res.extend(messagize(reserder, cigars=[valCigar], framed=True, gvrsn=Vrsn_2_0))

        Parser(version=Vrsn_2_0).parseOne(ims=res, kvy=coeKevery)
        # coeKevery.processOne(ims=res)  #  coe process the escrow receipt from val
        # no new receipt at valid dig
        result = coeKevery.db.rcts.get(keys=(coeKever.prefixer.qb64,coeKever.serder.said))
        assert len(result) == 1
        # no new receipt at invalid dig
        result = coeKevery.db.rcts.get(keys=(coeKever.prefixer.qb64,fake))
        assert not result

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == esn == 1
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.serder.said,
                        ndigs=[Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
                        sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)

        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # returns siger
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 2
        assert esn == 1
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.serder.said,
                        ndigs=[Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
                        sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 4
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 5
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 6
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        assert coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

        db_digs = [val for val in coeKever.db.kels.getAllIter(keys=coepre)]
        assert len(db_digs) == len(event_digs) == 7

        assert valKever.sn == coeKever.sn
        assert valKever.verfers[0].qb64 == coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

    """ Done Test """



def test_process_nontransferable():
    """
    Test process of generating and validating non-transferable key event messages.
    """
    skp0 = Signer(transferable=False)
    assert skp0.verfer.code == MtrDex.Ed25519N

    serder = incept(keys=[skp0.verfer.qb64], version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr
    assert serder.ked["i"] == skp0.verfer.qb64
    assert serder.ked["n"] == []

    siger = skp0.sign(serder.raw, index=0)
    assert skp0.verfer.verify(siger.raw, serder.raw)
    msg = messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)

    with openDB(name="nontrans") as db:
        kvy = Kevery(db=db)
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(msg), kvy=kvy)
        kever = kvy.kevers[serder.pre]
        assert kever.serder.said == serder.said
        assert kever.serder.pvrsn == Vrsn_2_0
        assert kever.serder.kind == Kinds.cesr

    """ Done Test """


def test_process_transferable():
    """
    Test process of generating and validating transferable key event messages.
    """
    skp0 = Signer()
    skp1 = Signer()
    nxt = [Diger(ser=skp1.verfer.qb64b).qb64]

    serder = incept(keys=[skp0.verfer.qb64], ndigs=nxt, version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr
    assert serder.ked["i"] == skp0.verfer.qb64
    assert serder.ked["n"] == nxt

    siger = skp0.sign(serder.raw, index=0)
    assert skp0.verfer.verify(siger.raw, serder.raw)
    msg = messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0)

    with openDB(name="trans") as db:
        kvy = Kevery(db=db)
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(msg), kvy=kvy)
        kever = kvy.kevers[serder.pre]
        assert kever.serder.said == serder.said
        assert kever.serder.pvrsn == Vrsn_2_0
        assert kever.serder.kind == Kinds.cesr
        assert [diger.qb64 for diger in kever.ndigers] == nxt

    """ Done Test """


def test_process_attached_receipt_couples_firner_missing_fels():
    """
    When processAttachedReceiptCouples is called with firner set (clone replay mode)
    but the db has no fels entry at firner.sn, it must escrow and raise
    UnverifiedReceiptError. This explicitly tests the fels.getOn(keys=pre, on=firner.sn)
    path in receipt processing.
    """
    salter = Salter(raw=b'firner_missing_fels_test_seed_0123456789')
    signer = salter.signers(count=1, path="ctl", temp=True)[0]
    valSigner = salter.signers(count=1, path="val", transferable=False, temp=True)[0]

    serder = incept(keys=[signer.verfer.qb64], ndigs=[Diger(ser=signer.verfer.qb64b).qb64], version=Vrsn_2_0, kind=Kinds.cesr)
    valCigar = valSigner.sign(ser=serder.raw)

    with openDB(name="firner_test") as db:
        kvy = Kevery(db=db)
        # DB is empty: no event, no fels entry at (pre, 0). Call with firner so
        # processAttachedReceiptCouples uses fels.getOn(keys=pre, on=0) -> None.
        with pytest.raises(UnverifiedReceiptError) as exc_info:
            kvy.processAttachedReceiptCouples(serder, [valCigar], firner=Seqner(sn=0))
        assert "Unverified receipt=" in str(exc_info.value)
        # Receipt must be escrowed (addUre via escrowUReceipt)
        sn = int(serder.sn, 16) if isinstance(serder.sn, str) else int(serder.sn)
        ures = db.ures.get(keys=(serder.pre, Number(num=sn, code=NumDex.Huge).qb64))
        assert len(ures) == 1
        diger, prefixer, cigar = ures[0]
        assert diger.qb64 == serder.said
        assert prefixer.qb64 == valSigner.verfer.qb64
        assert cigar.qb64 == valCigar.qb64

    """ Done Test """



def test_recovery():
    """
    Test Recovery event
    """
    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = Salter(raw=salt).signers(count=8)

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        event_digs = []  # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[esn].verfer.qb64],
                        ndigs=[Diger(ser=signers[esn + 1].verfer.qb64b).qb64], version=Vrsn_2_0, kind=Kinds.cesr)

        assert sn == int(serder.ked["s"], 16) == 0

        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], db=conlgr)
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == esn == 1
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)

        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 2
        assert esn == 1
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 4
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 5
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 6
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Rotation Recovery at sn = 5
        sn = 5
        esn += 1
        assert sn == 5
        assert esn == 3

        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=event_digs[sn - 1],
                        ndigs=[Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        # Next Event Interaction
        sn += 1  # do not increment esn
        assert sn == 6
        assert esn == 3
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=sn, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(messagize(serder, sigers=[siger], framed=True, gvrsn=Vrsn_2_0))

        assert kever.verfers[0].qb64 == signers[esn].verfer.qb64

        pre = kever.prefixer.qb64

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
        assert len(db_digs) == len(event_digs) == 9
        assert db_digs[0:6] == event_digs[0:6]
        assert db_digs[-1] == event_digs[-1]
        assert db_digs[7] == event_digs[6]
        assert db_digs[6] == event_digs[7]

        db_est_digs = [val for val in kever.db.kels.getLastIter(keys=pre)]
        assert len(db_est_digs) == 7
        assert db_est_digs[0:5] == event_digs[0:5]
        assert db_est_digs[5:7] == event_digs[7:9]

        kevery = Kevery(db=vallgr)
        Parser(version=Vrsn_2_0).parse(ims=kes, kvy=kevery)
        # kevery.process(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64 == signers[esn].verfer.qb64

        y_db_digs = [val for val in kevery.db.kels.getAllIter(keys=pre)]
        assert db_digs == y_db_digs
        y_db_est_digs = [val for val in kevery.db.kels.getLastIter(keys=pre)]
        assert db_est_digs == y_db_est_digs

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """



def test_multisig_digprefix():
    """
    Test multisig with self-addressing (digest) pre
    """

    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = Salter(raw=salt).signers(count=8)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        #  2 0f 3 multisig

        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        nxtkeys = [signers[3].verfer.qb64b, signers[4].verfer.qb64b, signers[5].verfer.qb64b]
        sith = "2"
        code = MtrDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        isith=sith,
                        ndigs=[Diger(ser=sig).qb64 for sig in nxtkeys], version=Vrsn_2_0, kind=Kinds.cesr)

        # create sig counter
        count = len(keys)
        counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers, db=conlgr)
        # extend key event stream
        msgs.extend(messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0))

        assert msgs

        # Event 1 Rotation Transferable
        keys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = "2"
        nxtkeys = [signers[5].verfer.qb64b, signers[6].verfer.qb64b, signers[7].verfer.qb64b]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        isith=sith,
                        dig=kever.serder.said,
                        ndigs=[Diger(ser=sig).qb64 for sig in nxtkeys],
                        sn=1, version=Vrsn_2_0, kind=Kinds.cesr)
        # create sig counter
        count = len(keys)
        counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0))

        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=2, version=Vrsn_2_0, kind=Kinds.cesr)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0))

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=3, version=Vrsn_2_0, kind=Kinds.cesr)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0))

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        keys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        isith="2",
                        dig=kever.serder.said,
                        sn=4, version=Vrsn_2_0, kind=Kinds.cesr)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - 5) for i in range(5, 8)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0))

        assert msgs

        kevery = Kevery(db=vallgr)
        Parser(version=Vrsn_2_0).parse(ims=msgs, kvy=kevery)
        # kevery.process(ims=msgs)

        pre = kever.prefixer.qb64
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[5].verfer.qb64

    assert not os.path.exists(kevery.db.path)

    """ Done Test """



def test_keyeventsequence_0():
    """
    Test generation of a sequence of key events

    """
    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = Salter(raw=salt).signers(count=8)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    with openDB(name="controller") as conlgr:
        event_digs = []  # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        ndiger1 = Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [ndiger1.qb64]  # transferable so nxt is not empty
        assert nxt1 == ['EIQsSW4KMrLzY1HQI9H_XxY6MyzhaFFXhG6fdBb5Wxta']
        serder0 = incept(keys=keys0, ndigs=nxt1, version=Vrsn_2_0, kind=Kinds.cesr)
        pre = serder0.ked["i"]
        event_digs.append(serder0.said)
        assert serder0.ked["i"] == signers[0].verfer.qb64
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.said == serder0.ked["d"]

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.said == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.ndigs == nxt1
        assert kever.estOnly is False
        assert kever.transferable is True

        pigers = kever.fetchPriorDigers()
        assert pigers is None

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2
        keys2 = [signers[2].verfer.qb64]
        ndiger2 = Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [ndiger2.qb64]  # transferable so nxt is not empty
        assert nxt2 == ['EHuvLs1hmwxo4ImDoCpaAermYVQhiPsPDNaZsz4bcgko']
        serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=nxt2, sn=1, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder1.said)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["kt"] == '1'
        assert serder1.ked["k"] == keys1
        assert serder1.ked["n"] == nxt2
        assert serder1.ked["p"] == serder0.said

        # sign serialization and verify signature
        sig1 = signers[1].sign(serder1.raw, index=0)
        assert signers[1].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        kever.update(serder=serder1, sigers=[sig1])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.said == serder1.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.ndigs  == nxt2

        pigers = kever.fetchPriorDigers()  # digs from inception before rotation
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt1


        # Event 2 Rotation Transferable
        # compute nxt digest from keys3
        keys3 = [signers[3].verfer.qb64]
        ndiger3 = Diger(ser=signers[3].verfer.qb64b)
        nxt3 = [ndiger3.qb64]  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys2, dig=serder1.said, ndigs=nxt3, sn=2, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder2.said)
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '2'
        assert serder2.ked["k"] == keys2
        assert serder2.ked["n"] == nxt3
        assert serder2.ked["p"] == serder1.said

        # sign serialization and verify signature
        sig2 = signers[2].sign(serder2.raw, index=0)
        assert signers[2].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 2
        assert kever.serder.said == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys2
        assert kever.ndigs  == nxt3

        pigers = kever.fetchPriorDigers()  # digs from rotation before rotation
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2

        # Event 3 Interaction
        serder3 = interact(pre=pre, dig=serder2.said, sn=3, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder3.said)
        assert serder3.ked["i"] == pre
        assert serder3.ked["s"] == '3'
        assert serder3.ked["p"] == serder2.said

        # sign serialization and verify signature
        sig3 = signers[2].sign(serder3.raw, index=0)
        assert signers[2].verfer.verify(sig3.raw, serder3.raw)
        # update key event verifier state
        kever.update(serder=serder3, sigers=[sig3])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 3
        assert kever.serder.said == serder3.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.ndigs  == nxt3  # no change

        pigers = kever.fetchPriorDigers()
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2  # digs from rot before rot before ixn

        # Event 4 Interaction
        serder4 = interact(pre=pre, dig=serder3.said, sn=4, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder4.said)
        assert serder4.ked["i"] == pre
        assert serder4.ked["s"] == '4'
        assert serder4.ked["p"] == serder3.said

        # sign serialization and verify signature
        sig4 = signers[2].sign(serder4.raw, index=0)
        assert signers[2].verfer.verify(sig4.raw, serder4.raw)
        # update key event verifier state
        kever.update(serder=serder4, sigers=[sig4])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 4
        assert kever.serder.said == serder4.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.ndigs  == nxt3  # no change

        pigers = kever.fetchPriorDigers()  # digs from rot before rot before ixn ixn
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2

        # Event 5 Rotation Transferable
        # compute nxt digest from keys4
        keys4 = [signers[4].verfer.qb64]
        ndiger4 = Diger(ser=signers[4].verfer.qb64b)
        nxt4 = [ndiger4.qb64]  # transferable so nxt is not empty
        serder5 = rotate(pre=pre, keys=keys3, dig=serder4.said, ndigs=nxt4, sn=5, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder5.said)
        assert serder5.ked["i"] == pre
        assert serder5.ked["s"] == '5'
        assert serder5.ked["k"] == keys3
        assert serder5.ked["n"] == nxt4
        assert serder5.ked["p"] == serder4.said

        # sign serialization and verify signature
        sig5 = signers[3].sign(serder5.raw, index=0)
        assert signers[3].verfer.verify(sig5.raw, serder5.raw)
        # update key event verifier state
        kever.update(serder=serder5, sigers=[sig5])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 5
        assert kever.serder.said == serder5.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys3
        assert kever.ndigs  == nxt4

        pigers = kever.fetchPriorDigers()  # digs from rot before ixn ixn before rot
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt3

        # Event 6 Interaction
        serder6 = interact(pre=pre, dig=serder5.said, sn=6, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder6.said)
        assert serder6.ked["i"] == pre
        assert serder6.ked["s"] == '6'
        assert serder6.ked["p"] == serder5.said

        # sign serialization and verify signature
        sig6 = signers[3].sign(serder6.raw, index=0)
        assert signers[3].verfer.verify(sig6.raw, serder6.raw)
        # update key event verifier state
        kever.update(serder=serder6, sigers=[sig6])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 6
        assert kever.serder.said == serder6.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
        assert kever.ndigs  == nxt4  # no change

        # Event 7 Rotation to null NonTransferable Abandon
        serder7 = rotate(pre=pre, keys=keys4, dig=serder6.said, sn=7, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder7.said)
        assert serder7.ked["i"] == pre
        assert serder7.ked["s"] == '7'
        assert serder7.ked["k"] == keys4
        assert serder7.ked["n"] == []
        assert serder7.ked["p"] == serder6.said

        # sign serialization and verify signature
        sig7 = signers[4].sign(serder7.raw, index=0)
        assert signers[4].verfer.verify(sig7.raw, serder7.raw)
        # update key event verifier state
        kever.update(serder=serder7, sigers=[sig7])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 7
        assert kever.serder.said == serder7.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys4
        assert kever.ndigs  == []
        assert not kever.transferable

        # Event 8 Interaction
        serder8 = interact(pre=pre, dig=serder7.said, sn=8, version=Vrsn_2_0, kind=Kinds.cesr)
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.said

        # sign serialization and verify signature
        sig8 = signers[4].sign(serder8.raw, index=0)
        assert signers[4].verfer.verify(sig8.raw, serder8.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder8, sigers=[sig8])

        # Event 8 Rotation
        keys5 = [signers[5].verfer.qb64]
        nexter5 = Diger(ser=signers[5].verfer.qb64b)
        nxt5 = [ndiger4.qb64]  # transferable so nxt is not empty
        serder8 = rotate(pre=pre, keys=keys5, dig=serder7.said, ndigs=nxt5, sn=8, version=Vrsn_2_0, kind=Kinds.cesr)
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.said

        # sign serialization and verify signature
        sig8 = signers[4].sign(serder8.raw, index=0)
        assert signers[4].verfer.verify(sig8.raw, serder8.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder8, sigers=[sig8])

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
        assert db_digs == event_digs

    """ Done Test """



def test_keyeventsequence_1():
    """
    Test generation of a sequence of key events
    Test when EstOnly trait in config of inception event. Establishment only
    """

    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = Salter(raw=salt).signers(count=8)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    # New Sequence establishment only
    with openDB(name="controller") as conlgr:
        event_digs = []  # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        ndiger1 = Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [ndiger1.qb64]  # transferable so nxt is not empty
        cnfg = [TraitDex.EstOnly]  # EstOnly
        serder0 = incept(keys=keys0, ndigs=nxt1, cnfg=cnfg, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder0.said)
        pre = serder0.ked["i"]
        assert serder0.ked["i"] == signers[0].verfer.qb64
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.ked["c"] == cnfg
        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.said == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.ndigs  == nxt1
        assert kever.estOnly is True
        assert kever.transferable is True

        # Event 1 Interaction. Because EstOnly, this event not included in KEL
        serder1 = interact(pre=pre, dig=serder0.said, sn=1, version=Vrsn_2_0, kind=Kinds.cesr)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["p"] == serder0.said
        # sign serialization and verify signature
        sig1 = signers[0].sign(serder1.raw, index=0)
        assert signers[0].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # attempt ixn with estOnly
            kever.update(serder=serder1, sigers=[sig1])

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2  but from event0
        ndiger2 = Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [ndiger2.qb64]  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=nxt2, sn=1, version=Vrsn_2_0, kind=Kinds.cesr)
        event_digs.append(serder2.said)
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '1'
        assert serder2.ked["kt"] == '1'
        assert serder2.ked["k"] == keys1
        assert serder2.ked["n"] == nxt2
        assert serder2.ked["p"] == serder0.said

        # sign serialization and verify signature
        sig2 = signers[1].sign(serder2.raw, index=0)
        assert signers[1].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.said == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.ndigs  == nxt2

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
        assert db_digs == event_digs

    """ Done Test """
