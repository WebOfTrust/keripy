# -*- encoding: utf-8 -*-
"""
tests.core.test_indexing module

"""


import pysodium

import pytest

from keri import kering

from keri.help import helping

from keri import core
from keri.core import (Tiers, )
from keri.core import (Matter, MtrDex, Cigar, Verfer, Prefixer)
from keri.core import (Indexer, IdrDex, )
from keri.core import (Signer, generateSigners, Salter,
                       Cipher, Encrypter, Decrypter, )



def test_signer():
    """
    Test Signer instance
    """
    signer = Signer()  # defaults provide Ed25519 signer Ed25519 verfer
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    # create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    index = 0
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False

    assert cigar.raw == siger.raw

    with pytest.raises(ValueError):  # use invalid code not SEED type code
        signer = Signer(code=MtrDex.Ed25519N)

    # Non transferable defaults
    signer = Signer(transferable=False)  # Ed25519N verifier
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519N
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    siger = signer.sign(ser, index=0)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False


    # non default seed
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=MtrDex.Ed25519_Seed)
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    index = 1
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    assert cigar.raw == siger.raw

    # different both so Big
    ondex = 3
    siger = signer.sign(ser, index=index, ondex=ondex)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == ondex
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # same but Big
    index = 67
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # different both so Big
    ondex = 67
    siger = signer.sign(ser, index=index, ondex=ondex)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == ondex
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # current only
    index = 4
    siger = signer.sign(ser, index=index, only=True)
    assert siger.code == IdrDex.Ed25519_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # ignores ondex if only
    siger = signer.sign(ser, index=index, only=True, ondex=index+2)
    assert siger.code == IdrDex.Ed25519_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # big current only
    index = 65
    siger = signer.sign(ser, index=index, only=True)
    assert siger.code == IdrDex.Ed25519_Big_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # ignores ondex if only
    siger = signer.sign(ser, index=index, only=True, ondex=index+2)
    assert siger.code == IdrDex.Ed25519_Big_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    with pytest.raises(ValueError):  # use invalid code not SEED type code
        signer = Signer(raw=seed, code=MtrDex.Ed25519N)

    # Test Secp256r1, default seed
    signer = Signer(code=MtrDex.ECDSA_256r1_Seed)
    assert signer.code == MtrDex.ECDSA_256r1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.ECDSA_256r1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.ECDSA_256r1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result is True

    # Test non-default seed
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256r1_Seed)
    assert signer.code == MtrDex.ECDSA_256r1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.ECDSA_256r1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    # Test hardcoded seed
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93')
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256r1_Seed)
    assert signer.code == MtrDex.ECDSA_256r1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.ECDSA_256r1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == "QJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T"
    assert signer.verfer.qb64 == "1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"

    # Test vectors from CERSide
    seed = (b'\x35\x86\xc9\xa0\x4d\x33\x67\x85\xd5\xe4\x6a\xda\x62\xf0\x54\xc5\xa5\xf4\x32\x3f\x46\xcb\x92\x23\x07'
            b'\xe0\xe2\x79\xb7\xe5\xf5\x0a')
    verkey = (b"\x03\x16\x99\xbc\xa0\x51\x8f\xa6\x6c\xb3\x5d\x6b\x0a\x92\xf6\x84\x96\x28\x7b\xb6\x64\xe8\xe8\x57\x69"
              b"\x15\xb8\xea\x9a\x02\x06\x2a\xff")
    sig = (b'\x8c\xfa\xb4\x40\x01\xd2\xab\x4a\xbc\xc5\x96\x8b\xa2\x65\x76\xcd\x51\x9d\x3b\x40\xc3\x35\x21\x73\x9a\x1b'
           b'\xe8\x2f\xe1\x30\x28\xe1\x07\x90\x08\xa6\x42\xd7\x3f\x36\x8c\x96\x32\xff\x01\x64\x03\x18\x08\x85\xb8\xa4'
           b'\x97\x76\xbe\x9c\xe4\xd7\xc5\xe7\x05\xda\x51\x23')

    signerqb64 = "QDWGyaBNM2eF1eRq2mLwVMWl9DI_RsuSIwfg4nm35fUK"
    verferqb64 = "1AAJAxaZvKBRj6Zss11rCpL2hJYoe7Zk6OhXaRW46poCBir_"
    cigarqb64 = "0ICM-rRAAdKrSrzFlouiZXbNUZ07QMM1IXOaG-gv4TAo4QeQCKZC1z82jJYy_wFkAxgIhbikl3a-nOTXxecF2lEj"

    ser = b'abc'
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256r1_Seed)
    cigar = signer.sign(ser)
    assert signer.code == MtrDex.ECDSA_256r1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.qb64 == signerqb64

    assert signer.verfer.code == MtrDex.ECDSA_256r1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.verfer.raw == verkey
    assert signer.verfer.qb64 == verferqb64

    assert cigar.code == MtrDex.ECDSA_256r1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    assert signer.verfer.verify(cigar.raw, ser)
    assert signer.verfer.verify(sig, ser)

    cigar = Cigar(raw=sig, code=MtrDex.ECDSA_256r1_Sig)
    assert cigar.qb64 == cigarqb64


    # Test Secp256k1, default seed
    signer = Signer(code=MtrDex.ECDSA_256k1_Seed)
    assert signer.code == MtrDex.ECDSA_256k1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.ECDSA_256k1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    # create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.ECDSA_256k1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result is True

    index = 0
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.ECDSA_256k1_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False

    # Non transferable
    signer = Signer(code=MtrDex.ECDSA_256k1_Seed, transferable=False)  # ECDSA_256k1N verifier
    assert signer.code == MtrDex.ECDSA_256k1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.ECDSA_256k1N
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.ECDSA_256k1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    siger = signer.sign(ser, index=0)
    assert siger.code == IdrDex.ECDSA_256k1_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False

    # Test non-default seed
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)
    assert signer.code == MtrDex.ECDSA_256k1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.ECDSA_256k1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.ECDSA_256k1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    index = 1
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.ECDSA_256k1_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False

    # different both so Big
    ondex = 3
    siger = signer.sign(ser, index=index, ondex=ondex)
    assert siger.code == IdrDex.ECDSA_256k1_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == ondex
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # Test hardcoded seed from CERSide
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93')
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)
    assert signer.code == MtrDex.ECDSA_256k1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.ECDSA_256k1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == "JJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T"
    assert signer.verfer.qb64 == "1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"

    # Test vectors from CERSide
    seed = (b'\x7f\x98\x0a\x3b\xe4\x45\xd7\x8c\xc9\x79\xa1\xee\x26\x20\x9c\x17\x71\x16\xab\xa6\xd6\xf1\x6a\x01\xe7\xb3\xce\xfe\xe2\x6c\x06\x08')
    verkey = (b"\x02\xdb\x98\x33\x85\xa8\x0e\xbb\x7c\x15\x5d\xdd\xc6\x47\x6a\x24\x07\x9a\x7c\x96\x5f\x05\x0f\x62\xde\x2d\x47\x56\x9b\x54\x29\x16\x79")
    sig = (b'\x5f\x80\xc0\x5a\xe4\x71\x32\x5d\xf7\xcb\xdb\x1b\xc2\xf4\x11\xc3\x05\xaf\xf4\xbe\x3b\x7e\xac\x3e\x8c\x15'
           b'\x3a\x9f\xa5\x0a\x3d\x69\x75\x45\x93\x34\xc8\x96\x2b\xfe\x79\x8d\xd1\x4e\x9c\x1f\x6c\xa7\xc8\x12\xd6'
           b'\x7a\x6c\xc5\x74\x9f\xef\x8d\xa7\x25\xa2\x95\x47\xcc')

    signerqb64 = "JH-YCjvkRdeMyXmh7iYgnBdxFqum1vFqAeezzv7ibAYI"
    verferqb64 = "1AABAtuYM4WoDrt8FV3dxkdqJAeafJZfBQ9i3i1HVptUKRZ5"
    cigarqb64 = "0CBfgMBa5HEyXffL2xvC9BHDBa_0vjt-rD6MFTqfpQo9aXVFkzTIliv-eY3RTpwfbKfIEtZ6bMV0n--NpyWilUfM"

    ser = b'abc'
    signer = Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)
    cigar = signer.sign(ser)
    assert signer.code == MtrDex.ECDSA_256k1_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.qb64 == signerqb64

    assert signer.verfer.code == MtrDex.ECDSA_256k1
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.verfer.raw == verkey
    assert signer.verfer.qb64 == verferqb64

    assert cigar.code == MtrDex.ECDSA_256k1_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    assert signer.verfer.verify(cigar.raw, ser)
    assert signer.verfer.verify(sig, ser)

    cigar = Cigar(raw=sig, code=MtrDex.ECDSA_256k1_Sig)
    assert cigar.qb64 == cigarqb64


    # test with only and ondex parameters

    """ Done Test """


# deprecated uses Salter.signers() instead
def test_generatesigners():
    """
    Test the support function genSigners

    """
    signers = generateSigners(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert signer.verfer.code == MtrDex.Ed25519N

    # raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)  # raw salt
    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    assert len(raw) == 16
    signers = generateSigners(raw=raw, count=4)  # default is transferable
    assert len(signers) == 4
    for signer in signers:
        assert signer.code == MtrDex.Ed25519_Seed
        assert signer.verfer.code == MtrDex.Ed25519

    sigkeys = [signer.qb64 for signer in signers]
    assert sigkeys == ['AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH',
                       'AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0',
                       'AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG',
                       'AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP']

    """ End Test """


def test_salter():
    """
    Test the support functionality for salter subclass of crymat
    """
    salter = Salter()  # defaults to CryTwoDex.Salt_128
    assert salter.code == MtrDex.Salt_128
    assert len(salter.raw) == Matter._rawSize(salter.code) == 16

    raw = b'0123456789abcdef'
    salter = Salter(raw=raw)
    assert salter.raw == raw
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'  #'0ACDEyMzQ1Njc4OWFiY2RlZg'

    signer = salter.signer(path="01", temp=True)  # defaults to Ed25519
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AMPsqBZxWdtYpBhrWnKYitwFa77s902Q-nX3sPTzqs0R'
    #'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE'
    assert signer.verfer.qb64 == 'DFYFwZJOMNy3FknECL8tUaQZRBUyQ9xCv6F8ckG-UCrC'  #
    # 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI'

    signer = salter.signer(path="01")  # defaults to Ed25519 temp = False level="low"
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AEkqQiNTexWB9fTLpgJp_lXW63tFlT-Y0_mgQww4o-dC'
    # 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I'
    assert signer.verfer.qb64 == 'DPJGyH9H1M_SUSf18RzX8OqdyhxEyZJpKm5Em0PnpsWd'
    #'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0'

    salter = Salter(qb64='0AAwMTIzNDU2Nzg5YWJjZGVm')
    assert salter.raw == raw
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'

    with pytest.raises(kering.ShortageError):
        salter = Salter(qb64='')

    salter = Salter(raw=raw)
    assert salter.stretch(temp=True) == b'\xd4@\xeb\xa6x\x86\xdf\x93\xd6C\xdc\xb8\xa6\x9b\x02\xafh\xc1m(L\xd6\xf6\x86YU>$[\xf9\xef\xc0'
    assert salter.stretch(tier=Tiers.low) == b'\xf8e\x80\xbaX\x08\xb9\xba\xc6\x1e\x84\r\x1d\xac\xa7\\\x82Wc@`\x13\xfd\x024t\x8ct\xd3\x01\x19\xe9'
    assert salter.stretch(tier=Tiers.med) == b',\xf3\x8c\xbb\xe9)\nSQ\xec\xad\x8c9?\xaf\xb8\xb0\xb3\xcdB\xda\xd8\xb6\xf7\r\xf6D}Z\xb9Y\x16'
    assert salter.stretch(tier=Tiers.high) == b'(\xcd\xc4\xb85\xcd\xe8:\xfc\x00\x8b\xfd\xa6\tj.y\x98\x0b\x04\x1c\xe3hBc!I\xe49K\x16-'

    """ Done Test """


def test_cipher():
    """
    Test Cipher subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    seedqb64b = Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
    #b'AGDswxA8qdkb646JFZWUflm_OKUeF41iG2gTw3N4GwCs'

    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    saltqb64b = Matter(raw=salt, code=MtrDex.Salt_128).qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'

    # seed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(kering.EmptyMaterialError):
        cipher = Cipher()

    raw = pysodium.crypto_box_seal(seedqb64b, pubkey)  # uses nonce so different everytime
    cipher = Cipher(raw=raw)
    assert cipher.code == MtrDex.X25519_Cipher_Seed
    uncb = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)
    assert uncb == seedqb64b

    # test .decrypt method needs qb64
    prikeyqb64 = Matter(raw=prikey, code=MtrDex.X25519_Private).qb64b
    assert cipher.decrypt(prikey=prikeyqb64).qb64b == seedqb64b

    cryptseedqb64 = Matter(raw=cryptseed, code=MtrDex.Ed25519_Seed).qb64b
    assert cipher.decrypt(seed=cryptseedqb64).qb64b == seedqb64b

    raw = pysodium.crypto_box_seal(saltqb64b, pubkey)  # uses nonce so different everytime
    cipher = Cipher(raw=raw)
    assert cipher.code == MtrDex.X25519_Cipher_Salt
    uncb = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)
    assert uncb == saltqb64b

    # test .decrypt method needs qb64
    prikeyqb64 = Matter(raw=prikey, code=MtrDex.X25519_Private).qb64b
    assert cipher.decrypt(prikey=prikeyqb64).qb64b == saltqb64b

    cryptseedqb64 = Matter(raw=cryptseed, code=MtrDex.Ed25519_Seed).qb64b
    assert cipher.decrypt(seed=cryptseedqb64).qb64b == saltqb64b

    with pytest.raises(ValueError):  # bad code
        cipher = Cipher(raw=raw, code=MtrDex.Ed25519N)
    """ Done Test """


def test_encrypter():
    """
    Test Encrypter subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    seedqb64b = Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'

    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    saltqb64b = Matter(raw=salt, code=MtrDex.Salt_128).qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'

    # seed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner = Signer(raw=cryptseed, code=MtrDex.Ed25519_Seed, transferable=True)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)  # raw
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(kering.EmptyMaterialError):
        encrypter = Encrypter()

    encrypter = Encrypter(raw=pubkey)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey
    assert encrypter.verifySeed(seed=cryptsigner.qb64)

    cipher = encrypter.encrypt(ser=seedqb64b)
    assert cipher.code == MtrDex.X25519_Cipher_Seed
    uncb = pysodium.crypto_box_seal_open(cipher.raw, encrypter.raw, prikey)
    assert uncb == seedqb64b

    cipher = encrypter.encrypt(ser=saltqb64b)
    assert cipher.code == MtrDex.X25519_Cipher_Salt
    uncb = pysodium.crypto_box_seal_open(cipher.raw, encrypter.raw, prikey)
    assert uncb == saltqb64b

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)

    encrypter = Encrypter(verkey=verfer.qb64)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    encrypter = Encrypter(verkey=verfer.qb64b)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    # user Prefixer to generate original verkey
    prefixer = Prefixer(qb64=verfer.qb64)
    encrypter = Encrypter(verkey=prefixer.qb64b)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey
    """ Done Test """


def test_decrypter():
    """
    Test Decrypter subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    signer = Signer(raw=seed, code=MtrDex.Ed25519_Seed)
    assert signer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable  # default
    seedqb64b = signer.qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
    # also works for Matter
    assert seedqb64b == Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b

    # raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    salter = Salter(raw=raw, code=MtrDex.Salt_128)
    assert salter.code == MtrDex.Salt_128
    saltqb64b = salter.qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'
    # also works for Matter
    assert saltqb64b == Matter(raw=raw, code=MtrDex.Salt_128).qb64b  #

    # cryptseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner = Signer(raw=cryptseed, code=MtrDex.Ed25519_Seed, transferable=True)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)  # raw
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(kering.EmptyMaterialError):
        decrypter = Decrypter()

    # create encrypter
    encrypter = Encrypter(raw=pubkey)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    # create cipher of seed
    seedcipher = encrypter.encrypt(ser=seedqb64b)
    assert seedcipher.code == MtrDex.X25519_Cipher_Seed
    # each encryption uses a nonce so not a stable representation for testing

    # create decrypter from prikey
    decrypter = Decrypter(raw=prikey)
    assert decrypter.code == MtrDex.X25519_Private
    assert decrypter.qb64 == 'OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ'
    assert decrypter.raw == prikey

    # decrypt seed cipher using ser
    designer = decrypter.decrypt(ser=seedcipher.qb64b, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable

    # decrypt seed cipher using cipher
    designer = decrypter.decrypt(cipher=seedcipher, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable

    # create cipher of salt
    saltcipher = encrypter.encrypt(ser=saltqb64b)
    assert saltcipher.code == MtrDex.X25519_Cipher_Salt
    # each encryption uses a nonce so not a stable representation for testing

    # decrypt salt cipher using ser
    desalter = decrypter.decrypt(ser=saltcipher.qb64b)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # decrypt salt cipher using cipher
    desalter = decrypter.decrypt(cipher=saltcipher)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # use previously stored fully qualified seed cipher with different nonce
    # get from seedcipher above
    cipherseed = ('PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_'
                  'NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw')
    designer = decrypter.decrypt(ser=cipherseed, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519

    # use previously stored fully qualified salt cipher with different nonce
    # get from saltcipher above
    ciphersalt = ('1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWy'
                  'IwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu')
    desalter = decrypter.decrypt(ser=ciphersalt)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # Create new decrypter but use seed parameter to init prikey
    decrypter = Decrypter(seed=cryptsigner.qb64b)
    assert decrypter.code == MtrDex.X25519_Private
    assert decrypter.qb64 == 'OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ'
    assert decrypter.raw == prikey

    # decrypt ciphersalt
    desalter = decrypter.decrypt(ser=saltcipher.qb64b)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    """ Done Test """



if __name__ == "__main__":
    test_signer()
    test_generatesigners()
    test_salter()
    test_cipher()
    test_encrypter()
    test_decrypter()

