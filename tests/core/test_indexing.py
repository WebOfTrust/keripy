# -*- encoding: utf-8 -*-
"""
tests.core.test_indexing module

"""
from dataclasses import dataclass, astuple, asdict
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pysodium

import pytest

from keri.kering import (EmptyMaterialError, RawMaterialError, ShortageError,
                         InvalidVarIndexError, )


from keri.help import helping
from keri.help.helping import (sceil, intToB64, b64ToInt,
                            codeB64ToB2, codeB2ToB64, nabSextets)

from keri.core import indexing
from keri.core.indexing import (IdrDex, IdxSigDex, IdxCrtSigDex, IdxBthSigDex,
                                Xizage, Indexer, Siger)


from keri.core.coring import (Verfer,)

def test_indexer_class():
    """
    Test Indexer class
    """

    assert Indexer.Codes == {
        'Ed25519_Sig': 'A',
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Sig': 'C',
        'ECDSA_256k1_Crt_Sig': 'D',
        'ECDSA_256r1_Sig': 'E',
        'ECDSA_256r1_Crt_Sig': 'F',
        'Ed448_Sig': '0A',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Sig': '2A',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Sig': '2C',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'ECDSA_256r1_Big_Sig': '2E',
        'ECDSA_256r1_Big_Crt_Sig': '2F',
        'Ed448_Big_Sig': '3A',
        'Ed448_Big_Crt_Sig': '3B',
        'TBD0': '0z',
        'TBD1': '1z',
        'TBD4': '4z',
    }

    assert Indexer.Names == \
    {
        'A': 'Ed25519_Sig',
        'B': 'Ed25519_Crt_Sig',
        'C': 'ECDSA_256k1_Sig',
        'D': 'ECDSA_256k1_Crt_Sig',
        'E': 'ECDSA_256r1_Sig',
        'F': 'ECDSA_256r1_Crt_Sig',
        '0A': 'Ed448_Sig',
        '0B': 'Ed448_Crt_Sig',
        '2A': 'Ed25519_Big_Sig',
        '2B': 'Ed25519_Big_Crt_Sig',
        '2C': 'ECDSA_256k1_Big_Sig',
        '2D': 'ECDSA_256k1_Big_Crt_Sig',
        '2E': 'ECDSA_256r1_Big_Sig',
        '2F': 'ECDSA_256r1_Big_Crt_Sig',
        '3A': 'Ed448_Big_Sig',
        '3B': 'Ed448_Big_Crt_Sig',
        '0z': 'TBD0',
        '1z': 'TBD1',
        '4z': 'TBD4'
    }


    assert IdrDex.Ed25519_Sig == 'A'
    assert IdrDex.Ed25519_Crt_Sig == 'B'
    assert IdrDex.ECDSA_256k1_Sig == 'C'
    assert IdrDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdrDex.ECDSA_256r1_Sig == 'E'
    assert IdrDex.ECDSA_256r1_Crt_Sig == 'F'
    assert IdrDex.Ed448_Sig == '0A'
    assert IdrDex.Ed448_Crt_Sig == '0B'
    assert IdrDex.Ed25519_Big_Sig == '2A'
    assert IdrDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdrDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdrDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdrDex.ECDSA_256r1_Big_Sig == '2E'
    assert IdrDex.ECDSA_256r1_Big_Crt_Sig == '2F'
    assert IdrDex.Ed448_Big_Sig == '3A'
    assert IdrDex.Ed448_Big_Crt_Sig == '3B'
    assert IdrDex.TBD0 == '0z'
    assert IdrDex.TBD1 == '1z'
    assert IdrDex.TBD4 == '4z'

    assert asdict(IdxSigDex) == {
        'Ed25519_Sig': 'A',
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Sig': 'C',
        'ECDSA_256k1_Crt_Sig': 'D',
        'ECDSA_256r1_Sig': 'E',
        'ECDSA_256r1_Crt_Sig': 'F',
        'Ed448_Sig': '0A',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Sig': '2A',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Sig': '2C',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'ECDSA_256r1_Big_Sig': '2E',
        'ECDSA_256r1_Big_Crt_Sig': '2F',
        'Ed448_Big_Sig': '3A',
        'Ed448_Big_Crt_Sig': '3B',
    }

    assert IdxSigDex.Ed25519_Sig == 'A'
    assert IdxSigDex.Ed25519_Crt_Sig == 'B'
    assert IdxSigDex.ECDSA_256k1_Sig == 'C'
    assert IdxSigDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdxSigDex.ECDSA_256r1_Sig == 'E'
    assert IdxSigDex.ECDSA_256r1_Crt_Sig == 'F'
    assert IdxSigDex.Ed448_Sig == '0A'
    assert IdxSigDex.Ed448_Crt_Sig == '0B'
    assert IdxSigDex.Ed25519_Big_Sig == '2A'
    assert IdxSigDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdxSigDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdxSigDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdxSigDex.ECDSA_256r1_Big_Sig == '2E'
    assert IdxSigDex.ECDSA_256r1_Big_Crt_Sig == '2F'
    assert IdxSigDex.Ed448_Big_Sig == '3A'
    assert IdxSigDex.Ed448_Big_Crt_Sig == '3B'


    assert asdict(IdxCrtSigDex) == {
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Crt_Sig': 'D',
        'ECDSA_256r1_Crt_Sig': 'F',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'ECDSA_256r1_Big_Crt_Sig': '2F',
        'Ed448_Big_Crt_Sig': '3B',
    }

    assert IdxCrtSigDex.Ed25519_Crt_Sig == 'B'
    assert IdxCrtSigDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdxCrtSigDex.ECDSA_256r1_Crt_Sig == 'F'
    assert IdxCrtSigDex.Ed448_Crt_Sig == '0B'
    assert IdxCrtSigDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdxCrtSigDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdxCrtSigDex.ECDSA_256r1_Big_Crt_Sig == '2F'
    assert IdxCrtSigDex.Ed448_Big_Crt_Sig == '3B'


    assert asdict(IdxBthSigDex) == {
        'Ed25519_Sig': 'A',
        'ECDSA_256k1_Sig': 'C',
        'ECDSA_256r1_Sig': 'E',
        'Ed448_Sig': '0A',
        'Ed25519_Big_Sig': '2A',
        'ECDSA_256k1_Big_Sig': '2C',
        'ECDSA_256r1_Big_Sig': '2E',
        'Ed448_Big_Sig': '3A',
    }

    assert IdxBthSigDex.Ed25519_Sig == 'A'
    assert IdxBthSigDex.ECDSA_256k1_Sig == 'C'
    assert IdxBthSigDex.ECDSA_256r1_Sig == 'E'
    assert IdxBthSigDex.Ed448_Sig == '0A'
    assert IdxBthSigDex.Ed25519_Big_Sig == '2A'
    assert IdxBthSigDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdxBthSigDex.ECDSA_256r1_Big_Sig == '2E'
    assert IdxBthSigDex.Ed448_Big_Sig == '3A'


    # first character of code with hard size of code
    assert Indexer.Hards == {
        'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
        'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
        'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
        'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
        'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
        's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
        '0': 2, '1': 2, '2': 2, '3': 2, '4': 2,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Indexer.Sizes == {
        'A': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'B': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'C': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'D': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'E': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'F': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        '0A': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '0B': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '2A': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2B': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2C': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2D': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2E': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2F': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '3A': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '3B': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '0z': Xizage(hs=2, ss=2, os=0, fs=None, ls=0),
        '1z': Xizage(hs=2, ss=2, os=1, fs=76, ls=1),
        '4z': Xizage(hs=2, ss=6, os=3, fs=80, ls=1),
    }

    assert Indexer.Sizes['A'].hs == 1  # hard size
    assert Indexer.Sizes['A'].ss == 1  # soft size
    assert Indexer.Sizes['A'].os == 0  # other size
    assert Indexer.Sizes['A'].fs == 88  # full size
    assert Indexer.Sizes['A'].ls == 0  # lead size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Indexer.Sizes.keys():
        assert Indexer.Hards[ckey[0]] == Indexer.Sizes[ckey].hs

    # verify all Codes have hs > 0 and ss > 0 and fs >= hs + ss if fs is not None
    # verify os is part of ss
    for val in Indexer.Sizes.values():
        assert val.hs > 0 and val.ss > 0
        assert val.os >= 0 and val.os < val.ss
        if val.os:
            assert val.os == val.ss // 2
        if val.fs is not None:
            assert val.fs >= val.hs + val.ss
            assert val.fs % 4 == 0

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Indexer.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Indexer.Bards[ckey] == sval

    """End Test"""


def test_indexer():
    """
    Test Indexer instance
    """


    with pytest.raises(EmptyMaterialError):
        indexer = Indexer()

    # Test signatures
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    ps = (3 - (len(sig) % 3)) % 3  # same pad size char and lead size bytes
    sig64b = encodeB64(bytes([0]* ps) +  sig)  # prepad with ps bytes of zeros
    sig64 = sig64b.decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == ('AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwq'
                     'ezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')

    # replace prepad  with code "A" plus index 0 == "A"
    qsc = IdrDex.Ed25519_Sig + intToB64(0, l=1)
    assert qsc == 'AA'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[ps:]  # replace prepad chars with clause
    assert qsig64 == ('AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFw'
                      'qezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    assert qsig2b == (b"\x00\x00\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
                      b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
                      b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64

    indexer._exfil(qsig64b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer._bexfil(qsig2b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test wrong size of raw
    longsig = sig + bytes([10, 11, 12])
    indexer = Indexer(raw=longsig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0

    shortsig = sig[:-3]
    with pytest.raises(RawMaterialError):
        indexer = Indexer(raw=shortsig)

    indexer = Indexer(qb64b=qsig64b)  # test with bytes not str
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)  # test with str not bytes
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test non-zero pad bits in qb64 init ps == 2
    badq64sig2= ('AA_Z0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFw'
                      'qezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    with pytest.raises(ValueError) as ex:
        indexer = Indexer(qb64=badq64sig2)
    assert str(ex.value) == "Non zeroed prepad bits = 111100 in b'_'."

    # test truncates extra bytes from qb64 parameter
    longqsig64 = qsig64 + "ABCD"
    indexer = Indexer(qb64=longqsig64)
    assert len(indexer.qb64) == Indexer.Sizes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsig64 = qsig64[:-4]  # too short
    with pytest.raises(ShortageError):
        indexer = Indexer(qb64=shortqsig64)

    indexer = Indexer(qb2=qsig2b)  # test with qb2
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test non-zero pad bits in qb2 init ps ==2
    badq2sig2= decodeB64(badq64sig2)
    with pytest.raises(ValueError) as ex:
        indexer = Indexer(qb2=badq2sig2)
    assert str(ex.value) == 'Non zeroed pad bits = 00001111 in 0x0f.'

    # test truncates extra bytes from qb2 parameter
    longqsig2b = qsig2b + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    indexer = Indexer(qb2=longqsig2b)
    assert isinstance(indexer.raw, bytes)
    assert indexer.qb2 == qsig2b
    assert len(indexer.qb64) == Indexer.Sizes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqsig2b = qsig2b[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        indexer = Indexer(qb2=shortqsig2b)

    # test with non-zero index=5
    # replace pad "==" with code "AF"
    qsc = IdrDex.Ed25519_Sig + intToB64(5, l=1)
    assert qsc == 'AF'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[ps:]  # replace prepad chars with code
    assert qsig64 == ('AFCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZF'
                      'wqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    qsig2b = (b"\x00P\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
              b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
              b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    indexer._exfil(qsig64b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    indexer._bexfil(qsig2b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=0)

    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=64)

    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0  #default index is zero
    assert indexer.ondex == 0
    assert indexer.qb64 != qsig64
    assert indexer.qb2 != qsig2b

    indexer = Indexer(qb2=qsig2b)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # Test ._bexfil
    indexer = Indexer(qb64=qsig64)  #
    raw = indexer.raw
    code = indexer.code
    index = indexer.index

    qb2 = indexer.qb2
    indexer._bexfil(qb2)
    assert indexer.raw == raw
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qsig64
    assert indexer.qb2 == qb2

    # Test ._binfil
    test = indexer._binfil()
    assert test == qb2

    # test ondex not None and not match index for not os
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=0)


    # test strip ims
    # strip ignored if qb64
    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    ims = bytearray(qsig64b)
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    ims = bytearray(qsig2b)
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    # test extra bytes in ims qb64b
    extra = bytearray(b"ABCD")
    ims = bytearray(qsig64b) + extra
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra

    # test extra bytes in ims qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qsig2b) + extra
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra


    # test index too big
    index = 65
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test negative index
    index = -1
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test non integer index
    index = 3.5
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test big code both different and same
    index = 67

    qb64 = '2ABDBDCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x00C\x040\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index, ondex=index)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    index = 90
    ondex = 65
    qb64 = '2ABaBBCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x00Z\x04\x10\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index, ondex=ondex)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    # test Crt only code
    index =  3
    code = IdrDex.Ed25519_Crt_Sig
    qb64 = 'BDCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b"\x040\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
           b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
           b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=code, index=index)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2


    # test ondex error conditions
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index)

    with pytest.raises(InvalidVarIndexError):  # non None ondex
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index+2)


    # test big code current only
    index =  68
    code = IdrDex.Ed25519_Big_Crt_Sig
    qb64 = '2BBEAACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x10D\x00\x00\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=code, index=index)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    # test ondex error conditions
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index)

    with pytest.raises(InvalidVarIndexError):  # non None ondex
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index+2)


    # Test of TBD Label Code (variable length)
    label = b'Hello_World_Peep'
    index = len(label) // 4
    assert not len(label) % 4
    assert index == 4
    lraw = decodeB64(label)
    assert len(lraw) == len(label) * 3 // 4
    assert lraw == b'\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'
    ltext = encodeB64(lraw)
    assert ltext == b'Hello_World_Peep' == label
    qsc = IdrDex.TBD0 + intToB64(index, l=2)
    assert qsc == '0zAE'
    qscb = qsc.encode("utf-8")
    lq64b = qscb + label
    assert lq64b == b'0zAEHello_World_Peep'
    lq64 = lq64b.decode("utf-8")

    # label from raw
    indexer = Indexer(raw=lraw, code=IdrDex.TBD0, index=index)
    assert indexer.raw == lraw
    assert indexer.code == IdrDex.TBD0
    assert indexer.index == index
    assert indexer.qb64b == lq64b
    assert indexer.qb64 == lq64
    assert indexer.qb2 == b'\xd30\x04\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'

    # index zero for empty label
    indexer = Indexer(raw=lraw, code=IdrDex.TBD0, index=0)
    assert indexer.raw == b''
    assert indexer.code == IdrDex.TBD0
    assert indexer.index == 0
    assert indexer.qb64b == b'0zAA'
    assert indexer.qb64 == '0zAA'
    assert indexer.qb2 == b'\xd30\x00'
    """ Done Test """




def test_siger():
    """
    Test Siger subclass of Indexer
    """
    with pytest.raises(EmptyMaterialError):
        siger = Siger()

    qsig64 = ('AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd'
              '7K_H9-1298F4Id1DxvIoEmCQ')
    #'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = qsig64.encode("utf-8")
    assert qsig64b == (b'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGR'
                       b'cKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ')

    siger = Siger(qb64b=qsig64b)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64b)  # also bytes
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    verkey, sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    siger.verfer = verfer
    assert siger.verfer == verfer

    siger = Siger(qb64=qsig64, verfer=verfer)
    assert siger.verfer == verfer

    siger = Siger(
        raw=b'abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456'
            b'789abcdef', code=IdrDex.Ed448_Sig, index=4)
    assert siger.qb64 == ('0AEEYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTI'
                          'zNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVm')


    """ Done Test """


if __name__ == "__main__":
    test_indexer_class()
    test_indexer()
    test_siger()

