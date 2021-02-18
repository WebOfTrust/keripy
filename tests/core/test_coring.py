# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import pytest

import pysodium
import blake3
import json
import hashlib
import dataclasses

import msgpack
import cbor2 as cbor

from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from fractions import Fraction

from keri.kering import Version, Versionage
from keri.kering import (ValidationError, EmptyMaterialError, DerivationError,
                         ShortageError)
from keri.core.coring import (CrySelDex, CryCntDex,
                              CryCntSizes, CryCntRawSizes, CryCntIdxSizes,
                              CryOneDex, CryOneSizes, CryOneRawSizes,
                              CryTwoDex, CryTwoSizes, CryTwoRawSizes,
                              CryFourDex, CryFourSizes, CryFourRawSizes,
                              CrySizes, CryRawSizes, MINCRYSIZE)

from keri.core.coring import Sizage, MtrDex, Matter, IdrDex, Indexer

from keri.core.coring import (CryMat, CryCounter, Verfer, Cigar, Signer, Salter,
                              Diger, Nexter, Prefixer)
from keri.core.coring import generateSigners,  generateSecrets
from keri.core.coring import (SigSelDex, SigCntDex, SigCntSizes, SigCntRawSizes,
                              SigTwoDex, SigTwoSizes, SigTwoRawSizes,
                              SigFourDex, SigFourSizes, SigFourRawSizes,
                              SigFiveDex, SigFiveSizes, SigFiveRawSizes,
                              SigSizes, SigRawSizes, MINSIGSIZE)

from keri.core.coring import IntToB64, B64ToInt
from keri.core.coring import SigMat, SigCounter, Seqner, Siger
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever, VERFULLSIZE, MINSNIFFSIZE
from keri.core.coring import Serder, Tholder
from keri.core.coring import Ilkage, Ilks


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
                          rct='rct', vrc='vrc')

    assert isinstance(Ilks, Ilkage)

    assert 'icp' in Ilks
    assert Ilks.icp == 'icp'
    assert 'rot' in Ilks
    assert Ilks.rot == 'rot'
    assert 'ixn' in Ilks
    assert Ilks.ixn == 'ixn'
    assert 'dip' in Ilks
    assert Ilks.dip == 'dip'
    assert 'drt' in Ilks
    assert Ilks.drt == 'drt'
    assert 'rct' in Ilks
    assert Ilks.rct == 'rct'
    assert 'vrc' in Ilks
    assert Ilks.vrc == 'vrc'

    """End Test """


def test_cryderivationcodes():
    """
    Test the support functionality for derivation codes
    """
    assert CrySelDex.two == '0'

    assert 'A' not in CrySelDex

    for x in ['0']:
        assert x in CrySelDex

    assert CryOneDex.Ed25519_Seed == 'A'
    assert CryOneDex.Ed25519N == 'B'
    assert CryOneDex.X25519 == 'C'
    assert CryOneDex.Ed25519 == 'D'
    assert CryOneDex.Blake3_256 == 'E'
    assert CryOneDex.Blake2b_256 == 'F'
    assert CryOneDex.Blake2s_256 == 'G'
    assert CryOneDex.SHA3_256 == 'H'
    assert CryOneDex.SHA2_256 == 'I'
    assert CryOneDex.ECDSA_256k1_Seed == 'J'
    assert CryOneDex.Ed448_Seed == 'K'
    assert CryOneDex.X448 == 'L'

    assert '0' not in CryOneDex

    for x in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',  'L']:
        assert x in CryOneDex
        assert x in CryOneSizes
        assert x in CryOneRawSizes

    assert CryTwoDex.Salt_128 == '0A'
    assert CryTwoDex.Ed25519_Sig == '0B'
    assert CryTwoDex.ECDSA_256k1_Sig == '0C'

    assert 'A' not in CryTwoDex

    for x in ['0A', '0B']:
        assert x in CryTwoDex
        assert x in CryTwoSizes
        assert x in CryTwoRawSizes

    assert CryFourDex.ECDSA_256k1N == '1AAA'
    assert CryFourDex.ECDSA_256k1 == '1AAB'

    assert '0' not in CryFourDex
    assert 'A' not in CryFourDex
    assert '0A' not in CryFourDex

    for x in ['1AAA', '1AAB']:
        assert x in CryFourDex
        assert x in CryFourSizes
        assert x in CryFourRawSizes


    for x in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', '0A', '0B',
              '1AAA', '1AAB']:
        assert x in CrySizes
        assert x in CryRawSizes

    assert MINCRYSIZE == 4

    """Done Test"""

def test_sigderivationcodes():
    """
    Test the support functionality for derivation codes
    """
    assert SigSelDex.four == '0'

    assert 'A' not in SigSelDex

    for x in ['0', '1', '2']:
        assert x in SigSelDex

    assert SigTwoDex.Ed25519 == 'A'
    assert SigTwoDex.ECDSA_256k1 == 'B'

    assert '0' not in SigTwoDex

    for x in ['A', 'B']:
        assert x in SigTwoDex
        assert x in SigTwoSizes
        assert x in SigTwoRawSizes

    assert SigFourDex.Ed448 == '0A'

    assert 'A' not in SigFourDex

    for x in ['0A']:
        assert x in SigFourDex
        assert x in SigFourSizes
        assert x in SigFourRawSizes

    assert '0' not in SigFiveDex
    assert 'A' not in SigFiveDex
    assert '0A' not in SigFiveDex

    for x in []:
        assert x in SigFiveDex
        assert x in SigFiveSizes
        assert x in SigFiveRawSizes


    for x in ['A', 'B', '0A']:
        assert x in SigSizes
        assert x in SigRawSizes

    assert MINSIGSIZE == 4
    """Done Test"""

def test_crymat():
    """
    Test the support functionality for cryptographic material
    """
    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'  #  str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
              b'IS\xf3\x874\xbao\x90\x8c')  # pure base 2 binary qb2

    with pytest.raises(EmptyMaterialError):
        crymat = CryMat()

    with pytest.raises(EmptyMaterialError):
        crymat = CryMat(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        crymat = CryMat(raw=verkey, code='')

    crymat = CryMat(raw=verkey)
    assert crymat.raw == verkey
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin
    assert crymat.transferable == False

    assert crymat.qb64 == encodeB64(crymat.qb2).decode("utf-8")
    assert crymat.qb2 == decodeB64(crymat.qb64.encode("utf-8"))

    crymat._exfil(prefixb)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64b=prefixb)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefixb)  #  works for either
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey


    # test wrong size of qb64
    longprefix = prefix + "ABCD"
    okcrymat = CryMat(qb64=longprefix)
    assert len(okcrymat.qb64) == CrySizes[okcrymat.code]

    shortprefix = prefix[:-4]
    with pytest.raises(ShortageError):
        okcrymat = CryMat(qb64=shortprefix)

    crymat = CryMat(qb2=prebin)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix.encode("utf-8"))  # test bytes not str
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey
    assert crymat.qb64 == prefix
    assert crymat.qb64b == prefix.encode("utf-8")

    # test wrong size of raw
    longverkey = verkey + bytes([10, 11, 12])
    crymat = CryMat(raw=longverkey)

    shortverkey =  verkey[:-3]
    with pytest.raises(ValidationError):
        crymat = CryMat(raw=shortverkey)

    # test prefix on full identifier
    full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
    crymat = CryMat(qb64=full)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    # test nongreedy prefixb on full identifier
    full = prefixb + b":mystuff/mypath/toresource?query=what#fragment"
    crymat = CryMat(qb64b=full)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64b = encodeB64(sig)
    assert sig64b == b'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='
    sig64 =  sig64b.decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = b'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsigB2 = (b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    crymat = CryMat(raw=sig, code=CryTwoDex.Ed25519_Sig)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519_Sig
    assert crymat.qb64 == qsig64
    assert crymat.qb64b == qsig64b
    assert crymat.qb2 == qsigB2
    assert crymat.transferable == True

    crymat = CryMat(qb64b=qsig64b)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519_Sig

    crymat = CryMat(qb64=qsig64)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519_Sig

    qsig64b  = qsig64.encode("utf-8")  #  test bytes input
    crymat = CryMat(qb64=qsig64b)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519_Sig

    crymat = CryMat(qb2=qsigB2)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519_Sig

    """ Done Test """

def test_crycounter():
    """
    Test CryCounter subclass of CryMat
    """
    # with pytest.raises(EmptyMaterialError):
    #    counter = SigCounter()

    qsc = CryCntDex.Base64 + IntToB64(1, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    assert qscb == b'-AAB'

    counter = CryCounter()
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(raw=b'')
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(qb64b=qscb)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(qb64=qscb)  #  also works with bytes
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(raw=b'', count=1)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 1
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = CryCounter(raw=b'', count=0)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == 0
    assert counter.qb64 == '-AAA'
    assert counter.qb64b == b'-AAA'
    assert counter.qb2 == b'\xf8\x00\x00'


    cnt = 5
    qsc = SigCntDex.Base64 + IntToB64(cnt, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    assert qscb == b'-AAF'

    counter = CryCounter(count=cnt)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x05'

    counter = CryCounter(qb64b=qscb)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x05'

    counter = CryCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x05'

    counter = CryCounter(qb64=qscb)  #  bytes also
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base64
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x00\x05'

    cnt = 5
    qsc = CryCntDex.Base2 + IntToB64(cnt, l=2)
    assert qsc == '-BAF'
    qscb = qsc.encode("utf-8")
    assert qscb == b'-BAF'

    counter = CryCounter(code=CryCntDex.Base2, count=cnt)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base2
    assert counter.index == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x10\x05'

    counter = CryCounter(qb64b=qscb)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base2
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x10\x05'

    counter = CryCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base2
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x10\x05'

    counter = CryCounter(qb64=qscb)  #  bytes also
    assert counter.raw == b''
    assert counter.code == CryCntDex.Base2
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb64b == qscb
    assert counter.qb2 == b'\xf8\x10\x05'
    """ Done Test """


def test_seqner():
    """
    Test Seqner sequence number subclass of CryMat
    """
    number = Seqner()  #  defaults to zero
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAA'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAAA'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    snraw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    snqb64b = b'0AAAAAAAAAAAAAAAAAAAAAAA'
    snqb64 = '0AAAAAAAAAAAAAAAAAAAAAAA'
    snqb2 = b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    with pytest.raises(ValidationError):
        number = Seqner(raw=b'')

    number = Seqner(qb64b=snqb64b)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    # test priority lower for sn and snh
    number = Seqner(qb64b=snqb64b, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(sn=5, snh='a')
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAABQ'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAABQ'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

    number = Seqner(snh='a')
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 10
    assert number.snh == 'a'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAACg'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAACg'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0'

    # More tests
    snraw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    snqb64b = b'0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb64 = '0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb2 = b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

    number = Seqner(qb64b=snqb64b)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2, sn=5)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw, sn=5)
    assert number.raw == snraw
    assert number.code == CryTwoDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    """ Done Test """


def test_verfer():
    """
    Test the support functionality for verifier subclass of crymat
    """
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)

    with pytest.raises(EmptyMaterialError):
        verfer = Verfer()

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    assert verfer.raw == verkey
    assert verfer.code == CryOneDex.Ed25519N

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    sig = pysodium.crypto_sign_detached(ser, seed + verkey)  # sigkey = seed + verkey

    result = verfer.verify(sig, ser)
    assert result == True

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519)
    assert verfer.raw == verkey
    assert verfer.code == CryOneDex.Ed25519

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    sig = pysodium.crypto_sign_detached(ser, seed + verkey)  # sigkey = seed + verkey

    result = verfer.verify(sig, ser)
    assert result == True

    with pytest.raises(ValueError):
        verfer = Verfer(raw=verkey, code=CryOneDex.Blake3_256)
    """ Done Test """

def test_cigar():
    """
    Test Cigar subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        cigar = Cigar()

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    cigar = Cigar(qb64=qsig64)
    assert cigar.code == CryTwoDex.Ed25519_Sig
    assert cigar.qb64 == qsig64
    assert cigar.verfer == None

    verkey,  sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    cigar.verfer = verfer
    assert  cigar.verfer == verfer

    cigar = Cigar(qb64=qsig64, verfer=verfer)
    assert  cigar.verfer == verfer
    """ Done Test """


def test_signer():
    """
    Test the support functionality for signer subclass of crymat
    """
    signer = Signer()  # defaults provide Ed25519 signer Ed25519 verfer
    assert signer.code == CryOneDex.Ed25519_Seed
    assert len(signer.raw) == CryOneRawSizes[signer.code]
    assert signer.verfer.code == CryOneDex.Ed25519
    assert len(signer.verfer.raw) == CryOneRawSizes[signer.verfer.code]

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    crymat = signer.sign(ser)
    assert crymat.code == CryTwoDex.Ed25519_Sig
    assert len(crymat.raw) == CryTwoRawSizes[crymat.code]
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=0)
    assert sigmat.code == SigTwoDex.Ed25519
    assert len(sigmat.raw) == SigTwoRawSizes[sigmat.code]
    assert sigmat.index == 0
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True
    result = signer.verfer.verify(sigmat.raw, ser + b'ABCDEFG')
    assert result == False

    assert crymat.raw == sigmat.raw

    signer = Signer(transferable=False)  # Ed25519N verifier
    assert signer.code == CryOneDex.Ed25519_Seed
    assert len(signer.raw) == CryOneRawSizes[signer.code]
    assert signer.verfer.code == CryOneDex.Ed25519N
    assert len(signer.verfer.raw) == CryOneRawSizes[signer.verfer.code]

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    crymat = signer.sign(ser)
    assert crymat.code == CryTwoDex.Ed25519_Sig
    assert len(crymat.raw) == CryTwoRawSizes[crymat.code]
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=0)
    assert sigmat.code == SigTwoDex.Ed25519
    assert len(sigmat.raw) == SigTwoRawSizes[sigmat.code]
    assert sigmat.index == 0
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True
    result = signer.verfer.verify(sigmat.raw, ser + b'ABCDEFG')
    assert result == False


    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=CryOneDex.Ed25519_Seed)
    assert signer.code == CryOneDex.Ed25519_Seed
    assert len(signer.raw) == CryOneRawSizes[signer.code]
    assert signer.raw == seed
    assert signer.verfer.code == CryOneDex.Ed25519
    assert len(signer.verfer.raw) == CryOneRawSizes[signer.verfer.code]

    crymat = signer.sign(ser)
    assert crymat.code == CryTwoDex.Ed25519_Sig
    assert len(crymat.raw) == CryTwoRawSizes[crymat.code]
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=1)
    assert sigmat.code == SigTwoDex.Ed25519
    assert len(sigmat.raw) == SigTwoRawSizes[sigmat.code]
    assert sigmat.index == 1
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True

    assert crymat.raw == sigmat.raw

    with pytest.raises(ValueError):  #  use invalid code not SEED
        signer = Signer(raw=seed, code=CryOneDex.Ed25519N)

    with pytest.raises(ValueError):  #  use invalid code not SEED
        signer = Signer(code=CryOneDex.Ed25519N)
    """ Done Test """


def test_salter():
    """
    Test the support functionality for salter subclass of crymat
    """
    salter = Salter()  # defaults to CryTwoDex.Salt_128
    assert salter.code == CryTwoDex.Salt_128
    assert len(salter.raw) == CryRawSizes[salter.code] == 16

    raw = b'0123456789abcdef'

    salter = Salter(raw=raw)
    assert salter.raw == raw
    assert salter.qb64 == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    signer = salter.signer(path="01", temp=True)  # defaults to Ed25519
    assert signer.code == CryOneDex.Ed25519_Seed
    assert len(signer.raw) == CryRawSizes[signer.code]
    assert signer.verfer.code == CryOneDex.Ed25519
    assert len(signer.verfer.raw) == CryRawSizes[signer.verfer.code]
    assert signer.qb64 == 'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE'
    assert signer.verfer.qb64 == 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI'

    signer = salter.signer(path="01")  # defaults to Ed25519 temp = False level="low"
    assert signer.code == CryOneDex.Ed25519_Seed
    assert len(signer.raw) == CryRawSizes[signer.code]
    assert signer.verfer.code == CryOneDex.Ed25519
    assert len(signer.verfer.raw) == CryRawSizes[signer.verfer.code]
    assert signer.qb64 == 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I'
    assert signer.verfer.qb64 == 'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0'

    salter = Salter(qb64='0AMDEyMzQ1Njc4OWFiY2RlZg')
    assert salter.raw == raw
    assert salter.qb64 == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    with pytest.raises(ShortageError):
        salter = Salter(qb64='')


    """ Done Test """


def test_generatesigners():
    """
    Test the support function genSigners

    """
    signers = generateSigners(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert signer.verfer.code == CryOneDex.Ed25519N

    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    assert len(root) == 16
    signers = generateSigners(salt=root, count=4)  # default is transferable
    assert len(signers) == 4
    for signer in signers:
        assert signer.code == CryOneDex.Ed25519_Seed
        assert signer.verfer.code == CryOneDex.Ed25519

    sigkeys = [signer.qb64 for signer in signers]
    assert sigkeys == ['ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                       'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                       'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                       'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8']

    secrets = generateSecrets(salt=root, count=4)
    assert secrets == sigkeys

    """ End Test """


def test_diger():
    """
    Test the support functionality for Diger subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        diger = Diger()

    #create something to digest and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    dig = blake3.blake3(ser).digest()
    with pytest.raises(ValueError):
        diger = Diger(raw=dig, code=CryOneDex.Ed25519)

    with pytest.raises(ValueError):
        diger = Diger(ser=ser, code=CryOneDex.Ed25519)

    diger = Diger(raw=dig)  # defaults provide Blake3_256 digester
    assert diger.code == CryOneDex.Blake3_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)
    assert not diger.verify(ser=ser+b'ABCDEF')

    diger = Diger(raw=dig, code=CryOneDex.Blake3_256)
    assert diger.code == CryOneDex.Blake3_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser)  # default code is  Blake3_256
    assert diger.code == CryOneDex.Blake3_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)
    assert diger.qb64b == b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'

    digb = b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    dig =  'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    diger = Diger(qb64b=digb)
    assert diger.qb64b == digb
    assert diger.qb64 == dig
    assert diger.code == CryOneDex.Blake3_256

    diger = Diger(qb64=dig)
    assert diger.qb64 == dig
    assert diger.qb64b == digb
    assert diger.code == CryOneDex.Blake3_256

    pig = b'sLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E='
    raw = decodeB64(pig)
    assert pig == encodeB64(raw)

    dig = hashlib.blake2b(ser, digest_size=32).digest()
    diger = Diger(raw=dig, code=CryOneDex.Blake2b_256)
    assert diger.code == CryOneDex.Blake2b_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=CryOneDex.Blake2b_256)
    assert diger.code == CryOneDex.Blake2b_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    dig = hashlib.blake2s(ser, digest_size=32).digest()
    diger = Diger(raw=dig, code=CryOneDex.Blake2s_256)
    assert diger.code == CryOneDex.Blake2s_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=CryOneDex.Blake2s_256)
    assert diger.code == CryOneDex.Blake2s_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    dig = hashlib.sha3_256(ser).digest()
    diger = Diger(raw=dig, code=CryOneDex.SHA3_256)
    assert diger.code == CryOneDex.SHA3_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=CryOneDex.SHA3_256)
    assert diger.code == CryOneDex.SHA3_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    dig = hashlib.sha256(ser).digest()
    diger = Diger(raw=dig, code=CryOneDex.SHA2_256)
    assert diger.code == CryOneDex.SHA2_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=CryOneDex.SHA2_256)
    assert diger.code == CryOneDex.SHA2_256
    assert len(diger.raw) == CryOneRawSizes[diger.code]
    assert diger.verify(ser=ser)

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    diger0 = Diger(ser=ser) # default code
    diger1 = Diger(ser=ser, code=CryOneDex.SHA3_256)
    diger2 = Diger(ser=ser, code=CryOneDex.Blake2b_256)

    assert diger0.compare(ser=ser, diger=diger1)
    assert diger0.compare(ser=ser, diger=diger2)
    assert diger1.compare(ser=ser, diger=diger2)

    assert diger0.compare(ser=ser, dig=diger1.qb64)
    assert diger0.compare(ser=ser, dig=diger2.qb64b)
    assert diger1.compare(ser=ser, dig=diger2.qb64)

    ser1 = b'ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789'

    assert not diger0.compare(ser=ser, diger=Diger(ser=ser1))  # codes match
    assert not diger0.compare(ser=ser, dig=Diger(ser=ser1).qb64)  # codes match
    assert not diger0.compare(ser=ser,  # codes not match
                              diger=Diger(ser=ser1, code=CryOneDex.SHA3_256))
    assert not diger0.compare(ser=ser,  # codes not match
                              dig=Diger(ser=ser1, code=CryOneDex.SHA3_256).qb64b)

    """ Done Test """


def test_nexter():
    """
    Test the support functionality for Nexter subclass of Diger
    """
    with pytest.raises(EmptyMaterialError):
        nexter = Nexter()

    #create something to digest and verify
    # verkey, sigkey = pysodium.crypto_sign_keypair()
    # verfer = Verfer(raw=verkey)
    # assert verfer.qb64 == 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    sith = "{:x}".format(2)
    sithdig = blake3.blake3(sith.encode("utf-8")).digest()
    assert sithdig == b"\x81>\x9br\x91A\xe7\xf3\x85\xaf\xa0\xa2\xd0\xdf>l7\x89\xe4'\xff\xe4\xae\xefVjV[\xc8\xf2\xfe="

    sithdiger = Diger(raw=sithdig, code=CryOneDex.Blake3_256)
    assert sithdiger.qb64 == 'EgT6bcpFB5_OFr6Ci0N8-bDeJ5Cf_5K7vVmpWW8jy_j0'

    keys = ['BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE',
            'BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk',
            'B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw']

    keydigs = [blake3.blake3(key.encode("utf-8")).digest() for key in keys]
    assert keydigs == [b'\x98\x1d\xba\xc8\xcc\xeb\xa0\x80\xa1\xfa\x8aJ5\xd9\x18\xc8\xfd4\xd2L\x1e\xbdM|Y\x02=\xe4\x96\x89\x0e6',
                       b';\x80\x97\xa7\xc8,\xd3"`\xd5\xf1a$\xbb9\x84~\xa7z\xa2p\x84Q\x18\xee\xfa\xc9\x11\xd3\xde\xf3\xb2',
                       b'-e\x99\x13 i\x8e\xb7\xcc\xd5E4\x9f}J#"\x17\x96Z\xc2\xa0\xb1\x0e#\x95\x07\x0f\xdc{[\x12']

    digers = [Diger(raw=keydig, code=CryOneDex.Blake3_256) for keydig in keydigs]
    digs = [diger.qb64 for diger in digers]

    assert digs == ['EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                    'EO4CXp8gs0yJg1fFhJLs5hH6neqJwhFEY7vrJEdPe87I',
                    'ELWWZEyBpjrfM1UU0n31KIyIXllrCoLEOI5UHD9x7WxI']

    kints = [int.from_bytes(diger.raw,'big') for diger in digers]
    sint = int.from_bytes(sithdiger.raw, 'big')
    for kint in kints:
        sint ^= kint  # xor together

    raw = sint.to_bytes(CryRawSizes[CryOneDex.Blake3_256], 'big')
    assert raw == (b'\x0f\xc6/\x0e\xb5\xef\x1a\xe6\x88U\x9e\xbd^\xc0U\x03\x96\r\xda\x93S}\x03\x85\xc2\x07\xa5\xa1Q\xdeX\xab')

    nexter = Nexter(raw=raw)  # defaults provide Blake3_256 digest
    assert nexter.code == CryOneDex.Blake3_256
    assert nexter.qb64 == 'ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs'
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(raw=raw)
    assert nexter.verify(raw=raw+b'ABCDEF') == False

    with pytest.raises(ValueError):  # bad code
        nexter = Nexter(raw=raw, code=CryOneDex.Ed25519)

    nexter = Nexter(digs=digs)  # compute sith from digs using default sith
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(digs=digs)
    assert nexter.verify(raw=raw)

    nexter = Nexter(sith=sith, digs=digs)  # compute sith from digs using default sith
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(sith=sith, digs=digs)
    assert nexter.verify(raw=raw)

    nexter = Nexter(sith=sith, keys=keys)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(sith=sith, keys=keys)
    assert nexter.verify(raw=raw)
    assert nexter.verify(raw=raw+b'ABCDEF') == False

    with pytest.raises(EmptyMaterialError):
        nexter = Nexter(sith=sith)

    nexter = Nexter(keys=keys)  # compute sith from keys default sith
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(keys=keys)
    assert nexter.verify(raw=raw)

    nexter = Nexter(sith="2", keys=keys)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(sith="2", keys=keys)
    assert nexter.verify(raw=raw)

    ked = dict(kt=sith, k=keys)  #  subsequent event
    nexter = Nexter(ked=ked)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(ked=ked)
    assert nexter.verify(raw=raw)

    """ Done Test """


def test_prefixer():
    """
    Test the support functionality for prefixer subclass of crymat
    """
    preN = 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
    pre = 'DrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = (b'\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0='
              b'`\xf7\xbf\x8a\x18\x8a`q')
    verfer = Verfer(raw=verkey )
    assert verfer.qb64 == 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    nxtkey = (b"\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2"
              b'\xc4_\xf6\x00')
    nxtfer = Verfer(raw=nxtkey, code=CryOneDex.Ed25519)
    assert nxtfer.qb64 == 'Dpl-JNEryNVTBgyMGmEym7xqzaOpBOngn2gSIssRf9gA'

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer()

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(raw=verkey, code='')

    with pytest.raises(ValueError):
        prefixer = Prefixer(raw=verkey, code=CryOneDex.SHA2_256)

    # test creation given raw and code no derivation
    prefixer = Prefixer(raw=verkey, code=CryOneDex.Ed25519N)  # default code is None
    assert prefixer.code == CryOneDex.Ed25519N
    assert len(prefixer.raw) == CryOneRawSizes[prefixer.code]
    assert len(prefixer.qb64) == CryOneSizes[prefixer.code]

    ked = dict(k=[prefixer.qb64], n="", t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[prefixer.qb64], n="ABC", t="icp")
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    prefixer = Prefixer(raw=verkey, code=CryOneDex.Ed25519)  # defaults provide Ed25519N prefixer
    assert prefixer.code == CryOneDex.Ed25519
    assert len(prefixer.raw) == CryOneRawSizes[prefixer.code]
    assert len(prefixer.qb64) == CryOneSizes[prefixer.code]

    ked = dict(k=[prefixer.qb64], t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519)
    prefixer = Prefixer(raw=verfer.raw, code=CryOneDex.Ed25519N)
    assert prefixer.code == CryOneDex.Ed25519N
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # Test basic derivation from ked
    ked = dict(k=[verfer.qb64], n="",  t="icp")
    prefixer = Prefixer(ked=ked, code=CryOneDex.Ed25519)
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[verfer.qb64], n="",  t="icp")  #  ked without prefix
    with pytest.raises(EmptyMaterialError):  # no code and no pre in ked
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519)  # verfer code not match pre code
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=pre)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=CryOneDex.Ed25519N)  # verfer code not match code

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=pre)
    prefixer = Prefixer(ked=ked, code=CryOneDex.Ed25519N)  # verfer code match code but not pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    prefixer = Prefixer(ked=ked, code=CryOneDex.Ed25519N)  # verfer code match code and pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    prefixer = Prefixer(ked=ked)  # verfer code match pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp")
    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(ked=ked)

    ked = dict(k=[verfer.qb64], n="ABCD",  t="icp")
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=CryOneDex.Ed25519)

    # Test digest derivation from inception ked
    vs = Versify(version=Version, kind=Serials.json, size=0)
    sn = 0
    ilk = Ilks.icp
    sith = "1"
    keys = [Prefixer(raw=verkey, code=CryOneDex.Ed25519).qb64]
    nxt = ""
    toad = 0
    wits = []
    cnfg = []

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
    assert prefixer.qb64 == 'E_P7GKEdbet8OudlQvqILlGn7Fll5q6zfddiSXc-XY5Y'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with Nexter
    nexter = Nexter(sith="1", keys=[nxtfer.qb64])
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
    assert prefixer.qb64 == 'E7iQvEO7xsRE8UfBB0DCWnksY8ju-9madY3jJ1Y-eYPE'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with fractionally weighted sith
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]


    # create signers from secrets
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets
    # each signer has verfer for keys

    # Test with sith with one clause
    keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
    sith = [["1/2", "1/2", "1"]]
    nexter = Nexter(sith="1", keys=[signers[3].verfer.qb64])
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer1 = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
    assert prefixer1.qb64 == 'En6Ks1QPlek3GMHFTDlr-ufdZzQyHay_E2k5wTNB_MHM'
    assert prefixer1.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # now test with different sith but same weights in two clauses
    sith = [["1/2", "1/2"], ["1"]]
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer2 = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
    assert prefixer2.qb64 == 'EITG4HqxAlyOrQBYW9utR7W_iJmq4NmOI9IrPicZfK5E'
    assert prefixer2.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False
    assert prefixer2.qb64 !=  prefixer1.qb64  # semantic diff -> syntactic diff

    sith = "1"
    seal = dict(i='EkbeB57LYWRYNqg4xarckyfd_LsaH0J350WmOdvMwU_Q',
                s='2',
                t=Ilks.ixn,
                d='E03rxRmMcP2-I2Gd0sUhlYwjk8KEz5gNGxPwPg-sGJds')

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=Ilks.dip,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               da=seal
               )

    prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
    assert prefixer.qb64 == 'EZHlPj5b4zrbJgd72n2sg3v5GYlam_BiX7Sl58mPRP84'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    #  Test signature derivation

    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed =  (b'\xdf\x95\xf9\xbcK@s="\xee\x95w\xbf>F&\xbb\x82\x8f)\x95\xb9\xc0\x1eS\x1b{L'
             b't\xcfH\xa6')
    signer = Signer(raw=seed)
    secret = signer.qb64
    assert secret ==  'A35X5vEtAcz0i7pV3vz5GJruCjymVucAeUxt7THTPSKY'

    vs = Versify(version=Version, kind=Serials.json, size=0)
    sn = 0
    ilk = Ilks.icp
    sith = "1"
    keys = [signer.verfer.qb64]
    nxt = ""
    toad = 0
    wits = []
    cnfg = []

    nexter = Nexter(sith="1", keys=[nxtfer.qb64])
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=CryTwoDex.Ed25519_Sig, seed=seed)
    assert prefixer.qb64 == '0Bi8d8LQu1Uk6JjsQil1bSWfErSQnobDIHXZOfoLC-d4XNz2MOKFXKkCx2ODKOMuodDjWrkw4sG6jC5HOl-HCRCg'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    prefixer = Prefixer(ked=ked, code=CryTwoDex.Ed25519_Sig, secret=secret)
    assert prefixer.qb64 == '0Bi8d8LQu1Uk6JjsQil1bSWfErSQnobDIHXZOfoLC-d4XNz2MOKFXKkCx2ODKOMuodDjWrkw4sG6jC5HOl-HCRCg'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    """ Done Test """


def test_sigmat():
    """
    Test the support functionality for attached signature cryptographic material
    """
    with pytest.raises(EmptyMaterialError):
        sigmet = SigMat()

    assert SigTwoDex.Ed25519 ==  'A'  # Ed25519 signature.
    assert SigTwoDex.ECDSA_256k1 == 'B'  # ECDSA secp256k1 signature.

    assert SigTwoSizes[SigTwoDex.Ed25519] == 88
    assert SigTwoSizes[SigTwoDex.ECDSA_256k1] == 88

    cs = IntToB64(0)
    assert cs == "A"
    i = B64ToInt(cs)
    assert i == 0

    cs = IntToB64(27)
    assert cs == "b"
    i = B64ToInt(cs)
    assert i == 27

    cs = IntToB64(27, l=2)
    assert cs == "Ab"
    i = B64ToInt(cs)
    assert i == 27

    cs = IntToB64(80)
    assert cs == "BQ"
    i = B64ToInt(cs)
    assert i == 80

    cs = IntToB64(4095)
    assert cs == '__'
    i = B64ToInt(cs)
    assert i == 4095

    cs = IntToB64(4096)
    assert cs == 'BAA'
    i = B64ToInt(cs)
    assert i == 4096

    cs = IntToB64(6011)
    assert cs == "Bd7"
    i = B64ToInt(cs)
    assert i == 6011

    # Test attached signature code (empty raw)
    qsc = SigCntDex.Base64 + IntToB64(0, l=2)
    assert qsc == '-AAA'

    qscb = qsc.encode("utf-8")
    sigmat = SigMat(raw=b'', code=SigCntDex.Base64, index=0)
    assert sigmat.raw == b''
    assert sigmat.code == SigCntDex.Base64
    assert sigmat.index == 0
    assert sigmat.qb64 == qsc
    assert sigmat.qb64b == qscb
    assert sigmat.qb2 == b'\xf8\x00\x00'

    sigmat = SigMat(qb64b=qscb)
    assert sigmat.raw == b''
    assert sigmat.code == SigCntDex.Base64
    assert sigmat.index == 0
    assert sigmat.qb64 == qsc
    assert sigmat.qb64b == qscb
    assert sigmat.qb2 == b'\xf8\x00\x00'

    sigmat = SigMat(qb64=qsc)
    assert sigmat.raw == b''
    assert sigmat.code == SigCntDex.Base64
    assert sigmat.index == 0
    assert sigmat.qb64 == qsc
    assert sigmat.qb64b == qscb
    assert sigmat.qb2 == b'\xf8\x00\x00'

    sigmat = SigMat(qb64=qscb)  #  also works for bytes
    assert sigmat.raw == b''
    assert sigmat.code == SigCntDex.Base64
    assert sigmat.index == 0
    assert sigmat.qb64 == qsc
    assert sigmat.qb64b == qscb
    assert sigmat.qb2 == b'\xf8\x00\x00'

    idx = 5
    qsc = SigCntDex.Base64 + IntToB64(idx, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    sigmat = SigMat(raw=b'', code=SigCntDex.Base64, index=idx)
    assert sigmat.raw == b''
    assert sigmat.code == SigCntDex.Base64
    assert sigmat.index == 5
    assert sigmat.qb64 == qsc
    assert sigmat.qb64b == qscb
    assert sigmat.qb2 == b'\xf8\x00\x05'

    # Test signatures
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    sig64b = encodeB64(sig)
    sig64 = sig64b.decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")
    qbin = decodeB64(qsig64b)
    assert len(qbin) == 66
    assert qbin == (b'\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
                    b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
                    b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')


    sigmat = SigMat(raw=sig)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0
    assert sigmat.qb64 == qsig64
    assert sigmat.qb2 == qbin

    # test wrong size of raw
    longsig = sig + bytes([10, 11, 12])
    sigmat = SigMat(raw=longsig)

    shortsig = sig[:-3]
    with pytest.raises(ValidationError):
        sigmat = SigMat(raw=shortsig)

    sigmat = SigMat(qb64b=qsig64b)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0

    sigmat = SigMat(qb64=qsig64)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0

    sigmat = SigMat(qb64=qsig64b)  # test with bytes not str
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0

    # test wrong size of qb64
    longqsig64 = qsig64 + "ABCD"
    oksigmat = SigMat(qb64=longqsig64)
    assert len(oksigmat.qb64) == SigSizes[oksigmat.code]

    shortqsig64 = qsig64[:-4]  # too short
    with pytest.raises(ShortageError):
        oksigmat = SigMat(qb64=shortqsig64)

    sigmat = SigMat(qb64=qsig64.encode("utf-8"))  # test bytes not str
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.raw == sig
    assert sigmat.qb64 == qsig64
    assert sigmat.qb64b == qsig64.encode("utf-8")

    sigmat = SigMat(qb2=qbin)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0

    sigmat = SigMat(raw=sig, code=SigTwoDex.Ed25519, index=5)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 5
    qsig64 = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert sigmat.qb64 == qsig64
    qbin = (b'\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')
    assert sigmat.qb2 == qbin

    sigmat = SigMat(qb64=qsig64)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 5

    sigmat = SigMat(qb2=qbin)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 5
    """ Done Test """

def test_sigcounter():
    """
    Test SigCounter subclass of Sigmat
    """
    # with pytest.raises(EmptyMaterialError):
    #    counter = SigCounter()

    qsc = SigCntDex.Base64 + IntToB64(1, l=2)
    assert qsc == '-AAB'

    counter = SigCounter()
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = SigCounter(raw=b'')
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = SigCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == 1
    assert counter.count == 1
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = SigCounter(raw=b'', count=1)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == 1
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x01'

    counter = SigCounter(raw=b'', count=0)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == 0
    assert counter.qb64 == '-AAA'
    assert counter.qb2 == b'\xf8\x00\x00'


    cnt = 5
    qsc = SigCntDex.Base64 + IntToB64(cnt, l=2)
    assert qsc == '-AAF'
    counter = SigCounter(count=cnt)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == cnt
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x05'

    counter = SigCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base64
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x00\x05'

    cnt = 5
    qsc = SigCntDex.Base2 + IntToB64(cnt, l=2)
    assert qsc == '-BAF'
    counter = SigCounter(code=SigCntDex.Base2, count=cnt)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base2
    assert counter.index == cnt
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x10\x05'

    counter = SigCounter(qb64=qsc)
    assert counter.raw == b''
    assert counter.code == SigCntDex.Base2
    assert counter.index == cnt
    assert counter.count == cnt
    assert counter.qb64 == qsc
    assert counter.qb2 == b'\xf8\x10\x05'
    """ Done Test """


def test_siger():
    """
    Test Siger subclass of Sigmat
    """
    with pytest.raises(EmptyMaterialError):
        siger = Siger()

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = qsig64.encode("utf-8")
    assert qsig64b == b'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    siger = Siger(qb64b=qsig64b)
    assert siger.code == SigTwoDex.Ed25519
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64)
    assert siger.code == SigTwoDex.Ed25519
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None

    siger = Siger(qb64=qsig64b)  #  also bytes
    assert siger.code == SigTwoDex.Ed25519
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None

    verkey,  sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    siger.verfer = verfer
    assert  siger.verfer == verfer

    siger = Siger(qb64=qsig64, verfer=verfer)
    assert  siger.verfer == verfer
    """ Done Test """


def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """
    assert Version == Versionage(major=1, minor=0)

    assert isinstance(Serials, Serialage)

    assert Serials.json == 'JSON'
    assert Serials.mgpk == 'MGPK'
    assert Serials.cbor == 'CBOR'

    assert 'JSON' in Serials
    assert 'MGPK' in Serials
    assert 'CBOR' in Serials

    assert Mimes.json == 'application/keri+json'
    assert Mimes.mgpk == 'application/keri+msgpack'
    assert Mimes.cbor == 'application/keri+cbor'

    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'


    icp = dict(vs = Vstrings.json,
              pre = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'icp',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              nxt = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              wits = [],
              cnfg = [],
             )

    rot = dict(vs = Vstrings.json,
              pre = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'rot',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              nxt = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              cuts = [],
              adds = [],
              data = [],
             )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 303
    assert icps == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"cnfg":[]}')

    match = Rever.search(icps)
    assert match.group() == Vstrings.json.encode("utf-8")

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 313
    assert rots == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"'
                    b'data":[]}')

    match = Rever.search(rots)
    assert match.group() == Vstrings.json.encode("utf-8")

    icp["vs"] = Vstrings.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\x8b\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4cnfg\x90')


    match = Rever.search(icps)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    rot["vs"] = Vstrings.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\x8c\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90')



    match = Rever.search(rots)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    icp["vs"] = Vstrings.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\xabbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80dcnfg\x80')



    match = Rever.search(icps)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    rot["vs"] = Vstrings.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\xacbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80')

    match = Rever.search(rots)
    assert match.group() == Vstrings.cbor.encode("utf-8")
    """Done Test"""

def test_versify():
    """
    Test Versify support
    """
    vs = Versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.json, size=65)
    assert vs == "KERI10JSON000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 65

    vs = Versify(kind=Serials.mgpk, size=0)
    assert vs == "KERI10MGPK000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    vs = Versify(kind=Serials.cbor, size=0)
    assert vs == "KERI10CBOR000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.cbor
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.cbor, size=65)
    assert vs == "KERI10CBOR000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.cbor
    assert version == Version
    assert size == 65
    """End Test"""


def test_serder():
    """
    Test the support functionality for Serder key event serialization deserialization
    """
    with pytest.raises(ValueError):
        serder = Serder()

    e1 = dict(v=Vstrings.json,
              i="ABCDEFG",
              s="0001",
              t="rot")
    serder = Serder(ked=e1)
    assert serder.ked == e1
    assert serder.kind == Serials.json
    assert serder.version == Versionage(major=1, minor=0)
    assert serder.dig == 'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert serder.digb == b'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert serder.size == 60
    assert serder.verfers == []
    assert serder.raw == b'{"v":"KERI10JSON00003c_","i":"ABCDEFG","s":"0001","t":"rot"}'
    assert serder.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert e1s == b'{"v":"KERI10JSON00003c_","i":"ABCDEFG","s":"0001","t":"rot"}'
    vs = Versify(kind=Serials.json, size=len(e1s))  # use real length
    assert vs == 'KERI10JSON00003c_'
    e1["v"] = vs  # has real length

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(ShortageError):  # test too short
        kind1, vers1, size1 = serder._sniff(e1s[:VERFULLSIZE])

    kind1, vers1, size1 = serder._sniff(e1s[:MINSNIFFSIZE])
    assert kind1 == Serials.json
    assert size1 == 60

    kind1, vers1, size1 = serder._sniff(e1s)
    assert kind1 == Serials.json
    assert size1 == 60
    e1ss = e1s + b'extra attached at the end.'
    ked1, knd1, vrs1, siz1 = serder._inhale(e1ss)
    assert ked1 == e1
    assert knd1 == kind1
    assert vrs1 == vers1
    assert siz1 == size1

    with pytest.raises(ShortageError):  # test too short
        ked1, knd1, vrs1, siz1 = serder._inhale(e1ss[:size1-1])

    raw1, knd1, ked1, ver1 = serder._exhale(ked=e1)
    assert raw1 == e1s
    assert knd1 == kind1
    assert ked1 == e1
    assert vrs1 == vers1

    e2 = dict(e1)
    e2["v"] = Vstrings.mgpk
    e2s = msgpack.dumps(e2)
    assert e2s == b'\x84\xa1v\xb1KERI10MGPK000000_\xa1i\xa7ABCDEFG\xa1s\xa40001\xa1t\xa3rot'
    vs = Versify(kind=Serials.mgpk, size=len(e2s))  # use real length
    assert vs == 'KERI10MGPK00002c_'
    e2["v"] = vs  # has real length
    e2s = msgpack.dumps(e2)

    with pytest.raises(ShortageError):  # test too short
        kind2, vers2, size2 = serder._sniff(e2s[:VERFULLSIZE])

    kind2, vers2, size2 = serder._sniff(e2s[:MINSNIFFSIZE])
    assert kind2 == Serials.mgpk
    assert size2 == 44

    kind2, vers2, size2 = serder._sniff(e2s)
    assert kind2 == Serials.mgpk
    assert size2 == 44
    e2ss = e2s + b'extra attached  at the end.'
    ked2, knd2, vrs2, siz2 = serder._inhale(e2ss)
    assert ked2 == e2
    assert knd2 == kind2
    assert vrs2 == vers2
    assert siz2 == size2

    with pytest.raises(ShortageError):  # test too short
        ked2, knd2, vrs2, siz2 = serder._inhale(e2ss[:size2-1])

    raw2, knd2, ked2, ver2 = serder._exhale(ked=e2)
    assert raw2 == e2s
    assert knd2 == kind2
    assert ked2 == e2
    assert vrs2 == vers2

    e3 = dict(e1)
    e3["v"] = Vstrings.cbor
    e3s = cbor.dumps(e3)
    assert e3s == b'\xa4avqKERI10CBOR000000_aigABCDEFGasd0001atcrot'
    vs = Versify(kind=Serials.cbor, size=len(e3s))  # use real length
    assert vs == 'KERI10CBOR00002c_'
    e3["v"] = vs  # has real length
    e3s = cbor.dumps(e3)

    with pytest.raises(ShortageError):  # test too short
        kind3, vers3, size3 = serder._sniff(e3s[:VERFULLSIZE])

    kind3, vers3, size3 = serder._sniff(e3s[:MINSNIFFSIZE])
    assert kind3 == Serials.cbor
    assert size3 == 44

    kind3, vers3, size3 = serder._sniff(e3s)
    assert kind3 == Serials.cbor
    assert size3 == 44
    e3ss = e3s + b'extra attached  at the end.'
    ked3, knd3, vrs3, siz3 = serder._inhale(e3ss)
    assert ked3 == e3
    assert knd3 == kind3
    assert vrs3 == vers3
    assert siz3 == size3

    with pytest.raises(ShortageError):  # test too short
        ked3, knd3, vrs3, siz3 = serder._inhale(e3ss[:size3-1])

    raw3, knd3, ked3, ver3 = serder._exhale(ked=e3)
    assert raw3 == e3s
    assert knd3 == kind3
    assert ked3 == e3
    assert vrs3 == vers3

    evt1 = Serder(raw=e1ss)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    # test digest properties .diger and .dig
    assert evt1.diger.qb64 == evt1.dig
    assert evt1.diger.code == CryOneDex.Blake3_256
    assert len(evt1.diger.raw) == 32
    assert len(evt1.dig) == 44
    assert len(evt1.dig) == CryOneSizes[CryOneDex.Blake3_256]
    assert evt1.dig == 'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert evt1.diger.verify(evt1.raw)

    evt1 = Serder(ked=ked1)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.diger.code == CryOneDex.Blake3_256
    assert serder.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    evt2 = Serder(raw=e2ss)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2
    assert evt2.version == vers2

    evt2 = Serder(ked=ked2)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2
    assert evt2.size == size2
    assert evt2.raw == e2ss[:size2]
    assert evt2.version == vers2

    evt3 = Serder(raw=e3ss)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3
    assert evt3.version == vers3

    evt3 = Serder(ked=ked3)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3
    assert evt3.size == size3
    assert evt3.raw == e3ss[:size3]
    assert evt3.version == vers3

    #  round trip
    evt2 = Serder(ked=evt1.ked)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2

    # Test change in kind by Serder
    evt1 = Serder(ked=ked1, kind=Serials.mgpk)  # ked is json but kind mgpk
    assert evt1.kind == kind2
    assert evt1.raw == e2s
    assert evt1.ked == ked2
    assert evt1.size == size2
    assert evt1.raw == e2ss[:size2]
    assert evt1.version == vers1
    assert evt1.dig == 'EbUOh76KAyZRbHsi9_uixhnX3zkcmN2bkIh-enCOmPRU'
    assert evt1.diger.verify(evt1.raw)

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2


    evt1 = Serder(ked=ked1, kind=Serials.cbor)  # ked is json but kind mgpk
    assert evt1.kind == kind3
    assert evt1.raw == e3s
    assert evt1.ked == ked3
    assert evt1.size == size3
    assert evt1.raw == e3ss[:size3]
    assert evt1.version == vers1

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2

    # use kind setter property
    assert evt2.kind == Serials.cbor
    evt2.kind = Serials.json
    assert evt2.kind == Serials.json
    knd, version, size = Deversify(evt2.ked["v"])
    assert knd == Serials.json

    #  Test diger code
    ked = {'vs': 'KERI10JSON000042_', 'pre': 'ABCDEFG', 'sn': '0001', 'ilk': 'rot'}
    raw = b'{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}'
    srdr = Serder(raw=raw, code=CryOneDex.SHA3_256)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.diger.code == CryOneDex.SHA3_256

    #  Test compare
    ked = {'vs': 'KERI10JSON000042_', 'pre': 'ABCDEFG', 'sn': '0001', 'ilk': 'rot'}
    raw = b'{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}'
    srdr = Serder(raw=raw)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.diger.code == CryOneDex.Blake3_256

    diger0 = Diger(ser=srdr.raw) # default code
    diger1 = Diger(ser=srdr.raw, code=CryOneDex.SHA3_256)
    diger2 = Diger(ser=srdr.raw, code=CryOneDex.Blake2b_256)

    # test Serder.compare
    assert srdr.compare(diger=diger0)
    assert srdr.compare(diger=diger1)
    assert srdr.compare(diger=diger2)

    assert srdr.compare(dig=diger0.qb64)
    assert srdr.compare(dig=diger1.qb64b)
    assert srdr.compare(dig=diger2.qb64)

    ser1 = b'ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789'

    assert not srdr.compare(diger=Diger(ser=ser1))  # codes match
    assert not srdr.compare(dig=Diger(ser=ser1).qb64)  # codes match
    assert not srdr.compare(diger=Diger(ser=ser1, code=CryOneDex.SHA3_256)) # codes not match
    assert not srdr.compare(dig=Diger(ser=ser1, code=CryOneDex.SHA2_256).qb64b)     # codes not match
    """Done Test """


def test_tholder():
    """
    Test Tholder signing threshold satisfier class
    """

    with pytest.raises(ValueError):
        tholder = Tholder()

    tholder = Tholder(sith="b")
    assert tholder.sith == "b"
    assert tholder.thold == 11
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))
    assert tholder.limen == "b"


    with pytest.raises(ValueError):
        tholder = Tholder(sith=0)

    with pytest.raises(ValueError):
        tholder = Tholder(sith="0")

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=["1/3", "1/2", []])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=["1/3", "1/2"])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[[], []])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[["1/3", "1/2"], ["1"]])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[["1/3", "1/2"], []])

    with pytest.raises(TypeError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], [[], "1"]])

    tholder = Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4"])
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)]]
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4'
    assert tholder.satisfy(indices=[0, 2, 4])
    assert tholder.satisfy(indices=[0, 1])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])

    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"]])
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"]]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)]]
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4'
    assert tholder.satisfy(indices=[1, 2, 3])
    assert tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 4, 4])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])


    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]])
    assert tholder.sith ==  [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)],
                           [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4&1,1'
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])


    """ Done Test """


def test_matter():
    """
    Test Matter class
    """
    assert dataclasses.asdict(MtrDex) == {
                                            'Ed25519_Seed': 'A',
                                            'Ed25519N': 'B',
                                            'X25519': 'C',
                                            'Ed25519': 'D',
                                            'Blake3_256': 'E',
                                            'Blake2b_256': 'F',
                                            'Blake2s_256': 'G',
                                            'SHA3_256': 'H',
                                            'SHA2_256': 'I',
                                            'ECDSA_256k1_Seed': 'J',
                                            'Ed448_Seed': 'K',
                                            'X448': 'L',
                                            'ShortTag': 'M',
                                            'Salt_128': '0A',
                                            'Ed25519_Sig': '0B',
                                            'ECDSA_256k1_Sig': '0C',
                                            'Blake3_512': '0D',
                                            'Blake2b_512': '0E',
                                            'SHA3_512': '0F',
                                            'SHA2_512': '0G',
                                            'LongTag': '0H',
                                            'ECDSA_256k1N': '1AAA',
                                            'ECDSA_256k1': '1AAB',
                                            'Ed448N': '1AAC',
                                            'Ed448': '1AAD',
                                            'Ed448_Sig': '1AAE'
                                         }

    assert Matter.Codex == MtrDex

    # first character of code with hard size of code
    assert Matter.Sizes == {
        'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
        'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1 ,'Q': 1, 'R': 1,
        'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
        'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
        'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
        's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
        '0': 2, '1': 4, '2': 5, '3': 6, '4': 8, '5': 9, '6': 10
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Matter.Codes == {
                            'A': Sizage(hs=1, ss=0, fs=44),
                            'B': Sizage(hs=1, ss=0, fs=44),
                            'C': Sizage(hs=1, ss=0, fs=44),
                            'D': Sizage(hs=1, ss=0, fs=44),
                            'E': Sizage(hs=1, ss=0, fs=44),
                            'F': Sizage(hs=1, ss=0, fs=44),
                            'G': Sizage(hs=1, ss=0, fs=44),
                            'H': Sizage(hs=1, ss=0, fs=44),
                            'I': Sizage(hs=1, ss=0, fs=44),
                            'J': Sizage(hs=1, ss=0, fs=44),
                            'K': Sizage(hs=1, ss=0, fs=76),
                            'L': Sizage(hs=1, ss=0, fs=76),
                            'M': Sizage(hs=1, ss=0, fs=4),
                            '0A': Sizage(hs=2, ss=0, fs=24),
                            '0B': Sizage(hs=2, ss=0, fs=88),
                            '0C': Sizage(hs=2, ss=0, fs=88),
                            '0D': Sizage(hs=2, ss=0, fs=88),
                            '0E': Sizage(hs=2, ss=0, fs=88),
                            '0F': Sizage(hs=2, ss=0, fs=88),
                            '0G': Sizage(hs=2, ss=0, fs=88),
                            '0H': Sizage(hs=2, ss=0, fs=8),
                            '1AAA': Sizage(hs=4, ss=0, fs=48),
                            '1AAB': Sizage(hs=4, ss=0, fs=48),
                            '1AAC': Sizage(hs=4, ss=0, fs=80),
                            '1AAD': Sizage(hs=4, ss=0, fs=80),
                            '1AAE': Sizage(hs=4, ss=0, fs=56)
                        }

    assert Matter.Codes['A'].hs == 1  # hard size
    assert Matter.Codes['A'].ss == 0  # soft size
    assert Matter.Codes['A'].fs == 44  # full size


    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'  #  str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
              b'IS\xf3\x874\xbao\x90\x8c')  # pure base 2 binary qb2

    with pytest.raises(EmptyMaterialError):
        matter = Matter()

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code='')

    matter = Matter(raw=verkey)
    assert matter.raw == verkey
    assert matter.code == MtrDex.Ed25519N
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64b=prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64=prefix)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64=prefixb)  #  works for either
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # test truncates extra bytes from qb64 parameter
    longprefix = prefix + "ABCD"  # extra bytes in size
    matter = Matter(qb64=longprefix)
    assert len(matter.qb64) == Matter.Codes[matter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortprefix = prefix[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        matter = Matter(qb64=shortprefix)

    matter = Matter(qb2=prebin)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64=prefix.encode("utf-8"))  # test bytes not str
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb64b == prefix.encode("utf-8")

    # test truncates extra bytes from raw parameter
    longverkey = verkey + bytes([10, 11, 12])  # extra bytes
    matter = Matter(raw=longverkey)

    # test raises ShortageError if not enough bytes in raw parameter
    shortverkey =  verkey[:-3]  # not enough bytes
    with pytest.raises(ValidationError):
        matter = Matter(raw=shortverkey)

    # test prefix on full identifier
    full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64=full)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin

    # test nongreedy prefixb on full identifier
    full = prefixb + b":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64b=full)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64b = encodeB64(sig)
    assert sig64b == b'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='
    sig64 =  sig64b.decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = b'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsigB2 = (b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    matter = Matter(raw=sig, code=MtrDex.Ed25519_Sig)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True

    matter = Matter(qb64b=qsig64b)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig

    matter = Matter(qb64=qsig64)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig

    qsig64b  = qsig64.encode("utf-8")  #  test bytes input
    matter = Matter(qb64=qsig64b)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig

    matter = Matter(qb2=qsigB2)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig

    """ Done Test """

def test_b64_conversions():
    """
    Test Base64 index and count conversion utility routines
    """

    cs = IntToB64(0)
    assert cs == "A"
    i = B64ToInt(cs)
    assert i == 0

    cs = IntToB64(27)
    assert cs == "b"
    i = B64ToInt(cs)
    assert i == 27

    cs = IntToB64(27, l=2)
    assert cs == "Ab"
    i = B64ToInt(cs)
    assert i == 27

    cs = IntToB64(80)
    assert cs == "BQ"
    i = B64ToInt(cs)
    assert i == 80

    cs = IntToB64(4095)
    assert cs == '__'
    i = B64ToInt(cs)
    assert i == 4095

    cs = IntToB64(4096)
    assert cs == 'BAA'
    i = B64ToInt(cs)
    assert i == 4096

    cs = IntToB64(6011)
    assert cs == "Bd7"
    i = B64ToInt(cs)
    assert i == 6011

    """End Test"""


def test_indexer():
    """
    Test Indexer class
    """
    assert dataclasses.asdict(IdrDex) == {
                                           'Ed25519_Sig': 'A',
                                           'ECDSA_256k1_Sig': 'B',
                                           'Ed448_Sig': '0A',
                                           'Label': '0B'
                                         }


    assert IdrDex.Ed25519_Sig ==  'A'  # Ed25519 signature.
    assert IdrDex.ECDSA_256k1_Sig == 'B'  # ECDSA secp256k1 signature.

    assert Indexer.Codex == IdrDex

    # first character of code with hard size of code
    assert Indexer.Sizes == {
       'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
       'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
       'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
       'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
       'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
       's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
       '0': 2, '1': 2, '2': 2, '3': 2, '4': 3, '5': 4
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Indexer.Codes == {
                                'A': Sizage(hs=1, ss=1, fs=88),
                                'B': Sizage(hs=1, ss=1, fs=88),
                                '0A': Sizage(hs=2, ss=2, fs=156),
                                '0B': Sizage(hs=2, ss=2, fs=None)
                            }

    assert Indexer.Codes['A'].hs == 1  # hard size
    assert Indexer.Codes['A'].ss == 1  # soft size
    assert Indexer.Codes['A'].fs == 88  # full size

    with pytest.raises(EmptyMaterialError):
        indexer = Indexer()

    # Test signatures
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    sig64b = encodeB64(sig)
    sig64 = sig64b.decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    # replace pad "==" with code "AA"
    qsc = IdrDex.Ed25519_Sig + IntToB64(0, l=1)
    assert qsc == 'AA'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[:-2]
    assert qsig64 == 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    assert qsig2b == (b'\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
                    b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
                    b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')


    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb2 == qsig2b

    # test wrong size of raw
    longsig = sig + bytes([10, 11, 12])
    indexer = Indexer(raw=longsig)

    shortsig = sig[:-3]
    with pytest.raises(ValidationError):
        indexer = Indexer(raw=shortsig)

    indexer = Indexer(qb64b=qsig64b)  # test with bytes not str
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)  # test with str not bytes
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test truncates extra bytes from qb64 parameter
    longqsig64 = qsig64 + "ABCD"
    indexer = Indexer(qb64=longqsig64)
    assert len(indexer.qb64) == Indexer.Codes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsig64 = qsig64[:-4]  # too short
    with pytest.raises(ShortageError):
        indexer = Indexer(qb64=shortqsig64)

    indexer = Indexer(qb2=qsig2b)  #  test with qb2
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test with non-zero index=5
    # replace pad "==" with code "AF"
    qsc = IdrDex.Ed25519_Sig + IntToB64(5, l=1)
    assert qsc == 'AF'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[:-2]
    assert qsig64 == 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = (b'\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b


    indexer = Indexer(qb2=qsig2b)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    #  Label Code (variable length)
    # last character must be A which is all zeros otherwise will not round trip
    label = b'Hello_World_Peep'
    index = len(label) // 4
    assert index == 4
    lraw = decodeB64(label)
    assert len(lraw) == len(label) * 3 // 4
    assert lraw == b'\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'
    ltext = encodeB64(lraw)
    assert ltext == b'Hello_World_Peep' == label
    qsc = IdrDex.Label + IntToB64(index, l=2)
    assert qsc == '0BAE'
    qscb = qsc.encode("utf-8")
    lq64b = qscb + label
    assert lq64b == b"0BAEHello_World_Peep"
    lq64 = lq64b.decode("utf-8")

    indexer = Indexer(raw=lraw, code=IdrDex.Label, index=index)
    assert indexer.raw == lraw
    assert indexer.code == IdrDex.Label
    assert indexer.index == index
    assert indexer.qb64b == lq64b
    assert indexer.qb64 == lq64
    assert indexer.qb2 == b'\xd0\x10\x04\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'




    """ Done Test """



if __name__ == "__main__":
    test_indexer()
