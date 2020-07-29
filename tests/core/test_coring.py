# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import pytest

import pysodium
import blake3
import json

import msgpack
import cbor2 as cbor

from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

from keri.kering import Version, Versionage
from keri.kering import ValidationError, EmptyMaterialError, DerivationError
from keri.core.coring import CrySelDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import CryOneSizes, CryOneRawSizes, CryTwoSizes, CryTwoRawSizes
from keri.core.coring import CryFourSizes, CryFourRawSizes, CrySizes, CryRawSizes
from keri.core.coring import CryMat, Verfer, Signer, Digester, Nexter, Aider
from keri.core.coring import SigSelDex, SigTwoDex, SigTwoSizes, SigTwoRawSizes
from keri.core.coring import SigFourDex, SigFourSizes, SigFourRawSizes
from keri.core.coring import SigFiveDex, SigFiveSizes, SigFiveRawSizes
from keri.core.coring import SigSizes, SigRawSizes
from keri.core.coring import IntToB64, B64ToInt
from keri.core.coring import SigMat
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever
from keri.core.coring import Serder
from keri.core.coring import Ilkage, Ilks



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
    assert CryOneDex.ECDSA_secp256k1_Seed == 'J'
    assert CryOneDex.Ed448_Seed == 'K'
    assert CryOneDex.X448 == 'L'

    assert '0' not in CryOneDex

    for x in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',  'L']:
        assert x in CryOneDex
        assert x in CryOneSizes
        assert x in CryOneRawSizes

    assert CryTwoDex.Seed_128 == '0A'
    assert CryTwoDex.Ed25519 == '0B'
    assert CryTwoDex.ECDSA_256k1 == '0C'

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
    """Done Test"""

def test_crymat():
    """
    Test the support functionality for cryptographic material
    """
    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
    prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
              b'IS\xf3\x874\xbao\x90\x8c')

    with pytest.raises(EmptyMaterialError):
        crymat = CryMat()

    crymat = CryMat(raw=verkey)
    assert crymat.raw == verkey
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    assert crymat.qb64 == encodeB64(crymat.qb2).decode("utf-8")
    assert crymat.qb2 == decodeB64(crymat.qb64.encode("utf-8"))

    crymat._exfil(prefix)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    # test wrong size of qb64
    longprefix = prefix + "ABCD"
    okcrymat = CryMat(qb64=longprefix)
    assert len(okcrymat.qb64) == CrySizes[okcrymat.code]

    shortprefix = prefix[:-4]
    with pytest.raises(ValidationError):
        okcrymat = CryMat(qb64=shortprefix)

    crymat = CryMat(qb2=prebin)
    assert crymat.code == CryOneDex.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix.encode("utf-8"))  # test auto convert bytes to str
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

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64 = encodeB64(sig).decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qbin = (b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    crymat = CryMat(raw=sig, code=CryTwoDex.Ed25519)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519
    assert crymat.qb64 == qsig64
    assert crymat.qb2 == qbin

    crymat = CryMat(qb64=qsig64)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519

    crymat = CryMat(qb2=qbin)
    assert crymat.raw == sig
    assert crymat.code == CryTwoDex.Ed25519

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

    cs = IntToB64(80)
    assert cs ==  "BQ"
    i = B64ToInt(cs)
    assert i ==  80

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    sig64 = encodeB64(sig).decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qbin = decodeB64(qsig64.encode("utf-8"))
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

    sigmat = SigMat(qb64=qsig64)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwoDex.Ed25519
    assert sigmat.index == 0

    # test wrong size of qb64
    longqsig64 = qsig64 + "ABCD"
    oksigmat = SigMat(qb64=longqsig64)
    assert len(oksigmat.qb64) == SigSizes[oksigmat.code]

    shortqsig64 = qsig64[:-4]
    with pytest.raises(ValidationError):
        oksigmat = SigMat(qb64=shortqsig64)

    sigmat = SigMat(qb64=qsig64.encode("utf-8"))  # test auto convert bytes to str
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


def test_sigter():
    """
    Test Sigter subclass of SigMat
    """
    with pytest.raises(EmptyMaterialError):
        sigter = Sigter()

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    sigter = SigMat(qb64=qsig64)
    assert sigter.code == SigTwoDex.Ed25519
    assert sigter.index == 0
    assert sigter.qb64 == qsig64
    assert sigter.verfer == None

    verkey,  sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    sigter.verfer = verfer
    assert  sigter.verfer == verfer

    sigter = SigMat(qb64=qsig64, verfer=verfer)
    assert  sigter.verfer == verfer
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
              id = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'icp',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              next = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              wits = [],
              conf = [],
              idxs = [0]
             )

    rot = dict(vs = Vstrings.json,
              id = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'rot',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              next = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              cuts = [],
              adds = [],
              data = [],
              idxs = [0]
             )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 314
    assert icps == (b'{"vs":"KERI10JSON000000_","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"conf":[],"'
                    b'idxs":[0]}')

    match = Rever.search(icps)
    assert match.group() == Vstrings.json.encode("utf-8")

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 324
    assert rots == (b'{"vs":"KERI10JSON000000_","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"'
                    b'data":[],"idxs":[0]}')

    match = Rever.search(rots)
    assert match.group() == Vstrings.json.encode("utf-8")

    icp["vs"] = Vstrings.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 271
    assert icps == (b'\x8c\xa2vs\xb1KERI10MGPK000000_\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS'
                    b'VPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ'
                    b'-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH'
                    b'3ULvYAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4conf\x90\xa4idxs\x91\x00')

    match = Rever.search(icps)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    rot["vs"] = Vstrings.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 277
    assert rots == (b'\x8d\xa2vs\xb1KERI10MGPK000000_\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS'
                    b'VPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ'
                    b'-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH'
                    b'3ULvYAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90\xa4idxs\x91\x00')

    match = Rever.search(rots)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    icp["vs"] = Vstrings.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 271
    assert icps == (b'\xacbvsqKERI10CBOR000000_bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMb'
                    b'snd0001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01d'
                    b'keys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80dconf\x80didxs\x81\x00')

    match = Rever.search(icps)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    rot["vs"] = Vstrings.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 277
    assert rots == (b'\xadbvsqKERI10CBOR000000_bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMb'
                    b'snd0001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01d'
                    b'keys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80didxs\x81'
                    b'\x00')

    match = Rever.search(rots)
    assert match.group() == Vstrings.cbor.encode("utf-8")
    """Done Test"""

def test_serder():
    """
    Test the support functionality for Serder key event serialization deserialization
    """
    vs = Versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    with pytest.raises(ValueError):
        serder = Serder()


    e1 = dict(vs=Vstrings.json, id="ABCDEFG", sn="0001", ilk="rot")
    serder = Serder(ked=e1)

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    vs = Versify(kind=Serials.json, size=len(e1s))  # use real length
    assert vs == 'KERI10JSON000041_'
    e1["vs"] = vs  # has real length
    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    kind1, vers1, size1 = serder._sniff(e1s)
    assert kind1 == Serials.json
    assert size1 == 65
    e1ss = e1s + b'extra attached at the end.'
    ked1, knd1, vrs1, siz1 = serder._inhale(e1ss)
    assert ked1 == e1
    assert knd1 == kind1
    assert vrs1 == vers1
    assert siz1 == size1

    raw1, knd1, ked1, ver1 = serder._exhale(ked=e1)
    assert raw1 == e1s
    assert knd1 == kind1
    assert ked1 == e1
    assert vrs1 == vers1

    e2 = dict(e1)
    e2["vs"] = Vstrings.mgpk
    e2s = msgpack.dumps(e2)
    vs = Versify(kind=Serials.mgpk, size=len(e2s))  # use real length
    assert vs == 'KERI10MGPK000031_'
    e2["vs"] = vs  # has real length
    e2s = msgpack.dumps(e2)
    kind2, vers2, size2 = serder._sniff(e2s)
    assert kind2 == Serials.mgpk
    assert size2 == 49
    e2ss = e2s + b'extra attached  at the end.'
    ked2, knd2, vrs2, siz2 = serder._inhale(e2ss)
    assert ked2 == e2
    assert knd2 == kind2
    assert vrs2 == vers2
    assert siz2 == size2

    raw2, knd2, ked2, ver2 = serder._exhale(ked=e2)
    assert raw2 == e2s
    assert knd2 == kind2
    assert ked2 == e2
    assert vrs2 == vers2

    e3 = dict(e1)
    e3["vs"] = Vstrings.cbor
    e3s = cbor.dumps(e3)
    vs = Versify(kind=Serials.cbor, size=len(e3s))  # use real length
    assert vs == 'KERI10CBOR000031_'
    e3["vs"] = vs  # has real length
    e3s = cbor.dumps(e3)
    kind3, vers3, size3 = serder._sniff(e3s)
    assert kind3 == Serials.cbor
    assert size3 == 49
    e3ss = e3s + b'extra attached  at the end.'
    ked3, knd3, vrs3, siz3 = serder._inhale(e3ss)
    assert ked3 == e3
    assert knd3 == kind3
    assert vrs3 == vers3
    assert siz3 == size3

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

    # test digest properties .digmat and .dig
    assert evt1.digmat.qb64 == evt1.dig
    assert evt1.digmat.code == CryOneDex.Blake3_256
    assert len(evt1.digmat.raw) == 32
    assert len(evt1.dig) == 44
    assert len(evt1.dig) == CryOneSizes[CryOneDex.Blake3_256]
    assert evt1.dig == 'EB_Qy67YQkcSWmCcZo_3RaoTUQwWGoggAwHlG_0rpmQo'

    evt1 = Serder(ked=ked1)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1

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
    knd, version, size = Deversify(evt2.ked['vs'])
    assert knd == Serials.json
    """Done Test """

def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt')

    assert isinstance(Ilks, Ilkage)

    assert Ilks.icp == 'icp'
    assert Ilks.rot == 'rot'
    assert Ilks.ixn == 'ixn'
    assert Ilks.dip == 'dip'
    assert Ilks.drt == 'drt'

    assert 'icp' in Ilks
    assert 'rot' in Ilks
    assert 'ixn' in Ilks
    assert 'dip' in Ilks
    assert 'drt' in Ilks


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
    assert crymat.code == CryTwoDex.Ed25519
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
    assert crymat.code == CryTwoDex.Ed25519
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
    assert crymat.code == CryTwoDex.Ed25519
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

    with pytest.raises(ValueError):
        signer = Signer(raw=seed, code=CryOneDex.Ed25519N)

    with pytest.raises(ValueError):
        signer = Signer(code=CryOneDex.Ed25519N)
    """ Done Test """

def test_digester():
    """
    Test the support functionality for Digester subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        digester = Digester()

    #create something to digest and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
    dig = blake3.blake3(ser).digest()

    digester = Digester(raw=dig)  # defaults provide Blake3_256 digester
    assert digester.code == CryOneDex.Blake3_256
    assert len(digester.raw) == CryOneRawSizes[digester.code]
    result = digester.verify(ser=ser)
    assert result == True
    result = digester.verify(ser=ser+b'ABCDEF')
    assert result == False

    digester = Digester(raw=dig, code=CryOneDex.Blake3_256)
    assert digester.code == CryOneDex.Blake3_256
    assert len(digester.raw) == CryOneRawSizes[digester.code]
    result = digester.verify(ser=ser)
    assert result == True

    with pytest.raises(ValueError):
        digester = Digester(raw=dig, code=CryOneDex.Ed25519)

    digester = Digester(ser=ser)
    assert digester.code == CryOneDex.Blake3_256
    assert len(digester.raw) == CryOneRawSizes[digester.code]
    result = digester.verify(ser=ser)
    assert result == True

    with pytest.raises(ValueError):
        digester = Digester(ser=ser, code=CryOneDex.Ed25519)
    """ Done Test """

def test_nexter():
    """
    Test the support functionality for Nexter subclass of Digester
    """
    with pytest.raises(EmptyMaterialError):
        nexter = Nexter()

    #create something to digest and verify
    verkey, sigkey = pysodium.crypto_sign_keypair()
    verkey = (b'\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0='
              b'`\xf7\xbf\x8a\x18\x8a`q')
    verfer = Verfer(raw=verkey)
    assert verfer.qb64 == 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
    sith = "{:x}".format(1)
    keys = [verfer.qb64]
    ser = (sith + verfer.qb64).encode("utf-8")

    nexter = Nexter(ser=ser)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter.verify(ser=ser)
    assert nexter.verify(ser=ser+b'ABCDEF') == False

    with pytest.raises(ValueError):  # bad code
        nexter = Nexter(ser=ser, code=CryOneDex.Ed25519)

    nexter = Nexter(sith=sith, keys=keys)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter._derive(sith=sith, keys=keys) == ser
    assert nexter.verify(ser=ser)
    assert nexter.verify(ser=ser+b'ABCDEF') == False
    assert nexter.verify(sith=sith, keys=keys)

    with pytest.raises(EmptyMaterialError):
        nexter = Nexter(sith=sith)

    with pytest.raises(EmptyMaterialError):
        nexter = Nexter(keys=keys)

    nexter = Nexter(sith=1, keys=keys)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter._derive(sith=sith, keys=keys) == ser
    assert nexter.verify(ser=ser)
    assert nexter.verify(ser=ser+b'ABCDEF') == False
    assert nexter.verify(sith=1, keys=keys)

    ked = dict(sith=sith, keys=keys)  #  subsequent event
    nexter = Nexter(ked=ked)  # defaults provide Blake3_256 digester
    assert nexter.code == CryOneDex.Blake3_256
    assert len(nexter.raw) == CryOneRawSizes[nexter.code]
    assert nexter._derive(ked=ked) == ser
    assert nexter.verify(ser=ser)
    assert nexter.verify(ser=ser+b'ABCDEF') == False
    assert nexter.verify(ked=ked)
    """ Done Test """


def test_aider():
    """
    Test the support functionality for aider subclass of crymat
    """
    with pytest.raises(EmptyMaterialError):
        aider = Aider()

    verkey,  sigkey = pysodium.crypto_sign_keypair()

    with pytest.raises(ValueError):
        aider = Aider(raw=verkey, code=CryOneDex.Blake3_256)

    aider = Aider(raw=verkey)  # defaults provide Ed25519N aider
    assert aider.code == CryOneDex.Ed25519N
    assert len(aider.raw) == CryOneRawSizes[aider.code]
    assert len(aider.qb64) == CryOneSizes[aider.code]

    ked = dict(keys=[aider.qb64], next="")
    assert aider.verify(ked=ked) == True

    ked = dict(keys=[aider.qb64], next="ABC")
    assert aider.verify(ked=ked) == False

    aider = Aider(raw=verkey, code=CryOneDex.Ed25519)  # defaults provide Ed25519N aider
    assert aider.code == CryOneDex.Ed25519
    assert len(aider.raw) == CryOneRawSizes[aider.code]
    assert len(aider.qb64) == CryOneSizes[aider.code]

    ked = dict(keys=[aider.qb64])
    assert aider.verify(ked=ked) == True

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519)
    aider = Aider(raw=verfer.raw)
    assert aider.code == CryOneDex.Ed25519N
    assert aider.verify(ked=ked) == False

    # derive from ked
    ked = dict(keys=[verfer.qb64], next="")
    aider = Aider(ked=ked)
    assert aider.qb64 == verfer.qb64
    assert aider.verify(ked=ked) == True

    verfer = Verfer(raw=verkey, code=CryOneDex.Ed25519N)
    ked = dict(keys=[verfer.qb64], next="")
    aider = Aider(ked=ked)
    assert aider.qb64 == verfer.qb64
    assert aider.verify(ked=ked) == True

    ked = dict(keys=[verfer.qb64], next="ABCD")
    with pytest.raises(DerivationError):
        aider = Aider(ked=ked)
    """ Done Test """


if __name__ == "__main__":
    test_aider()
