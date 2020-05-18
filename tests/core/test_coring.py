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

from keri.kering import VERSION
from keri.core.coring import Select, One, Two, Four, CryMat
from keri.core.coring import Serializations,  Serials, Mimes, Versions, Sniffs
from keri.core.coring import KeyEventer


def test_derivationcodes():
    """
    Test the support functionality for derivation codes
    """
    assert Select.two == '0'

    assert 'A' not in Select

    for x in ['0']:
        assert x in Select

    assert One.Ed25519N == 'A'
    assert One.X25519 == 'B'
    assert One.Ed25519 == 'C'
    assert One.Blake3_256 == 'D'
    assert One.Blake2b_256 == 'E'
    assert One.Blake2s_256 == 'F'
    assert One.ECDSA_256k1N == 'G'
    assert One.ECDSA_256k1 == 'H'
    assert One.SHA3_256 == 'I'
    assert One.SHA2_256 == 'J'

    assert '0' not in One

    for x in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']:
        assert x in One

    assert Two.Ed25519 == '0A'
    assert Two.ECDSA_256k1 == '0B'

    assert 'A' not in Two

    for x in ['0A', '0B']:
        assert x in Two

    assert '0' not in Four
    assert 'A' not in Four
    assert '0A' not in Four

    for x in []:
        assert x in Four


    """
    Done Test
    """

def test_crymat():
    """
    Test the support functionality for cryptographic material
    """
    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
    prebin = (b'\x01\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@'
              b'\xa13Y\x1fu\x0b\xbd\x80\x1fIS\xf3\x874\xbao\x90\x8c')

    with pytest.raises(ValueError):
        crymat = CryMat()

    crymat = CryMat(raw=verkey)
    assert crymat.raw == verkey
    assert crymat.code == One.Ed25519N
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    assert crymat.qb64 == encodeB64(crymat.qb2).decode("utf-8")
    assert crymat.qb2 == decodeB64(crymat.qb64.encode("utf-8"))

    crymat._exfil(prefix)
    assert crymat.code == One.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix)
    assert crymat.code == One.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb2=prebin)
    assert crymat.code == One.Ed25519N
    assert crymat.raw == verkey

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64 = encodeB64(sig).decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0AmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qbin = (b'\xd0\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    crymat = CryMat(raw=sig, code=Two.Ed25519)
    assert crymat.raw == sig
    assert crymat.code == Two.Ed25519
    assert crymat.qb64 == qsig64
    assert crymat.qb2 == qbin

    crymat = CryMat(qb64=qsig64)
    assert crymat.raw == sig
    assert crymat.code == Two.Ed25519

    crymat = CryMat(qb2=qbin)
    assert crymat.raw == sig
    assert crymat.code == Two.Ed25519

    """
    Done Test
    """




def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """

    assert isinstance(Serials, Serializations)

    assert Serials.json == 'json'
    assert Serials.mgpk == 'mgpk'
    assert Serials.cbor == 'cbor'

    assert 'json' in Serials
    assert 'mgpk' in Serials
    assert 'cbor' in Serials

    assert Mimes.json == 'application/keri+json'
    assert Mimes.mgpk == 'application/keri+msgpack'
    assert Mimes.cbor == 'application/keri+cbor'

    assert VERSION == (1, 0)
    assert Versions.json == 'KERI_json_1.0'
    assert Versions.mgpk == 'KERI_mgpk_1.0'
    assert Versions.cbor == 'KERI_cbor_1.0'


    icp = dict(vs = Versions.json,
              id = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'icp',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              next = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              wits = [],
              data = [],
              sigs = [0]
             )

    rot = dict(vs = Versions.json,
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
              sigs = [0]
             )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 310
    assert icps == (b'{"vs":"KERI_json_1.0","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","s'
                    b'n":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS","'
                    b'sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"DZ-i'
                    b'0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"data":[],"sigs'
                    b'":[0]}')

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 320
    assert rots == (b'{"vs":"KERI_json_1.0","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","s'
                    b'n":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS","'
                    b'sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"DZ-i'
                    b'0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"data'
                    b'":[],"sigs":[0]}')

    assert Sniffs.json == b'{"vs":"KERI_json_'
    assert icps.find(Sniffs.json) == 0
    assert rots.find(Sniffs.json) == 0

    icp["vs"] = Versions.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 267
    assert icps == (b'\x8c\xa2vs\xadKERI_mgpk_1.0\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzh'
                    b'zS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ-i0d'
                    b'8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULv'
                    b'YAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4data\x90\xa4sigs\x91\x00')


    rot["vs"] = Versions.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 273
    assert rots == (b'\x8d\xa2vs\xadKERI_mgpk_1.0\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzh'
                    b'zS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ-i0d'
                    b'8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULv'
                    b'YAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90\xa4sigs\x91\x00')


    assert Sniffs.mgpk == b'\xa2vs\xadKERI_mgpk_'
    assert icps.find(Sniffs.mgpk) == 1
    assert rots.find(Sniffs.mgpk) == 1

    icp["vs"] = Versions.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 267
    assert icps == (b'\xacbvsmKERI_cbor_1.0bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMbsnd0'
                    b'001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01dkeys'
                    b'\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZH3UL'
                    b'vaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80ddata\x80dsigs\x81\x00')


    rot["vs"] = Versions.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 273
    assert rots == (b'\xadbvsmKERI_cbor_1.0bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMbsnd0'
                    b'001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01dkeys'
                    b'\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZH3UL'
                    b'vaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80dsigs\x81\x00')



    assert Sniffs.cbor == b'bvsmKERI_cbor_'
    assert icps.find(Sniffs.cbor) == 1
    assert rots.find(Sniffs.cbor) == 1



    """
    Done Test
    """

def test_keyeventer():
    """
    Test the support functionality for key event serialization
    """
    event = KeyEventer()

    e1 = dict(vs=Versions.json, id="ABCDEFG", sn="0001", ilk="rot")
    e1["ilk"] = "rot"
    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    kind1 = event._sniff(e1s)
    assert kind1 == Serials.json
    ked1 = event._inhale(e1s, kind1)
    assert ked1 == e1

    e2 = dict(e1)
    e2["vs"] = Versions.mgpk
    e2s = msgpack.dumps(e2)
    kind2 = event._sniff(e2s)
    assert kind2 == Serials.mgpk
    ked2 = event._inhale(e2s, kind2)
    assert ked2 == e2

    e3 = dict(e1)
    e3["vs"] = Versions.cbor
    e3s = cbor.dumps(e3)
    kind3 = event._sniff(e3s)
    assert kind3 == Serials.cbor
    ked3 = event._inhale(e3s, kind3)
    assert ked3 == e3

    event = KeyEventer(raw=e1s)
    assert event.kind == kind1
    assert event.raw == e1s
    assert event.ked == ked1

    event = KeyEventer(raw=e2s)
    assert event.kind == kind2
    assert event.raw == e2s
    assert event.ked == ked2

    event = KeyEventer(raw=e3s)
    assert event.kind == kind3
    assert event.raw == e3s
    assert event.ked == ked3


    """
    Done Test
    """


def test_pysodium():
    """
    Test all the functions needed from pysodium libarary (libsodium)

    """
    # crypto_sign signatures with Ed25519 keys

    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    assert 32 == pysodium.crypto_sign_SEEDBYTES
    sigseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    assert  len(sigseed) == 32
    # seed = (b'J\xeb\x06\xf2BA\xd6/T\xe1\xe2\xe2\x838\x8a\x99L\xd9\xb5(\\I\xccRb\xc8\xd5\xc7Y\x1b\xb6\xf0')


    # Ann's seed
    sigseed = (b'PTi\x15\xd5\xd3`\xf1u\x15}^r\x9bfH\x02l\xc6\x1b\x1d\x1c\x0b9\xd7{\xc0_\xf2K\x93`')
    assert  len(sigseed) == 32

    #  try key stretching from 16 bytes using  pysodium.crypto_pwhash()
    assert 16 == pysodium.crypto_pwhash_SALTBYTES
    salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    assert len(salt) == 16
    #  salt = b'\x19?\xfa\xc7\x8f\x8b\x7f\x8b\xdbS"$\xd7[\x85\x87'

    # algorithm default is argon2id
    sigseed = pysodium.crypto_pwhash(outlen=32,
                                    passwd="",
                                    salt=salt,
                                    opslimit=pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    memlimit=pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                    alg=pysodium.crypto_pwhash_ALG_DEFAULT)

    assert len(sigseed) == 32
    #  seed = (b'\xa9p\x89\x7f+\x0e\xc4\x9c\xf2\x01r\xafTI\xc0\xfa\xac\xd5\x99\xf8O\x8f=\x843\xa2\xb6e\x9fO\xff\xd0')


    # creates signing/verification key pair from seed
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(sigseed)
    assert len(verkey) == 32
    assert len(sigkey) == 64
    # sigkey is seed and verkey concatenated. Libsodium does this as an optimization
    #  becasue the signing scheme needs both the private key (seed) and the public key so
    #  instead of recomputing the public key each time from the public key it requires
    #  input of the public key, and instead of doing this as two separate keys it
    #  uses a concatenated form.
    # https://crypto.stackexchange.com/questions/54353/why-are-nacl-secret-keys-64-bytes-for-signing-but-32-bytes-for-box
    assert sigseed == sigkey[:32]
    assert verkey == sigkey[32:]
    assert sigkey == sigseed + verkey
    # vk = (b'B\xdd\xbb}8V\xa0\xd6lk\xcf\x15\xad9\x1e\xa7\xa1\xfe\xe0p<\xb6\xbex\xb0s\x8d\xd6\xf5\xa5\xe8Q')

    #  utility function to extract seed from secret sigkey (really just extracting from front half)
    assert sigseed == pysodium.crypto_sign_sk_to_seed(sigkey)

    assert 64 == pysodium.crypto_sign_BYTES

    msg = "The lazy dog jumped over the river"
    msgb = msg.encode("utf-8") # must convert unicode string to bytes in order to sign it
    assert msgb == b'The lazy dog jumped over the river'
    sig = pysodium.crypto_sign_detached(msgb, sigseed + verkey)  #  sigkey = verkey + seed
    assert len(sig) == 64

    """
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    """
    #siga = pysodium.crypto_sign(msg.encode("utf-8"), sk)[:pysodium.crypto_sign_BYTES]
    #assert len(siga) == 64
    #assert sig == siga

    try:  #  verify returns None if valid else raises ValueError
        result = pysodium.crypto_sign_verify_detached(sig, msgb, verkey)
    except Exception as ex:
        assert False
    assert not result
    assert result is None

    sigbad = sig[:-1]
    sigbad += b'A'

    try:  #  verify returns None if valid else raises ValueError
        result = pysodium.crypto_sign_verify_detached(sigbad, msgb, verkey)
    except Exception as ex:
        assert True
        assert isinstance(ex, ValueError)


    # crypto_box authentication encryption with X25519 keys

    apubkey, aprikey = pysodium.crypto_box_keypair()
    assert len(apubkey) == 32 == pysodium.crypto_box_SECRETKEYBYTES
    assert len(aprikey) == 32 == pysodium.crypto_box_PUBLICKEYBYTES

    repubkey = pysodium.crypto_scalarmult_curve25519_base(aprikey)
    assert repubkey == apubkey

    assert 32 == pysodium.crypto_box_SEEDBYTES

    boxseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    assert  len(boxseed) == 32

    bpubkey, bprikey = pysodium.crypto_box_seed_keypair(boxseed)
    assert len(bpubkey) == 32
    assert len(bprikey) == 32

    repubkey = pysodium.crypto_scalarmult_curve25519_base(bprikey)
    assert repubkey == bpubkey

    assert 24 == pysodium.crypto_box_NONCEBYTES
    nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
    assert len(nonce) == 24
    # nonce = b'\x11\xfbi<\xf2\xb6k\xa05\x0c\xf9\x86t\x07\x8e\xab\x8a\x97nG\xe8\x87,\x94'

    atob_tx = "Hi Bob I'm Alice"
    atob_txb = atob_tx.encode("utf-8")

    # Detached recomputes shared key every time.
    # A encrypt to B
    acrypt, amac = pysodium.crypto_box_detached(atob_txb, nonce, bpubkey, aprikey)
    amacl = pysodium.crypto_box_MACBYTES
    assert  amacl == 16
    #  amac =  b'\xa1]\xc6ML\xe2\xa9:\xc0\xdc\xab\xa5\xc4\xc7\xf4\xdb'
    #  acrypt = (b'D\n\x17\xb6z\xd8+t)\xcc`y\x1d\x10\x0cTC\x02\xb5@\xe2\xf2\xc9-(\xec*O\xb8~\xe2\x1a\xebO')
    # when transmitting prepend amac to crypt

    acipher = pysodium.crypto_box(atob_txb, nonce, bpubkey, aprikey)
    assert acipher == amac + acrypt

    atob_rxb = pysodium.crypto_box_open_detached(acrypt, amac, nonce, apubkey, bprikey)
    atob_rx = atob_rxb.decode("utf-8")
    assert atob_rx == atob_tx
    assert atob_rxb == atob_txb

    atob_rxb =  pysodium.crypto_box_open(acipher, nonce, apubkey, bprikey)
    atob_rx = atob_rxb.decode("utf-8")
    assert atob_rx == atob_tx
    assert atob_rxb == atob_txb

    btoa_tx = "Hello Alice I am Bob"
    btoa_txb = btoa_tx.encode("utf-8")

    # B encrypt to A
    bcrypt, bmac = pysodium.crypto_box_detached(btoa_txb, nonce, apubkey, bprikey)
    # bmac = b'\x90\xe07=\xd22\x8fh2\xff\xdd\x84tC\x053'
    # bcrypt = (b'8\xb5\xba\xe7\xcc\xae B\xefx\xe6{U\xf7\xefA\x00\xc7|\xdbu\xcfc\x01$\xa9\xa2P\xa7\x84\xa5\xae\x180')
    # when transmitting prepend amac to crypt

    bcipher = pysodium.crypto_box(btoa_txb, nonce, apubkey, bprikey)
    assert bcipher == bmac + bcrypt

    btoa_rxb = pysodium.crypto_box_open_detached(bcrypt, bmac, nonce, bpubkey, aprikey)
    btoa_rx = btoa_rxb.decode("utf-8")
    assert btoa_rx == btoa_tx
    assert btoa_rxb == btoa_txb

    btoa_rxb =  pysodium.crypto_box_open(bcipher, nonce, bpubkey, aprikey)
    btoa_rx = btoa_rxb.decode("utf-8")
    assert btoa_rx == btoa_tx
    assert btoa_rxb == btoa_txb


    # compute shared key
    asymkey = pysodium.crypto_box_beforenm(bpubkey, aprikey)
    bsymkey = pysodium.crypto_box_beforenm(apubkey, bprikey)
    assert asymkey == bsymkey

    acipher = pysodium.crypto_box_afternm(atob_txb, nonce, asymkey)
    atob_rxb = pysodium.crypto_box_open_afternm(acipher, nonce, bsymkey)
    assert  atob_rxb == atob_txb

    bcipher = pysodium.crypto_box_afternm(btoa_txb, nonce, bsymkey)
    btoa_rxb = pysodium.crypto_box_open_afternm(bcipher, nonce, asymkey)
    assert  btoa_rxb == btoa_txb


    # crypto_box_seal public key encryption with X25519 keys
    #  uses same X25519 type of keys as crypto_box authenticated encryption
    #  so when converting sign key Ed25519 to X25519 can use for both types of encryption

    pubkey, prikey = pysodium.crypto_box_keypair()
    assert len(pubkey) == 32 == pysodium.crypto_box_PUBLICKEYBYTES
    assert len(prikey) == 32 ==  pysodium.crypto_box_SECRETKEYBYTES

    assert 48 == pysodium.crypto_box_SEALBYTES

    msg_txb = "Catch me if you can.".encode("utf-8")
    assert msg_txb == b'Catch me if you can.'
    cipher = pysodium.crypto_box_seal(msg_txb, pubkey)
    assert len(cipher) == 48 + len(msg_txb)

    msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, prikey)
    assert msg_rxb == msg_txb

    #  convert Ed25519 key pair to X25519 key pair
    #  https://blog.filippo.io/using-ed25519-keys-for-encryption/
    #  https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
    #  crypto_sign_ed25519_pk_to_curve25519
    #  crypto_sign_ed25519_sk_to_curve25519

    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    assert len(pubkey) == pysodium.crypto_box_PUBLICKEYBYTES

    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)
    assert len(prikey) == pysodium.crypto_box_SECRETKEYBYTES

    repubkey = pysodium.crypto_scalarmult_curve25519_base(prikey)
    assert repubkey == pubkey

    msg_txb = "Encoded using X25519 key converted from Ed25519 key".encode("utf-8")
    cipher = pysodium.crypto_box_seal(msg_txb, pubkey)
    assert len(cipher) == 48 + len(msg_txb)

    msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, prikey)
    assert msg_rxb == msg_txb



    """
    Done Test
    """



def test_blake3():
    """
    Test needed functions from blake3
    https://github.com/BLAKE3-team/BLAKE3/

    """
    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'

    #  digest of publickey
    digest = blake3.blake3(verkey).digest()
    assert len(digest) == 32 == blake3.OUT_LEN
    assert digest == b'\xb4\xaf\xd5,G\x97\xaf\x06\xda\xbbTNs\xcbM4\xa81\xb8\xcd\xc60\xc7c"\xe2B\xe5_\x96\xcb\x95'

    digestbig = blake3.blake3(verkey).digest(length=64)
    assert len(digestbig) == 64
    assert digestbig[:32] == digest


    """
    Done Test
    """
if __name__ == "__main__":
    test_keyeventer()
