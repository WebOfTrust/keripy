# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import pytest
import pysodium
import blake3
import hashlib

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions


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
                                    opslimit=2,  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    memlimit=67108864,  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                    alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)

    assert len(sigseed) == 32
    #  seed = (b'\xa9p\x89\x7f+\x0e\xc4\x9c\xf2\x01r\xafTI\xc0\xfa\xac\xd5\x99\xf8O\x8f=\x843\xa2\xb6e\x9fO\xff\xd0')


    # creates signing/verification key pair from seed
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(sigseed)
    assert len(verkey) == 32
    assert len(sigkey) == 64
    #  sigkey is seed and verkey concatenated. Libsodium does this as an optimization
    #  because the signing scheme needs both the private key (seed) and the public key so
    #  instead of recomputing the public key each time from the secret key it requires
    #  the public key as an input of and instead of two separate inputs, one for the
    #  secret key and one for the public key, it uses a concatenated form.
    #  Essentially crypto_sign_seed_keypair and crypto_sign_keypair return redundant
    #  information in the duple (verkey, sigkey) because sigkey includes verkey
    #  so one could just store sigkey and extract verkey or sigseed when needed
    #  or one could just store verkey and sigseed and reconstruct sigkey when needed.
    #  crypto_sign_detached requires sigkey (sigseed + verkey)
    #  crypto_sign_verify_detached reqires verkey only
    #  https://crypto.stackexchange.com/questions/54353/why-are-nacl-secret-keys-64-bytes-for-signing-but-32-bytes-for-box
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
    sig = pysodium.crypto_sign_detached(msgb, sigseed + verkey)  #  sigkey = seed + verkey
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
    assert len(prikey) == 32 == pysodium.crypto_box_SECRETKEYBYTES

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
    #  https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair
    #  crypto_sign_ed25519_pk_to_curve25519
    #  pysodium.crypto_sign_pk_to_box_pk
    #  crypto_sign_ed25519_sk_to_curve25519
    #  pysodium.crypto_sign_sk_to_box_sk
    #  pysodium.crypto_scalarmult_curve25519_base
    #  crypto_scalarmult_curve25519_base

    #  see also  crypto_scalarmult_ed25519_base()
    #  crypto_scalarmult_base
    #  pysodium.crypto_scalarmult_base

    # As X25519 encodes a field element that is always smaller than 2^255, the top bit is not used.

    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    assert len(pubkey) == pysodium.crypto_box_PUBLICKEYBYTES

    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)
    assert len(prikey) == pysodium.crypto_box_SECRETKEYBYTES

    repubkey = pysodium.crypto_scalarmult_curve25519_base(prikey)
    assert repubkey == pubkey

    gepubkey = pysodium.crypto_scalarmult_base(prikey)
    assert gepubkey == repubkey == pubkey

    msg_txb = "Encoded using X25519 key converted from Ed25519 key".encode("utf-8")
    cipher = pysodium.crypto_box_seal(msg_txb, pubkey)
    assert len(cipher) == 48 + len(msg_txb)

    msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, prikey)
    assert msg_rxb == msg_txb

    # generate X25519 box seal (asymmetric encryption) from random seed

    boxsealseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    assert  len(boxsealseed) == pysodium.crypto_box_SEEDBYTES == 32

    bspubkey, bsprikey = pysodium.crypto_box_seed_keypair(boxsealseed)
    assert len(bspubkey) == pysodium.crypto_box_PUBLICKEYBYTES == 32
    assert len(bsprikey) == pysodium.crypto_box_SECRETKEYBYTES == 32

    # unlike Ed25519, private key is not seed or does not contain seed but is
    # derived or changed from seed
    assert bsprikey != boxsealseed

    msg_txb = "Encoded using X25519 key generated from random seed".encode("utf-8")
    cipher = pysodium.crypto_box_seal(msg_txb, bspubkey)
    assert len(cipher) == 48 + len(msg_txb)

    msg_rxb = pysodium.crypto_box_seal_open(cipher, bspubkey, bsprikey)
    assert msg_rxb == msg_txb


    #  use same seed for both Ed25519 key pair and X25519 key pair
    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32
    dualseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(dualseed)
    pubkey, prikey = pysodium.crypto_box_seed_keypair(dualseed)

    copubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    coprikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    # same public asymmetric encryption key from same seed using
    #  either crypto_sign_xx_to_box_xx or crypto_box_seed_keypair but not
    # always the same private key.  Apparently (guessing) multiple private keys may
    # result in the same public key but both still work? The privatekeys, when
    #  they differ, only differ in the second byte and the second from last byte
    #  so those bytes or (bits in those bytes are not unique to the public key)
    assert copubkey == pubkey

    cipher = pysodium.crypto_box_seal(msg_txb, pubkey)
    cocipher = pysodium.crypto_box_seal(msg_txb, copubkey)

    if coprikey != prikey:  # sometimes rarely these match but usually not
        assert cocipher != cipher
    else:
        pass
        # sometimes even when prikeys match ciphers don't match
        #  assert cocipher == cipher

    msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, prikey)
    co_msg_rxb = pysodium.crypto_box_seal_open(cocipher, copubkey, coprikey)
    alt_msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, coprikey)
    co_alt_msg_rxb = pysodium.crypto_box_seal_open(cocipher, copubkey, prikey)
    assert msg_rxb == co_msg_rxb == alt_msg_rxb == co_alt_msg_rxb == msg_txb

    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

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
    assert len(digest) == 32
    assert digest == b'\xb4\xaf\xd5,G\x97\xaf\x06\xda\xbbTNs\xcbM4\xa81\xb8\xcd\xc60\xc7c"\xe2B\xe5_\x96\xcb\x95'

    digestbig = blake3.blake3(verkey).digest(length=64)
    assert len(digestbig) == 64
    assert digestbig[:32] == digest  # first 32 bytes of big same as little

    """Done Test"""


def test_blake3_modes():
    """ Test different blake3 modes
    https://github.com/BLAKE3-team/BLAKE3/

    """
    from blake3 import blake3 as blake

    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'
    assert verkey.hex() == '5a807381d3f4aa9480869b488a79c2f9896b5f9436f15f608ca9d8d262e40008'
    assert len(verkey) == 32

    #  digest of publickey
    dig = blake(verkey).digest()
    assert len(dig) == 32
    assert dig == b'\xb4\xaf\xd5,G\x97\xaf\x06\xda\xbbTNs\xcbM4\xa81\xb8\xcd\xc60\xc7c"\xe2B\xe5_\x96\xcb\x95'
    assert dig.hex() == 'b4afd52c4797af06dabb544e73cb4d34a831b8cdc630c76322e242e55f96cb95'

    digbig = blake(verkey).digest(length=64)
    assert len(digbig) == 64
    assert digbig[:32] == dig   # first 32 bytes of big same as little

    msgb = b"abcdefghijklmnopqrstuvwxyz012345"
    assert len(msgb) == 32
    msgdig = blake(msgb).digest()
    assert msgdig == (b"5^_\xd6%\xa9\xcd\\'\xb3\x12\xb3\xc4 \x8d\x026\xedm2Vk\xd5\xa0d%\x99\xc1"
                      b'\xc8\x99d\x06')
    assert msgdig.hex() == '355e5fd625a9cd5c27b312b3c4208d0236ed6d32566bd5a0642599c1c8996406'

    #prefixed message as hmac like mode
    vermsg = verkey + msgb
    assert len(vermsg) == 64
    vmdig = blake(vermsg).digest()
    assert len(vmdig) == 32
    assert vmdig == (b'\x9e\x9dD\x1d\xa1^\x0c)/\x14\x95\x91B);\xbf:\xdfF\xd5u\xf1%\xca\xe3\x8fw]'
                     b'N\xdcIm')
    assert vmdig.hex() == '9e9d441da15e0c292f14959142293bbf3adf46d575f125cae38f775d4edc496d'

    assert vmdig != msgdig

    # hmac key mode. Key loads state to key instead of default more difficult
    # to attack when using for HMAC
    keydig = blake(msgb, key=verkey).digest()
    assert keydig == (b'\xd4zf\x89js\x8a\xfd\x9b\xd7\xfb\xc2\xcf\xad\x10\xc0\xe9Q\x96\xb5'
                      b'\xad\xb6\xfb\xbc\xdc\xdf\xb3@q\xc8p\xa6')
    assert keydig.hex() == 'd47a66896a738afd9bd7fbc2cfad10c0e95196b5adb6fbbcdcdfb34071c870a6'

    assert keydig != vmdig
    assert keydig != msgdig

    # HDKeychain mode,  uses context as hdkey path and and data as salt
    context = '0_0'
    hierdig = blake(verkey, derive_key_context=context).digest()
    assert hierdig == (b'XU\xe7\\\x96\x12\xe2\xaej.q\x199Ok\xd2W\xdf\xfb\x03\xc5w\x07M.\x9d\xefX'
                       b'&\xce?\xb4')
    assert hierdig.hex() == '5855e75c9612e2ae6a2e7119394f6bd257dffb03c577074d2e9def5826ce3fb4'

    emptydig = blake(b'').digest()
    assert emptydig == (b'\xaf\x13I\xb9\xf5\xf9\xa1\xa6\xa0@M\xea6\xdc\xc9I\x9b\xcb%\xc9'
                        b'\xad\xc1\x12\xb7\xcc\x9a\x93\xca\xe4\x1f2b')
    assert emptydig.hex() == 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'

    zerosb = bytes([0]) *32
    assert zerosb.hex() == '0000000000000000000000000000000000000000000000000000000000000000'

    zerodig = blake(zerosb).digest()
    assert zerodig == (b'*\xda\x83\xc1\x81\x9aSr\xda\xe1#\x8f\xc1\xde\xd1#\xc8\x10O\xda\xa1Xb\xaa'
                       b'\xeeiB\x8a\x18 \xfc\xda')
    assert zerodig.hex() ==  '2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda'

    onesb = bytes([255]) *32
    assert onesb == (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
                   b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    assert onesb.hex() == 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

    onedig = blake(onesb).digest()
    assert onedig == (b'\x9b4\xf0`\xfb\xc0\xf0\xaa\x11\xf1P\xe2e\x19\xde\xffa2w\xb6\x06V\xf0\xf8'
                      b'5n\xd2&\x15\x05\xf5\xc5')
    assert onedig.hex() == '9b34f060fbc0f0aa11f150e26519deff613277b60656f0f8356ed2261505f5c5'


    # bitwise operations

    zero = int.from_bytes(zerosb)
    assert zero == 0

    ones = int.from_bytes(onesb)
    assert ones == 115792089237316195423570985008687907853269984665640564039457584007913129639935
    assert ones ==  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    # xor  ^
    assert ones ^ zero == ones
    assert ones ^ ones == zero
    assert zero ^ zero == zero

    vkint = int.from_bytes(verkey)
    assert vkint == 40935109997770152556746109449840531881192132167145235300759205962933009121288
    assert vkint == 0x5a807381d3f4aa9480869b488a79c2f9896b5f9436f15f608ca9d8d262e40008

    assert vkint ^ zero == vkint
    assert vkint ^ vkint == zero
    # ~vkint is in signed twos complement, must use zeroed sign bit or byte
    nvk = vkint ^ ones
    assert nvk ^ vkint == ones

    assert vkint & nvk == zero
    assert vkint & ones == vkint
    assert vkint & zero == zero
    assert vkint & vkint == vkint

    # test blinding with xor
    msgint = int.from_bytes(msgb)
    assert msgint == 44048183304486788312148433451363384677562265908331949128489393197024686584885

    blind = msgint ^ vkint
    assert blind == 0x3be210e5b692cdfce9ecf024e717ad89f8192ce043872818f5d3e8e350d7343d

    assert msgint ^ blind == vkint
    assert vkint ^ blind == msgint

    # test if H[a ^ b] = H[a] ^ H[b]
    vorm = vkint ^ msgint
    vormb = vorm.to_bytes(32)
    vormdig = blake(vormb).digest()
    assert vormdig.hex() == '28f555eb72a91cf495602f3d9f76110eee46a40d4b4dd49aa1245f50c1d37d06'

    digint = int.from_bytes(dig) # verkey
    msgdigint = int.from_bytes(msgdig)

    hvorhm = digint ^ msgdigint
    hvorhmdig = hvorhm.to_bytes(32)
    assert hvorhmdig.hex() == '81f18afa623e625afd0846fdb7ebc0369edcd5ff905b12c346c7db24970faf93'

    assert vormdig != hvorhmdig  # so blake3 hash does not commute with xor

    # test extension with zeros
    vkext = verkey + zerosb
    vkextdig = blake(vkext).digest()
    assert vkextdig.hex() == '0782639d57d1b01bdb4c4ab6d6c92636f45894f8ee430786eb0d8b9a0021a75c'
    # verkey '5a807381d3f4aa9480869b488a79c2f9896b5f9436f15f608ca9d8d262e40008'
    # dig 'b4afd52c4797af06dabb544e73cb4d34a831b8cdc630c76322e242e55f96cb95'

    # keyed mode extended with zeros
    vkext2dig = blake(zerosb, key=verkey).digest()
    assert vkext2dig.hex() == 'b34cfdde740c0e750ebec7d3f43389c184e803b7f355087a5bcef4f2ad96aa1b'


    # test kA ^ H[kB] = H[kA] ^ kB
    kA = verkey
    kB = msgb
    HkA = dig
    HkB = msgdig

    kAint = int.from_bytes(kA)
    kBint = int.from_bytes(kB)

    HkAint = int.from_bytes(HkA)
    HkBint = int.from_bytes(HkB)

    assert kAint ^ HkBint != HkAint ^ kBint

    """Done Test"""


def test_bext_b3():
    """BEXT-B3 key exchange protocol from
    https://www.researchgate.net/publication/394046262_Boolean_semiring_key-exchange_with_BLAKE3_security_BKEX-B3
    https://github.com/BLAKE3-team/BLAKE3/

    """
     # python code for BEXT-B3
    from blake3 import blake3

    p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    xA = 1234567890123456789123456789012345678901234567890123456789012345
    yA = 9876543210987654321098765432109876543210987654321098765432109876

    xB = 2234567890123456789223456789012345678922345678901234567890123456
    yB = 8876543210987654321988765432109876543210988765432109876543210987

    def enbool(x, y, p):
        a = ((x ^ y) & (x | y)) ^ ( ~x & ~y)
        b = ((x & y) | (x ^ ~y))
        g = (a * b) ^ ((x << 3) | ( y << 2))
        return g % p

    kA = enbool(xA, yA, p)
    kB = enbool(xB, yB, p)

    kAb = kA.to_bytes(32)
    kBb = kB.to_bytes(32)

    HkAb = blake3(kAb).digest()
    HkBb = blake3(kBb).digest()

    HkA = int.from_bytes(HkAb)
    HkB = int.from_bytes(HkBb)

    c1 = (kA ^ HkB) % p
    c1b = c1.to_bytes(32)
    sA = blake3(c1b).digest()

    c2 = (kB ^ HkA) % p
    c2b = c2.to_bytes(32)
    sB = blake3(c2b).digest()

    assert sA != sB  # why is this not == ?

    """Done Test"""


def test_blake2b():
    """
    Used generic hash in LibSodium which is Blake2b
    Also hash std lib

    """
    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'

    #  digest of publickey
    digest = pysodium.crypto_generichash(verkey)
    assert len(digest) == 32 == pysodium.crypto_generichash_BYTES
    assert digest == (b'\xf9\xa4\xe3\x87\x05\xc9\xf8\x9b\x18pI\xf3\xb5G@\xdf\x03\xbe\xcc\x9b)\xe7u\xeaH\x19\x1d\xe6*4Yp')


    digestbig = pysodium.crypto_generichash(verkey, outlen=64)
    assert len(digestbig) == 64
    # assert digestbig[:32] == digest  # not true for blake2b

    dig = hashlib.blake2b(verkey, digest_size=32).digest()
    assert dig ==  (b'\xf9\xa4\xe3\x87\x05\xc9\xf8\x9b\x18pI\xf3\xb5G@\xdf\x03\xbe\xcc\x9b)\xe7u\xeaH\x19\x1d\xe6*4Yp')
    assert len(dig) == 32
    assert dig == digest

    digbig =  hashlib.blake2b(verkey).digest()
    assert len(digbig) == 64
    assert digbig == digestbig

    """
    Done Test
    """

def test_blake2s():
    """
    Used hash std lib

    """
    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'

    dig = hashlib.blake2s(verkey, digest_size=32).digest()
    assert dig ==  (b'E(\x89\xec\xfc\xe4\x02\xba\x05\xcc\xf35=\xfa\xfa\xb1\x87\t\x99\xd0Q:\t\x80f^\xe4J\x17\xe9\x9d\x1a')
    assert len(dig) == 32

    """
    Done Test
    """


def test_sha2():
    """
    Used pysoidium.crypto_hash_sha256(message)

    """
    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'

    #  digest of publickey
    digest = pysodium.crypto_hash_sha256(verkey)
    assert len(digest) == 32 == pysodium.crypto_generichash_BYTES
    assert digest == (b'\x81\xce\x15L\x8b3\xb1mI\x9bF\xd9(\x0e\x99\x08SH6\xb9\xb5)\xf6\x93\xd0\x7f\x85\xe1r\xa7\x13\xd7')


    digestbig = pysodium.crypto_hash_sha512(verkey)
    assert len(digestbig) == 64
    # assert digestbig[:32] == digest  # not true for sha256 sha512

    dig = hashlib.sha256(verkey).digest()
    assert len(dig) == 32
    assert dig == digest

    digbig =  hashlib.sha512(verkey).digest()
    assert len(digbig) == 64
    assert digbig == digestbig


    """
    Done Test
    """

def test_sha3():
    """
    Used pysoidium.crypto_hash_sha256(message)

    """
    # create keypair without seed
    verkey,  sigkey = pysodium.crypto_sign_keypair()
    assert len(verkey) == 32 == pysodium.crypto_sign_PUBLICKEYBYTES
    assert len(sigkey) == 64 == pysodium.crypto_sign_SECRETKEYBYTES

    verkey = b'Z\x80s\x81\xd3\xf4\xaa\x94\x80\x86\x9bH\x8ay\xc2\xf9\x89k_\x946\xf1_`\x8c\xa9\xd8\xd2b\xe4\x00\x08'

    dig = hashlib.sha3_256(verkey).digest()
    assert len(dig) == 32
    assert dig == (b'\xd6\x00\xac_&\xeb\xd5"\xbaP\xdc\xb7\x06\x91^{\xa3\x18\xca\n+t\xbe\x1c7\xebY5ww\xdd7')

    digbig =  hashlib.sha3_512(verkey).digest()
    assert len(digbig) == 64
    assert digbig ==  (b'X\x0e\t\x03{--\xf1oms6\xb0\xb2\x94m.\xe1=?\xee\xbe\xd18\xa7\x90\x04\xc6'
                       b'd\xbd):\x9d\xaf\xd3\xc3\xb4V\xb3s8]G\x92F\x92\x0c\xb1\x86\xd1\x13\x88'
                       b':\xd5\xd6\x84%\x18\x94u\xf2\xff\xd5|')

    # assert digbig[:32] == dig  # not true for sha256 sha512

    """
    Done Test
    """


def test_secp256r1():
    """
    test secp256r1

    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
    """

    # create keypair without seed
    private_key = ec.generate_private_key(ec.SECP256R1())
    assert isinstance(private_key.curve, ec.SECP256R1)
    assert private_key.key_size == 256     # for the secp256r1 curve, the private key is 256-bit integer (32 bytes)

    public_key = private_key.public_key()
    assert isinstance(public_key.curve, ec.SECP256R1)
    assert public_key.key_size == 256

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
    signature = private_key.sign(ser, ec.ECDSA(hashes.SHA256()))
    try:
        public_key.verify(signature, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    # compress public key to bytes
    verkey = public_key.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint) # compressed public key is 257-bit integer (~ 33 bytes)
    assert len(verkey) == 33

    # convert back to public key and verify
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), verkey)
    try:
        public_key.verify(signature, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    # decode Ecdsa-Sig-Value signature to tuple (r, s)
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature
    (r, s) = utils.decode_dss_signature(signature)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    # encode signature to encoded Ecdsa-Sig-Value from raw r and s values
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    der = utils.encode_dss_signature(r, s)
    #  verify der
    try:
        public_key.verify(der, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    with pytest.raises(exceptions.InvalidSignature):
        public_key.verify(b'XYZ', ser, ec.ECDSA(hashes.SHA256()))

    """
    Done Test
    """


def test_secp256k1():
    """
    test secp256k1

    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
    """

    # create keypair without seed
    private_key = ec.generate_private_key(ec.SECP256K1())
    assert isinstance(private_key.curve, ec.SECP256K1)
    assert private_key.key_size == 256     # for the secp256k1 curve, the private key is 256-bit integer (32 bytes)

    public_key = private_key.public_key()
    assert isinstance(public_key.curve, ec.SECP256K1)
    assert public_key.key_size == 256

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
    signature = private_key.sign(ser, ec.ECDSA(hashes.SHA256()))
    try:
        public_key.verify(signature, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    # compress public key to bytes
    verkey = public_key.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint) # compressed public key is 257-bit integer (~ 33 bytes)
    assert len(verkey) == 33

    # convert back to public key and verify
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), verkey)
    try:
        public_key.verify(signature, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    # decode Ecdsa-Sig-Value signature to tuple (r, s)
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature
    (r, s) = utils.decode_dss_signature(signature)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    # encode signature to encoded Ecdsa-Sig-Value from raw r and s values
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    der = utils.encode_dss_signature(r, s)
    #  verify der
    try:
        public_key.verify(der, ser, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        assert False, f"signature verification, raised an exception {exc}"

    with pytest.raises(exceptions.InvalidSignature):
        public_key.verify(b'XYZ', ser, ec.ECDSA(hashes.SHA256()))

    """
    Done Test
    """



if __name__ == "__main__":
    test_pysodium()
    test_blake3()
    test_blake3_modes()
    test_bext_b3()
