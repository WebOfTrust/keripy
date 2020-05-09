# -*- encoding: utf-8 -*-
"""
tests.test_coring module

"""

import pysodium

def test_cryptoStuff():
    """


    https://crypto.stackexchange.com/questions/75834/difference-between-tag-and-signature

    """

    # crypto_sign signatures with Ed25519 keys
    sigseedl = pysodium.crypto_sign_SEEDBYTES
    assert sigseedl == 32

    sigseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    assert  len(sigseed) == 32
    # seed = (b'J\xeb\x06\xf2BA\xd6/T\xe1\xe2\xe2\x838\x8a\x99L\xd9\xb5(\\I\xccRb\xc8\xd5\xc7Y\x1b\xb6\xf0')


    # Ann's seed
    sigseed = (b'PTi\x15\xd5\xd3`\xf1u\x15}^r\x9bfH\x02l\xc6\x1b\x1d\x1c\x0b9\xd7{\xc0_\xf2K\x93`')
    assert  len(sigseed) == 32

    #  try key stretching from 16 bytes using  pysodium.crypto_pwhash()
    saltl = pysodium.crypto_pwhash_SALTBYTES
    assert saltl == 16
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


    # creates signing/verification key pair
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


    signl =  pysodium.crypto_sign_BYTES
    assert signl == 64

    msg = "The lazy dog jumped over the river"
    msgb = msg.encode("utf-8") # must convert unicode string to bytes in order to sign it
    assert msgb == b'The lazy dog jumped over the river'
    sig = pysodium.crypto_sign_detached(msgb, sigseed + verkey)  #  sigkey = verkey + seed
    assert len(sig) == 64

    """
    sig = (b'F\x82\x0b\x1b\xacmC\xf0E6&\xb7o\xca\xcau\x9b\xf26R\xf4f\xc4\xcd\x1a \x81\xaf'
           b'\x17\xae\x9d\xf8\xff\x96\xda\x06\x11\xb0\x16.\xb3\xe1N\xbc$\xa0`@'
           b'\x10\xfc'\xe2\n\xc6\x910\x05\x87\xe9\x1a\xa6*\xde\x0c')
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

    prikeyl = pysodium.crypto_box_SECRETKEYBYTES
    assert prikeyl == 32

    pubkeyl = pysodium.crypto_box_PUBLICKEYBYTES
    assert pubkeyl == 32

    apubkey, aprikey = pysodium.crypto_box_keypair()
    assert len(apubkey) == 32
    assert len(aprikey) == 32

    repubkey = pysodium.crypto_scalarmult_curve25519_base(aprikey)
    assert repubkey == apubkey

    boxseedl = pysodium.crypto_box_SEEDBYTES
    assert boxseedl == 32

    boxseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    assert  len(boxseed) == 32

    bpubkey, bprikey = pysodium.crypto_box_seed_keypair(boxseed)
    assert len(bpubkey) == 32
    assert len(bprikey) == 32

    repubkey = pysodium.crypto_scalarmult_curve25519_base(bprikey)
    assert repubkey == bpubkey

    noncel = pysodium.crypto_box_NONCEBYTES
    assert noncel == 24
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
    assert len(pubkey) == 32
    assert len(prikey) == 32

    seall = pysodium.crypto_box_SEALBYTES
    assert seall == 48

    msg_txb = "Catch me if you can.".encode("utf-8")
    assert msg_txb == b'Catch me if you can.'
    cipher = pysodium.crypto_box_seal(msg_txb, pubkey)
    assert len(cipher) == 48 + len(msg_txb)

    msg_rxb = pysodium.crypto_box_seal_open(cipher, pubkey, prikey)
    assert msg_rxb == msg_txb

    #  convert Ed25519 key pair to X25519 key pair
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




