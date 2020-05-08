# -*- encoding: utf-8 -*-
"""
tests.test_coring module

"""

import pysodium

def test_cryptoStuff():
    """

    """
    seedl = pysodium.crypto_sign_SEEDBYTES
    assert seedl == 32

    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    assert  len(seed) == 32
    # seed = (b'J\xeb\x06\xf2BA\xd6/T\xe1\xe2\xe2\x838\x8a\x99L\xd9\xb5(\\I\xccRb\xc8\xd5\xc7Y\x1b\xb6\xf0')


    # Ann's seed
    seed = (b'PTi\x15\xd5\xd3`\xf1u\x15}^r\x9bfH\x02l\xc6\x1b\x1d\x1c\x0b9\xd7{\xc0_\xf2K\x93`')
    assert  len(seed) == 32

    #  try key stretching from 16 bytes using  pysodium.crypto_pwhash()
    saltl = pysodium.crypto_pwhash_SALTBYTES
    assert saltl == 16
    salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    assert len(salt) == 16
    #  salt = b'\x19?\xfa\xc7\x8f\x8b\x7f\x8b\xdbS"$\xd7[\x85\x87'

    # algorithm default is argon2id
    seed = pysodium.crypto_pwhash(outlen=32,
                                    passwd="",
                                    salt=salt,
                                    opslimit=pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    memlimit=pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                    alg=pysodium.crypto_pwhash_ALG_DEFAULT)

    assert len(seed) == 32
    #  seed = (b'\xa9p\x89\x7f+\x0e\xc4\x9c\xf2\x01r\xafTI\xc0\xfa\xac\xd5\x99\xf8O\x8f=\x843\xa2\xb6e\x9fO\xff\xd0')


    # creates signing/verification key pair
    vk, sk = pysodium.crypto_sign_seed_keypair(seed)

    assert len(vk) == 32
    assert len(sk) == 64

    assert seed == sk[:32]
    assert vk == sk[32:]

    # vk = (b'B\xdd\xbb}8V\xa0\xd6lk\xcf\x15\xad9\x1e\xa7\xa1\xfe\xe0p<\xb6\xbex\xb0s\x8d\xd6\xf5\xa5\xe8Q')


    signl =  pysodium.crypto_sign_BYTES
    assert signl == 64

    msg = "The lazy dog jumped over the river"
    msgb = msg.encode("utf-8") # must convert unicode string to bytes in order to sign it
    assert msgb == b'The lazy dog jumped over the river'
    sig = pysodium.crypto_sign_detached(msgb, sk)
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
        result = pysodium.crypto_sign_verify_detached(sig, msgb, vk)
    except Exception as ex:
        assert False
    assert not result
    assert result is None

    sigbad = sig[:-1]
    sigbad += b'A'

    try:  #  verify returns None if valid else raises ValueError
        result = pysodium.crypto_sign_verify_detached(sigbad, msgb, vk)
    except Exception as ex:
        assert True
        assert isinstance(ex, ValueError)




    """
    Done Test
    """



"""



def crypto_sign_open(sm, pk):
    if sm is None or pk is None:
        raise ValueError("invalid parameters")
    if not (len(pk) == crypto_sign_PUBLICKEYBYTES): raise ValueError('Truncated public key')
    msg = ctypes.create_string_buffer(len(sm))
    msglen = ctypes.c_ulonglong()
    __check(sodium.crypto_sign_open(msg, ctypes.byref(msglen), sm, ctypes.c_ulonglong(len(sm)), pk))
    return msg.raw[:msglen.value]


def crypto_sign_verify_detached(sig, msg, pk):
    if None in (sig, msg, pk):
        raise ValueError
    if len(sig) != crypto_sign_BYTES:
        raise ValueError("invalid sign")
    if not (len(pk) == crypto_sign_PUBLICKEYBYTES): raise ValueError('Truncated public key')
    __check(sodium.crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), pk))


# int crypto_pwhash(unsigned char * const out,
#                   unsigned long long outlen,
#                   const char * const passwd,
#                   unsigned long long passwdlen,
#                   const unsigned char * const salt,
#                   unsigned long long opslimit,
#                   size_t memlimit, int alg);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash(outlen, passwd, salt, opslimit, memlimit, alg=crypto_pwhash_ALG_DEFAULT):
    if None in (outlen, passwd, salt, opslimit, memlimit):
        raise ValueError("invalid parameters")
    if len(salt) != crypto_pwhash_SALTBYTES: raise ValueError("invalid salt")
    if not (crypto_pwhash_BYTES_MIN <= outlen <= crypto_pwhash_BYTES_MAX): raise ValueError("invalid hash len")
    if not (crypto_pwhash_PASSWD_MIN <= len(passwd) <= crypto_pwhash_PASSWD_MAX): raise ValueError("invalid passwd len")
    if not (crypto_pwhash_OPSLIMIT_MIN <= opslimit <= crypto_pwhash_OPSLIMIT_MAX): raise ValueError("invalid opslimit")
    if not (crypto_pwhash_MEMLIMIT_MIN <= memlimit <= crypto_pwhash_MEMLIMIT_MAX): raise ValueError("invalid memlimit")

    out = ctypes.create_string_buffer(outlen)
    __check(sodium.crypto_pwhash(ctypes.byref(out), ctypes.c_ulonglong(outlen), passwd, ctypes.c_ulonglong(len(passwd)), salt, ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit), ctypes.c_int(alg)))
    return out.raw

# int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES],
#                       const char * const passwd,
#                       unsigned long long passwdlen,
#                       unsigned long long opslimit,
#                       size_t memlimit);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash_str(passwd, opslimit, memlimit):
    if None in (passwd, opslimit, memlimit):
        raise ValueError("invalid parameters")
    if not (crypto_pwhash_PASSWD_MIN <= len(passwd) <= crypto_pwhash_PASSWD_MAX): raise ValueError("invalid passwd len")
    if not (crypto_pwhash_OPSLIMIT_MIN <= opslimit <= crypto_pwhash_OPSLIMIT_MAX): raise ValueError("invalid opslimit")
    if not (crypto_pwhash_MEMLIMIT_MIN <= memlimit <= crypto_pwhash_MEMLIMIT_MAX): raise ValueError("invalid memlimit")
    out = ctypes.create_string_buffer(crypto_pwhash_STRBYTES)
    __check(sodium.crypto_pwhash_str(ctypes.byref(out), passwd, ctypes.c_ulonglong(len(passwd)), ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit)))
    return out.raw

# int crypto_pwhash_str_verify(const char str[crypto_pwhash_STRBYTES],
#                              const char * const passwd,
#                              unsigned long long passwdlen);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash_str_verify(pstr, passwd):
    if None in (pstr, passwd) or len(pstr) != crypto_pwhash_STRBYTES:
        raise ValueError("invalid parameters")
    if not (crypto_pwhash_PASSWD_MIN < len(passwd) <= crypto_pwhash_PASSWD_MAX): raise ValueError("invalid passwd len")
    return sodium.crypto_pwhash_str_verify(pstr, passwd, ctypes.c_ulonglong(len(passwd))) == 0



"""
