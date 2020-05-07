# -*- encoding: utf-8 -*-
"""
tests.test_coring module

"""
import pytest

import pysodium

def test_stuff():
    """

    """
    sb = pysodium.crypto_sign_SEEDBYTES
    assert sb == 32

    # Create registration for issuer Ike
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)

    assert  len(seed) == 32

    # Ann's seed
    seed = (b'PTi\x15\xd5\xd3`\xf1u\x15}^r\x9bfH\x02l\xc6\x1b\x1d\x1c\x0b9\xd7{\xc0_'
        b'\xf2K\x93`')

    assert  len(seed) == 32

    # creates signing/verification key pair
    vk, sk = pysodium.crypto_sign_seed_keypair(seed)

    assert len(vk) == 32
    assert len(sk) == 64

    assert seed == sk[:32]
    assert vk == sk[32:]

    #  try key stretching from 16 bytes using  pysodium.crypto_pwhash_



