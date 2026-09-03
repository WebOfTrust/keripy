# -*- coding: utf-8 -*-
"""
tests.sedi.test_sedi module

"""
import json
import os
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest

from jsonschema import Draft202012Validator

from keri import Vrsn_2_0, Kinds, Protocols, Ilks
from keri.core import MtrDex, Salter, incept


def test_core_identity():
    """Test core identity recipt and entitlement


    IAL3 process

    Proof-of-control over SMAID by citizen

    """
    """
    Create incepting key states for participants:
        Sue as State Issuer Department Level
        Pat as Proofer (Identity)
        Guy as Guardian Parent Citizen
        Wyn as Ward Child Citizen



    use same salter for a set of keys where each uses same salt but different path.
          salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    """
    salt = b'sediacdcworksalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABzZWRpYWNkY3dvcmtzYWx0'  # CESR encoded

    """
    Create set of signers each with private signing key and public verification key
        Under the hood, using Argon2, Salter creates a stretched 32 byte seed
        from 16 byte salt thusly;
        size=32
        path='0'
        salt=b'sediacdcworksalt'
        opslimit=1
        memlimit=8192
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
        Salter then uses 32 byte seed as private key to create public key Ed25519
        verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
        First 32 bytes of this internal sigkey is seed as private key so we can
        use seed externally as private signing key and verkey as public verification key
        Then Salter.signers generates a set of Signer instances with key pairs
        for signing all based on internal salt but different path for each in
        stretch

    """
    signers = salter.signers(count=8, transferable=True, temp=True)

    # create witness signers as nontransferable
    walt = b'sediacdcworkwits'  # different salt for witness keys
    walter = Salter(raw=walt)
    wigners = walter.signers(count=4,transferable=False, temp=True)


    # Create Sue's AID (State Issuer) with single sig single wit inception event JSON
    sueKeys = [signers[0].verfer.qb64]  # incepting public verification key(s)
    sueNKeys = [signers[1].verfer.qb64]  # next (rotation) public verification key(s)
    sueWits = [wigners[0].verfer.qb64]  # witness aids (same as public verkey)
    sueISerder = incept(sueKeys, code=MtrDex.Blake3_256, ndigs=sueNKeys, wits=sueWits,
                    version=Vrsn_2_0, kind=Kinds.json)

    assert sueISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        'i': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        's': '0',
        'kt': '1',
        'k': ['DOYgdUBxTqXE8f8se-S8JlqAAzRTLa1YV4_E6NkHBv6j'],
        'nt': '1',
        'n': ['DFSfjZGPYPHtEdq8J6qx5EfBXvZxL2K-wGtb5IxFeOGC'],
        'bt': '1',
        'b': ['BHxXu_PNY1C1MKAGiy_CusBjyd9Ys29v4tFNFJQd56GB'],
        'c': [],
        'a': []
    }

    assert sueISerder.aid == 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-'  # State Issuer Sue's AID
    assert sueISerder.said == sueISerder.aid

    # Create Pat's AID (Identity Proofer) with single sig single wit inception event JSON
    patKeys = [signers[2].verfer.qb64]  # incepting public verification key(s)
    patNKeys = [signers[3].verfer.qb64]  # next (rotation) public verification key(s)
    patWits = [wigners[1].verfer.qb64]  # witness aids (same as public verkey)
    patISerder = incept(patKeys, code=MtrDex.Blake3_256, ndigs=patNKeys, wits=patWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert patISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh',
        'i': 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh',
        's': '0',
        'kt': '1',
        'k': ['DKq0C5-ptAqPmpDi-hwPzNeIfZUWuBeq_bbb6UCF0_Oz'],
        'nt': '1',
        'n': ['DPJFmK2jfmifFVYvsCPGw-FQbl2xmHJ7fEb_nLlWx4pm'],
        'bt': '1',
        'b': ['BCxpCMenkwNVaaoDKiK0_U3IlCSHPGzQHdm9CYIotUY8'],
        'c': [],
        'a': []
    }
    assert patISerder.aid == 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh'  # Proofer Pat's AID
    assert patISerder.said == patISerder.aid

    # Create Guy's SMAID (Guardian Parent) with single sig single wit inception event JSON
    guyKeys = [signers[3].verfer.qb64]  # incepting public verification key(s)
    guyNKeys = [signers[4].verfer.qb64]  # next (rotation) public verification key(s)
    guyWits = [wigners[2].verfer.qb64]  # witness aids (same as public verkey)
    guyISerder = incept(guyKeys, code=MtrDex.Blake3_256, ndigs=guyNKeys, wits=guyWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert guyISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3',
        'i': 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3',
        's': '0',
        'kt': '1',
        'k': ['DPJFmK2jfmifFVYvsCPGw-FQbl2xmHJ7fEb_nLlWx4pm'],
        'nt': '1',
        'n': ['DLew-r-sGNE2Rr1mKBeNGI78UFgAM4bQ1LprmHHNoFUT'],
        'bt': '1',
        'b': ['BG3WKpXb9Ma91C4TnfbMCuLJ0_mgoCbrpMopUuH7M-cM'],
        'c': [],
        'a': []
    }
    assert guyISerder.aid == 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3'  # Guardian Guy's AID
    assert guyISerder.said == guyISerder.aid

    # Create Wyn's SMAID (Ward Child) with single sig single wit inception event JSON
    wynKeys = [signers[3].verfer.qb64]  # incepting public verification key(s)
    wynNKeys = [signers[4].verfer.qb64]  # next (rotation) public verification key(s)
    wynWits = [wigners[2].verfer.qb64]  # witness aids (same as public verkey)
    wynISerder = incept(wynKeys, code=MtrDex.Blake3_256, ndigs=wynNKeys, wits=wynWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert wynISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3',
        'i': 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3',
        's': '0',
        'kt': '1',
        'k': ['DPJFmK2jfmifFVYvsCPGw-FQbl2xmHJ7fEb_nLlWx4pm'],
        'nt': '1',
        'n': ['DLew-r-sGNE2Rr1mKBeNGI78UFgAM4bQ1LprmHHNoFUT'],
        'bt': '1',
        'b': ['BG3WKpXb9Ma91C4TnfbMCuLJ0_mgoCbrpMopUuH7M-cM'],
        'c': [],
        'a': []
    }

    assert wynISerder.aid == 'EFBN1EhcYJ17oA7hTVokJlLVnr8H5saVa_zX1ajXwnX3'  # Ward Wyn's AID
    assert wynISerder.said == wynISerder.aid


    """
    Setup Sue's Issuer ACDC Registries




    """

    # Identity Assurance Receipt as Signed by proofing agent (not anchored) ACDC
    iarMad = \
    {
        "v": "",  # VersionString
        "t": "acm",
        "d": "",  # SAID
        "u": "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux",  # 128 bit entropy challenge salty nonce
        "i": "ProofingAgentAID",  # identity assurance proofing agent AID
        "s": "",  # schema of identity assurance receipt
        "a":
        {
            "d": "",  # SAID
            "i": "CitizenSMAID",  # citizens SEDI managment AID (SMAID)

            "given": "John",  # given name first name(s)
            "middle":"Henry Davis",  # middle name(s) other names
            "surname": "Smith",  # last name family name
            "dateOfBirth": "2020-08-22T17:50:09.988921+00:00",
            "placeOfBirth": \
            {
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "country": "United States",
            },
            "facialBiometric": "",
            "legalPresence": "TBD",
            "datetimeOfProofing": "2020-08-22T17:50:09.988921+00:00",
            "url": "uniquerequesturlforseditimelimited", # place to go to get core sedi
        }
    }

    # Challenge Nonce Seal anchored in KEL of SMAID
    cns = {}

    # Challenge Seal Reference to event in KEL of SMAID
    csr = {}

    # core sedi credential ACDC issued to SMAID
    coreMad = \
    {
        "v": "",  #version string
        "t": "acm",
        "d": "",  # said
        "u": "",  # unique entropy
        "i": "StateIssuerAID",  # State Department Level Issuer AID
        "rd": "",  # registy
        "s": "",  # schema
        "a":  # partially disclosable attributes
        {
            "d": "",
            "u": "",
            "i": "CitizenSEDI_AID",
            "given": \
            {
                "d": "",
                "u": "",
                "value": "John",
            },
            "middle": \
            {
                "d": "",
                "u": "",
                "value": "Henry Davis",
            },
            "surname": \
            {
                "d": "",
                "u": "",
                "value": "Smith",
            },
            "dateOfBirth": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00", # time MBZ
            },
            "placeOfBirth": \
            {
                "d": "",
                "u": "",
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "country": "United States",
            },
            "facialImage": \
            {
                "d": "",
                "u": "",
                "value": "",  # Digest of image, actual image is attached as blindable typed media block
            },
            "legalPresence": \
            {
                "d": "",
                "u": "",
                "value": "TBD",
            },
            "dateOfIssuance": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00",  # Time MBZ
            },
            "dateOfExpiration": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00",  # Time MBZ
            },
        },
        "r":
        {
            "d": "",
            "l": ""
        }
    }

    """Done Test"""



if __name__ == "__main__":
    test_core_identity()
