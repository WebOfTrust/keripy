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
from keri.core import MtrDex, Noncer, Salter, incept
from keri.acdc import regcept, blindate, update, acdcmap


def test_sedi_schema():
    """Test setup of schema for core SEDI acdcs"""



    """done test"""

def test_core_identity():
    """Test core identity receipt and entitlement

    IAL3 process

    Proof-of-control over SMAID by citizen

    Create incepting key states for participants:
        Sue as State Issuer Department Level
        Pat as Proofer (Identity)
        Guy as Guardian Parent Citizen
        Gal as Guardian Parent Citizen
        Wyn as Ward Child Citizen

    use same salter for a set of keys where each uses same salt but different path.
          salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)

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

    Setup Sue's Issuer ACDC Registries and shared secret salts for blinds
        Create a set of unique entropy Noncer instances for the ue fields (old uuid)
        Creates a set of shared secret salts for later blinded update events
        Create datetime stap for rip events
        Creeate a set of rip events for vacuous registrys
        Create list of rids (registry id as rip event said )
    """

    salt = b'sediacdcworksalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABzZWRpYWNkY3dvcmtzYWx0'  # CESR encoded

    # create signers, each contains siging key pair
    signers = salter.signers(count=10, transferable=True, temp=True)  # two per

    # create witness signers as nontransferable, each contains key pair
    walt = b'sediacdcworkwits'  # different salt for witness keys
    walter = Salter(raw=walt)
    wigners = walter.signers(count=5,transferable=False, temp=True)  # one per


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
    sue = sueISerder.aid
    assert sue == 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-'  # State Issuer Sue's AID
    assert sueISerder.said == sue


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
    pat = patISerder.aid
    assert pat== 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh'  # Proofer Pat's AID
    assert patISerder.said == pat

    # Create Guy's SMAID (Guardian Parent) with single sig single wit inception event JSON
    guyKeys = [signers[4].verfer.qb64]  # incepting public verification key(s)
    guyNKeys = [signers[5].verfer.qb64]  # next (rotation) public verification key(s)
    guyWits = [wigners[2].verfer.qb64]  # witness aids (same as public verkey)
    guyISerder = incept(guyKeys, code=MtrDex.Blake3_256, ndigs=guyNKeys, wits=guyWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert guyISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        's': '0',
        'kt': '1',
        'k': ['DLew-r-sGNE2Rr1mKBeNGI78UFgAM4bQ1LprmHHNoFUT'],
        'nt': '1',
        'n': ['DPZOdALUpQMCqhrj2d43BSpwzSW7kn0z15odwVwhU4no'],
        'bt': '1',
        'b': ['BG3WKpXb9Ma91C4TnfbMCuLJ0_mgoCbrpMopUuH7M-cM'],
        'c': [],
        'a': []
    }
    guy = guyISerder.aid
    assert guy == 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR'  # Guardian Guy's AID
    assert guyISerder.said == guy

    # Create Gal's SMAID (Guardian Parent) with single sig single wit inception event JSON
    galKeys = [signers[6].verfer.qb64]  # incepting public verification key(s)
    galNKeys = [signers[7].verfer.qb64]  # next (rotation) public verification key(s)
    galWits = [wigners[3].verfer.qb64]  # witness aids (same as public verkey)
    galISerder = incept(galKeys, code=MtrDex.Blake3_256, ndigs=galNKeys, wits=galWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert galISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        'i': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        's': '0',
        'kt': '1',
        'k': ['DItB34DWsii2vL0nFZbFBRZQljDGmKTY72zZmMAY9_5e'],
        'nt': '1',
        'n': ['DBHznQBZMr94KRQ4lN8e1jS-IWCE_QmrE78d8I0coqyT'],
        'bt': '1',
        'b': ['BDkey6lzDqWVw6ANa6zr81Yl7gy6nzDblbt1_ENNAw0V'],
        'c': [],
        'a': []
    }
    gal = galISerder.aid
    assert gal == 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY'  # Guardian Guy's AID
    assert galISerder.said == gal

    # Create Wyn's SMAID (Ward Child) with single sig single wit inception event JSON
    wynKeys = [signers[8].verfer.qb64]  # incepting public verification key(s)
    wynNKeys = [signers[9].verfer.qb64]  # next (rotation) public verification key(s)
    wynWits = [wigners[4].verfer.qb64]  # witness aids (same as public verkey)
    wynISerder = incept(wynKeys, code=MtrDex.Blake3_256, ndigs=wynNKeys, wits=wynWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert wynISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1',
        'i': 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1',
        's': '0',
        'kt': '1',
        'k': ['DOZasipADYGcDse0RsrrdYKpn2RSLy3U6EDEi4yWrwjm'],
        'nt': '1',
        'n': ['DEep2D7cgt5AmS_QzPvdz0xaGnc9iDX5TO-rwPq9hxUt'],
        'bt': '1',
        'b': ['BA87lX6lbHymHSSunaf4b1X07KvquE-79TthnQ9_ks9A'],
        'c': [],
        'a': []
    }
    wyn = wynISerder.aid
    assert wyn == 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1'  # Ward Wyn's AID
    assert wynISerder.said == wyn


    # Setup Registries for Sue as Issuer
    # Create u field values for rip events
    ueraws = [b'sediacdcworkreg' + b'%0x'%(i, ) for i in range(8)]
    uens = [Noncer(raw=raw).qb64 for raw in ueraws]  # unique entropy nonce qb64
    # create shared secret salts for bup events
    ssraws = [b'sediacdcworkreg' + b'%0x'%(i, ) for i in range(8)]
    ssss = [Noncer(raw=raw).qb64 for raw in ssraws]  # shared secret salt qb64
    stamp = '2026-09-00T08:30:00.000000+00:00'

    # create registry serders for sue as Issuer
    regserders = [regcept(israid=sue, uuid=ue, stamp=stamp) for ue in uens]
    rids = [rss.said for rss in regserders]

    assert regserders[0].sad == \
    {
        'v': 'ACDCCAACAAJSONAADa.',
        't': 'rip',
        'd': 'ECvi_BgZw_Jp3qaVoNC-kOjW7X33i7fVQ0vIITy8Nfr5',
        'u': '0ABzZWRpYWNkY3dvcmtyZWcw',
        'i': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        'n': '0',
        'dt': '2026-09-00T08:30:00.000000+00:00'
    }
    assert rids[0] == regserders[0].said == 'ECvi_BgZw_Jp3qaVoNC-kOjW7X33i7fVQ0vIITy8Nfr5'
    assert regserders[0].israid == sue
    assert regserders[0].nonce == uens[0]
    assert regserders[0].sner.num == 0
    assert regserders[0].stamp == stamp



    # Identity Assurance Receipt (iar) as Signed by proofing agent (not anchored) ACDC
    iarMad = \
    {
        "v": "",  # VersionString
        "t": "acm",
        "d": "",  # SAID
        "u": "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux",  # 128 bit entropy challenge salty nonce
        "i": pat,  # pat as identity assurance proofing agent AID
        "s": "",  # schema of identity assurance receipt
        "a":
        {
            "d": "",  # SAID
            "i": "CitizenSMAID",  # citizens SEDI managment AID (SMAID)
            "givenName": "John",  # given name first name(s)
            "middleName":"Henry Davis",  # middle name(s) other names
            "familyName": "Smith",  # last name family name
            "dateOfBirth": "2020-08-22T00:00:00.000000+00:00",  # time MBZ
            "placeOfBirth": \
            {
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "country": "United States",
            },
            "facialImage": "",
            "legalPresence": "TBD",
            "datetimeOfProofing": "2026-09-01T09:30:00.000000+00:00",
            "url": "https://example.com/sedi/here", # place to go to get core sedi
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
            "givenName": \
            {
                "d": "",
                "u": "",
                "value": "John",
            },
            "middleName": \
            {
                "d": "",
                "u": "",
                "value": "Henry Davis",
            },
            "familyName": \
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
    test_sedi_schema()
    test_core_identity()
