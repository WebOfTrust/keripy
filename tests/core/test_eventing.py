# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import pytest

import pysodium
import blake3

from keri.kering import Version
from keri.kering import ValidationError, EmptyMaterialError, DerivationError

from keri.core.coring import CrySelDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import CryOneSizes, CryOneRawSizes, CryTwoSizes, CryTwoRawSizes
from keri.core.coring import CryFourSizes, CryFourRawSizes, CrySizes, CryRawSizes
from keri.core.coring import CryMat, Verfer, Signer, Diger, Nexter, Aider
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

from keri.core.eventing import Kever, Kevery, Keger


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


def test_kevery():
    """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """
    kevery = Kevery()
    """ Done Test """

def test_kever():
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """
    with pytest.raises(TypeError):
        kever = Kever()

    # Transferable case
    # Setup inception key event dict
    # create current key
    sith = 1  #  one signer
    skp0 = Signer()  #  original signing keypair transferable default
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    nxtsith = 1 #  one signer
    skp1 = Signer()  #  next signing keypair transferable is default
    assert skp1.code == CryOneDex.Ed25519_Seed
    assert skp1.verfer.code == CryOneDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute next digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                id="",  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=keys,  # list of signing keys each qual Base64
                next=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                conf=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )


    # Derive AID from ked
    aid0 = Aider(ked=ked0)
    assert aid0.code == CryOneDex.Ed25519

    # update ked with id
    ked0["id"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    kever = Kever(serder=tser0, sigxers=[tsig0])


    """ Done Test """

def test_keger():
    """
    Test the support functionality for Keger class
    Key Event Generator
    """
    keger = Keger()
    """ Done Test """


def test_process_nontransferable():
    """
    Test process of generating and validating key event messages
    """

    # Ephemeral (Nontransferable) case
    skp0 = Signer(transferable=False)  #  original signing keypair non transferable
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519N

    # Derive AID by merely assigning verifier public key
    aid0 = Aider(qb64=skp0.verfer.qb64)
    assert aid0.code == CryOneDex.Ed25519N

    # Ephemeral may be used without inception event
    # but when used with inception event must be compatible event
    sn = 0  #  inception event so 0
    sith = 1 #  one signer
    nxt = ""  # non-transferable so next is empty
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                id=aid0.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aid0.qb64],  # list of signing keys each qual Base64
                next=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                conf=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )

    # verify derivation of aid0 from ked0
    assert aid0.verify(ked=ked0)

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create packet
    msgb0 = bytearray(tser0.raw + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw

    del msgb0[:rser0.size]  # strip off event from front

    # extract attached sigs if any
    if "idxs" not in rser0.ked or not rser0.ked["idxs"]:  # no info on attached sigs
        assert False

    else:
        ridxs = rser0.ked["idxs"]  # exract signature indexes
        if isinstance(ridxs, list):
            for idx in ridxs:
                pass
            assert False

        else:
            nrsigs = int(ridxs, 16)
            assert nrsigs == 1
            keys = rser0.ked["keys"]
            for i in range(nrsigs): # verify each attached signature
                rsig = SigMat(qb64=msgb0)
                assert rsig.index == 0
                verfer = Verfer(qb64=keys[rsig.index])
                assert verfer.qb64 == aid0.qb64
                assert verfer.qb64 == skp0.verfer.qb64
                assert verfer.verify(rsig.raw, rser0.raw)
                del msgb0[:len(rsig.qb64)]

    # verify aid
    raid0 = Aider(qb64=rser0.ked["id"])
    assert raid0.verify(ked=rser0.ked)
    """ Done Test """

def test_process_transferable():
    """
    Test process of generating and validating key event messages
    """
    # Transferable case
    # Setup inception key event dict
    # create current key
    sith = 1  #  one signer
    skp0 = Signer()  #  original signing keypair transferable default
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    nxtsith = 1 #  one signer
    skp1 = Signer()  #  next signing keypair transferable is default
    assert skp1.code == CryOneDex.Ed25519_Seed
    assert skp1.verfer.code == CryOneDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute next digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                id="",  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=keys,  # list of signing keys each qual Base64
                next=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                conf=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )


    # Derive AID from ked
    aid0 = Aider(ked=ked0)
    assert aid0.code == CryOneDex.Ed25519

    # update ked with id
    ked0["id"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create packet
    msgb0 = bytearray(tser0.raw + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw

    del msgb0[:rser0.size]  # strip off event from front

    # extract attached idxs if any
    if "idxs" not in rser0.ked or not rser0.ked["idxs"]:  # no info on attached idxs
        assert False

    else:
        ridxs = rser0.ked["idxs"]  # exract signature indexes
        if isinstance(ridxs, list):
            for idx in ridxs:
                pass
            assert False

        else:
            nrsigs = int(ridxs, 16)
            assert nrsigs == 1
            keys = rser0.ked["keys"]
            for i in range(nrsigs): # verify each attached signature
                rsig = SigMat(qb64=msgb0)
                assert rsig.index == 0
                verfer = Verfer(qb64=keys[rsig.index])
                assert verfer.qb64 == aid0.qb64
                assert verfer.qb64 == skp0.verfer.qb64
                assert verfer.verify(rsig.raw, rser0.raw)
                del msgb0[:len(rsig.qb64)]

    # verify aid
    raid0 = Aider(qb64=rser0.ked["id"])
    assert raid0.verify(ked=rser0.ked)

    #verify nxt digest from event is still valid
    rnext1 = Nexter(qb64=rser0.ked["next"])
    assert rnext1.verify(sith=nxtsith, keys=nxtkeys)
    """ Done Test """



def test_process_manual():
    """
    Test manual process of generating and validating inception key event message
    """
    # create qualified aid in basic format
    # workflow is start with seed and save seed. Seed in this case is 32 bytes
    # aidseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    aidseed = b'p6\xac\xb7\x10R\xc4\x9c7\xe8\x97\xa3\xdb!Z\x08\xdf\xfaR\x07\x9a\xb3\x1e\x9d\xda\xee\xa2\xbc\xe4;w\xae'
    assert len(aidseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(aidseed)
    assert verkey == b'\xaf\x96\xb0p\xfb0\xa7\xd0\xa4\x18\xc9\xdc\x1d\x86\xc2:\x98\xf7?t\x1b\xde.\xcc\xcb;\x8a\xb0\xa2O\xe7K'
    assert len(verkey) == 32

    # create qualified aid in basic format
    aidmat = CryMat(raw=verkey, code=CryOneDex.Ed25519)
    assert aidmat.qb64 == 'Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'

    # create qualified next public key in basic format
    nxtseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    nxtseed = b'm\x04\xf9\xe4\xd5`<\x91]>y\xe9\xe5$\xb6\xd8\xd5D\xb7\xea\xf6\x13\xd4\x08TYL\xb6\xc7 D\xc7'
    assert len(nxtseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(nxtseed)
    assert verkey == b'\xf5DOB:<\xcd\x16\x18\x9b\x83L\xa5\x0c\x98X\x90C\x1a\xb30O\xa5\x0f\xe39l\xa6\xdfX\x185'
    assert len(verkey) == 32

    # create qualified nxt key in basic format
    nxtkeymat = CryMat(raw=verkey, code=CryOneDex.Ed25519)
    assert nxtkeymat.qb64 == 'D9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'

    # create next hash
    nxtsith =  "{:x}".format(1)  # lowecase hex no leading zeros
    assert nxtsith == "1"
    nxts = []  # create list to concatenate for hashing
    nxts.append(nxtsith.encode("utf-8"))
    nxts.append(nxtkeymat.qb64.encode("utf-8"))
    nxtsraw = b''.join(nxts)
    assert nxtsraw == b'1D9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'
    nxtdig = blake3.blake3(nxtsraw).digest()
    assert nxtdig == b'\xdeWy\xd3=\xcb`\xce\xe9\x99\x0cF\xdd\xb2C6\x03\xa7F\rS\xd6\xfem\x99\x89\xac`<\xaa\x88\xd2'

    nxtdigmat = CryMat(raw=nxtdig, code=CryOneDex.Blake3_256)
    assert nxtdigmat.qb64 == 'E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI'

    sn =  0
    sith = 1
    toad = 0
    index = 0

    #create key event dict
    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                id=aidmat.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aidmat.qb64],  # list of signing keys each qual Base64
                next=nxtdigmat.qb64,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                conf=[],  # list of config ordered mappings may be empty
                idxs=["{:x}".format(index)]  # optional list of lowercase hex strings no leading zeros or single lowercase hex string
               )


    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"vs":"KERI10JSON000108_","id":"Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'
                          b'","sn":"0","ilk":"icp","sith":"1","keys":["Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7M'
                          b'yzuKsKJP50s"],"next":"E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI","toad":"'
                          b'0","wits":[],"conf":[],"idxs":["0"]}')

    assert txsrdr.size == 264

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = CryMat(raw=txdig, code=CryOneDex.Blake3_256)
    assert txdigmat.qb64 == 'EPYPv3ouNLw45lAI1B40Io4KX935qfxcWdBrtA6-leFc'

    assert txsrdr.dig == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  #  sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = SigMat(raw=sig0raw, code=SigTwoDex.Ed25519, index=index)
    assert txsigmat.qb64 == 'AAxW5lxJxAmenWwfvgGeDgciKKT-7hP-jOZrHMVCAHgGlnpYX8dfzjppJvbC5s9GQWN4w_1IfTKcwWrU3C9KTYDA'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 352  #  264 + 88

    #  Recieve side
    rxsrdr = Serder(raw=msgb)
    assert rxsrdr.size == txsrdr.size
    assert rxsrdr.ked == ked0

    rxsigqb64 = msgb[rxsrdr.size:].decode("utf-8")
    assert len(rxsigqb64) == len(txsigmat.qb64)
    rxsigmat = SigMat(qb64=rxsigqb64)
    assert rxsigmat.index == index

    rxaidqb64 = rxsrdr.ked["id"]
    rxaidmat = CryMat(qb64=rxaidqb64)
    assert rxaidmat.qb64 == aidmat.qb64
    assert rxaidmat.code == CryOneDex.Ed25519

    rxverqb64 = rxsrdr.ked["keys"][index]
    rxvermat = CryMat(qb64=rxverqb64)
    assert rxvermat.qb64 == rxaidmat.qb64  #  basic derivation same

    indexes = [ int(index, 16) for index in rxsrdr.ked["idxs"]]
    assert indexes == [0]
    assert indexes[0] == rxsigmat.index

    result = pysodium.crypto_sign_verify_detached(rxsigmat.raw, rxsrdr.raw, rxvermat.raw)
    assert not result  # None if verifies successfully else raises ValueError
    """ Done Test """


if __name__ == "__main__":
        test_kever()
