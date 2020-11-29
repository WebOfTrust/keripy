# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import pytest

import pysodium
import blake3
from math import ceil

from keri.kering import Version
from keri.kering import (ValidationError, EmptyMaterialError, DerivationError,
                         ShortageError)

from keri.core.coring import CrySelDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import CryOneSizes, CryOneRawSizes, CryTwoSizes, CryTwoRawSizes
from keri.core.coring import CryFourSizes, CryFourRawSizes, CrySizes, CryRawSizes
from keri.core.coring import CryMat, CryCounter
from keri.core.coring import Verfer, Signer, Diger, Nexter, Prefixer
from keri.core.coring import generateSigners, generateSecrets
from keri.core.coring import SigSelDex, SigTwoDex, SigTwoSizes, SigTwoRawSizes
from keri.core.coring import SigFourDex, SigFourSizes, SigFourRawSizes
from keri.core.coring import SigFiveDex, SigFiveSizes, SigFiveRawSizes
from keri.core.coring import SigSizes, SigRawSizes
from keri.core.coring import IntToB64, B64ToInt
from keri.core.coring import SigMat, SigCounter
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever
from keri.core.coring import Serder
from keri.core.coring import Ilkage, Ilks

from keri.core.eventing import TraitDex, LastEstLoc
from keri.core.eventing import SealDigest, SealRoot, SealEvent, SealLocation
from keri.core.eventing import (incept, rotate, interact, receipt, chit,
                                delcept, deltate)
from keri.core.eventing import Kever, Kevery

from keri.db.dbing import dgKey, snKey, openDB, Baser

from keri.help import ogling

blogger, flogger = ogling.ogler.getLoggers()


def test_lastestloc():
    """
    Test LastEstLoc namedtuple
    """
    lastEst = LastEstLoc(sn=1, dig='E12345')

    assert isinstance(lastEst, LastEstLoc)

    assert 1 in lastEst
    assert lastEst.sn == 1
    assert 'E12345' in lastEst
    assert lastEst.dig == 'E12345'

    """End Test """

def test_seals():
    """
    Test seal namedtuples

    """
    seal = SealDigest(dig='E12345')
    assert isinstance(seal, SealDigest)
    assert 'E12345' in seal
    assert seal.dig == 'E12345'
    assert seal._asdict() == dict(dig='E12345')

    seal = SealRoot(root='EABCDE')
    assert isinstance(seal, SealRoot)
    assert 'EABCDE' in seal
    assert seal.root == 'EABCDE'
    assert seal._asdict() == dict(root='EABCDE')

    seal = SealEvent(pre='B4321', dig='Eabcd')
    assert isinstance(seal, SealEvent)
    assert 'B4321' in seal
    assert seal.pre == 'B4321'
    assert 'Eabcd' in seal
    assert seal.dig == 'Eabcd'
    assert seal._asdict() == dict(pre='B4321', dig='Eabcd')
    assert seal._fields == ('pre', 'dig')

    seal = SealLocation(pre='B4321', sn='1', ilk='ixn', dig='Eabcd')
    assert isinstance(seal, SealLocation)
    assert 'B4321' in seal
    assert seal.pre == 'B4321'
    assert '1' in seal
    assert seal.sn == '1'
    assert 'ixn' in seal
    assert seal.ilk == 'ixn'
    assert 'Eabcd' in seal
    assert seal.dig == 'Eabcd'
    assert seal._asdict() == dict(pre='B4321', sn='1', ilk='ixn', dig='Eabcd')
    assert seal._fields == ('pre', 'sn', 'ilk', 'dig')

    """End Test """

def test_keyeventfuncs():
    """
    Test the support functionality for key event generation functions

    """
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    # Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False)  #  original signing keypair non transferable
    assert signer0.code == CryOneDex.Ed25519_Seed
    assert signer0.verfer.code == CryOneDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["pre"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["nxt"] == ""
    assert serder.raw == (b'{"vs":"KERI10JSON0000cf_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c","sn":"0","ilk":"icp","sith":"1","keys":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                          b'Z-Wk1x4ejhcc"],"nxt":"","toad":"0","wits":[],"cnfg":[]}')


    with pytest.raises(DerivationError):
        # non-empty nxt wtih non-transferable code
        serder = incept(keys=keys0, code=CryOneDex.Ed25519N, nxt="ABCDE")

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  #  original signing keypair transferable default
    assert signer0.code == CryOneDex.Ed25519_Seed
    assert signer0.verfer.code == CryOneDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["pre"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["nxt"] == ""
    assert serder.raw == (b'{"vs":"KERI10JSON0000cf_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c","sn":"0","ilk":"icp","sith":"1","keys":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                          b'Z-Wk1x4ejhcc"],"nxt":"","toad":"0","wits":[],"cnfg":[]}')


    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
            b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  #  next signing keypair transferable is default
    assert signer1.code == CryOneDex.Ed25519_Seed
    assert signer1.verfer.code == CryOneDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nexter1 = Nexter(keys=keys1)  # dfault sith is 1
    assert nexter1.sith == '1'  # default from keys
    nxt1 = nexter1.qb64  # transferable so nxt is not empty
    assert nxt1 == 'EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4'
    serder0 = incept(keys=keys0, nxt=nxt1)
    pre = serder0.ked["pre"]
    assert serder0.ked["pre"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder0.ked["sn"] == '0'
    assert serder0.ked["ilk"] == Ilks.icp
    assert serder0.ked["nxt"] == nxt1
    assert serder0.raw == (b'{"vs":"KERI10JSON0000fb_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"0","ilk":"icp","sith":"1","keys":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                           b'Z-Wk1x4ejhcc"],"nxt":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","toad":"'
                           b'0","wits":[],"cnfg":[]}')

    assert serder0.dig == 'EIIUSTX04qnUbyuJiJc-udBgaKKoqK-XNUmA6eG7JKUA'


    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
            b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  #  next signing keypair transferable is default
    assert signer2.code == CryOneDex.Ed25519_Seed
    assert signer2.verfer.code == CryOneDex.Ed25519
    keys2 = [signer2.verfer.qb64]
    # compute nxt digest
    nexter2 = Nexter(keys=keys2)
    assert nexter2.sith == '1'  # default from keys
    nxt2 = nexter2.qb64  # transferable so nxt is not empty
    assert nxt2 == 'EAXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U'
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
    assert serder1.ked["pre"] == pre
    assert serder1.ked["sn"] == '1'
    assert serder1.ked["ilk"] == Ilks.rot
    assert serder1.ked["nxt"] == nxt2
    assert serder1.ked["dig"] == serder0.dig
    assert serder1.raw == (b'{"vs":"KERI10JSON00013a_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"1","ilk":"rot","dig":"EIIUSTX04qnUbyuJiJc-udBgaKKoqK-XNUmA6eG7JKUA"'
                           b',"sith":"1","keys":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"nxt":"E'
                           b'AXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U","toad":"0","cuts":[],"adds":[],'
                           b'"data":[]}')

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.dig, sn=2)
    assert serder2.ked["pre"] == pre
    assert serder2.ked["sn"] == '2'
    assert serder2.ked["ilk"] == Ilks.ixn
    assert serder2.ked["dig"] == serder1.dig
    assert serder2.raw == (b'{"vs":"KERI10JSON0000a3_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"2","ilk":"ixn","dig":"Ehl5-_BQFcAKqweFqEpqR6ClTAaJh3vrbHJPfOpISOOQ"'
                           b',"data":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, dig=serder2.dig)
    assert serder3.ked["pre"] == pre
    assert serder3.ked["sn"] == "0"
    assert serder3.ked["ilk"] == Ilks.rct
    assert serder3.ked["dig"] == serder2.dig
    assert serder3.raw == (b'{"vs":"KERI10JSON000099_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"0","ilk":"rct","dig":"EgWxcdJkGUDh08x02ZW9pc-7XhrLe-zXJp3Vv5M35tTQ"'
                           b'}')

    # ValReceipt  chit
    serderA = incept(keys=keys0, nxt=nxt1, code=CryOneDex.Blake3_256)
    seal = SealEvent(pre=serderA.ked["pre"], dig=serderA.dig)
    assert seal.pre == serderA.ked["pre"] == 'EykXsFe4u9epTUQFCL7YdNdHxtdjCQUM-TVO8CgJAKb8'
    assert seal.dig == serderA.dig == 'EaqN7zhqTEhkeDZ2zMuNWHss_H_kH4cG7Li1jn2DXfrE'

    serder4 = chit(pre=pre, sn=2, dig=serder2.dig, seal=seal)
    assert serder4.ked["pre"] == pre
    assert serder4.ked["sn"] == "2"
    assert serder4.ked["ilk"] == Ilks.vrc
    assert serder4.ked["dig"] == serder2.dig
    assert serder4.ked["seal"] == seal._asdict()
    assert serder4.raw == (b'{"vs":"KERI10JSON00010c_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"2","ilk":"vrc","dig":"EgWxcdJkGUDh08x02ZW9pc-7XhrLe-zXJp3Vv5M35tTQ"'
                           b',"seal":{"pre":"EykXsFe4u9epTUQFCL7YdNdHxtdjCQUM-TVO8CgJAKb8","dig":"EaqN7zh'
                           b'qTEhkeDZ2zMuNWHss_H_kH4cG7Li1jn2DXfrE"}}')


    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
            b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD)  #  next signing keypair transferable is default
    assert signerD.code == CryOneDex.Ed25519_Seed
    assert signerD.verfer.code == CryOneDex.Ed25519
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nexterD = Nexter(keys=keysD)  # default sith is 1
    assert nexterD.sith == '1'  # default from keys
    nxtD = nexterD.qb64  # transferable so nxt is not empty
    assert nxtD == 'EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4'

    seal = SealLocation(pre='ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd',
                        sn="{:x}".format(3),
                        ilk=Ilks.ixn,
                        dig='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    serderD = delcept(keys=keysD, seal=seal, nxt=nxtD)
    pre = serderD.ked["pre"]
    assert serderD.ked["pre"] == 'E69svP3NQcz6GxN3BlSH6c5bVzP5aXV1VAeXN3xjzfHg'
    assert serderD.ked["sn"] == '0'
    assert serderD.ked["ilk"] == Ilks.dip
    assert serderD.ked["nxt"] == nxtD
    assert serderD.raw == (b'{"vs":"KERI10JSON000183_","pre":"E69svP3NQcz6GxN3BlSH6c5bVzP5aXV1VAeXN3xjzfH'
                           b'g","sn":"0","ilk":"dip","sith":"1","keys":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRi'
                           b'af9FdA_-_49A"],"nxt":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","toad":"'
                           b'0","wits":[],"cnfg":[],"seal":{"pre":"ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQ'
                           b'FCL7Yd","sn":"3","ilk":"ixn","dig":"EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhke'
                           b'DZ2z"}}')
    assert serderD.dig == 'E8Cy-3XpLhzRwPzoNT2zCOhvfIfbzNfvygjzok9HAk4U'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
            b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR)  #  next signing keypair transferable is default
    assert signerR.code == CryOneDex.Ed25519_Seed
    assert signerR.verfer.code == CryOneDex.Ed25519
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    nexterR = Nexter(keys=keysR)  # default sith is 1
    assert nexterR.sith == '1'  # default from keys
    nxtR = nexterR.qb64  # transferable so nxt is not empty
    assert nxtR == 'EAXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U'

    seal = SealLocation(pre='ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd',
                        sn="{:x}".format(4),
                        ilk=Ilks.ixn,
                        dig='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EIIUSTX04qnUbyuJiJc-udBgaKKoqK-XNUmA6eG7JKUA',
                      seal=seal,
                      sn=4,
                      nxt=nxtR)

    assert serderR.ked["pre"] == pre
    assert serderR.ked["sn"] == '4'
    assert serderR.ked["ilk"] == Ilks.drt
    assert serderR.ked["nxt"] == nxtR
    assert serderR.raw == (b'{"vs":"KERI10JSON0001c2_","pre":"E69svP3NQcz6GxN3BlSH6c5bVzP5aXV1VAeXN3xjzfH'
                           b'g","sn":"4","ilk":"drt","dig":"EIIUSTX04qnUbyuJiJc-udBgaKKoqK-XNUmA6eG7JKUA"'
                           b',"sith":"1","keys":["D8u3hipCxZnkM_O0jfaZLJMk9ERI428T0psRO0JVgh4c"],"nxt":"E'
                           b'AXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U","toad":"0","cuts":[],"adds":[],'
                           b'"data":[],"seal":{"pre":"ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd","sn":'
                           b'"4","ilk":"ixn","dig":"EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z"}}')
    assert serderR.dig == 'EqBzOygGY1BVOS1pBas7kW8K_nvAVAziWfGabzAEK3to'


    """ Done Test """



def test_kever():
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """

    with pytest.raises(TypeError):
        kever = Kever()

    with openDB() as db:  # Transferable case
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
        # compute nxt digest
        nexter = Nexter(sith=nxtsith, keys=nxtkeys)
        nxt = nexter.qb64  # transferable so nxt is not empty

        sn = 0  #  inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  #  one attached signature unspecified index

        ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                    pre="",  # qual base 64 prefix
                    sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                    ilk=Ilks.icp,
                    sith="{:x}".format(sith), # hex string no leading zeros lowercase
                    keys=keys,  # list of signing keys each qual Base64
                    nxt=nxt,  # hash qual Base64
                    toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                    wits=[],  # list of qual Base64 may be empty
                    cnfg=[],  # list of config ordered mappings may be empty
                   )


        # Derive AID from ked
        aid0 = Prefixer(ked=ked0, code = CryOneDex.Ed25519)
        assert aid0.code == CryOneDex.Ed25519
        assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["pre"] = aid0.qb64

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], baser=db)  # no error

    with openDB() as db:  # Non-Transferable case
        # Setup inception key event dict
        # create current key
        sith = 1  #  one signer
        skp0 = Signer(transferable=False)  #  original signing keypair non-transferable
        assert skp0.code == CryOneDex.Ed25519_Seed
        assert skp0.verfer.code == CryOneDex.Ed25519N
        keys = [skp0.verfer.qb64]

        # create next key Error case
        nxtsith = 1 #  one signer
        skp1 = Signer()  #  next signing keypair transferable is default
        assert skp1.code == CryOneDex.Ed25519_Seed
        assert skp1.verfer.code == CryOneDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nexter = Nexter(sith=nxtsith, keys=nxtkeys)
        nxt = nexter.qb64  # nxt is not empty so error

        sn = 0  #  inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  #  one attached signature unspecified index

        ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                    pre="",  # qual base 64 prefix
                    sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                    ilk=Ilks.icp,
                    sith="{:x}".format(sith), # hex string no leading zeros lowercase
                    keys=keys,  # list of signing keys each qual Base64
                    nxt=nxt,  # hash qual Base64
                    toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                    wits=[],  # list of qual Base64 may be empty
                    cnfg=[],  # list of config ordered mappings may be empty
                   )


        # Derive AID from ked
        with pytest.raises(DerivationError):
            aid0 = Prefixer(ked=ked0, code = CryOneDex.Ed25519N)

        # assert aid0.code == CryOneDex.Ed25519N
        # assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["pre"] =skp0.verfer.qb64

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], baser=db)

        #retry with valid empty nxt
        nxt = ""  # nxt is empty so no error
        sn = 0  #  inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  #  one attached signature unspecified index

        ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                        pre="",  # qual base 64 prefix
                        sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                        ilk=Ilks.icp,
                        sith="{:x}".format(sith), # hex string no leading zeros lowercase
                        keys=keys,  # list of signing keys each qual Base64
                        nxt=nxt,  # hash qual Base64
                        toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                        wits=[],  # list of qual Base64 may be empty
                        cnfg=[],  # list of config ordered mappings may be empty
                        )


        # Derive AID from ked
        aid0 = Prefixer(ked=ked0, code=CryOneDex.Ed25519N)

        assert aid0.code == CryOneDex.Ed25519N
        assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["pre"] = aid0.qb64

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], baser=db)  # valid so no error


    """ Done Test """


def test_keyeventsequence_0():
    """
    Test generation of a sequence of key events

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    #root = '0AZxWJGkCkpDcHuVG4GM1KVw'
    #rooter = CryMat(qb64=root)
    #assert rooter.qb64 == root
    #assert rooter.code == CryTwoDex.Seed_128
    #signers = generateSigners(root=rooter.raw, count=8, transferable=True)
    #secrets = [signer.qb64 for signer in signers]
    #secrets =generateSecrets(root=rooter.raw, count=8, transferable=True)

    # Test sequence of events given set of secrets
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

    #  create signers
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [signer.qb64 for signer in signers] == secrets

    pubkeys = [signer.verfer.qb64 for  signer in  signers]
    assert pubkeys == [
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI',
                        'DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8',
                        'DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ',
                        'D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU',
                        'D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM',
                        'DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4',
                        'DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg'
                     ]

    with openDB(name="controller") as conlgr:

        event_digs = [] # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        nexter1 = Nexter(keys=keys1)
        assert nexter1.sith == '1'
        nxt1 = nexter1.qb64  # transferable so nxt is not empty
        assert nxt1 == 'EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU'
        serder0 = incept(keys=keys0, nxt=nxt1)
        pre = serder0.ked["pre"]
        event_digs.append(serder0.dig)
        assert serder0.ked["pre"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
        assert serder0.ked["sn"] == '0'
        assert serder0.ked["sith"] == '1'
        assert serder0.ked["keys"] == keys0
        assert serder0.ked["nxt"] == nxt1
        assert serder0.dig == 'Ew3MXaYk3VBkPAFyTZN6Oyev5sbKM_6ycHAds-A6znN8'

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], baser=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.diger.qb64 == serder0.dig
        assert kever.ilk == Ilks.icp
        assert kever.sith == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.qb64 == nxt1
        assert kever.estOnly == False
        assert kever.transferable == True

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2
        keys2 = [signers[2].verfer.qb64]
        nexter2 = Nexter(keys=keys2)
        assert nexter2.sith == '1'
        nxt2 = nexter2.qb64  # transferable so nxt is not empty
        assert nxt2 == 'E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
        serder1 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
        event_digs.append(serder1.dig)
        assert serder1.ked["pre"] == pre
        assert serder1.ked["sn"] == '1'
        assert serder1.ked["sith"] == '1'
        assert serder1.ked["keys"] == keys1
        assert serder1.ked["nxt"] == nxt2
        assert serder1.ked["dig"] == serder0.dig

        # sign serialization and verify signature
        sig1 = signers[1].sign(serder1.raw, index=0)
        assert signers[1].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        kever.update(serder=serder1, sigers=[sig1])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.diger.qb64 == serder1.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.nexter.qb64 == nxt2

        # Event 2 Rotation Transferable
        # compute nxt digest from keys3
        keys3 = [signers[3].verfer.qb64]
        nexter3 = Nexter(keys=keys3)
        nxt3 = nexter3.qb64  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys2, dig=serder1.dig, nxt=nxt3, sn=2)
        event_digs.append(serder2.dig)
        assert serder2.ked["pre"] == pre
        assert serder2.ked["sn"] == '2'
        assert serder2.ked["keys"] == keys2
        assert serder2.ked["nxt"] == nxt3
        assert serder2.ked["dig"] == serder1.dig

        # sign serialization and verify signature
        sig2 = signers[2].sign(serder2.raw, index=0)
        assert signers[2].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 2
        assert kever.diger.qb64 == serder2.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys2
        assert kever.nexter.qb64 == nxt3

        # Event 3 Interaction
        serder3 = interact(pre=pre, dig=serder2.dig, sn=3)
        event_digs.append(serder3.dig)
        assert serder3.ked["pre"] == pre
        assert serder3.ked["sn"] == '3'
        assert serder3.ked["dig"] == serder2.dig

        # sign serialization and verify signature
        sig3 = signers[2].sign(serder3.raw, index=0)
        assert signers[2].verfer.verify(sig3.raw, serder3.raw)
        # update key event verifier state
        kever.update(serder=serder3, sigers=[sig3])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 3
        assert kever.diger.qb64 == serder3.dig
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.nexter.qb64 == nxt3  # no change

        # Event 4 Interaction
        serder4 = interact(pre=pre, dig=serder3.dig, sn=4)
        event_digs.append(serder4.dig)
        assert serder4.ked["pre"] == pre
        assert serder4.ked["sn"] == '4'
        assert serder4.ked["dig"] == serder3.dig

        # sign serialization and verify signature
        sig4 = signers[2].sign(serder4.raw, index=0)
        assert signers[2].verfer.verify(sig4.raw, serder4.raw)
        # update key event verifier state
        kever.update(serder=serder4, sigers=[sig4])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 4
        assert kever.diger.qb64 == serder4.dig
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.nexter.qb64 == nxt3  # no change

        # Event 5 Rotation Transferable
        # compute nxt digest from keys4
        keys4 = [signers[4].verfer.qb64]
        nexter4 = Nexter(keys=keys4)
        nxt4 = nexter4.qb64  # transferable so nxt is not empty
        serder5 = rotate(pre=pre, keys=keys3, dig=serder4.dig, nxt=nxt4, sn=5)
        event_digs.append(serder5.dig)
        assert serder5.ked["pre"] == pre
        assert serder5.ked["sn"] == '5'
        assert serder5.ked["keys"] == keys3
        assert serder5.ked["nxt"] == nxt4
        assert serder5.ked["dig"] == serder4.dig

        # sign serialization and verify signature
        sig5 = signers[3].sign(serder5.raw, index=0)
        assert signers[3].verfer.verify(sig5.raw, serder5.raw)
        # update key event verifier state
        kever.update(serder=serder5, sigers=[sig5])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 5
        assert kever.diger.qb64 == serder5.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys3
        assert kever.nexter.qb64 == nxt4

        # Event 6 Interaction
        serder6 = interact(pre=pre, dig=serder5.dig, sn=6)
        event_digs.append(serder6.dig)
        assert serder6.ked["pre"] == pre
        assert serder6.ked["sn"] == '6'
        assert serder6.ked["dig"] == serder5.dig

        # sign serialization and verify signature
        sig6 = signers[3].sign(serder6.raw, index=0)
        assert signers[3].verfer.verify(sig6.raw, serder6.raw)
        # update key event verifier state
        kever.update(serder=serder6, sigers=[sig6])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 6
        assert kever.diger.qb64 == serder6.dig
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
        assert kever.nexter.qb64 == nxt4    # no change

        # Event 7 Rotation to null NonTransferable Abandon
        nxt5 = ""  # nxt digest is empty
        serder7 = rotate(pre=pre, keys=keys4, dig=serder6.dig, nxt=nxt5, sn=7)
        event_digs.append(serder7.dig)
        assert serder7.ked["pre"] == pre
        assert serder7.ked["sn"] == '7'
        assert serder7.ked["keys"] == keys4
        assert serder7.ked["nxt"] == nxt5
        assert serder7.ked["dig"] == serder6.dig

        # sign serialization and verify signature
        sig7 = signers[4].sign(serder7.raw, index=0)
        assert signers[4].verfer.verify(sig7.raw, serder7.raw)
        # update key event verifier state
        kever.update(serder=serder7, sigers=[sig7])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 7
        assert kever.diger.qb64 == serder7.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys4
        assert kever.nexter == None
        assert not kever.transferable

        # Event 8 Interaction
        serder8 = interact(pre=pre, dig=serder7.dig, sn=8)
        assert serder8.ked["pre"] == pre
        assert serder8.ked["sn"] == '8'
        assert serder8.ked["dig"] == serder7.dig

        # sign serialization and verify signature
        sig8 = signers[4].sign(serder8.raw, index=0)
        assert signers[4].verfer.verify(sig8.raw, serder8.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder8, sigers=[sig8])

        # Event 8 Rotation
        keys5 = [signers[5].verfer.qb64]
        nexter5 = Nexter(keys=keys5)
        nxt5 = nexter4.qb64  # transferable so nxt is not empty
        serder8 = rotate(pre=pre, keys=keys5, dig=serder7.dig, nxt=nxt5, sn=8)
        assert serder8.ked["pre"] == pre
        assert serder8.ked["sn"] == '8'
        assert serder8.ked["dig"] == serder7.dig

        # sign serialization and verify signature
        sig8 = signers[4].sign(serder8.raw, index=0)
        assert signers[4].verfer.verify(sig8.raw, serder8.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder8, sigers=[sig8])

        db_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelIter(pre)]
        assert db_digs == event_digs

    """ Done Test """

def test_keyeventsequence_1():
    """
    Test generation of a sequence of key events
    Test when EstOnly trait in config of inception event. Establishment only
    """

    # Test sequence of events given set of secrets
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

    #  create signers
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [signer.qb64 for signer in signers] == secrets

    pubkeys = [signer.verfer.qb64 for  signer in  signers]
    assert pubkeys == [
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI',
                        'DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8',
                        'DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ',
                        'D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU',
                        'D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM',
                        'DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4',
                        'DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg'
                     ]

    # New Sequence establishment only
    with openDB(name="controller") as conlgr:
        event_digs = [] # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        nexter1 = Nexter(keys=keys1)
        nxt1 = nexter1.qb64  # transferable so nxt is not empty
        cnfg = [dict(trait=TraitDex.EstOnly)]  #  EstOnly
        serder0 = incept(keys=keys0, nxt=nxt1, cnfg=cnfg)
        event_digs.append(serder0.dig)
        pre = serder0.ked["pre"]
        assert serder0.ked["pre"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
        assert serder0.ked["sn"] == '0'
        assert serder0.ked["sith"] == '1'
        assert serder0.ked["keys"] == keys0
        assert serder0.ked["nxt"] == nxt1
        assert serder0.ked["cnfg"] == cnfg
        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], baser=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.diger.qb64 == serder0.dig
        assert kever.ilk == Ilks.icp
        assert kever.sith == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.qb64 == nxt1
        assert kever.estOnly == True
        assert kever.transferable == True

        # Event 1 Interaction. Because EstOnly, this event not included in KEL
        serder1 = interact(pre=pre, dig=serder0.dig, sn=1)
        assert serder1.ked["pre"] == pre
        assert serder1.ked["sn"] == '1'
        assert serder1.ked["dig"] == serder0.dig
        # sign serialization and verify signature
        sig1 = signers[0].sign(serder1.raw, index=0)
        assert signers[0].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # attempt ixn with estOnly
            kever.update(serder=serder1, sigers=[sig1])

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2  but from event0
        keys2 = [signers[2].verfer.qb64]
        nexter2 = Nexter(keys=keys2)
        assert nexter2.sith == '1'
        nxt2 = nexter2.qb64  # transferable so nxt is not empty
        assert nxt2 == 'E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
        serder2 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
        event_digs.append(serder2.dig)
        assert serder2.ked["pre"] == pre
        assert serder2.ked["sn"] == '1'
        assert serder2.ked["sith"] == '1'
        assert serder2.ked["keys"] == keys1
        assert serder2.ked["nxt"] == nxt2
        assert serder2.ked["dig"] == serder0.dig

        # sign serialization and verify signature
        sig2 = signers[1].sign(serder2.raw, index=0)
        assert signers[1].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.diger.qb64 == serder2.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.nexter.qb64 == nxt2

        db_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelIter(pre)]
        assert db_digs == event_digs

    """ Done Test """

def test_kevery():
    """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """
    blogger.setLevel("ERROR")

    # Test sequence of events given set of secrets
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

    with openDB("controller") as conlgr, openDB("validator") as vallgr:
        event_digs = [] # list of event digs in sequence

        # create event stream
        kes = bytearray()
        #  create signers
        signers = [Signer(qb64=secret) for secret in secrets]  # faster
        assert [signer.qb64 for signer in signers] == secrets


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        nxt=Nexter(keys=[signers[1].verfer.qb64]).qb64)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], baser=conlgr)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert kes == bytearray(b'{"vs":"KERI10JSON0000fb_","pre":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_'
                                b'ZOoeKtWTOunRA","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                                b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz'
                                b'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA'
                                b'Ab9HVtXGZWUssiJdEOVMTNNy9jVfinHmDGIJxkD22ogiBI1rvUxPpCATf66DvilG'
                                b'QOhKbpumcrQRkZMe737QyBA')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[2].verfer.qb64]).qb64,
                        sn=1)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 2 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[2].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[3].verfer.qb64]).qb64,
                        sn=2)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 3 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=3)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=4)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[3].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[4].verfer.qb64]).qb64,
                        sn=5)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=6)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
       # nxt digest is empty
        serder = rotate(pre=kever.prefixer.qb64,
                    keys=[signers[4].verfer.qb64],
                    dig=kever.diger.qb64,
                    nxt="",
                    sn=7)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 8 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=8)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 8 Rotation
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[5].verfer.qb64]).qb64,
                        sn=8)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert len(kes) == 3349

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(baser=vallgr)

        # test for incomplete event in stream
        kevery.processAll(ims=kes[:20])
        assert pre not in kevery.kevers  # shortage so gives up

        kevery.processAll(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.baser.getKelIter(pre)]
        assert db_digs == event_digs


    assert not os.path.exists(kevery.baser.path)
    assert not os.path.exists(kever.baser.path)

    """ Done Test """


def test_multisig_digprefix():
    """
    Test multisig with self-addressing (digest) pre
    """


    # Test sequence of events given set of secrets
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

    with openDB("controller") as conlgr, openDB("validator") as vallgr:

        # create event stream
        kes = bytearray()
        #  create signers
        signers = [Signer(qb64=secret) for secret in secrets]  # faster
        assert [siger.qb64 for siger in signers] == secrets


        # Event 0  Inception Transferable (nxt digest not empty)
        #  2 0f 3 multisig

        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        nxtkeys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = 2
        code = CryOneDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        sith=sith,
                        nxt=Nexter(keys=nxtkeys).qb64)

        assert serder.ked["pre"] == 'EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc'
        # create sig counter
        count = len(keys)
        counter = SigCounter(count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers, baser=conlgr)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)

        assert kes == bytearray(b'{"vs":"KERI10JSON000159_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CI'
                                b'xq7QGP_dEQiwc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcP'
                                b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjG'
                                b'Td2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Gr'
                                b'h8"],"nxt":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","toad"'
                                b':"0","wits":[],"cnfg":[]}-AADAAh_trqX993WCZfZ2Mm8Rj2AnlpJzStsv2x'
                                b'4M3gKOIpA740SCYGTDIU4L2Zokd8Krfakt98vy2vAYTjrJ7_UMnBQABNgYwwmein'
                                b'upnrK8nIbVkz4iL7OgjAalNSNimZciYLCBRoKD5jbyXbHDxgycjl2vaw3roAzuaS'
                                b'i4686OY4P0kDgACbz0tl-U_EBbSfdKmtJHkSNfbDjB7pw_k9C9MuTv1eP3XM4OFA'
                                b'pLJyhshWDtWmUzb4uorpXWvqRKfkMIRCKyBDQ')



        # Event 1 Rotation Transferable
        keys = nxtkeys
        sith = 2
        nxtkeys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith=sith,
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=nxtkeys).qb64,
                        sn=1)
        # create sig counter
        count = len(keys)
        counter = SigCounter(count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)


        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=2)
        # create sig counter
        counter = SigCounter(count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=3)
        # create sig counter
        counter = SigCounter(count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        keys = nxtkeys
        serder = rotate(pre=kever.prefixer.qb64,
                    keys=keys,
                    sith=2,
                    dig=kever.diger.qb64,
                    nxt="",
                    sn=4)
        # create sig counter
        counter = SigCounter(count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-5) for i in range(5, 8)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)


        assert len(kes) == 2783

        kevery = Kevery(baser=vallgr)
        kevery.processAll(ims=kes)

        pre = kever.prefixer.qb64
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[5].verfer.qb64

    assert not os.path.exists(kevery.baser.path)

    """ Done Test """


def test_recovery():
    """
    Test Recovery event
    """
    # set of secrets
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

    #  create signers
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [signer.qb64 for signer in signers] == secrets

    with openDB("controller") as conlgr, openDB("validator") as vallgr:
        event_digs = [] # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[esn].verfer.qb64],
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64)

        assert sn == int(serder.ked["sn"], 16) == 0

        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], baser=conlgr)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == esn == 1
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 2
        assert esn == 1
        serder = interact(pre=kever.prefixer.qb64,
                              dig=kever.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 4
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 5
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 6
        assert esn == 2
        serder = interact(pre=kever.prefixer.qb64,
                              dig=kever.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)


        # Next Event Rotation Recovery at sn = 5
        sn = 5
        esn += 1
        assert sn == 5
        assert esn == 3

        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[esn].verfer.qb64],
                        dig=event_digs[sn-1],
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 6
        assert esn == 3
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert kever.verfers[0].qb64 == signers[esn].verfer.qb64


        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelIter(pre)]
        assert len(db_digs) == len(event_digs) == 9
        assert db_digs[0:6] ==  event_digs[0:6]
        assert db_digs[-1] == event_digs[-1]
        assert db_digs[7] ==  event_digs[6]
        assert db_digs[6] ==  event_digs[7]

        db_est_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelEstIter(pre)]
        assert len(db_est_digs) == 7
        assert db_est_digs[0:5] ==  event_digs[0:5]
        assert db_est_digs[5:7] ==  event_digs[7:9]

        kevery = Kevery(baser=vallgr)
        kevery.processAll(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64 == signers[esn].verfer.qb64


        y_db_digs = [bytes(val).decode("utf-8") for val in kevery.baser.getKelIter(pre)]
        assert db_digs == y_db_digs
        y_db_est_digs = [bytes(val).decode("utf-8") for val in kevery.baser.getKelEstIter(pre)]
        assert db_est_digs == y_db_est_digs

    assert not os.path.exists(kevery.baser.path)
    assert not os.path.exists(kever.baser.path)

    """ Done Test """

def test_receipt():
    """
    Test event receipt message and attached couplets
    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)


    #  Direct Mode coe is controller, val is validator

    # set of secrets  (seeds for private keys)
    coeSecrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create signers
    coeSigners = [Signer(qb64=secret) for secret in coeSecrets]
    assert [signer.qb64 for signer in coeSigners] == coeSecrets

    # set of secrets (seeds for private keys)
    valSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    #  create signers
    valSigners = [Signer(qb64=secret) for secret in valSecrets]
    assert [signer.qb64 for signer in valSigners] == valSecrets

    # create receipt signer prefixer  default code is non-transferable
    valSigner = Signer(qb64=valSecrets[0], transferable=False)
    valPrefixer = Prefixer(qb64=valSigner.verfer.qb64, )
    assert valPrefixer.code == CryOneDex.Ed25519N
    valpre = valPrefixer.qb64
    assert valpre == 'B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'

    with openDB("controller") as coeLogger, openDB("validator") as valLogger:
        coeKevery = Kevery(baser=coeLogger)
        valKevery = Kevery(baser=valLogger)
        event_digs = [] # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        #create receipt msg stream
        res = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[coeSigners[esn].verfer.qb64],
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64)

        assert sn == int(serder.ked["sn"], 16) == 0
        coepre = serder.ked['pre']
        assert coepre == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'

        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # return Siger if index

        #  attach to key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        # make copy of kes so can use again for valKevery
        coeKevery.processAll(ims=bytearray(kes))  # create Kever using Kevery
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre
        valKevery.processAll(ims=kes)
        assert coepre in valKevery.kevers
        valKever = valKevery.kevers[coepre]
        assert len(kes) ==  0


        # create receipt from val to coe
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           dig=coeKever.diger.qb64)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64 == '0Bi6u-ogCjhGeXMUV0Vls9RbefJ-W_daYc6aBVPY5fqMsBYhkl47TrhbpescYp-yBcfkEEKUQHEpZhoXgzw3IeDQ'
        recnt = CryCounter(count=1)
        assert recnt.qb64 == '-AAB'

        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)
        assert res == bytearray(b'{"vs":"KERI10JSON000099_","pre":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_'
                                b'ZOoeKtWTOunRA","sn":"0","ilk":"rct","dig":"Ew3MXaYk3VBkPAFyTZN6O'
                                b'yev5sbKM_6ycHAds-A6znN8"}-AABB8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzh'
                                b'DNZlEKiMc0Bi6u-ogCjhGeXMUV0Vls9RbefJ-W_daYc6aBVPY5fqMsBYhkl47Trh'
                                b'bpescYp-yBcfkEEKUQHEpZhoXgzw3IeDQ')


        coeKevery.processAll(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.baser.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.diger.qb64))
        assert bytes(result[0]) == valPrefixer.qb64b + valCigar.qb64b


        # create receipt to escrow use invalid dig and sn so not in db
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=2,
                           dig=fake)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        recnt = CryCounter(count=1)
        # attach to receipt msg stream
        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)

        coeKevery.processAll(ims=res)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.baser.getUres(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=fake))
        assert bytes(result[0]) == valPrefixer.qb64b + valCigar.qb64b


        # create receipt stale use invalid dig and valid sn so bad receipt
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                               sn=coeKever.sn,
                               dig=fake)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        recnt = CryCounter(count=1)
        # attach to receipt msg stream
        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)

        with pytest.raises(ValidationError):
            coeKevery.processOne(ims=res)  #  coe process the escrow receipt from val


        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == esn == 1
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # returns siger
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 2
        assert esn == 1
        serder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 4
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 5
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 6
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.processAll(ims=bytearray(kes))  # update key event verifier state
        valKevery.processAll(ims=kes)


        assert coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(event_digs) == 7


        assert valKever.sn == coeKever.sn
        assert valKever.verfers[0].qb64 == coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

    assert not os.path.exists(valKevery.baser.path)
    assert not os.path.exists(coeKever.baser.path)

    """ Done Test """

def test_direct_mode():
    """
    Test direct mode with transverable validator event receipts

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)


    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.

    # set of secrets  (seeds for private keys)
    coeSecrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create coe signers
    coeSigners = [Signer(qb64=secret) for secret in coeSecrets]
    assert [signer.qb64 for signer in coeSigners] == coeSecrets

    # set of secrets (seeds for private keys)
    valSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    #  create val signers
    valSigners = [Signer(qb64=secret) for secret in valSecrets]
    assert [signer.qb64 for signer in valSigners] == valSecrets


    with openDB("controller") as coeLogger, openDB("validator") as valLogger:
        #  init Keverys
        coeKevery = Kevery(baser=coeLogger)
        valKevery = Kevery(baser=valLogger)

        coe_event_digs = [] # list of coe's own event log digs to verify against database
        val_event_digs = [] # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                        nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                        code=CryOneDex.Blake3_256)

        assert csn == int(coeSerder.ked["sn"], 16) == 0
        coepre = coeSerder.ked['pre']
        assert coepre == 'EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI'

        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                                 b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz'
                                 b'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA'
                                 b'ApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOv'
                                 b'VjHpdZlty3Hgk6ilF8pVpAQ')

        # create own Coe Kever in  Coe's Kevery
        coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                            nxt=Nexter(keys=[valSigners[vesn+1].verfer.qb64]).qb64,
                            code=CryOneDex.Blake3_256)

        assert vsn == int(valSerder.ked["sn"], 16) == 0
        valpre = valSerder.ked['pre']
        assert valpre == 'E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0M'

        val_event_digs.append(valSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"vs":"KERI10JSON0000fb_","pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjM'
                                 b'Nap6ulAAzVt0M","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKm'
                                 b'gyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nxt":"EOWDAJvex5dZzDxeHB'
                                 b'ANyaIoUG3F4-ic81G6GwtnC4f4","toad":"0","wits":[],"cnfg":[]}-AABA'
                                 b'AR5dawnJxU_Gbb8EK2xUMLb2AU7wLlZDHlDzHvovP-YIowqFq719VMQc9hrEwW9J'
                                 b'Ks90leAm2rUp3_DOi7-olBg')

        # create own Val Kever in  Val's Kevery
        valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        valKevery.processAll(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.diger.qb64b == b'EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc'
        coeIcpRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdo'
                             b'I","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_Z'
                             b'OoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","toad":"'
                             b'0","wits":[],"cnfg":[]}')
        counter = SigCounter(count=1)
        assert counter.qb64 == '-AAB'
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAcQJDHTzG8k1WYCR6LahLCIlcDED21Slz66piD9tcZo4VEmyWHYDccj4aRvVdy9xHqHsn38FMGN26x4S2skJGCw'

        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = bytearray(reserder.raw)
        rmsg.extend(counter.qb64b)
        rmsg.extend(siger.qb64b)
        assert rmsg == bytearray(b'{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"0","ilk":"vrc","dig":"EdpkS5j6xIAnPFjovQKLa'
                                 b'ou1jF7XcLny-pYZde4p35jc","seal":{"pre":"E0uTVILY2KXdcxX40MSM9Fr8'
                                 b'EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p-qHut_JCfMKSFwpljZ-Wopp'
                                 b'azqZIid-A"}}-AABAAcQJDHTzG8k1WYCR6LahLCIlcDED21Slz66piD9tcZo4VEm'
                                 b'yWHYDccj4aRvVdy9xHqHsn38FMGN26x4S2skJGCw')

        valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        assert vmsg == bytearray(b'{"vs":"KERI10JSON0000fb_","pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjM'
                                 b'Nap6ulAAzVt0M","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKm'
                                 b'gyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nxt":"EOWDAJvex5dZzDxeHB'
                                 b'ANyaIoUG3F4-ic81G6GwtnC4f4","toad":"0","wits":[],"cnfg":[]}-AABA'
                                 b'AR5dawnJxU_Gbb8EK2xUMLb2AU7wLlZDHlDzHvovP-YIowqFq719VMQc9hrEwW9J'
                                 b'Ks90leAm2rUp3_DOi7-olBg{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz'
                                 b'52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI","sn":"0","ilk":"vrc","dig"'
                                 b':"EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc","seal":{"pre":"E'
                                 b'0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p'
                                 b'-qHut_JCfMKSFwpljZ-WoppazqZIid-A"}}-AABAAcQJDHTzG8k1WYCR6LahLCIl'
                                 b'cDED21Slz66piD9tcZo4VEmyWHYDccj4aRvVdy9xHqHsn38FMGN26x4S2skJGCw')


        # Simulate send to coe of val's incept and val's receipt of coe's inception message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0MEs0RthuviC_p-qHut_JCfMKSFwpljZ-W'
                                    b'oppazqZIid-AAAcQJDHTzG8k1WYCR6LahLCIlcDED21Slz66piD9tcZo4VEmyWHYDccj4aRvVdy9'
                                    b'xHqHsn38FMGN26x4S2skJGCw')

        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=10,
                        dig=fake,
                        seal=seal)
        # sign event not receipt
        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"a","ilk":"vrc","dig":"E5is8MshGFB8XPCz7OpPs'
                                 b'rDcD4qJUj9j25sqbeTGV1pw","seal":{"pre":"E0uTVILY2KXdcxX40MSM9Fr8'
                                 b'EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p-qHut_JCfMKSFwpljZ-Wopp'
                                 b'azqZIid-A"}}-AABAAcQJDHTzG8k1WYCR6LahLCIlcDED21Slz66piD9tcZo4VEm'
                                 b'yWHYDccj4aRvVdy9xHqHsn38FMGN26x4S2skJGCw')

        coeKevery.processAll(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.baser.getVres(key=dgKey(pre=coeKever.prefixer.qb64,
                                                   dig=fake))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)


        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(pre=coepre, dig=coeKever.lastEst.dig)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = chit(pre=valK.prefixer.qb64,
                        sn=valK.sn,
                        dig=valK.diger.qb64,
                        seal=seal)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.baser.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.diger.qb64b == b'Es0RthuviC_p-qHut_JCfMKSFwpljZ-WoppazqZIid-A'
        valIcpRaw = bytes(coeKevery.baser.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"vs":"KERI10JSON0000fb_","pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0'
                             b'M","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9'
                             b'yzhDNZlEKiMc"],"nxt":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","toad":"'
                             b'0","wits":[],"cnfg":[]}')

        counter = SigCounter(count=1)
        assert counter.qb64 == '-AAB'
        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AATMyrZLJRc1NiAJnOPqiysasNfmhzrN8hGurWOehxrT7riGQ5Cp0vv_WVXGvdkuvhbzgkULSAiia8RwteiN_JBA'

        # create receipt message
        cmsg = bytearray(reserder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"vs":"KERI10JSON00010c_","pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjM'
                                 b'Nap6ulAAzVt0M","sn":"0","ilk":"vrc","dig":"Es0RthuviC_p-qHut_JCf'
                                 b'MKSFwpljZ-WoppazqZIid-A","seal":{"pre":"EvEnZMhz52iTrJU8qKwtDxzm'
                                 b'ypyosgG70m6LIjkiCdoI","dig":"EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pY'
                                 b'Zde4p35jc"}}-AABAATMyrZLJRc1NiAJnOPqiysasNfmhzrN8hGurWOehxrT7riG'
                                 b'Q5Cp0vv_WVXGvdkuvhbzgkULSAiia8RwteiN_JBA')


        # coe process own receipt in own Kevery so have copy in own log
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        valKevery.processAll(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.baser.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                    dig=valKever.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    coeKever.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoIEdpkS5j6xIAnPFjovQKLaou1jF7XcLny'
                                    b'-pYZde4p35jcAATMyrZLJRc1NiAJnOPqiysasNfmhzrN8hGurWOehxrT7riGQ5Cp0vv_WVXGvdku'
                                    b'vhbzgkULSAiia8RwteiN_JBA')

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           sn=csn)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"vs":"KERI10JSON00013a_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"1","ilk":"rot","dig":"EdpkS5j6xIAnPFjovQKLa'
                                 b'ou1jF7XcLny-pYZde4p35jc","sith":"1","keys":["DVcuJOOJF1IE8svqEtr'
                                 b'SuyQjGTd2HhfAkt9y2QkUtFJI"],"nxt":"E-dapdcC6XR1KWmWDsNl4J_OxcGxN'
                                 b'Zw1Xd95JH5a34fI","toad":"0","cuts":[],"adds":[],"data":[]}-AABAA'
                                 b'KoZDhf2twFMQPf7l9hM3JTccR4MyogVqHb0SgZs_PPAiOPfPtvX2NeUPStF4UQjB'
                                 b'ZLELfU0bhcZ1Fa6rcQl-Bg')


        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.processAll(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.diger.qb64b == b'EcNPT1qtD-7jkVAFrU3BivIfoKbuQ8mRxhbvGOj9s0OQ'
        coeRotRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"vs":"KERI10JSON00013a_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdo'
                             b'I","sn":"1","ilk":"rot","dig":"EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc"'
                             b',"sith":"1","keys":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"nxt":"E'
                             b'-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","toad":"0","cuts":[],"adds":[],'
                             b'"data":[]}')
        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAbwCangbTsyr12mEjTuCgi8vHd584VemQ37DsN_c2m9raYg8TGiLvSaa4H3JZ7t-2fpnNQyuLcqUPFwb_zsKzAQ'

        # val create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"1","ilk":"vrc","dig":"EcNPT1qtD-7jkVAFrU3Bi'
                                 b'vIfoKbuQ8mRxhbvGOj9s0OQ","seal":{"pre":"E0uTVILY2KXdcxX40MSM9Fr8'
                                 b'EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p-qHut_JCfMKSFwpljZ-Wopp'
                                 b'azqZIid-A"}}-AABAAbwCangbTsyr12mEjTuCgi8vHd584VemQ37DsN_c2m9raYg'
                                 b'8TGiLvSaa4H3JZ7t-2fpnNQyuLcqUPFwb_zsKzAQ')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0MEs0RthuviC_p-qHut_JCfMKSFwpljZ-W'
                                    b'oppazqZIid-AAAbwCangbTsyr12mEjTuCgi8vHd584VemQ37DsN_c2m9raYg8TGiLvSaa4H3JZ7t'
                                    b'-2fpnNQyuLcqUPFwb_zsKzAQ')

        # Next Event 2 Coe Interaction
        csn += 1  #  do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.diger.qb64,
                              sn=csn)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"vs":"KERI10JSON0000a3_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"2","ilk":"ixn","dig":"EcNPT1qtD-7jkVAFrU3Bi'
                                 b'vIfoKbuQ8mRxhbvGOj9s0OQ","data":[]}-AABAAfwixVNNu4zYIIY0C28g3o5W'
                                 b'6GjvUFp9wnocOtrqVKivExzhnJKIKZ14XmaIdqWlpHSLKvo1ChD72TlNtyrCzDQ')


        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.processAll(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.diger.qb64 == coeSerder.dig


        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.diger.qb64b == b'E9kNZ4WLRTdbg7-DhvYpqpvW3cyKCbgCPipSEDOW2OE0'
        coeIxnRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"vs":"KERI10JSON0000a3_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdo'
                             b'I","sn":"2","ilk":"ixn","dig":"EcNPT1qtD-7jkVAFrU3BivIfoKbuQ8mRxhbvGOj9s0OQ"'
                             b',"data":[]}')
        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAJpvKidI4QI9ns1penElEeUHKmVvIHMbyQhZ8m9IauY41Be-IdGhZOIL0MVh-JIMiWYWLo9pHeUQf__FH0p2KDQ'


        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                                 b'70m6LIjkiCdoI","sn":"2","ilk":"vrc","dig":"E9kNZ4WLRTdbg7-DhvYpq'
                                 b'pvW3cyKCbgCPipSEDOW2OE0","seal":{"pre":"E0uTVILY2KXdcxX40MSM9Fr8'
                                 b'EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p-qHut_JCfMKSFwpljZ-Wopp'
                                 b'azqZIid-A"}}-AABAAJpvKidI4QI9ns1penElEeUHKmVvIHMbyQhZ8m9IauY41Be'
                                 b'-IdGhZOIL0MVh-JIMiWYWLo9pHeUQf__FH0p2KDQ')


        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0MEs0RthuviC_p-qHut_JCfMKSFwpljZ-W'
                                    b'oppazqZIid-AAAJpvKidI4QI9ns1penElEeUHKmVvIHMbyQhZ8m9IauY41Be-IdGhZOIL0MVh-JI'
                                    b'MiWYWLo9pHeUQf__FH0p2KDQ')


        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc',
                                             'EcNPT1qtD-7jkVAFrU3BivIfoKbuQ8mRxhbvGOj9s0OQ',
                                             'E9kNZ4WLRTdbg7-DhvYpqpvW3cyKCbgCPipSEDOW2OE0']


        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc',
                                             'EcNPT1qtD-7jkVAFrU3BivIfoKbuQ8mRxhbvGOj9s0OQ',
                                             'E9kNZ4WLRTdbg7-DhvYpqpvW3cyKCbgCPipSEDOW2OE0']


        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['Es0RthuviC_p-qHut_JCfMKSFwpljZ-WoppazqZIid-A']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['Es0RthuviC_p-qHut_JCfMKSFwpljZ-WoppazqZIid-A']

    assert not os.path.exists(valKevery.baser.path)
    assert not os.path.exists(coeKever.baser.path)

    """ Done Test """

def test_direct_mode_cbor_mgpk():
    """
    Test direct mode with transverable validator event receipts but using
    cbor and mspk serializations

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)


    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.

    # set of secrets  (seeds for private keys)
    coeSecrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create coe signers
    coeSigners = [Signer(qb64=secret) for secret in coeSecrets]
    assert [signer.qb64 for signer in coeSigners] == coeSecrets

    # set of secrets (seeds for private keys)
    valSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    #  create val signers
    valSigners = [Signer(qb64=secret) for secret in valSecrets]
    assert [signer.qb64 for signer in valSigners] == valSecrets


    with openDB("controller") as coeLogger, openDB("validator") as valLogger:
        #  init Keverys
        coeKevery = Kevery(baser=coeLogger)
        valKevery = Kevery(baser=valLogger)

        coe_event_digs = [] # list of coe's own event log digs to verify against database
        val_event_digs = [] # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           code=CryOneDex.Blake3_256,
                           kind=Serials.cbor)

        assert csn == int(coeSerder.ked["sn"], 16) == 0
        coepre = coeSerder.ked['pre']
        assert coepre == 'EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxw'

        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg ==  bytearray(b'\xaabvsqKERI10CBOR0000d5_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_'
                                  b'hiWPJPxwbsna0cilkcicpdsitha1dkeys\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wR'
                                  b'CG_ZOoeKtWTOunRAcnxtx,EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtl'
                                  b'qUdtoada0dwits\x80dcnfg\x80-AABAADt4Wdj3bzP6UvKsdNiXRnihQ0Aj1tBwxd'
                                  b'6qCLiZZg2dRKODi6j31bqrVymejoA9G-IUMVkf6fG6N82W3v8ozDg')

        # create own Coe Kever in  Coe's Kevery
        coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                            nxt=Nexter(keys=[valSigners[vesn+1].verfer.qb64]).qb64,
                            code=CryOneDex.Blake3_256,
                            kind=Serials.mgpk)

        assert vsn == int(valSerder.ked["sn"], 16) == 0
        valpre = valSerder.ked['pre']
        assert valpre == 'EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I'

        val_event_digs.append(valSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x8a\xa2vs\xb1KERI10MGPK0000d5_\xa3pre\xd9,EqnG_-DkA5CGCmx6kItDRKhT'
                                 b'5IvQYtJDr3z9WcJ9-N_I\xa2sn\xa10\xa3ilk\xa3icp\xa4sith\xa11\xa4key'
                                 b's\x91\xd9,D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa3nxt'
                                 b'\xd9,EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4\xa4toad\xa1'
                                 b'0\xa4wits\x90\xa4cnfg\x90-AABAAmDNr4AHdiDZRMuLJEzQrAi8pEWcvQhOve'
                                 b'Aa3ViUxHE7nEsYgvDJNUqjXl2ISQzSvJVN5rcWtw8tCYbM8t454AQ')

        # create own Val Kever in  Val's Kevery
        valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        valKevery.processAll(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.diger.qb64b == b'ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4'
        coeIcpRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'\xaabvsqKERI10CBOR0000d5_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxw'
                             b'bsna0cilkcicpdsitha1dkeys\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
                             b'cnxtx,EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqUdtoada0dwits\x80dcnfg\x80')


        counter = SigCounter(count=1)
        assert counter.qb64 == '-AAB'
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAZH9dsO6GDbGEYp27bMX442u8DlAx9qxH6f4fGRjcC8OB4iUEzw7YgK2AQ5w_AG6YhrlS31mZ7aR3Qt9bHA0JCQ'

        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = bytearray(reserder.raw)
        rmsg.extend(counter.qb64b)
        rmsg.extend(siger.qb64b)
        assert rmsg == bytearray(b'\x86\xa2vs\xb1KERI10MGPK0000f1_\xa3pre\xd9,EIg6YUFgkOh50O_4Z_1Bnv3y'
                                 b'YbPfW2lT-C2_hiWPJPxw\xa2sn\xa10\xa3ilk\xa3vrc\xa3dig\xd9,ETQyg_rXa'
                                 b'kwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4\xa4seal\x82\xa3pre\xd9,EqnG_'
                                 b'-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I\xa3dig\xd9,Eh17ypedXkwkrfl'
                                 b'D5WJ5VFIbXbHtlZKBDQq4GyM7K3aU-AABAAZH9dsO6GDbGEYp27bMX442u8DlAx9'
                                 b'qxH6f4fGRjcC8OB4iUEzw7YgK2AQ5w_AG6YhrlS31mZ7aR3Qt9bHA0JCQ')

        valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        assert vmsg == bytearray(b'\x8a\xa2vs\xb1KERI10MGPK0000d5_\xa3pre\xd9,EqnG_-DkA5CGCmx6kItDRKhT'
                                 b'5IvQYtJDr3z9WcJ9-N_I\xa2sn\xa10\xa3ilk\xa3icp\xa4sith\xa11\xa4key'
                                 b's\x91\xd9,D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa3nxt'
                                 b'\xd9,EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4\xa4toad\xa1'
                                 b'0\xa4wits\x90\xa4cnfg\x90-AABAAmDNr4AHdiDZRMuLJEzQrAi8pEWcvQhOve'
                                 b'Aa3ViUxHE7nEsYgvDJNUqjXl2ISQzSvJVN5rcWtw8tCYbM8t454AQ\x86\xa2v'
                                 b's\xb1KERI10MGPK0000f1_\xa3pre\xd9,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2l'
                                 b'T-C2_hiWPJPxw\xa2sn\xa10\xa3ilk\xa3vrc\xa3dig\xd9,ETQyg_rXakwWXCrJ'
                                 b'eIW7AZ3jzAJ610aQRG9rkhZmEbE4\xa4seal\x82\xa3pre\xd9,EqnG_-DkA5CG'
                                 b'Cmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I\xa3dig\xd9,Eh17ypedXkwkrflD5WJ5VF'
                                 b'IbXbHtlZKBDQq4GyM7K3aU-AABAAZH9dsO6GDbGEYp27bMX442u8DlAx9qxH6f4f'
                                 b'GRjcC8OB4iUEzw7YgK2AQ5w_AG6YhrlS31mZ7aR3Qt9bHA0JCQ')



        # Simulate send to coe of val's receipt of coe's inception message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_IEh17ypedXkwkrflD5WJ5VFIbXbHtlZKB'
                                    b'DQq4GyM7K3aUAAZH9dsO6GDbGEYp27bMX442u8DlAx9qxH6f4fGRjcC8OB4iUEzw7YgK2AQ5w_AG'
                                    b'6YhrlS31mZ7aR3Qt9bHA0JCQ')

        # create receipt to escrow use invalid dig so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=10,
                        dig=fake,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign event not receipt
        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa2vs\xb1KERI10MGPK0000f1_\xa3pre\xd9,EIg6YUFgkOh50O_4Z_1Bnv3y'
                                 b'YbPfW2lT-C2_hiWPJPxw\xa2sn\xa1a\xa3ilk\xa3vrc\xa3dig\xd9,ET85aV-_8'
                                 b'XGPoejUXxmOpnhuhXtizPP11Kg2N4ZmtP2Q\xa4seal\x82\xa3pre\xd9,EqnG_'
                                 b'-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I\xa3dig\xd9,Eh17ypedXkwkrfl'
                                 b'D5WJ5VFIbXbHtlZKBDQq4GyM7K3aU-AABAAZH9dsO6GDbGEYp27bMX442u8DlAx9'
                                 b'qxH6f4fGRjcC8OB4iUEzw7YgK2AQ5w_AG6YhrlS31mZ7aR3Qt9bHA0JCQ')


        coeKevery.processAll(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.baser.getVres(key=dgKey(pre=coeKever.prefixer.qb64,
                                                   dig=fake))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)


        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(pre=coepre, dig=coeKever.lastEst.dig)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = chit(pre=valK.prefixer.qb64,
                        sn=valK.sn,
                        dig=valK.diger.qb64,
                        seal=seal,
                        kind=Serials.cbor)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.baser.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.diger.qb64b == b'Eh17ypedXkwkrflD5WJ5VFIbXbHtlZKBDQq4GyM7K3aU'
        valIcpRaw = bytes(coeKevery.baser.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'\x8a\xa2vs\xb1KERI10MGPK0000d5_\xa3pre\xd9,EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJD'
                             b'r3z9WcJ9-N_I\xa2sn\xa10\xa3ilk\xa3icp\xa4sith\xa11\xa4keys\x91\xd9,D8KY1sKm'
                             b'gyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa3nxt\xd9,EOWDAJvex5dZzDxeHBANyaIoUG'
                             b'3F4-ic81G6GwtnC4f4\xa4toad\xa10\xa4wits\x90\xa4cnfg\x90')


        counter = SigCounter(count=1)
        assert counter.qb64 == '-AAB'
        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAleFjojDzyrLOwKfmOlHnbH_c5Qg5rAszLrCj_DVDdvWnCTKWbvi2jU6--MoFZkFMGVCUsbn1l1G59gRDYWBTCA'

        # create receipt message
        cmsg = bytearray(reserder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xa6bvsqKERI10CBOR0000f1_cprex,EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9'
                                 b'WcJ9-N_Ibsna0cilkcvrccdigx,Eh17ypedXkwkrflD5WJ5VFIbXbHtlZKBDQq4G'
                                 b'yM7K3aUdseal\xa2cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxwc'
                                 b'digx,ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4-AABAAleFjojDzy'
                                 b'rLOwKfmOlHnbH_c5Qg5rAszLrCj_DVDdvWnCTKWbvi2jU6--MoFZkFMGVCUsbn1l'
                                 b'1G59gRDYWBTCA')


        # coe process own receipt in own Kevery so have copy in own log
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        valKevery.processAll(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.baser.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                    dig=valKever.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    coeKever.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxwETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQ'
                                    b'RG9rkhZmEbE4AAleFjojDzyrLOwKfmOlHnbH_c5Qg5rAszLrCj_DVDdvWnCTKWbvi2jU6--MoFZk'
                                    b'FMGVCUsbn1l1G59gRDYWBTCA')

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           sn=csn,
                           kind=Serials.cbor)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xacbvsqKERI10CBOR00010d_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_'
                                 b'hiWPJPxwbsna1cilkcrotcdigx,ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rk'
                                 b'hZmEbE4dsitha1dkeys\x81x,DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtF'
                                 b'JIcnxtx,E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fIdtoada0dcuts'
                                 b'\x80dadds\x80ddata\x80-AABAAwZ0TUK0fogg-xNIYgzusZJVx42sCET_i6_ma-'
                                 b'0HmuZ3FWQxVPVDGlF83SiC9KlFUYJ7WLnxQ-6Bp9Y_xrHg_AA')

        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.processAll(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.diger.qb64b == b'EjXM5dH2RF7aVBZ3gQycxCR6DTS3dtDgHFZGEJFI0IUk'
        coeRotRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'\xacbvsqKERI10CBOR00010d_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxw'
                             b'bsna1cilkcrotcdigx,ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4dsitha1dk'
                             b'eys\x81x,DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIcnxtx,E-dapdcC6XR1KWmW'
                             b'DsNl4J_OxcGxNZw1Xd95JH5a34fIdtoada0dcuts\x80dadds\x80ddata\x80')


        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAyqCqS7xIUKg64dbV0F-nk-YPeOa2GlKcs4gXNQUHxoOU8poQ9XxUr1DYObUoXBXKAcSVX1Afnj4AxwljSkcSAg'

        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa2vs\xb1KERI10MGPK0000f1_\xa3pre\xd9,EIg6YUFgkOh50O_4Z_1Bnv3y'
                                 b'YbPfW2lT-C2_hiWPJPxw\xa2sn\xa11\xa3ilk\xa3vrc\xa3dig\xd9,EjXM5dH2R'
                                 b'F7aVBZ3gQycxCR6DTS3dtDgHFZGEJFI0IUk\xa4seal\x82\xa3pre\xd9,EqnG_'
                                 b'-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I\xa3dig\xd9,Eh17ypedXkwkrfl'
                                 b'D5WJ5VFIbXbHtlZKBDQq4GyM7K3aU-AABAAyqCqS7xIUKg64dbV0F-nk-YPeOa2G'
                                 b'lKcs4gXNQUHxoOU8poQ9XxUr1DYObUoXBXKAcSVX1Afnj4AxwljSkcSAg')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_IEh17ypedXkwkrflD5WJ5VFIbXbHtlZKB'
                                    b'DQq4GyM7K3aUAAyqCqS7xIUKg64dbV0F-nk-YPeOa2GlKcs4gXNQUHxoOU8poQ9XxUr1DYObUoXB'
                                    b'XKAcSVX1Afnj4AxwljSkcSAg')

        # Next Event Coe Interaction
        csn += 1  #  do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.diger.qb64,
                              sn=csn,
                              kind=Serials.cbor)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = SigCounter()  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xa6bvsqKERI10CBOR00008d_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_'
                                 b'hiWPJPxwbsna2cilkcixncdigx,EjXM5dH2RF7aVBZ3gQycxCR6DTS3dtDgHFZGE'
                                 b'JFI0IUkddata\x80-AABAAqc6aOfFA1xZAXq9yUJhw4HgHDQ5R5KEPogWRagUxT49U4'
                                 b'34SHoaLjBKkXnKUN9e1YjZqfB8DfkCKjNoMENlbCg')

        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.processAll(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.diger.qb64 == coeSerder.dig


        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.baser.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.diger.qb64b == b'Eo9swR_3jo2AV5cn0ndHB4JdNV9BymIUhQ6ByuTbEcuY'
        coeIxnRaw = bytes(valKevery.baser.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'\xa6bvsqKERI10CBOR00008d_cprex,EIg6YUFgkOh50O_4Z_1Bnv3yYbPfW2lT-C2_hiWPJPxw'
                             b'bsna2cilkcixncdigx,EjXM5dH2RF7aVBZ3gQycxCR6DTS3dtDgHFZGEJFI0IUkddata\x80')

        counter = SigCounter(count=1)
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAvIeL1S3AE__VYixpe0T34TYgW0ZXvgNLQM_qg8DOOk4vVt0M73mjZjrk9iDBb_I9cUDIC6q6_MahNNP_t0z5AA'

        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa2vs\xb1KERI10MGPK0000f1_\xa3pre\xd9,EIg6YUFgkOh50O_4Z_1Bnv3y'
                                 b'YbPfW2lT-C2_hiWPJPxw\xa2sn\xa12\xa3ilk\xa3vrc\xa3dig\xd9,Eo9swR_3j'
                                 b'o2AV5cn0ndHB4JdNV9BymIUhQ6ByuTbEcuY\xa4seal\x82\xa3pre\xd9,EqnG_'
                                 b'-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_I\xa3dig\xd9,Eh17ypedXkwkrfl'
                                 b'D5WJ5VFIbXbHtlZKBDQq4GyM7K3aU-AABAAvIeL1S3AE__VYixpe0T34TYgW0ZXv'
                                 b'gNLQM_qg8DOOk4vVt0M73mjZjrk9iDBb_I9cUDIC6q6_MahNNP_t0z5AA')




        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.processAll(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.baser.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    valKever.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EqnG_-DkA5CGCmx6kItDRKhT5IvQYtJDr3z9WcJ9-N_IEh17ypedXkwkrflD5WJ5VFIbXbHtlZKB'
                                    b'DQq4GyM7K3aUAAvIeL1S3AE__VYixpe0T34TYgW0ZXvgNLQM_qg8DOOk4vVt0M73mjZjrk9iDBb_'
                                    b'I9cUDIC6q6_MahNNP_t0z5AA')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4',
                                             'EjXM5dH2RF7aVBZ3gQycxCR6DTS3dtDgHFZGEJFI0IUk',
                                             'Eo9swR_3jo2AV5cn0ndHB4JdNV9BymIUhQ6ByuTbEcuY']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['ETQyg_rXakwWXCrJeIW7AZ3jzAJ610aQRG9rkhZmEbE4',
                                             'EjXM5dH2RF7aVBZ3gQycxCR6DTS3dtDgHFZGEJFI0IUk',
                                             'Eo9swR_3jo2AV5cn0ndHB4JdNV9BymIUhQ6ByuTbEcuY']


        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['Eh17ypedXkwkrflD5WJ5VFIbXbHtlZKBDQq4GyM7K3aU']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['Eh17ypedXkwkrflD5WJ5VFIbXbHtlZKBDQq4GyM7K3aU']

    assert not os.path.exists(valKevery.baser.path)
    assert not os.path.exists(coeKever.baser.path)

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
    aid0 = Prefixer(qb64=skp0.verfer.qb64)
    assert aid0.code == CryOneDex.Ed25519N

    # Ephemeral may be used without inception event
    # but when used with inception event must be compatible event
    sn = 0  #  inception event so 0
    sith = 1 #  one signer
    nxt = ""  # non-transferable so nxt is empty
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                pre=aid0.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aid0.qb64],  # list of signing keys each qual Base64
                nxt=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
               )

    # verify derivation of aid0 from ked0
    assert aid0.verify(ked=ked0)

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create attached sig counter
    cnt0 = SigCounter(raw=b'', count=1)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw
    del msgb0[:rser0.size]  # strip off event from front

    # extract sig counter
    rcnt0 = SigCounter(qb64=msgb0)
    nrsigs = rcnt0.count
    assert nrsigs == 1
    del msgb0[:len(rcnt0.qb64)]

    # extract attached sigs
    keys = rser0.ked["keys"]
    for i in range(nrsigs): # verify each attached signature
        rsig = SigMat(qb64=msgb0)
        assert rsig.index == 0
        verfer = Verfer(qb64=keys[rsig.index])
        assert verfer.qb64 == aid0.qb64
        assert verfer.qb64 == skp0.verfer.qb64
        assert verfer.verify(rsig.raw, rser0.raw)
        del msgb0[:len(rsig.qb64)]

    # verify pre
    raid0 = Prefixer(qb64=rser0.ked["pre"])
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
    # compute nxt digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                pre="",  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=keys,  # list of signing keys each qual Base64
                nxt=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
               )


    # Derive AID from ked
    aid0 = Prefixer(ked=ked0, code=CryOneDex.Ed25519)
    assert aid0.code == CryOneDex.Ed25519
    assert aid0.qb64 == skp0.verfer.qb64

    # update ked with pre
    ked0["pre"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create attached sig counter
    cnt0 = SigCounter(raw=b'', count=1)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw
    del msgb0[:rser0.size]  # strip off event from front

    # extract sig counter
    rcnt0 = SigCounter(qb64=msgb0)
    nrsigs = rcnt0.count
    assert nrsigs == 1
    del msgb0[:len(rcnt0.qb64)]

    # extract attached sigs
    keys = rser0.ked["keys"]
    for i in range(nrsigs): # verify each attached signature
        rsig = SigMat(qb64=msgb0)
        assert rsig.index == 0
        verfer = Verfer(qb64=keys[rsig.index])
        assert verfer.qb64 == aid0.qb64
        assert verfer.qb64 == skp0.verfer.qb64
        assert verfer.verify(rsig.raw, rser0.raw)
        del msgb0[:len(rsig.qb64)]

    # verify pre
    raid0 = Prefixer(qb64=rser0.ked["pre"])
    assert raid0.verify(ked=rser0.ked)

    #verify nxt digest from event is still valid
    rnxt1 = Nexter(qb64=rser0.ked["nxt"])
    assert rnxt1.verify(sith=nxtsith, keys=nxtkeys)
    """ Done Test """



def test_process_manual():
    """
    Test manual process of generating and validating inception key event message
    """
    # create qualified pre in basic format
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

    # create qualified pre in basic format
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

    # create nxt digest
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
                pre=aidmat.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aidmat.qb64],  # list of signing keys each qual Base64
                nxt=nxtdigmat.qb64,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
               )


    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"vs":"KERI10JSON0000fb_","pre":"Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50'
                          b's","sn":"0","ilk":"icp","sith":"1","keys":["Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7'
                          b'MyzuKsKJP50s"],"nxt":"E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI","toad":"'
                          b'0","wits":[],"cnfg":[]}')

    assert txsrdr.size == 251

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = CryMat(raw=txdig, code=CryOneDex.Blake3_256)
    assert txdigmat.qb64 == 'EdZaosuU8YMf2LUnjr6HEjDqeuP42SeiIC4OIGl9pF_k'

    assert txsrdr.dig == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  #  sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = SigMat(raw=sig0raw, code=SigTwoDex.Ed25519, index=index)
    assert txsigmat.qb64 == 'AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 339  #  251 + 88

    #  Recieve side
    rxsrdr = Serder(raw=msgb)
    assert rxsrdr.size == txsrdr.size
    assert rxsrdr.ked == ked0

    rxsigqb64 = msgb[rxsrdr.size:].decode("utf-8")
    assert len(rxsigqb64) == len(txsigmat.qb64)
    rxsigmat = SigMat(qb64=rxsigqb64)
    assert rxsigmat.index == index

    rxaidqb64 = rxsrdr.ked["pre"]
    rxaidmat = CryMat(qb64=rxaidqb64)
    assert rxaidmat.qb64 == aidmat.qb64
    assert rxaidmat.code == CryOneDex.Ed25519

    rxverqb64 = rxsrdr.ked["keys"][index]
    rxvermat = CryMat(qb64=rxverqb64)
    assert rxvermat.qb64 == rxaidmat.qb64  #  basic derivation same

    result = pysodium.crypto_sign_verify_detached(rxsigmat.raw, rxsrdr.raw, rxvermat.raw)
    assert not result  # None if verifies successfully else raises ValueError
    """ Done Test """


if __name__ == "__main__":
    test_keyeventfuncs()
