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

from keri.core.coring import MtrDex, Matter, IdrDex, Indexer, CtrDex, Counter
from keri.core.coring import Seqner, Verfer, Signer, Diger, Nexter, Prefixer
from keri.core.coring import Salter, Serder, Siger, Cigar
from keri.core.coring import Ilks

from keri.core.eventing import TraitDex, LastEstLoc, Serials, Versify
from keri.core.eventing import (deWitnessCouple, deReceiptCouple, deReceiptTriple,
                                deTransReceiptQuadruple, deTransReceiptQuintuple)
from keri.core.eventing import (SealDigest, SealRoot, SealEvent, SealLocation,
                                StateEvent, StateEstEvent)
from keri.core.eventing import (incept, rotate, interact, receipt, chit,
                                delcept, deltate, state, messagize, receiptize)
from keri.core.eventing import Kever, Kevery

from keri.db.dbing import dgKey, snKey, openDB, Baser
from keri.base.keeping import openKS, Manager

from keri import help

logger = help.ogler.getLogger()


def test_dewitnesscouple():
    """
    test deWitnessCouple function
    """
    dig = 'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    wig = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    digb = b'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    wigb = b'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    # str
    couple = dig + wig
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64 == dig
    assert wiger.qb64 == wig
    assert len(couple) == 132  # not strip delete

    # bytes
    couple = digb + wigb
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == digb
    assert wiger.qb64b == wigb
    assert len(couple) == 132  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == digb
    assert wiger.qb64b == wigb
    assert len(couple) == 132  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == digb
    assert wiger.qb64b == wigb
    assert len(couple) == 132  # not strip delete

    # test strip delete
    # str
    couple = dig + wig
    assert len(couple) == 132
    with pytest.raises(TypeError):  # immutable str so no delete
        diger, wiger = deWitnessCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytes
    couple = digb + wigb
    with pytest.raises(TypeError):  # immutable bytes so no delete
        diger, wiger = deWitnessCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # memoryview
    couple = memoryview(couple)
    with pytest.raises(TypeError):  # memoryview converted to bytes so no delete
        diger, wiger = deWitnessCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytearray
    couple = bytearray(couple)
    diger, wiger = deWitnessCouple(couple, strip=True)
    assert diger.qb64b == digb
    assert wiger.qb64b == wigb
    assert len(couple) == 0  # bytearray mutable so strip delete succeeds

    """end test"""


def test_dereceiptcouple():
    """
    test deReceiptCouple function
    """
    pre = 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cig = '0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'
    preb = b'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cigb = b'0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'

    # str
    couple = pre + cig
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64 == pre
    assert cigar.qb64 == cig
    assert len(couple) == 132  # not strip delete

    # bytes
    couple = preb + cigb
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(couple) == 132  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(couple) == 132  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(couple) == 132  # not strip delete

    # test strip delete
    # str
    couple = pre + cig
    assert len(couple) == 132
    with pytest.raises(TypeError):  # immutable str so no delete
        prefixer, cigar = deReceiptCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytes
    couple = preb + cigb
    with pytest.raises(TypeError):  # immutable bytes so no delete
        prefixer, cigar = deReceiptCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # memoryview
    couple = memoryview(couple)
    with pytest.raises(TypeError):  # memoryview converted to bytes so no delete
        prefixer, cigar = deReceiptCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytearray
    couple = bytearray(couple)
    prefixer, cigar = deReceiptCouple(couple, strip=True)
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(couple) == 0  # bytearray mutable so strip delete succeeds

    """end test"""


def test_dereceipttriple():
    """
    test deReceiptTriple function
    """
    dig = 'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    pre = 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cig = '0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'

    digb = b'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    preb = b'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cigb = b'0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'

    # str
    triple = dig + pre + cig
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64 == dig
    assert prefixer.qb64 == pre
    assert cigar.qb64 == cig
    assert len(triple) == 176

    # bytes
    triple = digb + preb + cigb
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == digb
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(triple) == 176

    # memoryview
    triple = memoryview(triple)
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == digb
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(triple) == 176

    # bytearray
    triple = bytearray(triple)
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == digb
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(triple) == 176

    # test strip delete
    # str converts to bytes
    triple = dig + pre + cig
    assert len(triple) == 176
    with pytest.raises(TypeError):
        diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert len(triple) == 176  # immutable so no strip delete

    # bytes
    triple = digb + preb + cigb
    assert len(triple) == 176
    with pytest.raises(TypeError):
        diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert len(triple) == 176   # immutable so no strip delete

    # memoryview converts to bytes
    triple = memoryview(triple)
    assert len(triple) == 176
    with pytest.raises(TypeError):
        diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert len(triple) == 176   # immutable so no strip delete

    # bytearray
    triple = bytearray(triple)
    assert len(triple) == 176
    diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert diger.qb64b == digb
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(triple) == 0   # mutable so strip delete

    """end test"""

def test_dequadruple():
    """
    test test_dequadruple function
    """
    spre = 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnu = '0AAAAAAAAAAAAAAAAAAAAABQ'
    sdig = 'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sig = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    spreb = b'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnub = b'0AAAAAAAAAAAAAAAAAAAAABQ'
    sdigb = b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sigb = b'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    #str
    quadruple = spre + ssnu + sdig + sig
    sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64 == spre
    assert sseqner.qb64 == ssnu
    assert sdiger.qb64 == sdig
    assert siger.qb64 == sig
    assert len(quadruple) == 200

    # bytes
    quadruple = spreb + ssnub + sdigb + sigb
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quadruple) == 200

    # memoryview
    quadruple = memoryview(quadruple)
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quadruple) == 200

    # bytearray
    quadruple = bytearray(quadruple)
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quadruple) == 200

    # test strip delete
    # str converts to bytes
    quadruple = spre + ssnu + sdig + sig
    assert len(quadruple) == 200
    with pytest.raises(TypeError):  # immutable so no strip delete
        sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple, strip=True)
    assert len(quadruple) == 200  # immutable so no strip delete

    # bytes
    quadruple = spreb + ssnub + sdigb + sigb
    assert len(quadruple) == 200
    with pytest.raises(TypeError):  # immutable so no strip delete
        sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple, strip=True)
    assert len(quadruple) == 200  # immutable so no strip delete

    # memoryview converts to bytes
    quadruple = memoryview(quadruple)
    assert len(quadruple) == 200
    with pytest.raises(TypeError):  # immutable so no strip delete
        sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple, strip=True)
    assert len(quadruple) == 200  # immutable so no strip delete

    # bytearray
    quadruple = bytearray(quadruple)
    assert len(quadruple) == 200
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple, strip=True)
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quadruple) == 0  # mutable so strip delete

    """end test"""


def test_dequintuple():
    """
    test dequintuple function
    """
    edig = 'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    spre = 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnu = '0AAAAAAAAAAAAAAAAAAAAABQ'
    sdig = 'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sig = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    edigb = b'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    spreb = b'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnub = b'0AAAAAAAAAAAAAAAAAAAAABQ'
    sdigb = b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sigb = b'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    #str
    sealet = spre + ssnu + sdig
    quintuple = edig + sealet + sig
    ediger, sprefixer, sseqner, sdiger, siger = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64 == edig
    assert sprefixer.qb64 == spre
    assert sseqner.qb64 == ssnu
    assert sdiger.qb64 == sdig
    assert siger.qb64 == sig
    assert len(quintuple) == 244

    # bytes
    quintuple = edigb + spreb + ssnub + sdigb + sigb
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edigb
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quintuple) == 244

    # memoryview
    quintuple = memoryview(quintuple)
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edigb
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quintuple) == 244

    # bytearray
    quintuple = bytearray(quintuple)
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edigb
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quintuple) == 244

    # test deletive
    # str converts to bytes
    sealet = spre + ssnu + sdig
    quintuple = edig + sealet + sig
    assert len(quintuple) == 244
    with pytest.raises(TypeError):
        ediger, sprefixer, sseqner, sdiger, siger = deTransReceiptQuintuple(quintuple, strip=True)
    assert len(quintuple) == 244  # immutable so no strip delete

    # bytes
    quintuple = edigb + spreb + ssnub + sdigb + sigb
    assert len(quintuple) == 244
    with pytest.raises(TypeError):
        ediger, sprefixer, sseqner, sdiger, siger = deTransReceiptQuintuple(quintuple, strip=True)
    assert len(quintuple) == 244  # immutable so no strip delete

    # memoryview converts to bytes
    quintuple = memoryview(quintuple)
    assert len(quintuple) == 244
    with pytest.raises(TypeError):
        ediger, sprefixer, sseqner, sdiger, siger = deTransReceiptQuintuple(quintuple, strip=True)
    assert len(quintuple) == 244 # immutable so no strip delete

    # bytearray
    quintuple = bytearray(quintuple)
    assert len(quintuple) == 244
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple, strip=True)
    assert ediger.qb64b == edigb
    assert sprefixer.qb64b == spreb
    assert sseqner.qb64b == ssnub
    assert sdiger.qb64b == sdigb
    assert siger.qb64b == sigb
    assert len(quintuple) == 0  # mutable so strip delete

    """end test"""


def test_lastestloc():
    """
    Test LastEstLoc namedtuple
    """
    lastEst = LastEstLoc(s=1, d='E12345')

    assert isinstance(lastEst, LastEstLoc)

    assert 1 in lastEst
    assert lastEst.s == 1
    assert 'E12345' in lastEst
    assert lastEst.d == 'E12345'

    """End Test """

def test_seals():
    """
    Test seal namedtuples

    """
    seal = SealDigest(d='E12345')
    assert isinstance(seal, SealDigest)
    assert 'E12345' in seal
    assert seal.d == 'E12345'
    assert seal._asdict() == dict(d='E12345')

    seal = SealRoot(rd='EABCDE')
    assert isinstance(seal, SealRoot)
    assert 'EABCDE' in seal
    assert seal.rd == 'EABCDE'
    assert seal._asdict() == dict(rd='EABCDE')

    seal = SealEvent(i='B4321', s='1', d='Eabcd')
    assert isinstance(seal, SealEvent)
    assert 'B4321' in seal
    assert seal.i == 'B4321'
    assert '1' in seal
    assert seal.s ==  '1'
    assert 'Eabcd' in seal
    assert seal.d == 'Eabcd'
    assert seal._asdict() == dict(i='B4321', s='1', d='Eabcd')
    assert seal._fields == ('i', 's', 'd')

    seal = SealLocation(i='B4321', s='1', t='ixn', p='Eabcd')
    assert isinstance(seal, SealLocation)
    assert 'B4321' in seal
    assert seal.i == 'B4321'
    assert '1' in seal
    assert seal.s == '1'
    assert 'ixn' in seal
    assert seal.t == 'ixn'
    assert 'Eabcd' in seal
    assert seal.p == 'Eabcd'
    assert seal._asdict() == dict(i='B4321', s='1', t='ixn', p='Eabcd')
    assert seal._fields == ('i', 's', 't', 'p')

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
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["i"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == ""
    assert serder.raw == (b'{"v":"KERI10JSON0000ba_","i":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                          b'"s":"0","t":"icp","kt":"1","k":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c"],"n":"","wt":"0","w":[],"c":[]}')


    with pytest.raises(DerivationError):
        # non-empty nxt wtih non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, nxt="ABCDE")

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  #  original signing keypair transferable default
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["i"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == ""
    assert serder.raw == (b'{"v":"KERI10JSON0000ba_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                          b'"s":"0","t":"icp","kt":"1","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c"],"n":"","wt":"0","w":[],"c":[]}')


    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
            b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  #  next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nexter1 = Nexter(keys=keys1)  # dfault sith is 1
    nxt1 = nexter1.qb64  # transferable so nxt is not empty
    assert nxt1 == 'EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4'
    serder0 = incept(keys=keys0, nxt=nxt1)
    pre = serder0.ked["i"]
    assert serder0.ked["i"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["n"] == nxt1
    assert serder0.raw == (b'{"v":"KERI10JSON0000e6_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"0","t":"icp","kt":"1","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c"],"n":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","wt":"0","w":[],"c":['
                           b']}')

    assert serder0.dig == 'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'


    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
            b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  #  next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [signer2.verfer.qb64]
    # compute nxt digest
    nexter2 = Nexter(keys=keys2)
    nxt2 = nexter2.qb64  # transferable so nxt is not empty
    assert nxt2 == 'EAXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U'
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["n"] == nxt2
    assert serder1.ked["p"] == serder0.dig
    assert serder1.raw == (b'{"v":"KERI10JSON000122_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"1","t":"rot","p":"E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ","kt":"1'
                           b'","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"n":"EAXTvbATMnVRGjyC'
                           b'_VCNuXcPTxxpLanfzj14u3QMsD_U","wt":"0","wr":[],"wa":[],"a":[]}')

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.dig, sn=2)
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["p"] == serder1.dig
    assert serder2.raw == (b'{"v":"KERI10JSON000098_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"2","t":"ixn","p":"EvHM3Dnx0Z9Vorzjv0e5YWZ84B9VMdw5eP9nE15LuMZ0","a":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, dig=serder2.dig)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.dig
    assert serder3.raw == (b'{"v":"KERI10JSON000091_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"0","t":"rct","d":"EoLKHoaFmo5VFzaOpCQXmUo5Wxf_cRuIbx7LcyBS69lQ"}')

    # ValReceipt  chit
    serderA = incept(keys=keys0, nxt=nxt1, code=MtrDex.Blake3_256)
    seal = SealEvent(i=serderA.ked["i"], s=serderA.ked["s"], d=serderA.dig)
    assert seal.i == serderA.ked["i"]
    assert seal.d == serderA.dig

    serder4 = chit(pre=pre, sn=2, dig=serder2.dig, seal=seal)
    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.vrc
    assert serder4.ked["d"] == serder2.dig
    assert serder4.ked["a"] == seal._asdict()
    assert serder4.raw == (b'{"v":"KERI10JSON000105_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"2","t":"vrc","d":"EoLKHoaFmo5VFzaOpCQXmUo5Wxf_cRuIbx7LcyBS69lQ","a":{"i'
                           b'":"E8_l6JIkQQJ_XkTtB_AXtrfIL-_YWj1E6IOgWdebGbH8","s":"0","d":"ECZulFZrupDyv7'
                           b'LEAyKgQDi4kvq22o0V5t47JzrsB8nM"}}')

    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
            b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD)  #  next signing keypair transferable is default
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nexterD = Nexter(keys=keysD)  # default sith is 1
    nxtD = nexterD.qb64  # transferable so nxt is not empty

    seal = SealLocation(i='ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd',
                        s="{:x}".format(3),
                        t=Ilks.ixn,
                        p='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    serderD = delcept(keys=keysD, seal=seal, nxt=nxtD)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'EfapXTFyvnBKzdmilHH4nstrxJImEdi6m_1hOHwyZYT8'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'{"v":"KERI10JSON000165_","i":"EfapXTFyvnBKzdmilHH4nstrxJImEdi6m_1hOHwyZYT8",'
                           b'"s":"0","t":"dip","kt":"1","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49'
                           b'A"],"n":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","wt":"0","w":[],"c":['
                           b'],"da":{"i":"ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd","s":"3","t":"ixn"'
                           b',"p":"EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z"}}')
    assert serderD.dig == 'EEHl2j5lYCSisgNtdNDAb1c5qkqmyLux01UARjaYikVA'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
            b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR)  #  next signing keypair transferable is default
    assert signerR.code == MtrDex.Ed25519_Seed
    assert signerR.verfer.code == MtrDex.Ed25519
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    nexterR = Nexter(keys=keysR)  # default sith is 1
    nxtR = nexterR.qb64  # transferable so nxt is not empty

    seal = SealLocation(i='ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd',
                        s="{:x}".format(4),
                        t=Ilks.ixn,
                        p='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      seal=seal,
                      sn=4,
                      nxt=nxtR)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'{"v":"KERI10JSON0001a1_","i":"EfapXTFyvnBKzdmilHH4nstrxJImEdi6m_1hOHwyZYT8",'
                           b'"s":"4","t":"drt","p":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1'
                           b'","k":["D8u3hipCxZnkM_O0jfaZLJMk9ERI428T0psRO0JVgh4c"],"n":"EAXTvbATMnVRGjyC'
                           b'_VCNuXcPTxxpLanfzj14u3QMsD_U","wt":"0","wr":[],"wa":[],"a":[],"da":{"i":"ENd'
                           b'HxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd","s":"4","t":"ixn","p":"EMuNWHss_H'
                           b'_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z"}}')
    assert serderR.dig == 'EfBbEpSIXiLJuLcTg-MYX2OnrVmIULiut6VcBqDYkkt4'


    # State KSN
    """
    state(pre,
          sn,
          dig,
          eilk,
          keys,
          eevt,
          sith=None, # default based on keys
          nxt="",
          toad=None, # default based on wits
          wits=None, # default to []
          cnfg=None, # default to []
          dpre=None,
          version=Version,
          kind=Serials.json,
          ):


    Key State Dict
    {
        "v": "KERI10JSON00011c_",
        "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "s": "2",
        "t": "ksn",
        "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
        "te": "rot",
        "kt": "1",
        "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
        "n": "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
        "wt": "1",
        "w": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"],
        "c": ["eo"],
        "ee":
          {
            "s": "1",
            "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
            "wr": ["Dd8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CMZ-i0"],
            "wa": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"]
          },
        "di": "EYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv",
    }

    "di": "" when not delegated

    """
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=salt)

    # State NonDelegated (key state notification)
    # create transferable key pair for controller of KEL
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 trans pre
    assert preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    sith = '1'
    keys = [signerC.verfer.qb64]
    nexter = Nexter(keys=keys, sith=sith)  # compute nxt digest (dummy reuse keys)
    nxt = nexter.qb64
    assert nxt == 'E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ'

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y'

    wits = [preW1, preW2, preW3]
    toad = 2

    #create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         wr=[preW0],
                         wa=[preW3])


    serderK = state(pre=preC,
                    sn=4,
                    dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                    eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    nxt=nxt,
                    toad=toad,
                    wits=wits,
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON000266_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","te":"i'
                           b'xn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdM'
                           b'uF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4J'
                           b'gvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","Br'
                           b'uKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskH'
                           b'I462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUfFBJv0R1IoNNjKpWK6zEZ'
                           b'PxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"d'
                           b'i":""}')
    assert serderK.dig == 'EcVMFLIY2ah-j4emWwTkoub0iPc2NvSde3BRRmQ3y8NI'
    assert serderK.pre == preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    assert serderK.sn == 4

    # create endorsed ksn with nontrans endorser
    # create nontrans key pair for endorder of KSN
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'ByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    cigarE = signerE.sign(ser=serderK.raw)
    assert signerE.verfer.verify(sig=cigarE.raw, ser=serderK.raw)
    msg = messagize(serderK, cigars=[cigarE])
    assert msg == bytearray(b'{"v":"KERI10JSON000266_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                            b'WVK9ZBNZk0","s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462C'
                            b'uIMS_HQIO132Z30","te":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGA'
                            b'VhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQD'
                            b'HCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2i'
                            b'lmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL'
                            b'_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d'
                            b'":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUf'
                            b'FBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12'
                            b'DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":""}-CABByvCLRr5luWmp7keDvDuLP'
                            b'0kIqcyBYq79b3Dho1QvrjI0BvSA8hnCm895RwsecfRkbPcScZMDLSHqDtnOtaiQW'
                            b'TBPrpmuoODWaJUQI0DcsJarRQWy-xA5Ym0XACfJjA0-XAA')

    # create endorsed ksn with trans endorser
    # create trans key pair for endorder of KSN
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    # create endorsed ksn
    sigerE = signerE.sign(ser=serderK.raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=serderK.raw)
    msg = messagize(serderK, sigers=[sigerE], seal=seal)
    assert msg == bytearray(b'{"v":"KERI10JSON000266_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                            b'WVK9ZBNZk0","s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462C'
                            b'uIMS_HQIO132Z30","te":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGA'
                            b'VhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQD'
                            b'HCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2i'
                            b'lmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL'
                            b'_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d'
                            b'":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUf'
                            b'FBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12'
                            b'DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":""}-FABDyvCLRr5luWmp7keDvDuLP'
                            b'0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAAAAAAAEMuNWHss_H_kH4cG7L'
                            b'i1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAvSA8hnCm895RwsecfRkbPcScZMDLSHqD'
                            b'tnOtaiQWTBPrpmuoODWaJUQI0DcsJarRQWy-xA5Ym0XACfJjA0-XAA')


    # State Delegated (key state notification)
    # create transferable key pair for controller of KEL
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    sith = '1'
    keys = [signerC.verfer.qb64]
    nexter = Nexter(keys=keys, sith=sith)  # compute nxt digest (dummy reuse keys)
    nxt = nexter.qb64
    assert nxt == 'E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ'

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y'

    wits = [preW1, preW2, preW3]
    toad = 2

    #create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         wr=[preW0],
                         wa=[preW3])

    # create transferable key pair for delegator of KEL
    signerD = salter.signer(path="D", temp=True)
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519  # transferable
    preD = signerD.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preD == 'DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U'

    serderK = state(pre=preC,
                       sn=4,
                       dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                       eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    nxt=nxt,
                    toad=toad,
                    wits=wits,
                    dpre=preD
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON000292_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","te":"i'
                           b'xn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdM'
                           b'uF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4J'
                           b'gvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","Br'
                           b'uKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskH'
                           b'I462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUfFBJv0R1IoNNjKpWK6zEZ'
                           b'PxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"d'
                           b'i":"DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}')

    assert serderK.dig == 'E58qjy4mw58X2Eiqd-1LeS4o-UtewbjypHP7XheNQzak'
    assert serderK.pre == preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    assert serderK.sn == 4

    # create endorsed ksn with nontrans endorser
    # create nontrans key pair for endorder of KSN
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'ByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    # create endorsed ksn
    cigarE = signerE.sign(ser=serderK.raw)
    assert signerE.verfer.verify(sig=cigarE.raw, ser=serderK.raw)
    msg = messagize(serderK, cigars=[cigarE])
    assert msg == bytearray(b'{"v":"KERI10JSON000292_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                            b'WVK9ZBNZk0","s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462C'
                            b'uIMS_HQIO132Z30","te":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGA'
                            b'VhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQD'
                            b'HCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2i'
                            b'lmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL'
                            b'_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d'
                            b'":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUf'
                            b'FBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12'
                            b'DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoH'
                            b'uXecuz733f-zkh7U"}-CABByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1Qvr'
                            b'jI0BH4ehxZZhSlXOjMl-XEdhlGwq5kxqHpuwBWWLaDZQgGRF_d_LOwLywE3Gn1jC'
                            b'mI0CoJ7_aRU0_l4lbsxiqbXAAw')

    # create endorsed ksn with trans endorser
    # create trans key pair for endorder of KSN
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    # create endorsed ksn
    sigerE = signerE.sign(ser=serderK.raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=serderK.raw)
    msg = messagize(serderK, sigers=[sigerE], seal=seal)
    assert msg == bytearray(b'{"v":"KERI10JSON000292_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                            b'WVK9ZBNZk0","s":"4","t":"ksn","d":"EgNkcl_QewzrRSKH2p9zUskHI462C'
                            b'uIMS_HQIO132Z30","te":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGA'
                            b'VhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQD'
                            b'HCyOpsW5AqQ","wt":"2","w":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2i'
                            b'lmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL'
                            b'_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"3","d'
                            b'":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","wr":["BNTkstUf'
                            b'FBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"wa":["BruKyL_b4D5ETo9u12'
                            b'DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoH'
                            b'uXecuz733f-zkh7U"}-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1Qvr'
                            b'jI0AAAAAAAAAAAAAAAAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEh'
                            b'keDZ2z-AABAAH4ehxZZhSlXOjMl-XEdhlGwq5kxqHpuwBWWLaDZQgGRF_d_LOwLy'
                            b'wE3Gn1jCmI0CoJ7_aRU0_l4lbsxiqbXAAw')


    """ Done Test """


def test_messagize():
    """
    Test messagize utility function
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(keeper=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256)

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)
        msg = messagize(serder, sigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-AABAA'
                                b'IgWopWicnwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZVb3m'
                                b'7bNX7nkHJysJU5QbUyYrBQ')

        # Test with pipelined
        msg =  messagize(serder, sigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VAX-A'
                                b'ABAAIgWopWicnwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZ'
                                b'Vb3m7bNX7nkHJysJU5QbUyYrBQ')

        # Test with seal
        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealEvent(i='DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, sigers, seal=seal)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-FABDy'
                                b'vCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAAAAA'
                                b'AAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAIgWopWicnwXv'
                                b'4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZVb3m7bNX7nkHJysJ'
                                b'U5QbUyYrBQ')

        # Test with pipelined
        msg = messagize(serder, sigers, seal=seal, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VA0-F'
                                b'ABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAA'
                                b'AAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAIgWopWic'
                                b'nwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZVb3m7bNX7nkH'
                                b'JysJU5QbUyYrBQ')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-17X1oXx6jbfgwTD4LZUwfVO7leuFb4kG'
                                b'Oq2OrrZtY9B_BLru3ZaLCw')

        # Test with wigers and pipelined
        msg = messagize(serder, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VAX-B'
                                b'ABAA4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-17X1oXx6jbfgwTD4LZUwfVO7leuF'
                                b'b4kGOq2OrrZtY9B_BLru3ZaLCw')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-CABBm'
                                b'MfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BJz7ERavCir_H532HUn6Q'
                                b'6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with cigars and pipelined
        msg = messagize(serder, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VAi-C'
                                b'ABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BJz7ERavCir_H532H'
                                b'Un6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1E'
                                b'EIlvBA')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-17X1oXx6jbfgwTD4LZUwfVO7leuFb4kG'
                                b'Oq2OrrZtY9B_BLru3ZaLCw-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G'
                                b'939ArM0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczI'
                                b'fTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VA5-B'
                                b'ABAA4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-17X1oXx6jbfgwTD4LZUwfVO7leuF'
                                b'b4kGOq2OrrZtY9B_BLru3ZaLCw-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXc'
                                b'aK9G939ArM0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4'
                                b'eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-AABAA'
                                b'IgWopWicnwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZVb3m'
                                b'7bNX7nkHJysJU5QbUyYrBQ-BABAA4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-17X1'
                                b'oXx6jbfgwTD4LZUwfVO7leuFb4kGOq2OrrZtY9B_BLru3ZaLCw-CABBmMfUwIOyw'
                                b'Rkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BJz7ERavCir_H532HUn6Q6BWnTmuc'
                                b'GBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with sigers and wigers and cigars and pipelines
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VBQ-A'
                                b'ABAAIgWopWicnwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZ'
                                b'Vb3m7bNX7nkHJysJU5QbUyYrBQ-BABAA4ZkgTz8zm7uetNZh3vlN1usF2LxUHfA-'
                                b'17X1oXx6jbfgwTD4LZUwfVO7leuFb4kGOq2OrrZtY9B_BLru3ZaLCw-CABBmMfUw'
                                b'IOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BJz7ERavCir_H532HUn6Q6BWn'
                                b'TmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with receipt message
        ked = serder.ked
        reserder = receipt(pre=ked["i"],
                           sn=int(ked["s"], 16),
                           dig=serder.dig)

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'Jz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B'
                                b'8G9xQYrBut0Wbt1EEIlvBA')

        # Test with cigars
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt
        msg = messagize(reserder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON000091_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"rct","d":"E7DAW2AqEFMbrH4OZPDYTiWTB9jeB'
                                b'pZ9SNJ8ErUU-6I8"}-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939Ar'
                                b'M0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6S'
                                b'l4B8G9xQYrBut0Wbt1EEIlvBA')


        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, )
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'Jz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6Sl4B'
                                b'8G9xQYrBut0Wbt1EEIlvBA-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G'
                                b'939ArM0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczI'
                                b'fTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, wigers=wigers, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VA5-B'
                                b'ABAAJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4eczIfTw6'
                                b'Sl4B8G9xQYrBut0Wbt1EEIlvBA-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXc'
                                b'aK9G939ArM0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRICZym-oQ4'
                                b'eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        # Test with sigers and seal and wigers and cigars and pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, wigers=wigers,
                        cigars=cigars, pipelined=True)
        assert msg ==   bytearray(b'{"v":"KERI10JSON0000ba_","i":"EYkVu-hmKhInGbL3P0zP5Sdxv52TyTeaaK'
                                  b'8uGu2ETrDo","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                  b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","wt":"0","w":[],"c":[]}-VBt-F'
                                  b'ABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAA'
                                  b'AAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAIgWopWic'
                                  b'nwXv4oH6QqI2DNVrZj5zKsTLjX0ktZHAHsFC2T6oZhTSzyML6GgZVb3m7bNX7nkH'
                                  b'JysJU5QbUyYrBQ-BABAAJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V2gdKhoRI'
                                  b'CZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA-CABBmMfUwIOywRkyc5GyQ'
                                  b'XfgDA4UOAMvjvnXcaK9G939ArM0BJz7ERavCir_H532HUn6Q6BWnTmucGBky2r2V'
                                  b'2gdKhoRICZym-oQ4eczIfTw6Sl4B8G9xQYrBut0Wbt1EEIlvBA')

        """ Done Test """


def test_receiptize():
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(keeper=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="")
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256)


        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = receiptize(serder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-CABBx'
                                b'nLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX_5Ch'
                                b'vHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5bUvXBQ')

        # Test with pipelined
        msg = receiptize(serder, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-VAi-C'
                                b'ABBxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX'
                                b'_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5'
                                b'bUvXBQ')

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = receiptize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'ZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGj'
                                b'GMHui-QHvy11Eon5bUvXBQ')

        #test with cigars and wigers
        msg = receiptize(serder, cigars=cigars, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-CABBx'
                                b'nLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX_5Ch'
                                b'vHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5bUvX'
                                b'BQ-BABAAZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA'
                                b'6vj-leGjGMHui-QHvy11Eon5bUvXBQ')

        #test with cigars and wigers and pipelined
        msg = receiptize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-VA5-C'
                                b'ABBxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX'
                                b'_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5'
                                b'bUvXBQ-BABAAZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkja'
                                b'cpCA6vj-leGjGMHui-QHvy11Eon5bUvXBQ')



        ked = serder.ked
        reserder = receipt(pre=ked["i"],
                           sn=int(ked["s"], 16),
                           dig=serder.dig)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt
        msg = receiptize(reserder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON000091_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"rct","d":"EugpBKqnZiNI_2WR4aEjzKrU2Vdr-'
                                b'okSy_XOW954CGME"}-CABBxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jc'
                                b'Q0BZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-l'
                                b'eGjGMHui-QHvy11Eon5bUvXBQ')

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        msg = receiptize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-BABAA'
                                b'ZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGj'
                                b'GMHui-QHvy11Eon5bUvXBQ')

        #test with cigars and wigers
        msg = receiptize(serder, cigars=cigars, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-CABBx'
                                b'nLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX_5Ch'
                                b'vHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5bUvX'
                                b'BQ-BABAAZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA'
                                b'6vj-leGjGMHui-QHvy11Eon5bUvXBQ')

        #test with cigars and wigers and pipelined
        msg = receiptize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000ba_","i":"ExINzBU4THG-px0LkLV3veaY3ZLr1dqqsr'
                                b'vjpcc9SzWQ","s":"0","t":"icp","kt":"1","k":["BxnLqpuCcrO8ITn3i1D'
                                b'hI-zqkgQJdNhAEfsGQLiE1jcQ"],"n":"","wt":"0","w":[],"c":[]}-VA5-C'
                                b'ABBxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ0BZqE8BIY0wYqi7swX'
                                b'_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkjacpCA6vj-leGjGMHui-QHvy11Eon5'
                                b'bUvXBQ-BABAAZqE8BIY0wYqi7swX_5ChvHwKKoLlBgXLeVdm3WMeEu6WFxHnSkja'
                                b'cpCA6vj-leGjGMHui-QHvy11Eon5bUvXBQ')
        """ Done Test """


def test_kever():
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """

    with pytest.raises(TypeError):  # Missing required positional arguments
        kever = Kever()

    with openDB() as db:  # Transferable case
        # Setup inception key event dict
        salt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
        salter = Salter(raw=salt)
        # create current key
        sith = 1  #  one signer
        #  original signing keypair transferable default
        skp0 = salter.signer(path="A", temp=True)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519
        keys = [skp0.verfer.qb64]

        # create next key
        nxtsith = "1" #  one signer
        #  next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nexter = Nexter(sith=nxtsith, keys=nxtkeys)
        nxt = nexter.qb64
        assert nxt == "E_d8cX6vuQwmD5P62_b663OeaVCLbiBFsirRHJsHn9co"  # transferable so nxt is not empty

        sn = 0  #  inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  #  one attached signature unspecified index

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith), # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    w=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                   )

        # Derive AID from ked
        aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519)
        assert aid0.code == MtrDex.Ed25519
        assert aid0.qb64 == skp0.verfer.qb64 == 'DBQOqSaf6GqVAoPxb4UARrklS8kLYj3JqsR6b4AASDd4'

        # update ked with pre
        ked0["i"] = aid0.qb64

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], baser=db)  # no error
        assert kever.baser == db
        assert kever.cues == None
        assert kever.prefixer.qb64 == aid0.qb64
        assert kever.sn == 0
        assert [verfer.qb64 for verfer in kever.verfers] == [skp0.verfer.qb64]
        assert kever.nexter.qb64 == nexter.qb64

        serderK = kever.state()
        assert serderK.pre == kever.prefixer.qb64
        assert serderK.sn == kever.sn
        assert ([verfer.qb64 for verfer in serderK.verfers] ==
                [verfer.qb64 for verfer in kever.verfers])
        assert serderK.raw == (b'{"v":"KERI10JSON00017e_","i":"DBQOqSaf6GqVAoPxb4UARrklS8kLYj3JqsR6b4AASDd4",'
                               b'"s":"0","t":"ksn","d":"EiJRSTJQFjunT82GMPq3XLt4iMjEl00jVCaL97g0kkMQ","te":"i'
                               b'cp","kt":"1","k":["DBQOqSaf6GqVAoPxb4UARrklS8kLYj3JqsR6b4AASDd4"],"n":"E_d8c'
                               b'X6vuQwmD5P62_b663OeaVCLbiBFsirRHJsHn9co","wt":"0","w":[],"c":[],"ee":{"s":"0'
                               b'","d":"EiJRSTJQFjunT82GMPq3XLt4iMjEl00jVCaL97g0kkMQ","wr":[],"wa":[]},"di":"'
                               b'"}')

    with openDB() as db:  # Non-Transferable case
        # Setup inception key event dict
        # create current key
        sith = 1  #  one signer
        skp0 = Signer(transferable=False)  #  original signing keypair non-transferable
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        keys = [skp0.verfer.qb64]

        # create next key Error case
        nxtsith = "1" #  one signer
        skp1 = Signer()  #  next signing keypair transferable is default
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nexter = Nexter(sith=nxtsith, keys=nxtkeys)
        nxt = nexter.qb64  # nxt is not empty so error

        sn = 0  #  inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  #  one attached signature unspecified index

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith), # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    w=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                   )


        # Derive AID from ked
        with pytest.raises(DerivationError):
            aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        # assert aid0.code == MtrDex.Ed25519N
        # assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["i"] =skp0.verfer.qb64

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

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith), # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    w=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    )


        # Derive AID from ked
        aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        assert aid0.code == MtrDex.Ed25519N
        assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["i"] = aid0.qb64

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
        nxt1 = nexter1.qb64  # transferable so nxt is not empty
        assert nxt1 == 'EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU'
        serder0 = incept(keys=keys0, nxt=nxt1)
        pre = serder0.ked["i"]
        event_digs.append(serder0.dig)
        assert serder0.ked["i"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.dig == 'EB5PLgogAWw5iniBXk0MKnFU9udCHa9ez_HJxCuvL_xM'

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], baser=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.diger.qb64 == serder0.dig
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.qb64 == nxt1
        assert kever.estOnly == False
        assert kever.transferable == True

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2
        keys2 = [signers[2].verfer.qb64]
        nexter2 = Nexter(keys=keys2)
        nxt2 = nexter2.qb64  # transferable so nxt is not empty
        assert nxt2 == 'E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
        serder1 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
        event_digs.append(serder1.dig)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["kt"] == '1'
        assert serder1.ked["k"] == keys1
        assert serder1.ked["n"] == nxt2
        assert serder1.ked["p"] == serder0.dig

        # sign serialization and verify signature
        sig1 = signers[1].sign(serder1.raw, index=0)
        assert signers[1].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        kever.update(serder=serder1, sigers=[sig1])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.diger.qb64 == serder1.dig
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
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '2'
        assert serder2.ked["k"] == keys2
        assert serder2.ked["n"] == nxt3
        assert serder2.ked["p"] == serder1.dig

        # sign serialization and verify signature
        sig2 = signers[2].sign(serder2.raw, index=0)
        assert signers[2].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 2
        assert kever.serder.diger.qb64 == serder2.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys2
        assert kever.nexter.qb64 == nxt3

        # Event 3 Interaction
        serder3 = interact(pre=pre, dig=serder2.dig, sn=3)
        event_digs.append(serder3.dig)
        assert serder3.ked["i"] == pre
        assert serder3.ked["s"] == '3'
        assert serder3.ked["p"] == serder2.dig

        # sign serialization and verify signature
        sig3 = signers[2].sign(serder3.raw, index=0)
        assert signers[2].verfer.verify(sig3.raw, serder3.raw)
        # update key event verifier state
        kever.update(serder=serder3, sigers=[sig3])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 3
        assert kever.serder.diger.qb64 == serder3.dig
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.nexter.qb64 == nxt3  # no change

        # Event 4 Interaction
        serder4 = interact(pre=pre, dig=serder3.dig, sn=4)
        event_digs.append(serder4.dig)
        assert serder4.ked["i"] == pre
        assert serder4.ked["s"] == '4'
        assert serder4.ked["p"] == serder3.dig

        # sign serialization and verify signature
        sig4 = signers[2].sign(serder4.raw, index=0)
        assert signers[2].verfer.verify(sig4.raw, serder4.raw)
        # update key event verifier state
        kever.update(serder=serder4, sigers=[sig4])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 4
        assert kever.serder.diger.qb64 == serder4.dig
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
        assert serder5.ked["i"] == pre
        assert serder5.ked["s"] == '5'
        assert serder5.ked["k"] == keys3
        assert serder5.ked["n"] == nxt4
        assert serder5.ked["p"] == serder4.dig

        # sign serialization and verify signature
        sig5 = signers[3].sign(serder5.raw, index=0)
        assert signers[3].verfer.verify(sig5.raw, serder5.raw)
        # update key event verifier state
        kever.update(serder=serder5, sigers=[sig5])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 5
        assert kever.serder.diger.qb64 == serder5.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys3
        assert kever.nexter.qb64 == nxt4

        # Event 6 Interaction
        serder6 = interact(pre=pre, dig=serder5.dig, sn=6)
        event_digs.append(serder6.dig)
        assert serder6.ked["i"] == pre
        assert serder6.ked["s"] == '6'
        assert serder6.ked["p"] == serder5.dig

        # sign serialization and verify signature
        sig6 = signers[3].sign(serder6.raw, index=0)
        assert signers[3].verfer.verify(sig6.raw, serder6.raw)
        # update key event verifier state
        kever.update(serder=serder6, sigers=[sig6])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 6
        assert kever.serder.diger.qb64 == serder6.dig
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
        assert kever.nexter.qb64 == nxt4    # no change

        # Event 7 Rotation to null NonTransferable Abandon
        nxt5 = ""  # nxt digest is empty
        serder7 = rotate(pre=pre, keys=keys4, dig=serder6.dig, nxt=nxt5, sn=7)
        event_digs.append(serder7.dig)
        assert serder7.ked["i"] == pre
        assert serder7.ked["s"] == '7'
        assert serder7.ked["k"] == keys4
        assert serder7.ked["n"] == nxt5
        assert serder7.ked["p"] == serder6.dig

        # sign serialization and verify signature
        sig7 = signers[4].sign(serder7.raw, index=0)
        assert signers[4].verfer.verify(sig7.raw, serder7.raw)
        # update key event verifier state
        kever.update(serder=serder7, sigers=[sig7])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 7
        assert kever.serder.diger.qb64 == serder7.dig
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys4
        assert kever.nexter == None
        assert not kever.transferable

        # Event 8 Interaction
        serder8 = interact(pre=pre, dig=serder7.dig, sn=8)
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.dig

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
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.dig

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
        cnfg = [TraitDex.EstOnly]  #  EstOnly
        serder0 = incept(keys=keys0, nxt=nxt1, cnfg=cnfg)
        event_digs.append(serder0.dig)
        pre = serder0.ked["i"]
        assert serder0.ked["i"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.ked["c"] == cnfg
        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], baser=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.diger.qb64 == serder0.dig
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.qb64 == nxt1
        assert kever.estOnly == True
        assert kever.transferable == True

        # Event 1 Interaction. Because EstOnly, this event not included in KEL
        serder1 = interact(pre=pre, dig=serder0.dig, sn=1)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["p"] == serder0.dig
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
        nxt2 = nexter2.qb64  # transferable so nxt is not empty
        assert nxt2 == 'E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
        serder2 = rotate(pre=pre, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
        event_digs.append(serder2.dig)
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '1'
        assert serder2.ked["kt"] == '1'
        assert serder2.ked["k"] == keys1
        assert serder2.ked["n"] == nxt2
        assert serder2.ked["p"] == serder0.dig

        # sign serialization and verify signature
        sig2 = signers[1].sign(serder2.raw, index=0)
        assert signers[1].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.diger.qb64 == serder2.dig
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
    logger.setLevel("ERROR")

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
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], baser=conlgr)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert kes ==bytearray(b'{"v":"KERI10JSON0000e6_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOo'
                               b'eKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5t'
                               b'zHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIy'
                               b'a3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAyIoOoziM1_fGb-1gKWY_'
                               b'LtlKiZIwuaJ5iPkYflmqOxxBn6MspbvCcLf8bF_uAgxCVLG1W4IMEhvDi_8rPORgDw')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[2].verfer.qb64]).qb64,
                        sn=1)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[3].verfer.qb64]).qb64,
                        sn=2)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=3)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=4)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[4].verfer.qb64]).qb64,
                        sn=5)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=6)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                    dig=kever.serder.diger.qb64,
                    nxt="",
                    sn=7)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nulled so reject any more events
            kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Event 8 Rotation
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[5].verfer.qb64]).qb64,
                        sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert len(kes) == 3164

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.baser.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=vallgr)

        # test for incomplete event in stream  (new process just hangs waiting for more bytes)
        # kevery.process(ims=kes[:20])
        # assert pre not in kevery.kevers  # shortage so gives up

        kevery.process(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs


    assert not os.path.exists(kevery.db.path)
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
        sith = "2"
        code = MtrDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        sith=sith,
                        nxt=Nexter(keys=nxtkeys).qb64)

        # create sig counter
        count = len(keys)
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers, baser=conlgr)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)

        assert kes == bytearray(b'{"v":"KERI10JSON000144_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4Y'
                                b'eUSqBv5sEk","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5t'
                                b'zHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y'
                                b'2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E'
                                b'9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","wt":"0","w":[],"c"'
                                b':[]}-AADAA74a3kHBjpaY2h3AzX8UursaGoW8kKU1rRLlMTYffMvKSTbhHHy96br'
                                b'GN2P6ehcmEW2nlUNZVuMf8zo6Qd8PkCgABIJfoSJejaDh1g-UZKkldxtTCwic7kB'
                                b'3s15EsDPKpm_6EhGcxVTt0AFXQUQMroKgKrGnxL0GP6gwEdmdu9dVRAgACtJFQBQ'
                                b'iRX5iqWpJQntfAZTx6VIv_Ghydg1oB0QCq7s8D8LuKH5n1S5t8AbbQPXv6Paf7AV'
                                b'JRFv8lhCT5cdx3Bg')

        # Event 1 Rotation Transferable
        keys = nxtkeys
        sith = "2"
        nxtkeys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith=sith,
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=nxtkeys).qb64,
                        sn=1)
        # create sig counter
        count = len(keys)
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=2)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=3)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
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
                    sith="2",
                    dig=kever.serder.diger.qb64,
                    nxt="",
                    sn=4)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-5) for i in range(5, 8)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        for siger in sigers:
            kes.extend(siger.qb64b)

        assert len(kes) == 2692

        kevery = Kevery(db=vallgr)
        kevery.process(ims=kes)

        pre = kever.prefixer.qb64
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[5].verfer.qb64

    assert not os.path.exists(kevery.db.path)

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

        assert sn == int(serder.ked["s"], 16) == 0

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                              dig=kever.serder.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                              dig=kever.serder.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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
                          dig=kever.serder.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
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

        kevery = Kevery(db=vallgr)
        kevery.process(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64 == signers[esn].verfer.qb64


        y_db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == y_db_digs
        y_db_est_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelEstIter(pre)]
        assert db_est_digs == y_db_est_digs

    assert not os.path.exists(kevery.db.path)
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
    valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
    assert valPrefixer.code == MtrDex.Ed25519N
    valpre = valPrefixer.qb64
    assert valpre == 'B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'

    with openDB("controller") as coeLogger, openDB("validator") as valLogger:
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)
        event_digs = [] # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        #create receipt msg stream
        res = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[coeSigners[esn].verfer.qb64],
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64)

        assert sn == int(serder.ked["s"], 16) == 0
        coepre = serder.ked["i"]
        assert coepre == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # return Siger if index

        #  attach to key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        # make copy of kes so can use again for valKevery
        coeKevery.process(ims=bytearray(kes))  # create Kever using Kevery
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre
        valKevery.process(ims=kes)
        assert coepre in valKevery.kevers
        valKever = valKevery.kevers[coepre]
        assert len(kes) ==  0

        # create receipt from val to coe
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           dig=coeKever.serder.diger.qb64)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64 == '0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
        assert recnt.qb64 == '-CAB'

        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)
        assert res == bytearray(b'{"v":"KERI10JSON000091_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOo'
                                b'eKtWTOunRA","s":"0","t":"rct","d":"EB5PLgogAWw5iniBXk0MKnFU9udCH'
                                b'a9ez_HJxCuvL_xM"}-CABB8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiM'
                                b'c0BMszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8'
                                b'Fu_5asnM7m67KlGC9EYaw0KDQ')

        coeKevery.process(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == valPrefixer.qb64b + valCigar.qb64b


        # create receipt to escrow use invalid dig and sn so not in db
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=2,
                           dig=fake)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
        # attach to receipt msg stream
        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)

        coeKevery.process(ims=res)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.getUres(key=snKey(pre=coeKever.prefixer.qb64,
                                                        sn=2))
        assert bytes(result[0]) == fake.encode("utf-8") + valPrefixer.qb64b + valCigar.qb64b

        # create receipt stale use invalid dig and valid sn so bad receipt
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                               sn=coeKever.sn,
                               dig=fake)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
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
                        dig=coeKever.serder.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # returns siger
        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 2
        assert esn == 1
        serder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.serder.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.serder.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn+1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 4
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 5
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                          dig=coeKever.serder.diger.qb64,
                          sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  #  do not increment esn
        assert sn == 6
        assert esn == 2
        serder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.serder.diger.qb64,
                              sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        #extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        valKevery.process(ims=kes)

        assert coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(event_digs) == 7


        assert valKever.sn == coeKever.sn
        assert valKever.verfers[0].qb64 == coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.baser.path)

    """ Done Test """

def test_direct_mode():
    """
    Test direct mode with transferable validator event receipts

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
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = [] # list of coe's own event log digs to verify against database
        val_event_digs = [] # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                        nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                        code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'

        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5t'
                                 b'zHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIy'
                                 b'a3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAmDoPp9jDio1hznNDO-3T'
                                 b'2KA_FUbY8f_qybT6_FqPAuf89e9AMDXP5wch6jvT4Ev4QRp8HqtTb9t2Y6_KJPYlBw')

        # create own Coe Kever in  Coe's Kevery
        coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                            nxt=Nexter(keys=[valSigners[vesn+1].verfer.qb64]).qb64,
                            code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == 'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'

        val_event_digs.append(valSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY'
                                 b'_qrIZIicQg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBP'
                                 b'NPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-i'
                                 b'c81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAAll_W0_FsjUyJnYokSNPq'
                                 b'q7xdwIBs0ebq2eUez6RKNB-UG_y6fD0e6fb_nANvmNCWjsoFjWv3XP3ApXUabMgyBA')

        # create own Val Kever in  Val's Kevery
        valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.diger.qb64b == b'EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o'
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"v":"KERI10JSON0000e6_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w",'
                             b'"s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunR'
                             b'A"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":['
                             b']}')
        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg'

        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = bytearray(reserder.raw)
        rmsg.extend(counter.qb64b)
        rmsg.extend(siger.qb64b)
        assert rmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"0","t":"vrc","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwl'
                                 b'vMwZIzdOM0Z3u7o","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qr'
                                 b'IZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzu'
                                 b'po"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWc'
                                 b'QYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg')


        valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        assert vmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY'
                                 b'_qrIZIicQg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBP'
                                 b'NPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-i'
                                 b'c81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAAll_W0_FsjUyJnYokSNPq'
                                 b'q7xdwIBs0ebq2eUez6RKNB-UG_y6fD0e6fb_nANvmNCWjsoFjWv3XP3ApXUabMgy'
                                 b'BA{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlR'
                                 b'YyB-6n4WDi7w","s":"0","t":"vrc","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYz'
                                 b'wlvMwZIzdOM0Z3u7o","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_'
                                 b'qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJ'
                                 b'zupo"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbT'
                                 b'WcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg')


        # Simulate send to coe of val's incept and val's receipt of coe's inception message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg0AAAAAAAAAAAAAAAAAAAAAAAEGFSGYH2'
                                    b'BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupoAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uN'
                                    b'U8m7buVSPVLbTWcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg')


        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=10,
                        dig=fake,
                        seal=seal)
        # sign event not receipt
        counter = Counter(CtrDex.ControllerIdxSigs)
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"a","t":"vrc","d":"EiRvswmIbhsbdz95TuwZSZkKL5jLn'
                                 b'R-kM0qwQ6PXH0hs","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qr'
                                 b'IZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzu'
                                 b'po"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWc'
                                 b'QYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg')

        coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                   sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)


        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = chit(pre=valK.prefixer.qb64,
                        sn=valK.sn,
                        dig=valK.serder.diger.qb64,
                        seal=seal)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.diger.qb64b == b'EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo'
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg",'
                             b'"s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiM'
                             b'c"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","wt":"0","w":[],"c":['
                             b']}')

        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAZqxNTt_LDZnmwEIaJX0cK9VKkCGq1UieEx6881MKKOtlRirvs_4pzFgmw3aRwAaIM2XV0biQ7xHeOoXglluDCA'

        # create receipt message
        cmsg = bytearray(reserder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY'
                                 b'_qrIZIicQg","s":"0","t":"vrc","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo'
                                 b'3lMkveRoPIJzupo","a":{"i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6'
                                 b'n4WDi7w","s":"0","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u'
                                 b'7o"}}-AABAAZqxNTt_LDZnmwEIaJX0cK9VKkCGq1UieEx6881MKKOtlRirvs_4pz'
                                 b'Fgmw3aRwAaIM2XV0biQ7xHeOoXglluDCA')

        # coe process own receipt in own Kevery so have copy in own log
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                    dig=valKever.serder.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w0AAAAAAAAAAAAAAAAAAAAAAAEEnwxEm5'
                                    b'Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7oAAZqxNTt_LDZnmwEIaJX0cK9VKkCGq1UieEx6881'
                                    b'MKKOtlRirvs_4pzFgmw3aRwAaIM2XV0biQ7xHeOoXglluDCA')

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           sn=csn)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000122_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"1","t":"rot","p":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwl'
                                 b'vMwZIzdOM0Z3u7o","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfA'
                                 b'kt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
                                 b'","wt":"0","wr":[],"wa":[],"a":[]}-AABAAEuHTj2jo-QgGg1FP0tq_q2Mj'
                                 b'CeJnzYoJY1Iw2h4ov3J4ki82aHDWxYhxMiXX-E8b0vRDfr3-EB11ofd_zx3cBQ')

        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.diger.qb64b == b'Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk'
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"v":"KERI10JSON000122_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w",'
                             b'"s":"1","t":"rot","p":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","kt":"1'
                             b'","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmW'
                             b'DsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}')


        counter = Counter(CtrDex.ControllerIdxSigs)
        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAb1BJLLTkcTlefF1DOPKiOixLgQqnqxRsqEqGaaADLNwQ-uDeb2nNTQBB6SeclaihimPg9QwLnulUbdgYxI5ADg'

        # val create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"1","t":"vrc","d":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy'
                                 b'9K1zZ5BavqGDKnk","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qr'
                                 b'IZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzu'
                                 b'po"}}-AABAAb1BJLLTkcTlefF1DOPKiOixLgQqnqxRsqEqGaaADLNwQ-uDeb2nNT'
                                 b'QBB6SeclaihimPg9QwLnulUbdgYxI5ADg')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg0AAAAAAAAAAAAAAAAAAAAAAAEGFSGYH2'
                                    b'BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupoAAb1BJLLTkcTlefF1DOPKiOixLgQqnqxRsqEqGaa'
                                    b'ADLNwQ-uDeb2nNTQBB6SeclaihimPg9QwLnulUbdgYxI5ADg')

        # Next Event 2 Coe Interaction
        csn += 1  #  do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.serder.diger.qb64,
                              sn=csn)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000098_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"2","t":"ixn","p":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy'
                                 b'9K1zZ5BavqGDKnk","a":[]}-AABAARxj7iqT5m3wQIPOfCPFkeGEw1j5QY-lXbR'
                                 b'GaRSVxzW9SZIX-mXJfIjs7m6MlaYFEIJs3fiCWCj9JdUz0BHlRDA')



        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig


        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.diger.qb64b == b'E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w'
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"v":"KERI10JSON000098_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w",'
                             b'"s":"2","t":"ixn","p":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk","a":[]}')
        counter = Counter(CtrDex.ControllerIdxSigs)
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AA71XY3Y7gt3FQ3RkRDN2JN5wsKVFSqxc55yBl3PecKEpSSn_tjjtKxhvZZgWtvUxHiaSt94h8huBZ0jVdWeM6DA'

        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYy'
                                 b'B-6n4WDi7w","s":"2","t":"vrc","d":"E-5RimdY_OWoreR-Z-Q5G81-I4tjA'
                                 b'SJCaP_MqkBbtM2w","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qr'
                                 b'IZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzu'
                                 b'po"}}-AABAA71XY3Y7gt3FQ3RkRDN2JN5wsKVFSqxc55yBl3PecKEpSSn_tjjtKx'
                                 b'hvZZgWtvUxHiaSt94h8huBZ0jVdWeM6DA')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg0AAAAAAAAAAAAAAAAAAAAAAAEGFSGYH2'
                                    b'BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupoAA71XY3Y7gt3FQ3RkRDN2JN5wsKVFSqxc55yBl3P'
                                    b'ecKEpSSn_tjjtKxhvZZgWtvUxHiaSt94h8huBZ0jVdWeM6DA')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o',
                                             'Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk',
                                             'E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w']


        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs


        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
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
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = [] # list of coe's own event log digs to verify against database
        val_event_digs = [] # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           code=MtrDex.Blake3_256,
                           kind=Serials.cbor)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]

        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg ==  bytearray(b'\xaaavqKERI10CBOR0000c0_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5Cy'
                                  b'axJvUasa0atcicpbkta1ak\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWT'
                                  b'OunRAanx,EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqUbwta0aw'
                                  b'\x80ac\x80-AABAAc47yJQzrwCZpqluZC-J8IhILDaBgogcA8SwRSRxRzKhY2peya5'
                                  b'E7Swfq4Q30l-UGcqEk3GllaIseiGST80NhDg')

        # create own Coe Kever in  Coe's Kevery
        coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                            nxt=Nexter(keys=[valSigners[vesn+1].verfer.qb64]).qb64,
                            code=MtrDex.Blake3_256,
                            kind=Serials.mgpk)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]

        val_event_digs.append(valSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x8a\xa1v\xb1KERI10MGPK0000c0_\xa1i\xd9,E-5yGMmTDo6Qkr4G36Jy91gz5bF'
                                 b'2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1t\xa3icp\xa2kt\xa11\xa1k\x91\xd9,D8K'
                                 b'Y1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa1n\xd9,EOWDAJvex5dZzDx'
                                 b'eHBANyaIoUG3F4-ic81G6GwtnC4f4\xa2wt\xa10\xa1w\x90\xa1c\x90-AABAAGx'
                                 b'dXTaW3YidjLXOxNHghvzdc45FD_ElMdon2-qw1XdnpnVl0DRczwqMrSbv2QRdUCt'
                                 b'KdOoPJbH2q8YcjEH0QBw')

        # create own Val Kever in  Val's Kevery
        valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.diger.qb64b
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'\xaaavqKERI10CBOR0000c0_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvUasa'
                             b'0atcicpbkta1ak\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRAanx,EPYuj8m'
                             b'q_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqUbwta0aw\x80ac\x80')

        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = bytearray(reserder.raw)
        rmsg.extend(counter.qb64b)
        rmsg.extend(siger.qb64b)
        assert rmsg == bytearray(b'\x86\xa1v\xb1KERI10MGPK0000e6_\xa1i\xd9,EMejbZsIeOI5TTb73MKIVbjkYFU'
                                 b'RM8iREGeX5CyaxJvU\xa1s\xa10\xa1t\xa3vrc\xa1d\xd9,EyAyl33W9ja_wLX85'
                                 b'UrzRnL4KNzlsIKIA7CrD04nVX1w\xa1a\x83\xa1i\xd9,E-5yGMmTDo6Qkr4G36'
                                 b'Jy91gz5bF2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1d\xd9,EHJmsEzpuzz6QA9aHA'
                                 b'nvJhCONuiONwraOPWcgenQBlYI-AABAAiWta7sNV-ZEchQh8sN6FIcxYY8b9-Uc2'
                                 b'pvq8n64SnY-QfPs-tIO3WgMr15LSM-_tFbLxCkkSwQltTu2MdeT7CQ')

        valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        assert vmsg == bytearray(b'\x8a\xa1v\xb1KERI10MGPK0000c0_\xa1i\xd9,E-5yGMmTDo6Qkr4G36Jy91gz5bF'
                                 b'2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1t\xa3icp\xa2kt\xa11\xa1k\x91\xd9,D8K'
                                 b'Y1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa1n\xd9,EOWDAJvex5dZzDx'
                                 b'eHBANyaIoUG3F4-ic81G6GwtnC4f4\xa2wt\xa10\xa1w\x90\xa1c\x90-AABAAGx'
                                 b'dXTaW3YidjLXOxNHghvzdc45FD_ElMdon2-qw1XdnpnVl0DRczwqMrSbv2QRdUCt'
                                 b'KdOoPJbH2q8YcjEH0QBw\x86\xa1v\xb1KERI10MGPK0000e6_\xa1i\xd9,EMejbZs'
                                 b'IeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvU\xa1s\xa10\xa1t\xa3vrc\xa1'
                                 b'd\xd9,EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w\xa1a\x83\xa1i'
                                 b'\xd9,E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1d'
                                 b'\xd9,EHJmsEzpuzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYI-AABAAiWta7sNV-ZEc'
                                 b'hQh8sN6FIcxYY8b9-Uc2pvq8n64SnY-QfPs-tIO3WgMr15LSM-_tFbLxCkkSwQlt'
                                 b'Tu2MdeT7CQ')

        # Simulate send to coe of val's receipt of coe's inception message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                    dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_S0jIfaoOY0AAAAAAAAAAAAAAAAAAAAAAAEHJmsEzp'
                                    b'uzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYIAAiWta7sNV-ZEchQh8sN6FIcxYY8b9-Uc2pvq8n6'
                                    b'4SnY-QfPs-tIO3WgMr15LSM-_tFbLxCkkSwQltTu2MdeT7CQ')

        # create receipt to escrow use invalid dig so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=10,
                        dig=fake,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign event not receipt
        counter = Counter(CtrDex.ControllerIdxSigs)
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa1v\xb1KERI10MGPK0000e6_\xa1i\xd9,EMejbZsIeOI5TTb73MKIVbjkYFU'
                                 b'RM8iREGeX5CyaxJvU\xa1s\xa1a\xa1t\xa3vrc\xa1d\xd9,Em76-KfV_5y0Qw8uN'
                                 b'pg20X9-eJWwBAivyZwmRLOh_sSI\xa1a\x83\xa1i\xd9,E-5yGMmTDo6Qkr4G36'
                                 b'Jy91gz5bF2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1d\xd9,EHJmsEzpuzz6QA9aHA'
                                 b'nvJhCONuiONwraOPWcgenQBlYI-AABAAiWta7sNV-ZEchQh8sN6FIcxYY8b9-Uc2'
                                 b'pvq8n64SnY-QfPs-tIO3WgMr15LSM-_tFbLxCkkSwQltTu2MdeT7CQ')

        coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                       sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                        valKever.prefixer.qb64b +
                                        Seqner(sn=valKever.sn).qb64b +
                                        valKever.serder.diger.qb64b +
                                        siger.qb64b)


        # Send receipt from coe to val
        # create receipt of val's inception
        # create seal of coe's last est event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from coe's .kevers
        # create validator receipt
        reserder = chit(pre=valK.prefixer.qb64,
                        sn=valK.sn,
                        dig=valK.serder.diger.qb64,
                        seal=seal,
                        kind=Serials.cbor)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.diger.qb64b
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'\x8a\xa1v\xb1KERI10MGPK0000c0_\xa1i\xd9,E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_'
                             b'S0jIfaoOY\xa1s\xa10\xa1t\xa3icp\xa2kt\xa11\xa1k\x91\xd9,D8KY1sKmgyjAiUDdUBP'
                             b'NPyrSz_ad_Qf9yzhDNZlEKiMc\xa1n\xd9,EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6Gwt'
                             b'nC4f4\xa2wt\xa10\xa1w\x90\xa1c\x90')

        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index

        # create receipt message
        cmsg = bytearray(reserder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xa6avqKERI10CBOR0000e6_aix,E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_S0jI'
                                 b'faoOYasa0atcvrcadx,EHJmsEzpuzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYIa'
                                 b'a\xa3aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvUasa0adx,EyAyl3'
                                 b'3W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w-AABAAUyrt4Syep6LfJhqFjQnP'
                                 b'6Ay4Z7voIQGDmbzmktzrT6vkuidQQpf-_-LAtW6iOiYzAyuDfVl1Z9ybMMW2dUueCQ')

        # coe process own receipt in own Kevery so have copy in own log
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                    dig=valKever.serder.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvU0AAAAAAAAAAAAAAAAAAAAAAAEyAyl33W'
                                    b'9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1wAAUyrt4Syep6LfJhqFjQnP6Ay4Z7voIQGDmbzmkt'
                                    b'zrT6vkuidQQpf-_-LAtW6iOiYzAyuDfVl1Z9ybMMW2dUueCQ')

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn+1].verfer.qb64]).qb64,
                           sn=csn,
                           kind=Serials.cbor)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xacavqKERI10CBOR0000f5_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5Cy'
                                 b'axJvUasa1atcrotapx,EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1wb'
                                 b'kta1ak\x81x,DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIanx,E-dapdc'
                                 b'C6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fIbwta0bwr\x80bwa\x80aa\x80-AA'
                                 b'BAAr5jhKMA_bRDRAx1zBDtte3HMJvV4bKyj-g9ioWhAIJNvfAQE4jSzeHe3lr24F'
                                 b'YaYFk5MBlAFgiKSsO7pVyQpDQ')

        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.diger.qb64b
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'\xacavqKERI10CBOR0000f5_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvUasa'
                             b'1atcrotapx,EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1wbkta1ak\x81x,DVcuJOO'
                             b'JF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIanx,E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd9'
                             b'5JH5a34fIbwta0bwr\x80bwa\x80aa\x80')


        counter = Counter(CtrDex.ControllerIdxSigs, )
        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index

        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa1v\xb1KERI10MGPK0000e6_\xa1i\xd9,EMejbZsIeOI5TTb73MKIVbjkYFU'
                                 b'RM8iREGeX5CyaxJvU\xa1s\xa11\xa1t\xa3vrc\xa1d\xd9,ER73b7reENuBahMJs'
                                 b'MTLbeyyNPsfTRzKRWtJ3ytmInvw\xa1a\x83\xa1i\xd9,E-5yGMmTDo6Qkr4G36'
                                 b'Jy91gz5bF2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1d\xd9,EHJmsEzpuzz6QA9aHA'
                                 b'nvJhCONuiONwraOPWcgenQBlYI-AABAAocVnaxQqJbSaeOOmQbkdtt4NXJaSC3X0'
                                 b'8Bsc96ahmzMSI8YIeMIXEB6426jlHOnOMTTSLngnnOuZFqn8lHjHDA')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_S0jIfaoOY0AAAAAAAAAAAAAAAAAAAAAAAEHJmsEzp'
                                    b'uzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYIAAocVnaxQqJbSaeOOmQbkdtt4NXJaSC3X08Bsc96'
                                    b'ahmzMSI8YIeMIXEB6426jlHOnOMTTSLngnnOuZFqn8lHjHDA')

        # Next Event Coe Interaction
        csn += 1  #  do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                              dig=coeKever.serder.diger.qb64,
                              sn=csn,
                              kind=Serials.cbor)
        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xa6avqKERI10CBOR000082_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5Cy'
                                 b'axJvUasa2atcixnapx,ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvwa'
                                 b'a\x80-AABAAblowxEBYCMzh5nTKzt0foP9fRe3zoFhIvWNlah7379IttdS92sJYCANN'
                                 b'IzTI9AFzGZZzEBgjwSCfeAHOmtnCAA')

        # update coe's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig


        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal,
                        kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.diger.qb64b
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'\xa6avqKERI10CBOR000082_aix,EMejbZsIeOI5TTb73MKIVbjkYFURM8iREGeX5CyaxJvUasa'
                             b'2atcixnapx,ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvwaa\x80')

        counter = Counter(CtrDex.ControllerIdxSigs)
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index

        # create receipt message
        vmsg = bytearray(reserder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x86\xa1v\xb1KERI10MGPK0000e6_\xa1i\xd9,EMejbZsIeOI5TTb73MKIVbjkYFU'
                                 b'RM8iREGeX5CyaxJvU\xa1s\xa12\xa1t\xa3vrc\xa1d\xd9,EA4vCeJswIBJlO3Rq'
                                 b'E-wsE72Vt3wAceJ_LzqKvbDtBSY\xa1a\x83\xa1i\xd9,E-5yGMmTDo6Qkr4G36'
                                 b'Jy91gz5bF2y_Ef-s_S0jIfaoOY\xa1s\xa10\xa1d\xd9,EHJmsEzpuzz6QA9aHA'
                                 b'nvJhCONuiONwraOPWcgenQBlYI-AABAA3KhzhdmhWauqL_WN8zO3njFGBDtwmIXo'
                                 b'ZAGFboAj3QIXffCnFse3hD5qGdmAK6Qi8nWyk1U9Thc6ut-BCmQ0Aw')

        # val process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                        dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E-5yGMmTDo6Qkr4G36Jy91gz5bF2y_Ef-s_S0jIfaoOY0AAAAAAAAAAAAAAAAAAAAAAAEHJmsEzp'
                                    b'uzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYIAA3KhzhdmhWauqL_WN8zO3njFGBDtwmIXoZAGFbo'
                                    b'Aj3QIXffCnFse3hD5qGdmAK6Qi8nWyk1U9Thc6ut-BCmQ0Aw')


        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs == ['EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w',
                                             'ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw',
                                             'EA4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn+1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs == ['EHJmsEzpuzz6QA9aHAnvJhCONuiONwraOPWcgenQBlYI']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn+1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.baser.path)

    """ Done Test """


def test_process_nontransferable():
    """
    Test process of generating and validating key event messages
    """

    # Ephemeral (Nontransferable) case
    skp0 = Signer(transferable=False)  #  original signing keypair non transferable
    assert skp0.code == MtrDex.Ed25519_Seed
    assert skp0.verfer.code == MtrDex.Ed25519N

    # Derive AID by merely assigning verifier public key
    aid0 = Prefixer(qb64=skp0.verfer.qb64)
    assert aid0.code == MtrDex.Ed25519N

    # Ephemeral may be used without inception event
    # but when used with inception event must be compatible event
    sn = 0  #  inception event so 0
    sith = 1 #  one signer
    nxt = ""  # non-transferable so nxt is empty
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i=aid0.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith), # hex string no leading zeros lowercase
                k=[aid0.qb64],  # list of signing keys each qual Base64
                n=nxt,  # hash qual Base64
                wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                w=[],  # list of qual Base64 may be empty
                c=[],  # list of config ordered mappings may be empty
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
    cnt0 = Counter(CtrDex.ControllerIdxSigs)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw
    del msgb0[:rser0.size]  # strip off event from front

    # extract sig counter
    rcnt0 = Counter(qb64=msgb0)
    nrsigs = rcnt0.count
    assert nrsigs == 1
    del msgb0[:len(rcnt0.qb64)]

    # extract attached sigs
    keys = rser0.ked["k"]
    for i in range(nrsigs): # verify each attached signature
        rsig = Indexer(qb64=msgb0)
        assert rsig.index == 0
        verfer = Verfer(qb64=keys[rsig.index])
        assert verfer.qb64 == aid0.qb64
        assert verfer.qb64 == skp0.verfer.qb64
        assert verfer.verify(rsig.raw, rser0.raw)
        del msgb0[:len(rsig.qb64)]

    # verify pre
    raid0 = Prefixer(qb64=rser0.pre)
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
    assert skp0.code == MtrDex.Ed25519_Seed
    assert skp0.verfer.code == MtrDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    nxtsith = "1" #  one signer
    skp1 = Signer()  #  next signing keypair transferable is default
    assert skp1.code == MtrDex.Ed25519_Seed
    assert skp1.verfer.code == MtrDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute nxt digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i="",  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith), # hex string no leading zeros lowercase
                k=keys,  # list of signing keys each qual Base64
                n=nxt,  # hash qual Base64
                wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                w=[],  # list of qual Base64 may be empty
                c=[],
               )


    # Derive AID from ked
    aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519)
    assert aid0.code == MtrDex.Ed25519
    assert aid0.qb64 == skp0.verfer.qb64

    # update ked with pre
    ked0["i"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create attached sig counter
    cnt0 = Counter(CtrDex.ControllerIdxSigs)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw
    del msgb0[:rser0.size]  # strip off event from front

    # extract sig counter
    rcnt0 = Counter(qb64=msgb0)
    nrsigs = rcnt0.count
    assert nrsigs == 1
    del msgb0[:len(rcnt0.qb64)]

    # extract attached sigs
    keys = rser0.ked["k"]
    for i in range(nrsigs): # verify each attached signature
        rsig = Indexer(qb64=msgb0)
        assert rsig.index == 0
        verfer = Verfer(qb64=keys[rsig.index])
        assert verfer.qb64 == aid0.qb64
        assert verfer.qb64 == skp0.verfer.qb64
        assert verfer.verify(rsig.raw, rser0.raw)
        del msgb0[:len(rsig.qb64)]

    # verify pre
    raid0 = Prefixer(qb64=rser0.pre)
    assert raid0.verify(ked=rser0.ked)

    #verify nxt digest from event is still valid
    rnxt1 = Nexter(qb64=rser0.ked["n"])
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
    aidmat = Matter(raw=verkey, code=MtrDex.Ed25519)
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
    nxtkeymat = Matter(raw=verkey, code=MtrDex.Ed25519)
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

    nxtdigmat = Matter(raw=nxtdig, code=MtrDex.Blake3_256)
    assert nxtdigmat.qb64 == 'E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI'

    sn =  0
    sith = 1
    toad = 0
    index = 0

    #create key event dict
    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i=aidmat.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith), # hex string no leading zeros lowercase
                k=[aidmat.qb64],  # list of signing keys each qual Base64
                n=nxtdigmat.qb64,  # hash qual Base64
                wt ="{:x}".format(toad),  # hex string no leading zeros lowercase
                w=[],  # list of qual Base64 may be empty
                c=[],  # list of config ordered mappings may be empty
               )


    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"v":"KERI10JSON0000e6_","i":"Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s",'
                          b'"s":"0","t":"icp","kt":"1","k":["Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50'
                          b's"],"n":"E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI","wt":"0","w":[],"c":['
                          b']}')


    assert txsrdr.size == 230

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = Matter(raw=txdig, code=MtrDex.Blake3_256)
    assert txdigmat.qb64 == 'Ea-gtTKs7O4bJUXI5Rl7FM1xYgv-GtLd322iMGe0UZV8'

    assert txsrdr.dig == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  #  sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = Indexer(raw=sig0raw, code=IdrDex.Ed25519_Sig, index=index)
    assert txsigmat.qb64 == 'AAACj90Gx1W_YKEIKBuCB3H4_dNIUEXYpkm-oCW9MhnbqYqFKb4BhZU9PQRuVfExEPcvlrzzuxB-1B4ALXwOhqDQ'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 318  #  230 + 88

    #  Recieve side
    rxsrdr = Serder(raw=msgb)
    assert rxsrdr.size == txsrdr.size
    assert rxsrdr.ked == ked0

    rxsigqb64 = msgb[rxsrdr.size:].decode("utf-8")
    assert len(rxsigqb64) == len(txsigmat.qb64)
    rxsigmat = Indexer(qb64=rxsigqb64)
    assert rxsigmat.index == index

    rxaidqb64 = rxsrdr.ked["i"]
    rxaidmat = Matter(qb64=rxaidqb64)
    assert rxaidmat.qb64 == aidmat.qb64
    assert rxaidmat.code == MtrDex.Ed25519

    rxverqb64 = rxsrdr.ked["k"][index]
    rxvermat = Matter(qb64=rxverqb64)
    assert rxvermat.qb64 == rxaidmat.qb64  #  basic derivation same

    result = pysodium.crypto_sign_verify_detached(rxsigmat.raw, rxsrdr.raw, rxvermat.raw)
    assert not result  # None if verifies successfully else raises ValueError
    """ Done Test """




if __name__ == "__main__":
    test_messagize()
