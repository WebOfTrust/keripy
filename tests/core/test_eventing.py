# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import blake3
import pysodium
import pytest

from keri import help
from keri.app import habbing, keeping
from keri.app.keeping import openKS, Manager
from keri.core import coring, eventing, parsing
from keri.core.coring import Ilks
from keri.core.coring import MtrDex, Matter, IdrDex, Indexer, CtrDex, Counter
from keri.core.coring import Salter, Serder, Siger, Cigar
from keri.core.coring import Seqner, Verfer, Signer, Nexter, Prefixer
from keri.core.eventing import Kever, Kevery
from keri.core.eventing import (SealDigest, SealRoot, SealBacker,
                                SealEvent, SealLast, SealLocation,
                                StateEvent, StateEstEvent)
from keri.core.eventing import (TraitDex, LastEstLoc, Serials, Versify,
                                simple, ample)
from keri.core.eventing import (deWitnessCouple, deReceiptCouple, deSourceCouple,
                                deReceiptTriple,
                                deTransReceiptQuadruple, deTransReceiptQuintuple)
from keri.core.eventing import (incept, rotate, interact, receipt, query,
                                delcept, deltate, state, messagize)
from keri.db import dbing, basing
from keri.db.basing import openDB
from keri.db.dbing import dgKey, snKey
from keri.kering import (ValidationError, DerivationError)

logger = help.ogler.getLogger()


def test_simple():
    """
    test simple majority function
    """
    assert simple(-2) == 0
    assert simple(-1) == 0
    assert simple(0) == 0
    assert simple(1) == 1
    assert simple(2) == 2
    assert simple(3) == 2
    assert simple(4) == 3
    assert simple(5) == 3
    assert simple(6) == 4


def test_ample():
    """
    test ample majority function  (sufficient immune majority)
    """
    assert ample(0) == 0
    assert ample(0, weak=False) == 0
    assert ample(0, f=0) == 0
    assert ample(0, f=0, weak=False) == 0
    assert ample(0, f=1) == 0
    assert ample(0, f=1, weak=False) == 0

    assert ample(1) == 1
    assert ample(1, weak=False) == 1
    with pytest.raises(ValueError):
        assert ample(1, f=1) == 1
    with pytest.raises(ValueError):
        assert ample(1, f=1, weak=False) == 1

    assert ample(2) == 2
    assert ample(2, weak=False) == 2
    with pytest.raises(ValueError):
        assert ample(2, f=1) == 2
    with pytest.raises(ValueError):
        assert ample(2, f=1, weak=False) == 2

    assert ample(3) == 3
    assert ample(3, weak=False) == 3
    with pytest.raises(ValueError):
        assert ample(3, f=1) == 3
    with pytest.raises(ValueError):
        assert ample(3, f=1) == 3

    assert ample(4) == 3
    assert ample(4, weak=False) == 3
    assert ample(4, f=1) == 3
    assert ample(4, f=1) == 3

    assert ample(5) == 4
    assert ample(5, weak=False) == 4
    assert ample(5, f=1) == 4
    assert ample(5, f=1) == 4

    assert ample(6) == 4
    assert ample(6, weak=False) == 5
    assert ample(6, f=1) == 4
    assert ample(6, f=1, weak=False) == 5

    assert ample(7) == 5
    assert ample(7, weak=False) == 5
    assert ample(7, f=2) == 5
    assert ample(7, f=2, weak=False) == 5

    assert ample(8) == 6
    assert ample(8, weak=False) == 6
    assert ample(8, f=2) == 6
    assert ample(8, f=2, weak=False) == 6

    assert ample(9) == 6
    assert ample(9, weak=False) == 7
    assert ample(9, f=2) == 6
    assert ample(9, f=2, weak=False) == 7

    assert ample(10) == 7
    assert ample(10, weak=False) == 7
    assert ample(10, f=3) == 7
    assert ample(10, f=3, weak=False) == 7

    assert ample(11) == 8
    assert ample(11, weak=False) == 8
    assert ample(11, f=3) == 8
    assert ample(11, f=3, weak=False) == 8

    assert ample(12) == 8
    assert ample(12, weak=False) == 9
    assert ample(12, f=3) == 8
    assert ample(12, f=3, weak=False) == 9

    assert ample(13) == 9
    assert ample(13, weak=False) == 9
    assert ample(13, f=4) == 9
    assert ample(13, f=4, weak=False) == 9


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


def test_desourcecouple():
    """
    test deSourceCouple function
    """
    snu = '0AAAAAAAAAAAAAAAAAAAAABQ'
    dig = 'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    snub = b'0AAAAAAAAAAAAAAAAAAAAABQ'
    digb = b'E62X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'

    # str
    couple = snu + dig
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64 == snu
    assert diger.qb64 == dig
    assert len(couple) == 68  # not strip delete

    # bytes
    couple = snub + digb
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snub
    assert diger.qb64b == digb
    assert len(couple) == 68  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snub
    assert diger.qb64b == digb
    assert len(couple) == 68  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snub
    assert diger.qb64b == digb
    assert len(couple) == 68  # not strip delete

    # test strip delete
    # str
    couple = snu + dig
    assert len(couple) == 68
    with pytest.raises(TypeError):  # immutable str so no delete
        seqner, diger = deSourceCouple(couple, strip=True)
    assert len(couple) == 68  # immutable so no delete

    # bytes
    couple = snub + digb
    with pytest.raises(TypeError):  # immutable bytes so no delete
        seqner, diger = deSourceCouple(couple, strip=True)
    assert len(couple) == 68  # immutable so no delete

    # memoryview
    couple = memoryview(couple)
    with pytest.raises(TypeError):  # memoryview converted to bytes so no delete
        seqner, diger = deSourceCouple(couple, strip=True)
    assert len(couple) == 68  # immutable so no delete

    # bytearray
    couple = bytearray(couple)
    seqner, diger = deSourceCouple(couple, strip=True)
    assert seqner.qb64b == snub
    assert diger.qb64b == digb
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
    assert len(triple) == 176  # immutable so no strip delete

    # memoryview converts to bytes
    triple = memoryview(triple)
    assert len(triple) == 176
    with pytest.raises(TypeError):
        diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert len(triple) == 176  # immutable so no strip delete

    # bytearray
    triple = bytearray(triple)
    assert len(triple) == 176
    diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert diger.qb64b == digb
    assert prefixer.qb64b == preb
    assert cigar.qb64b == cigb
    assert len(triple) == 0  # mutable so strip delete

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

    # str
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

    # str
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
    assert len(quintuple) == 244  # immutable so no strip delete

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


def test_seals_states():
    """
    Test seal and state namedtuples

    """
    seal = SealDigest(d='E12345')
    assert isinstance(seal, SealDigest)
    assert 'E12345' in seal
    assert seal.d == 'E12345'
    assert seal._asdict() == dict(d='E12345')
    assert seal._fields == ('d',)

    seal = SealRoot(rd='EABCDE')
    assert isinstance(seal, SealRoot)
    assert 'EABCDE' in seal
    assert seal.rd == 'EABCDE'
    assert seal._asdict() == dict(rd='EABCDE')
    assert seal._fields == ('rd',)

    seal = SealBacker(bi='B4321', d='EABCDE')
    assert isinstance(seal, SealBacker)
    assert 'B4321' in seal
    assert seal.bi == 'B4321'
    assert 'EABCDE' in seal
    assert seal.d == 'EABCDE'
    assert seal._asdict() == dict(bi='B4321', d='EABCDE')
    assert seal._fields == ('bi', 'd')

    seal = SealEvent(i='B4321', s='1', d='Eabcd')
    assert isinstance(seal, SealEvent)
    assert 'B4321' in seal
    assert seal.i == 'B4321'
    assert '1' in seal
    assert seal.s == '1'
    assert 'Eabcd' in seal
    assert seal.d == 'Eabcd'
    assert seal._asdict() == dict(i='B4321', s='1', d='Eabcd')
    assert seal._fields == ('i', 's', 'd')

    seal = SealLast(i='B4321')
    assert isinstance(seal, SealLast)
    assert 'B4321' in seal
    assert seal.i == 'B4321'
    assert seal._asdict() == dict(i='B4321')
    assert seal._fields == ('i',)

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

    seal = StateEvent(s='1', t='ixn', d='Eabcd')
    assert isinstance(seal, StateEvent)
    assert '1' in seal
    assert seal.s == '1'
    assert 'ixn' in seal
    assert seal.t == 'ixn'
    assert 'Eabcd' in seal
    assert seal.d == 'Eabcd'
    assert seal._asdict() == dict(s='1', t='ixn', d='Eabcd')
    assert seal._fields == ('s', 't', 'd')

    seal = StateEstEvent(s='1', d='Eabcd', br=['E9876'], ba=['E1234'])
    assert isinstance(seal, StateEstEvent)
    assert '1' in seal
    assert seal.s == '1'
    assert 'Eabcd' in seal
    assert seal.d == 'Eabcd'
    assert ['E9876'] in seal
    assert seal.br == ['E9876']
    assert ['E1234'] in seal
    assert seal.ba == ['E1234']
    assert seal._asdict() == dict(s='1', d='Eabcd', br=['E9876'], ba=['E1234'])
    assert seal._fields == ('s', 'd', 'br', 'ba')

    """End Test """


def test_keyeventfuncs(mockHelpingNowUTC):
    """
    Test the support functionality for key event generation functions

    """
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    # Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False)  # original signing keypair non transferable
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == ""
    assert serder.raw == (b'{"v":"KERI10JSON0000c1_","i":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                          b'"s":"0","t":"icp","kt":"1","k":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c"],"n":"","bt":"0","b":[],"c":[],"a":[]}')

    with pytest.raises(DerivationError):
        # non-empty nxt wtih non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, nxt="ABCDE")

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == ""
    assert serder.raw == (b'{"v":"KERI10JSON0000c1_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                          b'"s":"0","t":"icp","kt":"1","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c"],"n":"","bt":"0","b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
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
    assert (b'{"v":"KERI10JSON0000ed_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
            b'"s":"0","t":"icp","kt":"1","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
            b'c"],"n":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","bt":"0","b":[],"c":['
            b'],"a":[]}')

    assert serder0.dig == 'E9VNRo_h8UsObC0Qn7tvbssuij3d-fSE3hU9_4mg4Czk'

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
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
                           b'"s":"1","t":"rot","p":"E9VNRo_h8UsObC0Qn7tvbssuij3d-fSE3hU9_4mg4Czk","kt":"1'
                           b'","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"n":"EAXTvbATMnVRGjyC'
                           b'_VCNuXcPTxxpLanfzj14u3QMsD_U","bt":"0","br":[],"ba":[],"a":[]}')

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.dig, sn=2)
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["p"] == serder1.dig
    assert serder2.raw == (b'{"v":"KERI10JSON000098_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"2","t":"ixn","p":"Ep7NXM1Yz6N1zZBAkoBr2BaTxUVWlJD7r9AWfG3c1bXk","a":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, dig=serder2.dig)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.dig
    assert serder3.raw == (b'{"v":"KERI10JSON000091_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"0","t":"rct","d":"ENjADDuGb8QwXfG2-Q6mqFCZqnze_L9dufxLAg8AGtCE"}')

    # Receipt  transferable identifier
    serderA = incept(keys=keys0, nxt=nxt1, code=MtrDex.Blake3_256)
    seal = SealEvent(i=serderA.ked["i"], s=serderA.ked["s"], d=serderA.dig)
    assert seal.i == serderA.ked["i"]
    assert seal.d == serderA.dig

    serder4 = receipt(pre=pre, sn=2, dig=serder2.dig)

    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.dig
    assert serder4.raw == (b'{"v":"KERI10JSON000091_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                           b'"s":"2","t":"rct","d":"ENjADDuGb8QwXfG2-Q6mqFCZqnze_L9dufxLAg8AGtCE"}')

    siger = signer0.sign(ser=serderA.raw, index=0)
    msg = messagize(serder=serder4, sigers=[siger], seal=seal)
    assert msg == bytearray(b'{"v":"KERI10JSON000091_","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-'
                            b'Wk1x4ejhcc","s":"2","t":"rct","d":"ENjADDuGb8QwXfG2-Q6mqFCZqnze_'
                            b'L9dufxLAg8AGtCE"}-FABEheV9-CZwshHxId9DgDh_r3r00QpK7jzbA4EF2HIZ9o'
                            b'c0AAAAAAAAAAAAAAAAAAAAAAAEEl4SNEyeZhL_TfPclHCaaXNaofpNedM6l21ilJ'
                            b'0I3i4-AABAAUMALurW2PdrOG5l_sfRdiIdKqpDZShNcPNQ-6vJb6dwG9-wahbQrj'
                            b'303CRsAVT0gOqI9Ty4EoEyiv6LAX5w9Cw')

    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD)  # next signing keypair transferable is default
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nexterD = Nexter(keys=keysD)  # default sith is 1
    nxtD = nexterD.qb64  # transferable so nxt is not empty

    delpre = 'ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, nxt=nxtD)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'EZUY3a0vbBLqUtC1d9ZrutSeg1nlMPVuDfxUi4LpE03g'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'{"v":"KERI10JSON000121_","i":"EZUY3a0vbBLqUtC1d9ZrutSeg1nlMPVuDfxUi4LpE03g",'
                           b'"s":"0","t":"dip","kt":"1","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49'
                           b'A"],"n":"EcBCalw7Oe2ohLDra2ovwlv72PrlQZdQdaoSZ1Vvk5P4","bt":"0","b":[],"c":['
                           b'],"a":[],"di":"ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}')
    assert serderD.dig == 'EJvaOecTdGRsMG1ZBosajDHAWDL6wmmSrn13q5AhSuGU'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR)  # next signing keypair transferable is default
    assert signerR.code == MtrDex.Ed25519_Seed
    assert signerR.verfer.code == MtrDex.Ed25519
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    nexterR = Nexter(keys=keysR)  # default sith is 1
    nxtR = nexterR.qb64  # transferable so nxt is not empty

    delpre = 'ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      nxt=nxtR)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'{"v":"KERI10JSON000122_","i":"EZUY3a0vbBLqUtC1d9ZrutSeg1nlMPVuDfxUi4LpE03g",'
                           b'"s":"4","t":"drt","p":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1'
                           b'","k":["D8u3hipCxZnkM_O0jfaZLJMk9ERI428T0psRO0JVgh4c"],"n":"EAXTvbATMnVRGjyC'
                           b'_VCNuXcPTxxpLanfzj14u3QMsD_U","bt":"0","br":[],"ba":[],"a":[]}')
    assert serderR.dig == 'E99ece6FIrvll2dlnNjXfuHGvclWeNqvErHxCZPZDwGs'

    """ Done Test """


def test_state(mockHelpingNowUTC):
    """
    Test key state notice 'ksn'
    """

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
          route="",
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
        "r": "route/to/endpoint/buffer",
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
    nexter = Nexter(keys=keys)  # compute nxt digest (dummy reuse keys)
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

    # create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         br=[preW0],
                         ba=[preW3])

    serderK = state(pre=preC,
                    sn=4,
                    pig='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                    dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                    fn=4,
                    eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    nxt=nxt,
                    toad=toad,
                    wits=wits,
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON0002bf_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EgNkcl_Qewzr'
                           b'RSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+0'
                           b'0:00","et":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
                           b'"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1yt'
                           b'EFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrS'
                           b'B6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"'
                           b'3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1'
                           b'IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBK'
                           b'rBFz_1Y"]},"di":""}')

    assert serderK.dig == 'EcTO0kxOr49dIY8_XLEljCIFFGxPAuswUdgbtqFZIggg'
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
    assert msg == (b'{"v":"KERI10JSON0002bf_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9'
                   b'rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1ytEFHq'
                   b'aUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYW'
                   b'O5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"'
                   b'],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQ'
                   b'IO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],'
                   b'"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":""}-'
                   b'CABByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0BWGCQOoDC5E_VaBs'
                   b'xLtfB37HLMMhiPnECIW0gSrQa0etFKSX9lKfuHNy4YBLQBtkPCuDQTG4QMgpWRoa'
                   b'WDolZCw')

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
    assert msg == (b'{"v":"KERI10JSON0002bf_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9'
                   b'rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1ytEFHq'
                   b'aUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYW'
                   b'O5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"'
                   b'],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQ'
                   b'IO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],'
                   b'"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":""}-'
                   b'FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAA'
                   b'AAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAWGCQOoD'
                   b'C5E_VaBsxLtfB37HLMMhiPnECIW0gSrQa0etFKSX9lKfuHNy4YBLQBtkPCuDQTG4'
                   b'QMgpWRoaWDolZCw')

    # State Delegated (key state notification)
    # create transferable key pair for controller of KEL
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    sith = '1'
    keys = [signerC.verfer.qb64]
    nexter = Nexter(keys=keys)  # compute nxt digest (dummy reuse keys)
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

    # create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         br=[preW0],
                         ba=[preW3])

    # create transferable key pair for delegator of KEL
    signerD = salter.signer(path="D", temp=True)
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519  # transferable
    preD = signerD.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preD == 'DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U'

    serderK = state(pre=preC,
                    sn=4,
                    pig='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                    dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                    fn=4,
                    eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    nxt=nxt,
                    toad=toad,
                    wits=wits,
                    dpre=preD
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON0002eb_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EgNkcl_Qewzr'
                           b'RSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+0'
                           b'0:00","et":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
                           b'"],"n":"E9GdMuF9rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1yt'
                           b'EFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrS'
                           b'B6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],"ee":{"s":"'
                           b'3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1'
                           b'IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBK'
                           b'rBFz_1Y"]},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}')

    assert serderK.dig == 'EXuEleW4p6jz4QZTJRjtTkoupxLNNnWSsm2Irkwfpwlg'
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
    assert msg == (b'{"v":"KERI10JSON0002eb_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9'
                   b'rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1ytEFHq'
                   b'aUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYW'
                   b'O5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"'
                   b'],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQ'
                   b'IO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],'
                   b'"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":"DGz'
                   b'6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}-CABByvCLRr5luWmp7keD'
                   b'vDuLP0kIqcyBYq79b3Dho1QvrjI0B2qBC_LNRwoFyQnaBbbUdy8oSfsR3IpdHgm4'
                   b'wsln317OJJ4b2CpYpjtSdbUbddEYOPOOtuiSOY1Hb1LxvC3zNCQ')

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
    assert msg == (b'{"v":"KERI10JSON0002eb_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"n":"E9GdMuF9'
                   b'rZZ9uwTjqgiCGA8r2mRsC5SQDHCyOpsW5AqQ","bt":"2","b":["BaEI1ytEFHq'
                   b'aUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62LMYW'
                   b'O5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"'
                   b'],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQ'
                   b'IO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],'
                   b'"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]},"di":"DGz'
                   b'6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}-FABDyvCLRr5luWmp7keD'
                   b'vDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAAAAAAAEMuNWHss_H_kH'
                   b'4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAA2qBC_LNRwoFyQnaBbbUdy8oSfsR'
                   b'3IpdHgm4wsln317OJJ4b2CpYpjtSdbUbddEYOPOOtuiSOY1Hb1LxvC3zNCQ')

    """Done Test"""


def test_messagize():
    """
    Test messagize utility function
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers, cst, nst = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256)

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)
        msg = messagize(serder, sigers=sigers)
        assert bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                         b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                         b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                         b'}-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFantYynS'
                         b'BLWXjxYc5c_sW0052it_g6rX30kDA')

        # Test with pipelined
        msg = messagize(serder, sigers=sigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VAX-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFant'
                                b'YynSBLWXjxYc5c_sW0052it_g6rX30kDA')

        # Test with seal
        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealEvent(i='DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, sigers=sigers, seal=seal)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA'
                                b'AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAA0X9ey'
                                b'ML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFantYynSBLWXjxYc5c_s'
                                b'W0052it_g6rX30kDA')

        # Test with pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VA0-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAA'
                                b'AAAAAAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAA0'
                                b'X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFantYynSBLWXjxYc'
                                b'5c_sW0052it_g6rX30kDA')

        # Test with wigers
        verfers, digers, cst, nst = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-BABAAWha5gf4wk__OEK_ZvAyA4WYArQVKfVKevOmZWliDBpdIn7oHsWgvm8T7U'
                                b'vEjfnKobH8lKD1ILacrT6KVIxNeCw')

        # Test with wigers and pipelined
        msg = messagize(serder, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VAX-BABAAWha5gf4wk__OEK_ZvAyA4WYArQVKfVKevOmZWliDBpdIn7oHsWgvm'
                                b'8T7UvEjfnKobH8lKD1ILacrT6KVIxNeCw')

        # Test with cigars
        verfers, digers, cst, nst = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BT7b5PzUBmts-l'
                                b'blgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywggLATx'
                                b'BDnqQ3aBg')

        # Test with cigars and pipelined
        msg = messagize(serder, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VAi-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BT7b5PzUBm'
                                b'ts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywgg'
                                b'LATxBDnqQ3aBg')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-BABAAWha5gf4wk__OEK_ZvAyA4WYArQVKfVKevOmZWliDBpdIn7oHsWgvm8T7U'
                                b'vEjfnKobH8lKD1ILacrT6KVIxNeCw-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjv'
                                b'nXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6'
                                b'CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VA5-BABAAWha5gf4wk__OEK_ZvAyA4WYArQVKfVKevOmZWliDBpdIn7oHsWgvm'
                                b'8T7UvEjfnKobH8lKD1ILacrT6KVIxNeCw-CABBmMfUwIOywRkyc5GyQXfgDA4UOA'
                                b'MvjvnXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0J'
                                b'yfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers)
        assert bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                         b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                         b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                         b'}-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFantYynS'
                         b'BLWXjxYc5c_sW0052it_g6rX30kDA-BABAAWha5gf4wk__OEK_ZvAyA4WYArQVKf'
                         b'VKevOmZWliDBpdIn7oHsWgvm8T7UvEjfnKobH8lKD1ILacrT6KVIxNeCw-CABBmM'
                         b'fUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdT'
                         b'hIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with sigers and wigers and cigars and pipelines
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VBQ-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFant'
                                b'YynSBLWXjxYc5c_sW0052it_g6rX30kDA-BABAAWha5gf4wk__OEK_ZvAyA4WYAr'
                                b'QVKfVKevOmZWliDBpdIn7oHsWgvm8T7UvEjfnKobH8lKD1ILacrT6KVIxNeCw-CA'
                                b'BBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BT7b5PzUBmts-lblgO'
                                b'BzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnq'
                                b'Q3aBg')

        # Test with receipt message
        ked = serder.ked
        reserder = receipt(pre=ked["i"],
                           sn=int(ked["s"], 16),
                           dig=serder.dig)

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                         b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                         b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                         b'}-BABAAT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqq'
                         b'UYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with cigars
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt
        msg = messagize(reserder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON000091_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"rct","d":"EumwYGLL1YseRT1_oSyUwt5AJVGvw'
                                b'2hFIcmNpzEHvbm0"}-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939Ar'
                                b'M0BT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqqUYFm'
                                b'RhABQ-vPywggLATxBDnqQ3aBg')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, )
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-BABAAT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZhsOqq'
                                b'UYFmRhABQ-vPywggLATxBDnqQ3aBg-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjv'
                                b'nXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6'
                                b'CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, wigers=wigers, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VA5-BABAAT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0JyfN6CjZh'
                                b'sOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg-CABBmMfUwIOywRkyc5GyQXfgDA4UOA'
                                b'MvjvnXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhymgr4_dD0J'
                                b'yfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with sigers and seal and wigers and cigars and pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, wigers=wigers,
                        cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000c1_","i":"ECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                                b'GOM-ijM93o","s":"0","t":"icp","kt":"1","k":["D6J_jzCECalv_iTKSwx'
                                b'zPnuycxEi5fRuo3UUN7T0CVGM"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                                b'}-VBt-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAA'
                                b'AAAAAAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAA0'
                                b'X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFantYynSBLWXjxYc'
                                b'5c_sW0052it_g6rX30kDA-BABAAT7b5PzUBmts-lblgOBzdThIQjKCbq8gMinhym'
                                b'gr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg-CABBmMfUwIOywR'
                                b'kyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BT7b5PzUBmts-lblgOBzdThIQjKCbq'
                                b'8gMinhymgr4_dD0JyfN6CjZhsOqqUYFmRhABQ-vPywggLATxBDnqQ3aBg')

        # Test with query message
        ked = serder.ked
        qserder = query(route="log",
                        query=dict(i='DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=help.helping.DTS_BASE_0)

        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealLast(i=ked["i"])
        msg = messagize(qserder, sigers=sigers, seal=seal)
        assert msg == (b'{"v":"KERI10JSON000096_","t":"qry","dt":"2021-01-01T00:00:00.000'
                       b'000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kI'
                       b'qcyBYq79b3Dho1QvrjI"}}-HABECE-_06hkl9stCfQu4IluYevW5_YlxHc6eGOM-'
                       b'ijM93o-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjLrFan'
                       b'tYynSBLWXjxYc5c_sW0052it_g6rX30kDA')

        # create SealEvent for endorsers est evt whose keys use to sign
        msg = messagize(qserder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON000096_","t":"qry","dt":"2021-01-01T00:00:00.000'
                       b'000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kI'
                       b'qcyBYq79b3Dho1QvrjI"}}-VAj-HABECE-_06hkl9stCfQu4IluYevW5_YlxHc6e'
                       b'GOM-ijM93o-AABAA0X9eyML4ioPIk9AuBQFN5hGnGeRgywzNorzFydvyFTm-sjjL'
                       b'rFantYynSBLWXjxYc5c_sW0052it_g6rX30kDA')

        """ Done Test """


def test_kever(mockHelpingNowUTC):
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """

    with pytest.raises(ValueError):  # Missing required arguments
        kever = Kever()

    with openDB() as db:  # Transferable case
        # Setup inception key event dict
        salt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
        salter = Salter(raw=salt)
        # create current key
        sith = 1  # one signer
        #  original signing keypair transferable default
        skp0 = salter.signer(path="A", temp=True)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519
        keys = [skp0.verfer.qb64]

        # create next key
        #  next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nexter = Nexter(keys=nxtkeys)
        nxt = nexter.qb64
        assert nxt == "E_d8cX6vuQwmD5P62_b663OeaVCLbiBFsirRHJsHn9co"  # transferable so nxt is not empty

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a=[],  # list of seals
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

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # no error
        assert kever.db == db
        assert kever.cues == None
        assert kever.prefixer.qb64 == aid0.qb64
        assert kever.sn == 0
        assert [verfer.qb64 for verfer in kever.verfers] == [skp0.verfer.qb64]
        assert kever.nexter.qb64 == nexter.qb64
        state = kever.db.states.get(keys=kever.prefixer.qb64)
        assert state.sn == kever.sn == 0
        feqner = kever.db.firsts.get(keys=(kever.prefixer.qb64, kever.serder.dig))
        assert feqner.sn == kever.sn

        serderK = kever.state()
        assert serderK.ked == state.ked
        assert serderK.pre == kever.prefixer.qb64
        assert serderK.sn == kever.sn
        assert ([verfer.qb64 for verfer in serderK.verfers] ==
                [verfer.qb64 for verfer in kever.verfers])
        assert serderK.raw == (b'{"v":"KERI10JSON0001ab_","i":"DBQOqSaf6GqVAoPxb4UARrklS8kLYj3JqsR6b4AASDd4",'
                               b'"s":"0","p":"","d":"ErSmGekLPyCOf0VIVmYJJLHo6CVdd1K_ApeFUYsU_5WE","f":"0","d'
                               b't":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DBQOqSaf6GqV'
                               b'AoPxb4UARrklS8kLYj3JqsR6b4AASDd4"],"n":"E_d8cX6vuQwmD5P62_b663OeaVCLbiBFsirR'
                               b'HJsHn9co","bt":"0","b":[],"c":[],"ee":{"s":"0","d":"ErSmGekLPyCOf0VIVmYJJLHo'
                               b'6CVdd1K_ApeFUYsU_5WE","br":[],"ba":[]},"di":""}')

    with openDB() as db:  # Non-Transferable case
        # Setup inception key event dict
        # create current key
        sith = 1  # one signer
        skp0 = Signer(transferable=False)  # original signing keypair non-transferable
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        keys = [skp0.verfer.qb64]

        # create next key Error case
        skp1 = Signer()  # next signing keypair transferable is default
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nexter = Nexter(keys=nxtkeys)
        nxt = nexter.qb64  # nxt is not empty so error

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a={},  # list of seals
                    )

        # Derive AID from ked
        with pytest.raises(DerivationError):
            aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        # assert aid0.code == MtrDex.Ed25519N
        # assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["i"] = skp0.verfer.qb64

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)

        # retry with valid empty nxt
        nxt = ""  # nxt is empty so no error
        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=Versify(kind=Serials.json, size=0),
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    t=Ilks.icp,
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=[],  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a=[],  # list of seals
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

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

    """ Done Test """


def test_keyeventsequence_0():
    """
    Test generation of a sequence of key events

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    # root = '0AZxWJGkCkpDcHuVG4GM1KVw'
    # rooter = CryMat(qb64=root)
    # assert rooter.qb64 == root
    # assert rooter.code == CryTwoDex.Seed_128
    # signers = generateSigners(root=rooter.raw, count=8, transferable=True)
    # secrets = [signer.qb64 for signer in signers]
    # secrets =generateSecrets(root=rooter.raw, count=8, transferable=True)

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

    pubkeys = [signer.verfer.qb64 for signer in signers]
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
        event_digs = []  # list of event digs in sequence

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
        assert serder0.dig == 'ECw4ANul798tewQs25OLSDVXs-VHF_qXtm_EHk8ojTng'

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
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
        assert kever.nexter.qb64 == nxt4  # no change

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

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
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

    pubkeys = [signer.verfer.qb64 for signer in signers]
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
        event_digs = []  # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        nexter1 = Nexter(keys=keys1)
        nxt1 = nexter1.qb64  # transferable so nxt is not empty
        cnfg = [TraitDex.EstOnly]  # EstOnly
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
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
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

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
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

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()
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
        kever = Kever(serder=serder, sigers=[siger], db=conlgr)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert msgs == bytearray(b'{"v":"KERI10JSON0000ed_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOo'
                                 b'eKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5t'
                                 b'zHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIy'
                                 b'a3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAmagesCSY8QhYY'
                                 b'HCJXEWpsGD62qoLt2uyT0_Mq5lZPR88JyS5UrwFKFdcjPqyKc_SKaKDJhkGWCk07'
                                 b'k_kVkjyCA')

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

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
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert len(msgs) == 3171

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=vallgr)

        # test for incomplete event in stream  (new process just hangs waiting for more bytes)
        # kevery.process(ims=kes[:20])
        # assert pre not in kevery.kevers  # shortage so gives up

        parsing.Parser().parse(ims=msgs, kvy=kevery)
        # kevery.process(ims=msgs)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

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

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:

        # create event stream
        msgs = bytearray()
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
        kever = Kever(serder=serder, sigers=sigers, db=conlgr)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        assert msgs == bytearray(b'{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpg'
                                 b'OAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5t'
                                 b'zHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y'
                                 b'2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E'
                                 b'9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c"'
                                 b':[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVG'
                                 b'NpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPb'
                                 b'eOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAA'
                                 b'Cj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY5'
                                 b'0ezEjV81hkI1Yce75M_bPCQ')

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
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.diger.qb64,
                          sn=2)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.diger.qb64,
                          sn=3)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs, count=count)  # default is count = 1
        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i - count) for i in range(count, count + count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

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
        sigers = [signers[i].sign(serder.raw, index=i - 5) for i in range(5, 8)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        assert len(msgs) == 2699

        kevery = Kevery(db=vallgr)
        parsing.Parser().parse(ims=msgs, kvy=kevery)
        # kevery.process(ims=msgs)

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

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        event_digs = []  # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[esn].verfer.qb64],
                        nxt=Nexter(keys=[signers[esn + 1].verfer.qb64]).qb64)

        assert sn == int(serder.ked["s"], 16) == 0

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], db=conlgr)
        # extend key event stream
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
                        nxt=Nexter(keys=[signers[esn + 1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  # do not increment esn
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
        # extend key event stream
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
                        nxt=Nexter(keys=[signers[esn + 1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  # do not increment esn
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
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  # do not increment esn
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
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  # do not increment esn
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
        # extend key event stream
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
                        dig=event_digs[sn - 1],
                        nxt=Nexter(keys=[signers[esn + 1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[esn].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        # Next Event Interaction
        sn += 1  # do not increment esn
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
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)

        assert kever.verfers[0].qb64 == signers[esn].verfer.qb64

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert len(db_digs) == len(event_digs) == 9
        assert db_digs[0:6] == event_digs[0:6]
        assert db_digs[-1] == event_digs[-1]
        assert db_digs[7] == event_digs[6]
        assert db_digs[6] == event_digs[7]

        db_est_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelEstIter(pre)]
        assert len(db_est_digs) == 7
        assert db_est_digs[0:5] == event_digs[0:5]
        assert db_est_digs[5:7] == event_digs[7:9]

        kevery = Kevery(db=vallgr)
        parsing.Parser().parse(ims=kes, kvy=kevery)
        # kevery.process(ims=kes)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64 == signers[esn].verfer.qb64

        y_db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == y_db_digs
        y_db_est_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelEstIter(pre)]
        assert db_est_digs == y_db_est_digs

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

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

    with openDB(name="controller") as coeLogger, openDB(name="validator") as valLogger:
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)
        event_digs = []  # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # create receipt msg stream
        res = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[coeSigners[esn].verfer.qb64],
                        nxt=Nexter(keys=[coeSigners[esn + 1].verfer.qb64]).qb64)

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
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # create Kever using Kevery
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre
        assert coeKever.serder.raw == serder.raw

        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)  # process by Val
        assert coepre in valKevery.kevers
        valKever = valKevery.kevers[coepre]
        assert len(kes) == 0

        # create receipt from val to coe
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           dig=coeKever.serder.diger.qb64)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64 == \
               '0Bs2d05m7zpn6C9IJhb_GspbllxJwwxdrBg9bcbCjR5B8lrXJlglmiitpq3lEusEWdmmHSY4C_fxElKfF8mySfDQ'
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
        assert recnt.qb64 == '-CAB'

        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)
        assert res == bytearray(b'{"v":"KERI10JSON000091_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOo'
                                b'eKtWTOunRA","s":"0","t":"rct","d":"ECw4ANul798tewQs25OLSDVXs-VHF'
                                b'_qXtm_EHk8ojTng"}-CABB8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiM'
                                b'c0Bs2d05m7zpn6C9IJhb_GspbllxJwwxdrBg9bcbCjR5B8lrXJlglmiitpq3lEus'
                                b'EWdmmHSY4C_fxElKfF8mySfDQ')

        parsing.Parser().parse(ims=res, kvy=coeKevery)
        # coeKevery.process(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == valPrefixer.qb64b + valCigar.qb64b
        assert len(result) == 1

        # create invalid receipt to escrow use invalid dig and sn so not in db
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

        parsing.Parser().parse(ims=res, kvy=coeKevery)
        # coeKevery.process(ims=res)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.getUres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=2))
        assert bytes(result[0]) == fake.encode("utf-8") + valPrefixer.qb64b + valCigar.qb64b

        # create invalid receipt stale use valid sn so in database but invalid dig
        # so bad receipt
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

        parsing.Parser().parseOne(ims=res, kvy=coeKevery)
        # coeKevery.processOne(ims=res)  #  coe process the escrow receipt from val
        # no new receipt at valid dig
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert len(result) == 1
        # no new receipt at invalid dig
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=fake))
        assert not result

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == esn == 1
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.serder.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn + 1].verfer.qb64]).qb64,
                        sn=sn)

        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)  # returns siger
        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
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

        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Rotation Transferable
        sn += 1
        esn += 1
        assert sn == 3
        assert esn == 2
        serder = rotate(pre=coeKever.prefixer.qb64,
                        keys=[coeSigners[esn].verfer.qb64],
                        dig=coeKever.serder.diger.qb64,
                        nxt=Nexter(keys=[coeSigners[esn + 1].verfer.qb64]).qb64,
                        sn=sn)
        event_digs.append(serder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[esn].sign(serder.raw, index=0)

        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
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

        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
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

        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        # Next Event Interaction
        sn += 1  # do not increment esn
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

        # extend key event stream
        kes.extend(serder.raw)
        kes.extend(counter.qb64b)
        kes.extend(siger.qb64b)
        parsing.Parser().parse(ims=bytearray(kes), kvy=coeKevery)
        # coeKevery.process(ims=bytearray(kes))  # update key event verifier state
        parsing.Parser().parse(ims=kes, kvy=valKevery)
        # valKevery.process(ims=kes)

        assert coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(event_digs) == 7

        assert valKever.sn == coeKever.sn
        assert valKever.verfers[0].qb64 == coeKever.verfers[0].qb64 == coeSigners[esn].verfer.qb64

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

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

    with openDB(name="controller") as coeLogger, openDB(name="validator") as valLogger:
        #  init Keverys
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = []  # list of coe's own event log digs to verify against database
        val_event_digs = []  # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           nxt=Nexter(keys=[coeSigners[cesn + 1].verfer.qb64]).qb64,
                           code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == 'EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA'

        coe_event_digs.append(coeSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON0000ed_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                                 b'3bjPu5wuqA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5t'
                                 b'zHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIy'
                                 b'a3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAvA7i3r6vs3ckx'
                                 b'EZ2zVO8AtbjnaLKE_gwu0XNtzwB9p0fLKnC05cA07FWVx-mqoLDUO8mF1RcnoQvX'
                                 b'WkVv_dtBA')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           nxt=Nexter(keys=[valSigners[vesn + 1].verfer.qb64]).qb64,
                           code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == 'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM'

        val_event_digs.append(valSerder.dig)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON0000ed_","i":"ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fj'
                                 b'ew2KMl3FQM","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBP'
                                 b'NPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-i'
                                 b'c81G6GwtnC4f4","bt":"0","b":[],"c":[],"a":[]}-AABAArFZxr-FnvQVZF'
                                 b'X8WSipIxCGVCJjT6fj6qkZ-ei9UAGshPsqdX7scy0zNIB4_AfIjdSLLRWgL33AJm'
                                 b'C2neaxuDg')

        # create own Val Kever in  Val's Kevery
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        parsing.Parser().parse(ims=bytearray(cmsg), kvy=valKevery)
        # valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.diger.qb64b == b'EXeKMHPw0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYHo4v6w'
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"v":"KERI10JSON0000ed_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA",'
                             b'"s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunR'
                             b'A"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":['
                             b'],"a":[]}')
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAocy9m9ToxeeZk-FkgjFh1x839Ims4peTy2C5MdawIwoa9wlIDbD-wGmiGO4QdrQ1lSntqUAUMkcGAzB0Q6SsAA'
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'{"v":"KERI10JSON000091_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                        b'3bjPu5wuqA","s":"0","t":"rct","d":"EXeKMHPw0ql8vHiBOpo72AOrOsWZ3'
                        b'bRDL-DKkYHo4v6w"}-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQ'
                        b'M0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUr'
                        b'he6Z0-AABAAocy9m9ToxeeZk-FkgjFh1x839Ims4peTy2C5MdawIwoa9wlIDbD-w'
                        b'GmiGO4QdrQ1lSntqUAUMkcGAzB0Q6SsAA')

        # process own Val receipt in Val's Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(rmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)
        # Simulate send to coe of val's incept and val's receipt of coe's inception message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24E'
                                    b'nxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0AAocy9m9ToxeeZk-FkgjFh1x839Ims4peTy2C5Md'
                                    b'awIwoa9wlIDbD-wGmiGO4QdrQ1lSntqUAUMkcGAzB0Q6SsAA')

        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           dig=fake)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                        b'3bjPu5wuqA","s":"a","t":"rct","d":"EpX7M0uQUxXFaY80_-O6Tn3xGRe9_'
                        b'unGqSTN8a9bAnTw"}-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQ'
                        b'M0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUr'
                        b'he6Z0-AABAAocy9m9ToxeeZk-FkgjFh1x839Ims4peTy2C5MdawIwoa9wlIDbD-w'
                        b'GmiGO4QdrQ1lSntqUAUMkcGAzB0Q6SsAA')
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
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
        reserder = receipt(pre=valK.prefixer.qb64,
                           sn=valK.sn,
                           dig=valK.serder.diger.qb64)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.diger.qb64b == b'EeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0'
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"v":"KERI10JSON0000ed_","i":"ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM",'
                             b'"s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiM'
                             b'c"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","bt":"0","b":[],"c":['
                             b'],"a":[]}')

        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAv33KFtbsfcOWbefKGnlf1hbtypw8RFtLZ-tdpZ3Purcs2YA1q1PDInwgm8nRV57M8dtRUG62DrNVtE7t8onjAA'
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'{"v":"KERI10JSON000091_","i":"ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fj'
                        b'ew2KMl3FQM","s":"0","t":"rct","d":"EeGqW24EnxUgO_wfuFo6GR_vii-RN'
                        b'v5iGo8ibUrhe6Z0"}-FABEQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuq'
                        b'A0AAAAAAAAAAAAAAAAAAAAAAAEXeKMHPw0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYH'
                        b'o4v6w-AABAAv33KFtbsfcOWbefKGnlf1hbtypw8RFtLZ-tdpZ3Purcs2YA1q1PDI'
                        b'nwgm8nRV57M8dtRUG62DrNVtE7t8onjAA')

        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA0AAAAAAAAAAAAAAAAAAAAAAAEXeKMHPw'
                                    b'0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYHo4v6wAAv33KFtbsfcOWbefKGnlf1hbtypw8RFtLZ-tdpZ'
                                    b'3Purcs2YA1q1PDInwgm8nRV57M8dtRUG62DrNVtE7t8onjAA')

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn + 1].verfer.qb64]).qb64,
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
        assert cmsg == bytearray(b'{"v":"KERI10JSON000122_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                                 b'3bjPu5wuqA","s":"1","t":"rot","p":"EXeKMHPw0ql8vHiBOpo72AOrOsWZ3'
                                 b'bRDL-DKkYHo4v6w","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfA'
                                 b'kt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI'
                                 b'","bt":"0","br":[],"ba":[],"a":[]}-AABAAegis-9tsF45eBLhvqsztm-lA'
                                 b'LFkFK_T1epqHvOy3EkDVmk5g3sFps_ahsqXh7Ahitcbi-dWzRjh2ZsfzsB4OBw')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.diger.qb64b == b'EQK8BvEIsvM9r3VGd1Qi10Gzzllodv0Vmnl7nl_a05eY'
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"v":"KERI10JSON000122_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA",'
                             b'"s":"1","t":"rot","p":"EXeKMHPw0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYHo4v6w","kt":"1'
                             b'","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmW'
                             b'DsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAVFlKWaMfEee7tvDO7PLUVoCfbylu4zDH8Lrj2tmbsInqIN5oNSupo7S_j7AnCOdBaGf9WQMwwfHkeQpayCCyAA'
        # val create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                        b'3bjPu5wuqA","s":"1","t":"rct","d":"EQK8BvEIsvM9r3VGd1Qi10Gzzllod'
                        b'v0Vmnl7nl_a05eY"}-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQ'
                        b'M0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUr'
                        b'he6Z0-AABAAVFlKWaMfEee7tvDO7PLUVoCfbylu4zDH8Lrj2tmbsInqIN5oNSupo'
                        b'7S_j7AnCOdBaGf9WQMwwfHkeQpayCCyAA')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24E'
                                    b'nxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0AAVFlKWaMfEee7tvDO7PLUVoCfbylu4zDH8Lrj2t'
                                    b'mbsInqIN5oNSupo7S_j7AnCOdBaGf9WQMwwfHkeQpayCCyAA')

        # Next Event 2 Coe Interaction
        csn += 1  # do not increment esn
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
        assert cmsg == bytearray(b'{"v":"KERI10JSON000098_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                                 b'3bjPu5wuqA","s":"2","t":"ixn","p":"EQK8BvEIsvM9r3VGd1Qi10Gzzllod'
                                 b'v0Vmnl7nl_a05eY","a":[]}-AABAAN4jrweIzLru2oSHdSeikFxXQcArKO2tzAa'
                                 b'6ThfyBvUJQ8e6OsjvuV7wmmsa817kHYUjXsLx0OjKuCWV_VivMBg')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.diger.qb64b == b'EaQ7xvXmDpg7twdzEUEJGokBS6S_TXzmlY1a93ZQkx84'
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"v":"KERI10JSON000098_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA",'
                             b'"s":"2","t":"ixn","p":"EQK8BvEIsvM9r3VGd1Qi10Gzzllodv0Vmnl7nl_a05eY","a":[]}')
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAFyuqh4gxmfs7NcXRV5RN6iL2_OJAtYbDjBv3oL_UwFyolhS1EhBBjeLXvsCAVXOqrj7GMW9t3tpxL7Xtfsc5Bw'
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq9'
                        b'3bjPu5wuqA","s":"2","t":"rct","d":"EaQ7xvXmDpg7twdzEUEJGokBS6S_T'
                        b'XzmlY1a93ZQkx84"}-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQ'
                        b'M0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUr'
                        b'he6Z0-AABAAFyuqh4gxmfs7NcXRV5RN6iL2_OJAtYbDjBv3oL_UwFyolhS1EhBBj'
                        b'eLXvsCAVXOqrj7GMW9t3tpxL7Xtfsc5Bw')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24E'
                                    b'nxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0AAFyuqh4gxmfs7NcXRV5RN6iL2_OJAtYbDjBv3oL'
                                    b'_UwFyolhS1EhBBjeLXvsCAVXOqrj7GMW9t3tpxL7Xtfsc5Bw')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['EXeKMHPw0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYHo4v6w',
                                             'EQK8BvEIsvM9r3VGd1Qi10Gzzllodv0Vmnl7nl_a05eY',
                                             'EaQ7xvXmDpg7twdzEUEJGokBS6S_TXzmlY1a93ZQkx84']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['EeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

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

    with openDB(name="controller") as coeLogger, openDB(name="validator") as valLogger:
        #  init Keverys
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = []  # list of coe's own event log digs to verify against database
        val_event_digs = []  # list of val's own event log digs to verify against database

        #  init sequence numbers for both coe and val
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Coe Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeSigners[cesn].verfer.qb64],
                           nxt=Nexter(keys=[coeSigners[cesn + 1].verfer.qb64]).qb64,
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
        assert cmsg == bytearray(b'\xabavqKERI10CBOR0000c3_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQT'
                                 b'Dqe1wasa0atcicpbkta1ak\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWT'
                                 b'OunRAanx,EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqUbbta0ab'
                                 b'\x80ac\x80aa\x80-AABAAEiOvc6Yv5oBR6tHMAOJvAg_YKkHR4ifXF2mIsPYmDjE'
                                 b'q-WL3uimpNHMdGoSRVmXCotuCfDGTx3h0Gk5tz2jFBA')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           nxt=Nexter(keys=[valSigners[vesn + 1].verfer.qb64]).qb64,
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
        assert vmsg == bytearray(b'\x8b\xa1v\xb1KERI10MGPK0000c3_\xa1i\xd9,EPtxTO5d2FgPXkav6cS9NEPvcxh'
                                 b'fomsfKi3fvyMMuhZw\xa1s\xa10\xa1t\xa3icp\xa2kt\xa11\xa1k\x91\xd9,D8K'
                                 b'Y1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa1n\xd9,EOWDAJvex5dZzDx'
                                 b'eHBANyaIoUG3F4-ic81G6GwtnC4f4\xa2bt\xa10\xa1b\x90\xa1c\x90'
                                 b'\xa1a\x90-AABAABD5vMFZKjWg2GBWr0mXxYCqGUMXLNRL_4cn6dunE9eHFVst5CkV'
                                 b'd8Oam6ZuDV3IPHoy1FAXJrxouHuiAKKmRCg')

        # create own Val Kever in  Val's Kevery
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of coe's inception message to val
        parsing.Parser().parse(ims=bytearray(cmsg), kvy=valKevery)
        # valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for coe in val's .kevers

        # create receipt of coe's inception
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from val's .kevers
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.diger.qb64b
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'\xabavqKERI10CBOR0000c3_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQTDqe1wasa'
                             b'0atcicpbkta1ak\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRAanx,EPYuj8m'
                             b'q_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqUbbta0ab\x80ac\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1i\xd9,EVA41BuPTjEEtBXWwBSeD4yRHz_'
                        b'TyyzfGE1ldQTDqe1w\xa1s\xa10\xa1t\xa3rct\xa1d\xd9,ETtM9-qTtHK-KKnFe'
                        b'rFmtFQAaw70dGBFOQwz7tp85w6E-FABEPtxTO5d2FgPXkav6cS9NEPvcxhfomsfK'
                        b'i3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqduuxWenrs4SlX0RFV-VmcU'
                        b'-SSywAKr5PZV-0k-AABAA-ul0YeOLwffGCc5GUnAvgzwITCF2KXLfAzSbCANOkbr'
                        b'apY5w0Ybyeyiy1jTB_3OPEWa0_3tEMt6wZpb2zqICCw')

        parsing.Parser().parseOne(ims=bytearray(rmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach reciept message to existing message with val's incept message
        vmsg.extend(rmsg)

        # Simulate send to coe of val's receipt of coe's inception message
        parsing.Parser().parse(ims=bytearray(vmsg), kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        # check if val Kever in coe's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EPtxTO5d2FgPXkav6cS9NEPvcxhfomsfKi3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqd'
                                    b'uuxWenrs4SlX0RFV-VmcU-SSywAKr5PZV-0kAA-ul0YeOLwffGCc5GUnAvgzwITCF2KXLfAzSbCA'
                                    b'NOkbrapY5w0Ybyeyiy1jTB_3OPEWa0_3tEMt6wZpb2zqICCw')

        # create receipt to escrow use invalid dig so not in coe's db
        fake = reserder.dig  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           dig=fake,
                           kind=Serials.mgpk)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1i\xd9,EVA41BuPTjEEtBXWwBSeD4yRHz_'
                        b'TyyzfGE1ldQTDqe1w\xa1s\xa1a\xa1t\xa3rct\xa1d\xd9,Eo-3IvwDgH3uR3M0z'
                        b'Op8eYnrZTDHibWlhkISlU_HxRek-FABEPtxTO5d2FgPXkav6cS9NEPvcxhfomsfK'
                        b'i3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqduuxWenrs4SlX0RFV-VmcU'
                        b'-SSywAKr5PZV-0k-AABAA-ul0YeOLwffGCc5GUnAvgzwITCF2KXLfAzSbCANOkbr'
                        b'apY5w0Ybyeyiy1jTB_3OPEWa0_3tEMt6wZpb2zqICCw')

        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
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
        reserder = receipt(pre=valK.prefixer.qb64,
                           sn=valK.sn,
                           dig=valK.serder.diger.qb64,
                           kind=Serials.cbor)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.diger.qb64b
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'\x8b\xa1v\xb1KERI10MGPK0000c3_\xa1i\xd9,EPtxTO5d2FgPXkav6cS9NEPvcxhfomsfKi3'
                             b'fvyMMuhZw\xa1s\xa10\xa1t\xa3icp\xa2kt\xa11\xa1k\x91\xd9,D8KY1sKmgyjAiUDdUBP'
                             b'NPyrSz_ad_Qf9yzhDNZlEKiMc\xa1n\xd9,EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6Gwt'
                             b'nC4f4\xa2bt\xa10\xa1b\x90\xa1c\x90\xa1a\x90')

        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'\xa5avqKERI10CBOR00007f_aix,EPtxTO5d2FgPXkav6cS9NEPvcxhfomsfKi3fvyM'
                        b'MuhZwasa0atcrctadx,EER-hNqduuxWenrs4SlX0RFV-VmcU-SSywAKr5PZV-0k-'
                        b'FABEVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQTDqe1w0AAAAAAAAAAAAAAAA'
                        b'AAAAAAAETtM9-qTtHK-KKnFerFmtFQAaw70dGBFOQwz7tp85w6E-AABAAJiCMw2T'
                        b'oI_EUZpMQh9TZ59CPmV40IiFtY01yW-7pXSVZO5Bd7Ldj8mgJvTxMs9zMVDcSKsT'
                        b'KRBLMqtjeJjcSCA')

        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.diger.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQTDqe1w0AAAAAAAAAAAAAAAAAAAAAAAETtM9-qT'
                                    b'tHK-KKnFerFmtFQAaw70dGBFOQwz7tp85w6EAAJiCMw2ToI_EUZpMQh9TZ59CPmV40IiFtY01yW-'
                                    b'7pXSVZO5Bd7Ldj8mgJvTxMs9zMVDcSKsTKRBLMqtjeJjcSCA')

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.diger.qb64,
                           nxt=Nexter(keys=[coeSigners[cesn + 1].verfer.qb64]).qb64,
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
        assert cmsg == bytearray(b'\xacavqKERI10CBOR0000f5_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQT'
                                 b'Dqe1wasa1atcrotapx,ETtM9-qTtHK-KKnFerFmtFQAaw70dGBFOQwz7tp85w6Eb'
                                 b'kta1ak\x81x,DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIanx,E-dapdc'
                                 b'C6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fIbbta0bbr\x80bba\x80aa\x80-AA'
                                 b'BAAeAYbccb63ysFIn_4Yji_H7ofLyCiDLReIvuRHrFkl_i5A4xQGixszS8Xbkz8S'
                                 b'3W6hcXlNr4-1_m7qh4HEbCoCw')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.diger.qb64b
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'\xacavqKERI10CBOR0000f5_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQTDqe1wasa'
                             b'1atcrotapx,ETtM9-qTtHK-KKnFerFmtFQAaw70dGBFOQwz7tp85w6Ebkta1ak\x81x,DVcuJOO'
                             b'JF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIanx,E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd9'
                             b'5JH5a34fIbbta0bbr\x80bba\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1i\xd9,EVA41BuPTjEEtBXWwBSeD4yRHz_'
                        b'TyyzfGE1ldQTDqe1w\xa1s\xa11\xa1t\xa3rct\xa1d\xd9,EPHvonlASEhFuMiLw'
                        b'zbNp9cB9t2DJrcnvVvrK_P4G4Ss-FABEPtxTO5d2FgPXkav6cS9NEPvcxhfomsfK'
                        b'i3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqduuxWenrs4SlX0RFV-VmcU'
                        b'-SSywAKr5PZV-0k-AABAAVRZVF2PkwQe5oFFQoDM_efMgGHCKlf1denoAa1NJZ45'
                        b'jnz1AP1VeVmfSFLsjApfJmgCBp-mYw0mP8KwrolsICQ')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EPtxTO5d2FgPXkav6cS9NEPvcxhfomsfKi3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqd'
                                    b'uuxWenrs4SlX0RFV-VmcU-SSywAKr5PZV-0kAAVRZVF2PkwQe5oFFQoDM_efMgGHCKlf1denoAa1'
                                    b'NJZ45jnz1AP1VeVmfSFLsjApfJmgCBp-mYw0mP8KwrolsICQ')

        # Next Event Coe Interaction
        csn += 1  # do not increment esn
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
        assert cmsg == bytearray(b'\xa6avqKERI10CBOR000082_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQT'
                                 b'Dqe1wasa2atcixnapx,EPHvonlASEhFuMiLwzbNp9cB9t2DJrcnvVvrK_P4G4Ssa'
                                 b'a\x80-AABAAW7s0SV5i1KMDOufvgTAkER4lhvxkKA6AacFa5G9ZX3UE0H65-GHV8MbM'
                                 b'8zMmtirALCQSXfMXoODdLuclkJElBQ')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           dig=coeK.serder.diger.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.diger.qb64b
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'\xa6avqKERI10CBOR000082_aix,EVA41BuPTjEEtBXWwBSeD4yRHz_TyyzfGE1ldQTDqe1wasa'
                             b'2atcixnapx,EPHvonlASEhFuMiLwzbNp9cB9t2DJrcnvVvrK_P4G4Ssaa\x80')

        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1i\xd9,EVA41BuPTjEEtBXWwBSeD4yRHz_'
                        b'TyyzfGE1ldQTDqe1w\xa1s\xa12\xa1t\xa3rct\xa1d\xd9,EOMlWNCvqWStLVUUB'
                        b'lhwEbo3slpOD6-iVCtPBEsW9ofQ-FABEPtxTO5d2FgPXkav6cS9NEPvcxhfomsfK'
                        b'i3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqduuxWenrs4SlX0RFV-VmcU'
                        b'-SSywAKr5PZV-0k-AABAAMkr7U_m3dAj9t4l6vBYp-KJaioD46oc5uUdwRzrt8bm'
                        b'yvx7qJuFeM_rv9mYvY_lHN5kP9BDjig6dD6Fheo2fDg')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EPtxTO5d2FgPXkav6cS9NEPvcxhfomsfKi3fvyMMuhZw0AAAAAAAAAAAAAAAAAAAAAAAEER-hNqd'
                                    b'uuxWenrs4SlX0RFV-VmcU-SSywAKr5PZV-0kAAMkr7U_m3dAj9t4l6vBYp-KJaioD46oc5uUdwRz'
                                    b'rt8bmyvx7qJuFeM_rv9mYvY_lHN5kP9BDjig6dD6Fheo2fDg')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['ETtM9-qTtHK-KKnFerFmtFQAaw70dGBFOQwz7tp85w6E',
                                             'EPHvonlASEhFuMiLwzbNp9cB9t2DJrcnvVvrK_P4G4Ss',
                                             'EOMlWNCvqWStLVUUBlhwEbo3slpOD6-iVCtPBEsW9ofQ']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['EER-hNqduuxWenrs4SlX0RFV-VmcU-SSywAKr5PZV-0k']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)

    """ Done Test """


def test_process_nontransferable():
    """
    Test process of generating and validating key event messages
    """

    # Ephemeral (Nontransferable) case
    skp0 = Signer(transferable=False)  # original signing keypair non transferable
    assert skp0.code == MtrDex.Ed25519_Seed
    assert skp0.verfer.code == MtrDex.Ed25519N

    # Derive AID by merely assigning verifier public key
    aid0 = Prefixer(qb64=skp0.verfer.qb64)
    assert aid0.code == MtrDex.Ed25519N

    # Ephemeral may be used without inception event
    # but when used with inception event must be compatible event
    sn = 0  # inception event so 0
    sith = 1  # one signer
    nxt = ""  # non-transferable so nxt is empty
    toad = 0  # no witnesses
    nsigs = 1  # one attached signature unspecified index

    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i=aid0.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
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
    for i in range(nrsigs):  # verify each attached signature
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
    sith = 1  # one signer
    skp0 = Signer()  # original signing keypair transferable default
    assert skp0.code == MtrDex.Ed25519_Seed
    assert skp0.verfer.code == MtrDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    skp1 = Signer()  # next signing keypair transferable is default
    assert skp1.code == MtrDex.Ed25519_Seed
    assert skp1.verfer.code == MtrDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute nxt digest
    nexter = Nexter(keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  # inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  # one attached signature unspecified index

    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i="",  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
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
    for i in range(nrsigs):  # verify each attached signature
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

    # verify nxt digest from event is still valid
    rnxt1 = Nexter(qb64=rser0.ked["n"])
    assert rnxt1.verify(keys=nxtkeys)
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
    assert verkey == b'\xaf\x96\xb0p\xfb0\xa7\xd0\xa4\x18\xc9\xdc\x1d\x86\xc2:\x98\xf7?t\x1b\xde.\xcc\xcb;\x8a\xb0' \
                     b'\xa2O\xe7K'
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
    nxtsith = "{:x}".format(1)  # lowecase hex no leading zeros
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

    sn = 0
    sith = 1
    toad = 0
    index = 0

    # create key event dict
    ked0 = dict(v=Versify(kind=Serials.json, size=0),
                i=aidmat.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                t=Ilks.icp,
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                k=[aidmat.qb64],  # list of signing keys each qual Base64
                n=nxtdigmat.qb64,  # hash qual Base64
                wt="{:x}".format(toad),  # hex string no leading zeros lowercase
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

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  # sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = Indexer(raw=sig0raw, code=IdrDex.Ed25519_Sig, index=index)
    assert txsigmat.qb64 == 'AAACj90Gx1W_YKEIKBuCB3H4_dNIUEXYpkm-oCW9MhnbqYqFKb4BhZU9PQRuVfExEPcvlrzzuxB-1B4ALXwOhqDQ'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 318  # 230 + 88

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
    assert rxvermat.qb64 == rxaidmat.qb64  # basic derivation same

    result = pysodium.crypto_sign_verify_detached(rxsigmat.raw, rxsrdr.raw, rxvermat.raw)
    assert not result  # None if verifies successfully else raises ValueError
    """ Done Test """


def test_reload_kever(mockHelpingNowUTC):
    """
    Test reload Kever from keystate state message
    """

    with basing.openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
        # setup Nat's habitat using default salt multisig already incepts
        natHab = habbing.Habitat(name='nat', ks=natKS, db=natDB,
                                 isith=2, icount=3, temp=True)
        assert natHab.name == 'nat'
        assert natHab.ks == natKS
        assert natHab.db == natDB
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.pre in natHab.prefixes
        assert natHab.db.path.endswith("/keri/db/nat")
        path = natHab.db.path  # save for later

        # Create series of events for Nat
        natHab.interact()
        natHab.rotate()
        natHab.interact()
        natHab.interact()
        natHab.interact()
        natHab.interact()

        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.dig == 'En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI'
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.digb
        serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre, ldig))))
        assert serder.dig == natHab.kever.serder.dig
        nstate = natHab.kever.state()

        state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
        assert state.pretty() == ('{\n'
                                  ' "v": "KERI10JSON000235_",\n'
                                  ' "i": "E5lskf_uSh7ymhplif9nKREEsuwbBfHbHTJuMZyV6Fls",\n'
                                  ' "s": "6",\n'
                                  ' "p": "E4T5Gk5v7cv9x5oxT34zwBrTQ7K-x_Atw_kFFBNs_Mgw",\n'
                                  ' "d": "En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI",\n'
                                  ' "f": "6",\n'
                                  ' "dt": "2021-01-01T00:00:00.000000+00:00",\n'
                                  ' "et": "ixn",\n'
                                  ' "kt": "2",\n'
                                  ' "k": [\n'
                                  '  "DI5E8Zqgy0j9HIkVRMjOTTF3Nr_PqwFDZ7bDNi0QCzew",\n'
                                  '  "D2NIcFtglppQom493fiftJFiJkeKvC9b5CIdG19G8GHg",\n'
                                  '  "D36Ev0IqfpZ2wg0QbbTtPilJ2NowjFT1IqF954cLB-9M"\n'
                                  ' ],\n'
                                  ' "n": "EyIxjAmcXOeiFzlIlRpRa7byustaKPabVGDXIIQHvBHg",\n'
                                  ' "bt": "0",\n'
                                  ' "b": [],\n'
                                  ' "c": [],\n'
                                  ' "ee": {\n'
                                  '  "s": "2",\n'
                                  '  "d": "EVqqrPEkZ08J82HsZss8FUWyzUrDM3mavPTPb0meWr1s",\n'
                                  '  "br": [],\n'
                                  '  "ba": []\n'
                                  ' },\n'
                                  ' "di": ""\n'
                                  '}')
        assert state.sn == 6
        assert state.ked["f"] == '6'
        assert state.ked == nstate.ked

        # now create new Kever with state
        kever = eventing.Kever(state=state, db=natDB)
        assert kever.sn == 6
        assert kever.fn == 6
        assert kever.serder.ked == natHab.kever.serder.ked
        assert kever.serder.dig == natHab.kever.serder.dig

        kstate = kever.state()
        assert kstate.ked == state.ked
        assert state.pretty() == ('{\n'
                                  ' "v": "KERI10JSON000235_",\n'
                                  ' "i": "E5lskf_uSh7ymhplif9nKREEsuwbBfHbHTJuMZyV6Fls",\n'
                                  ' "s": "6",\n'
                                  ' "p": "E4T5Gk5v7cv9x5oxT34zwBrTQ7K-x_Atw_kFFBNs_Mgw",\n'
                                  ' "d": "En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI",\n'
                                  ' "f": "6",\n'
                                  ' "dt": "2021-01-01T00:00:00.000000+00:00",\n'
                                  ' "et": "ixn",\n'
                                  ' "kt": "2",\n'
                                  ' "k": [\n'
                                  '  "DI5E8Zqgy0j9HIkVRMjOTTF3Nr_PqwFDZ7bDNi0QCzew",\n'
                                  '  "D2NIcFtglppQom493fiftJFiJkeKvC9b5CIdG19G8GHg",\n'
                                  '  "D36Ev0IqfpZ2wg0QbbTtPilJ2NowjFT1IqF954cLB-9M"\n'
                                  ' ],\n'
                                  ' "n": "EyIxjAmcXOeiFzlIlRpRa7byustaKPabVGDXIIQHvBHg",\n'
                                  ' "bt": "0",\n'
                                  ' "b": [],\n'
                                  ' "c": [],\n'
                                  ' "ee": {\n'
                                  '  "s": "2",\n'
                                  '  "d": "EVqqrPEkZ08J82HsZss8FUWyzUrDM3mavPTPb0meWr1s",\n'
                                  '  "br": [],\n'
                                  '  "ba": []\n'
                                  ' },\n'
                                  ' "di": ""\n'
                                  '}')

    assert not os.path.exists(natKS.path)
    assert not os.path.exists(natDB.path)

    """End Test"""


if __name__ == "__main__":
    # pytest.main(['-vv', 'test_eventing.py::test_keyeventfuncs'])
    test_messagize()
