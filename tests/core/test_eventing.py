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
from keri.core.coring import Ilks, Diger
from keri.core.coring import MtrDex, Matter, IdrDex, Indexer, CtrDex, Counter
from keri.core.coring import Salter, Serder, Siger, Cigar
from keri.core.coring import Seqner, Verfer, Signer, Nexter, Prefixer
from keri.core.eventing import Kever, Kevery
from keri.core.eventing import (SealDigest, SealRoot, SealBacker,
                                SealEvent, SealLast, StateEvent, StateEstEvent)
from keri.core.eventing import (TraitDex, LastEstLoc, Serials, versify,
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
    print()
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    # Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False)  # original signing keypair non transferable
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EwslIRt-LtDgutEmsju1WAM9dAf3wzrivvNP'
                          b'En8ANo4k","i":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"0","kt":"1'
                          b'","k":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"],"nt":"0","n":[],"bt":'
                          b'"0","b":[],"c":[],"a":[]}')
    saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    assert saider.verify(serder.ked) is True

    with pytest.raises(DerivationError):
        # non-empty nxt with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, nkeys=["ABCDE"])

    with pytest.raises(DerivationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, wits=["ABCDE"])

    with pytest.raises(DerivationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, data=[{"i": "ABCDE"}])

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EdPc03U4_IgGhLQqQP2qxi1s-3r8UHzxFk8i'
                          b'NO72bap4","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"0","kt":"1'
                          b'","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"],"nt":"0","n":[],"bt":'
                          b'"0","b":[],"c":[],"a":[]}')
    saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    assert saider.verify(serder.ked) is True

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EpitDPyhh6qvfj0tMgO8RiBz5LV07OobY84WKs15XQHk']
    serder0 = incept(keys=keys0, nkeys=nxt1)
    pre = serder0.ked["i"]
    assert serder0.ked["i"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["n"] == nxt1
    assert serder0.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EKWhDaMeK0DPrGcdem78_dPpofitWMAg7ZvZ'
                           b'ceMGi2_4","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"0","kt":"1'
                           b'","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"],"nt":"1","n":["EpitDP'
                           b'yhh6qvfj0tMgO8RiBz5LV07OobY84WKs15XQHk"],"bt":"0","b":[],"c":[],"a":[]}')

    saider = coring.Saider(sad=serder0.ked, code=MtrDex.Blake3_256)
    assert saider.qb64 == serder0.said
    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, nkeys=keys2, sn=1)
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["n"] == keys2
    assert serder1.ked["p"] == serder0.said
    assert serder1.raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"E4cK99hX4C0AdlzihyusaT6zOShm6mPCXSlg'
                           b'9sBWSTSQ","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"1","p":"EK'
                           b'WhDaMeK0DPrGcdem78_dPpofitWMAg7ZvZceMGi2_4","kt":"1","k":["DHgZa-u7veNZkqk2A'
                           b'xCnxrINGKfQ0bRiaf9FdA_-_49A"],"nt":"1","n":["E1082xCJjDJW4LFEpDkePQyHc1P4gNS'
                           b'U2Fl89uwafq3I"],"bt":"0","br":[],"ba":[],"a":[]}')
    saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    assert serder1.said == saider.qb64

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.said, sn=2)
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["p"] == serder1.said
    assert serder2.raw ==(b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EInKU64yZ9yUCog0e9fu4gVaLifTa8xtpLyM'
                          b'YOhX8w9w","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"2","p":"E4'
                          b'cK99hX4C0AdlzihyusaT6zOShm6mPCXSlg9sBWSTSQ","a":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, said=serder2.said)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.said
    assert serder3.raw == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EInKU64yZ9yUCog0e9fu4gVaLifTa8xtpLyM'
                           b'YOhX8w9w","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"0"}')

    # Receipt  transferable identifier
    serderA = incept(keys=keys0, nkeys=nxt1, code=MtrDex.Blake3_256)
    assert serderA.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EUGHc8RcfrYg3Gg-kwRqrPoJJv6Cl3r1fUs_'
                           b'BX_Z4yMs","i":"EUGHc8RcfrYg3Gg-kwRqrPoJJv6Cl3r1fUs_BX_Z4yMs","s":"0","kt":"1'
                           b'","k":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"],"nt":"1","n":["EpitDP'
                           b'yhh6qvfj0tMgO8RiBz5LV07OobY84WKs15XQHk"],"bt":"0","b":[],"c":[],"a":[]}')
    seal = SealEvent(i=serderA.ked["i"], s=serderA.ked["s"], d=serderA.said)
    assert seal.i == serderA.ked["i"]
    assert seal.d == serderA.said

    serder4 = receipt(pre=pre, sn=2, said=serder2.said)

    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.said
    assert serder4.raw == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EInKU64yZ9yUCog0e9fu4gVaLifTa8xtpLyM'
                           b'YOhX8w9w","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"2"}')

    siger = signer0.sign(ser=serderA.raw, index=0)
    msg = messagize(serder=serder4, sigers=[siger], seal=seal)
    assert msg == bytearray(b'{"v":"KERI10JSON000091_","t":"rct","d":"EInKU64yZ9yUCog0e9fu4gVa'
                            b'LifTa8xtpLyMYOhX8w9w","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1'
                            b'x4ejhcc","s":"2"}-FABEUGHc8RcfrYg3Gg-kwRqrPoJJv6Cl3r1fUs_BX_Z4yM'
                            b's0AAAAAAAAAAAAAAAAAAAAAAAEUGHc8RcfrYg3Gg-kwRqrPoJJv6Cl3r1fUs_BX_'
                            b'Z4yMs-AABAAL8Wa4NvM8X7djH5lAm2SmmV568mGYpwZ5yR9yOYdbJq9tUMlK3Ldc'
                            b'8dKIzj8rH29J5UD2syn3IENWdvmOUtpAw')

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
    nxtD = nexterD.digs  # transferable so nxt is not empty

    delpre = 'ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, nkeys=nxtD)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'ECaG4EEg_L2cX3XAE4CGb5JxpHcZ5gMCD8Z8Plaf3_UU'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'{"v":"KERI10JSON00015f_","t":"dip","d":"ECaG4EEg_L2cX3XAE4CGb5JxpHcZ5gMCD8Z8'
                           b'Plaf3_UU","i":"ECaG4EEg_L2cX3XAE4CGb5JxpHcZ5gMCD8Z8Plaf3_UU","s":"0","kt":"1'
                           b'","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"nt":"1","n":["EpitDP'
                           b'yhh6qvfj0tMgO8RiBz5LV07OobY84WKs15XQHk"],"bt":"0","b":[],"c":[],"a":[],"di":'
                           b'"ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}')
    assert serderD.said == "ECaG4EEg_L2cX3XAE4CGb5JxpHcZ5gMCD8Z8Plaf3_UU"

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
    nxtR = nexterR.digs  # transferable so nxt is not empty

    delpre = 'ENdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      nkeys=nxtR)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'{"v":"KERI10JSON000160_","t":"drt","d":"EwKpz0HE3_eGARUswRQOWw7nvJiKxznWToCQ'
                           b'Cb5SrOJE","i":"ECaG4EEg_L2cX3XAE4CGb5JxpHcZ5gMCD8Z8Plaf3_UU","s":"4","p":"Eg'
                           b'Nkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1","k":["D8u3hipCxZnkM_O0j'
                           b'faZLJMk9ERI428T0psRO0JVgh4c"],"nt":"1","n":["E1082xCJjDJW4LFEpDkePQyHc1P4gNS'
                           b'U2Fl89uwafq3I"],"bt":"0","br":[],"ba":[],"a":[]}')
    assert serderR.said == 'EwKpz0HE3_eGARUswRQOWw7nvJiKxznWToCQCb5SrOJE'

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
    nxt = nexter.digs
    assert nxt == ['EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM']

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
                    nkeys=nxt,
                    toad=toad,
                    wits=wits,
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON0002ca_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EgNkcl_Qewzr'
                           b'RSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+0'
                           b'0:00","et":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
                           b'"],"nt":"1","n":["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b'
                           b'":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62L'
                           b'MYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],'
                           b'"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BNTk'
                           b'stUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6K'
                           b'c1CQnigIUBKrBFz_1Y"]},"di":""}')

    assert serderK.said == 'EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30'
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
    assert msg == (b'{"v":"KERI10JSON0002ca_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"nt":"1","n":'
                   b'["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b":["'
                   b'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2'
                   b'GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigI'
                   b'UBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_Qewz'
                   b'rRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7K'
                   b'S2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]'
                   b'},"di":""}-CABByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0B1d61'
                   b'-SOrSSKSyfguotWdJIQ7-AGWBO9rsNU2liCAHm-tavH9x3RFaym1LZM1uRIkDMD8'
                   b'NXsrw_XPG73I9yNfBA')

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
    assert msg == (b'{"v":"KERI10JSON0002ca_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"nt":"1","n":'
                   b'["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b":["'
                   b'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2'
                   b'GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigI'
                   b'UBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_Qewz'
                   b'rRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7K'
                   b'S2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]'
                   b'},"di":""}-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAA'
                   b'AAAAAAAAAAAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-A'
                   b'ABAA1d61-SOrSSKSyfguotWdJIQ7-AGWBO9rsNU2liCAHm-tavH9x3RFaym1LZM1'
                   b'uRIkDMD8NXsrw_XPG73I9yNfBA')

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
    nxt = nexter.digs
    assert nxt == ['EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM']

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
                    nkeys=nxt,
                    toad=toad,
                    wits=wits,
                    dpre=preD
                    )

    assert serderK.raw == (b'{"v":"KERI10JSON0002f6_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",'
                           b'"s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EgNkcl_Qewzr'
                           b'RSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+0'
                           b'0:00","et":"ixn","kt":"1","k":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
                           b'"],"nt":"1","n":["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b'
                           b'":["BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2GU5ud62L'
                           b'MYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"],"c":[],'
                           b'"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BNTk'
                           b'stUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6K'
                           b'c1CQnigIUBKrBFz_1Y"]},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}')

    assert serderK.said == 'EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30'
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
    assert msg == (b'{"v":"KERI10JSON0002f6_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"nt":"1","n":'
                   b'["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b":["'
                   b'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2'
                   b'GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigI'
                   b'UBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_Qewz'
                   b'rRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7K'
                   b'S2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]'
                   b'},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}-CABByvCLR'
                   b'r5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0BIV9LO2uGArLX9IQCA0RCwuOh'
                   b'5Wop0t4u7PoL9XQ7_Xr-Co424PFJs_x7PeHaY5Mos016AKa4JC0SI5nR8rzUBA')

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
    assert msg == (b'{"v":"KERI10JSON0002f6_","i":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPq'
                   b'WVK9ZBNZk0","s":"4","p":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO1'
                   b'32Z30","d":"EgNkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","f":"4'
                   b'","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn","kt":"1","k'
                   b'":["D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0"],"nt":"1","n":'
                   b'["EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM"],"bt":"2","b":["'
                   b'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU","B7vHpy1IDsWWUnHf2'
                   b'GU5ud62LMYWO5lPWOrSB6ejQ1Eo","BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigI'
                   b'UBKrBFz_1Y"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS_gNkcl_Qewz'
                   b'rRSKH2p9zHQIO132Z30","br":["BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7K'
                   b'S2Q6_lG0"],"ba":["BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y"]'
                   b'},"di":"DGz6B3ecka0XQKHaOfs0tpQqwIoHuXecuz733f-zkh7U"}-FABDyvCLR'
                   b'r5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAAAAAAAEM'
                   b'uNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAIV9LO2uGArLX9IQC'
                   b'A0RCwuOh5Wop0t4u7PoL9XQ7_Xr-Co424PFJs_x7PeHaY5Mos016AKa4JC0SI5nR'
                   b'8rzUBA')

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
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'X-AABAAVVUmAlrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzT'
                                b'Ar5P2A73ntpflGMqklHr8IxJziQDw')

        # Test with seal
        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealEvent(i='DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, sigers=sigers, seal=seal)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-FA'
                                b'BDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAA'
                                b'AAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAVVUmAlrVp'
                                b'7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzTAr5P2A73ntpflGMq'
                                b'klHr8IxJziQDw')

        # Test with pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'0-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA'
                                b'AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAVVUmA'
                                b'lrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzTAr5P2A73ntpf'
                                b'lGMqklHr8IxJziQDw')

        # Test with wigers
        verfers, digers, cst, nst = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                                b'BAAN2RwmlUX7gr971K9XLvfoIJkilGtMdZK2v66L_6FhG25p6sjvu2Y-iOJOEVNg'
                                b'sOxjVnsBi7lxU_EbAJ6lZKACQ')

        # Test with wigers and pipelined
        msg = messagize(serder, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'X-BABAAN2RwmlUX7gr971K9XLvfoIJkilGtMdZK2v66L_6FhG25p6sjvu2Y-iOJO'
                                b'EVNgsOxjVnsBi7lxU_EbAJ6lZKACQ')

        # Test with cigars
        verfers, digers, cst, nst = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                                b'BBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BXnaQZ5HNLapcED6GY'
                                b'GXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9'
                                b'SMECQ')

        # Test with cigars and pipelined
        msg = messagize(serder, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'i-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BXnaQZ5HNLapcE'
                                b'D6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZq'
                                b'DgM9SMECQ')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                                b'BAAN2RwmlUX7gr971K9XLvfoIJkilGtMdZK2v66L_6FhG25p6sjvu2Y-iOJOEVNg'
                                b'sOxjVnsBi7lxU_EbAJ6lZKACQ-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXca'
                                b'K9G939ArM0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackIt'
                                b'qcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'5-BABAAN2RwmlUX7gr971K9XLvfoIJkilGtMdZK2v66L_6FhG25p6sjvu2Y-iOJO'
                                b'EVNgsOxjVnsBi7lxU_EbAJ6lZKACQ-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjv'
                                b'nXcaK9G939ArM0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5Za'
                                b'ckItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers)
        assert bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                         b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                         b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                         b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                         b'Q-AABAAVVUmAlrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzT'
                         b'Ar5P2A73ntpflGMqklHr8IxJziQDw-BABAAN2RwmlUX7gr971K9XLvfoIJkilGtM'
                         b'dZK2v66L_6FhG25p6sjvu2Y-iOJOEVNgsOxjVnsBi7lxU_EbAJ6lZKACQ-CABBmM'
                         b'fUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BXnaQZ5HNLapcED6GYGXOV'
                         b'38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with sigers and wigers and cigars and pipelines
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                                b'Q-AABAAVVUmAlrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzT'
                                b'Ar5P2A73ntpflGMqklHr8IxJziQDw-BABAAN2RwmlUX7gr971K9XLvfoIJkilGtM'
                                b'dZK2v66L_6FhG25p6sjvu2Y-iOJOEVNgsOxjVnsBi7lxU_EbAJ6lZKACQ-CABBmM'
                                b'fUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939ArM0BXnaQZ5HNLapcED6GYGXOV'
                                b'38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with receipt message
        ked = serder.ked
        reserder = receipt(pre=ked["i"],
                           sn=int(ked["s"], 16),
                           said=serder.said)

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                                b'BAAXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6W'
                                b'BaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with cigars
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt
        msg = messagize(reserder, cigars=cigars)
        assert msg == bytearray(b'{"v":"KERI10JSON000091_","t":"rct","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0"}-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXcaK9G939Ar'
                                b'M0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6W'
                                b'BaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, )
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                                b'BAAXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgEGN6W'
                                b'BaEcPJ6aTvjLLDZqDgM9SMECQ-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjvnXca'
                                b'K9G939ArM0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackIt'
                                b'qcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, wigers=wigers, cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                                b'5-BABAAXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5ZackItqcgE'
                                b'GN6WBaEcPJ6aTvjLLDZqDgM9SMECQ-CABBmMfUwIOywRkyc5GyQXfgDA4UOAMvjv'
                                b'nXcaK9G939ArM0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7XXY-A5Za'
                                b'ckItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with sigers and seal and wigers and cigars and pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, wigers=wigers,
                        cigars=cigars, pipelined=True)
        assert msg == bytearray(b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ExYUckri7vGPH0L-9DmE3Znm'
                                b'6dc47brGolln481gZ38Q","i":"ExYUckri7vGPH0L-9DmE3Znm6dc47brGolln4'
                                b'81gZ38Q","s":"0","kt":"1","k":["D6J_jzCECalv_iTKSwxzPnuycxEi5fRu'
                                b'o3UUN7T0CVGM"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                                b't-FABDyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA'
                                b'AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAVVUmA'
                                b'lrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzTAr5P2A73ntpf'
                                b'lGMqklHr8IxJziQDw-BABAAXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1Me8w88y7'
                                b'XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ-CABBmMfUwIOywRkyc5'
                                b'GyQXfgDA4UOAMvjvnXcaK9G939ArM0BXnaQZ5HNLapcED6GYGXOV38RRWSrotdH1'
                                b'Me8w88y7XXY-A5ZackItqcgEGN6WBaEcPJ6aTvjLLDZqDgM9SMECQ')

        # Test with query message
        ked = serder.ked
        qserder = query(route="log",
                        query=dict(i='DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=help.helping.DTS_BASE_0)

        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealLast(i=ked["i"])
        msg = messagize(qserder, sigers=sigers, seal=seal)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAV'
                       b'z3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                       b'1QvrjI"}}-HABExYUckri7vGPH0L-9DmE3Znm6dc47brGolln481gZ38Q-AABAAV'
                       b'VUmAlrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzTAr5P2A73'
                       b'ntpflGMqklHr8IxJziQDw')

        # create SealEvent for endorsers est evt whose keys use to sign
        msg = messagize(qserder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAV'
                       b'z3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                       b'1QvrjI"}}-VAj-HABExYUckri7vGPH0L-9DmE3Znm6dc47brGolln481gZ38Q-AA'
                       b'BAAVVUmAlrVp7CJnjpa4urI9FnsWEnuMfxR-DE6XVCKzmBaHJqc4DRo5bBzTAr5P'
                       b'2A73ntpflGMqklHr8IxJziQDw')

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
        # compute nxt digest
        nexter = Diger(ser=skp1.verfer.qb64b)
        nxt = [nexter.qb64]
        assert nxt == ['EK-TF941B0sh9R48gp9pbwgWVR8aw10OpE7VUQMRUUU0']  # transferable so nxt is not empty

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
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
        _, ked0 = coring.Saider.saidify(sad=ked0)
        assert ked0['d'] == "EXo8l7KYph7GtQepz37He-AN6MAhfRqqk91O4WqRF_-I"

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
        assert kever.nexter.digs == [nexter.qb64]
        state = kever.db.states.get(keys=kever.prefixer.qb64)
        assert state.sn == kever.sn == 0
        feqner = kever.db.fons.get(keys=(kever.prefixer.qb64, kever.serder.said))
        assert feqner.sn == kever.sn

        serderK = kever.state()
        assert serderK.ked == state.ked
        assert serderK.pre == kever.prefixer.qb64
        assert serderK.sn == kever.sn
        assert ([verfer.qb64 for verfer in serderK.verfers] ==
                [verfer.qb64 for verfer in kever.verfers])
        assert serderK.raw == (b'{"v":"KERI10JSON0001b6_","i":"DBQOqSaf6GqVAoPxb4UARrklS8kLYj3JqsR6b4AASDd4",'
                               b'"s":"0","p":"","d":"EXo8l7KYph7GtQepz37He-AN6MAhfRqqk91O4WqRF_-I","f":"0","d'
                               b't":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DBQOqSaf6GqV'
                               b'AoPxb4UARrklS8kLYj3JqsR6b4AASDd4"],"nt":"0","n":["EK-TF941B0sh9R48gp9pbwgWVR'
                               b'8aw10OpE7VUQMRUUU0"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EXo8l7KYph7Gt'
                               b'Qepz37He-AN6MAhfRqqk91O4WqRF_-I","br":[],"ba":[]},"di":""}')

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
        nxt = nexter.digs  # nxt is not empty so error

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
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

        _, ked0 = coring.Saider.saidify(sad=ked0)

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

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
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
        _, ked0 = coring.Saider.saidify(sad=ked0)

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

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
        nxt = ""

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        baks = ["BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"]

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=baks,  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a={},  # list of seals
                    )

        # Derive AID from ked
        with pytest.raises(DerivationError):
            aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        # update ked with pre
        ked0["i"] = skp0.verfer.qb64
        _, ked0 = coring.Saider.saidify(sad=ked0)

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)

        # retry with valid empty baks
        baks = []
        # use some data, also invalid
        a = [dict(i="E_z8Wqqom6eeIFsng3cGQiUJ1uiNelCrR9VgFlk_8QAM")]
        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=baks,  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a=a,  # list of seals
                    )

        # Derive AID from ked
        with pytest.raises(DerivationError):
            aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        # update ked with pre
        ked0["i"] = aid0.qb64
        _, ked0 = coring.Saider.saidify(sad=ked0)

        # Serialize ked0
        tser0 = Serder(ked=ked0)

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

        # retry with valid empty baks and empty a
        baks = []
        a = []
        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        ked0 = dict(v=versify(kind=Serials.json, size=0),
                    t=Ilks.icp,
                    d="",
                    i="",  # qual base 64 prefix
                    s="{:x}".format(sn),  # hex string no leading zeros lowercase
                    kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                    k=keys,  # list of signing keys each qual Base64
                    n=nxt,  # hash qual Base64
                    bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                    b=baks,  # list of qual Base64 may be empty
                    c=[],  # list of config ordered mappings may be empty
                    a=a,  # list of seals
                    )

        # Derive AID from ked
        aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519N)

        assert aid0.code == MtrDex.Ed25519N
        assert aid0.qb64 == skp0.verfer.qb64

        # update ked with pre
        ked0["i"] = aid0.qb64
        _, ked0 = coring.Saider.saidify(sad=ked0)

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
        nexter1 = coring.Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [nexter1.qb64]  # transferable so nxt is not empty
        assert nxt1 == ['E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiI']
        serder0 = incept(keys=keys0, nkeys=nxt1)
        pre = serder0.ked["i"]
        event_digs.append(serder0.said)
        assert serder0.ked["i"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.said == 'ELeMG3OOxWi5n1Zud603_Bn6Hzm3hIRZXlQnSgC5lU7A'

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.saider.qb64 == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.digs == nxt1
        assert kever.estOnly is False
        assert kever.transferable is True

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2
        keys2 = [signers[2].verfer.qb64]
        nexter2 = coring.Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [nexter2.qb64]  # transferable so nxt is not empty
        assert nxt2 == ['EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF-S7t9aeZMERXU']
        serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, nkeys=nxt2, sn=1)
        event_digs.append(serder1.said)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["kt"] == '1'
        assert serder1.ked["k"] == keys1
        assert serder1.ked["n"] == nxt2
        assert serder1.ked["p"] == serder0.said

        # sign serialization and verify signature
        sig1 = signers[1].sign(serder1.raw, index=0)
        assert signers[1].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        kever.update(serder=serder1, sigers=[sig1])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.saider.qb64 == serder1.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.nexter.digs == nxt2

        # Event 2 Rotation Transferable
        # compute nxt digest from keys3
        keys3 = [signers[3].verfer.qb64]
        nexter3 = coring.Diger(ser=signers[3].verfer.qb64b)
        nxt3 = [nexter3.qb64]  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys2, dig=serder1.said, nkeys=nxt3, sn=2)
        event_digs.append(serder2.said)
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '2'
        assert serder2.ked["k"] == keys2
        assert serder2.ked["n"] == nxt3
        assert serder2.ked["p"] == serder1.said

        # sign serialization and verify signature
        sig2 = signers[2].sign(serder2.raw, index=0)
        assert signers[2].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 2
        assert kever.serder.saider.qb64 == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys2
        assert kever.nexter.digs == nxt3

        # Event 3 Interaction
        serder3 = interact(pre=pre, dig=serder2.said, sn=3)
        event_digs.append(serder3.said)
        assert serder3.ked["i"] == pre
        assert serder3.ked["s"] == '3'
        assert serder3.ked["p"] == serder2.said

        # sign serialization and verify signature
        sig3 = signers[2].sign(serder3.raw, index=0)
        assert signers[2].verfer.verify(sig3.raw, serder3.raw)
        # update key event verifier state
        kever.update(serder=serder3, sigers=[sig3])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 3
        assert kever.serder.saider.qb64 == serder3.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.nexter.digs == nxt3  # no change

        # Event 4 Interaction
        serder4 = interact(pre=pre, dig=serder3.said, sn=4)
        event_digs.append(serder4.said)
        assert serder4.ked["i"] == pre
        assert serder4.ked["s"] == '4'
        assert serder4.ked["p"] == serder3.said

        # sign serialization and verify signature
        sig4 = signers[2].sign(serder4.raw, index=0)
        assert signers[2].verfer.verify(sig4.raw, serder4.raw)
        # update key event verifier state
        kever.update(serder=serder4, sigers=[sig4])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 4
        assert kever.serder.saider.qb64 == serder4.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.nexter.digs == nxt3  # no change

        # Event 5 Rotation Transferable
        # compute nxt digest from keys4
        keys4 = [signers[4].verfer.qb64]
        nexter4 = coring.Diger(ser=signers[4].verfer.qb64b)
        nxt4 = [nexter4.qb64]  # transferable so nxt is not empty
        serder5 = rotate(pre=pre, keys=keys3, dig=serder4.said, nkeys=nxt4, sn=5)
        event_digs.append(serder5.said)
        assert serder5.ked["i"] == pre
        assert serder5.ked["s"] == '5'
        assert serder5.ked["k"] == keys3
        assert serder5.ked["n"] == nxt4
        assert serder5.ked["p"] == serder4.said

        # sign serialization and verify signature
        sig5 = signers[3].sign(serder5.raw, index=0)
        assert signers[3].verfer.verify(sig5.raw, serder5.raw)
        # update key event verifier state
        kever.update(serder=serder5, sigers=[sig5])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 5
        assert kever.serder.saider.qb64 == serder5.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys3
        assert kever.nexter.digs == nxt4

        # Event 6 Interaction
        serder6 = interact(pre=pre, dig=serder5.said, sn=6)
        event_digs.append(serder6.said)
        assert serder6.ked["i"] == pre
        assert serder6.ked["s"] == '6'
        assert serder6.ked["p"] == serder5.said

        # sign serialization and verify signature
        sig6 = signers[3].sign(serder6.raw, index=0)
        assert signers[3].verfer.verify(sig6.raw, serder6.raw)
        # update key event verifier state
        kever.update(serder=serder6, sigers=[sig6])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 6
        assert kever.serder.saider.qb64 == serder6.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
        assert kever.nexter.digs == nxt4  # no change

        # Event 7 Rotation to null NonTransferable Abandon
        serder7 = rotate(pre=pre, keys=keys4, dig=serder6.said, sn=7)
        event_digs.append(serder7.said)
        assert serder7.ked["i"] == pre
        assert serder7.ked["s"] == '7'
        assert serder7.ked["k"] == keys4
        assert serder7.ked["n"] == []
        assert serder7.ked["p"] == serder6.said

        # sign serialization and verify signature
        sig7 = signers[4].sign(serder7.raw, index=0)
        assert signers[4].verfer.verify(sig7.raw, serder7.raw)
        # update key event verifier state
        kever.update(serder=serder7, sigers=[sig7])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 7
        assert kever.serder.saider.qb64 == serder7.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys4
        assert kever.nexter.digs == []
        assert not kever.transferable

        # Event 8 Interaction
        serder8 = interact(pre=pre, dig=serder7.said, sn=8)
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.said

        # sign serialization and verify signature
        sig8 = signers[4].sign(serder8.raw, index=0)
        assert signers[4].verfer.verify(sig8.raw, serder8.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder8, sigers=[sig8])

        # Event 8 Rotation
        keys5 = [signers[5].verfer.qb64]
        nexter5 = coring.Diger(ser=signers[5].verfer.qb64b)
        nxt5 = [nexter4.qb64]  # transferable so nxt is not empty
        serder8 = rotate(pre=pre, keys=keys5, dig=serder7.said, nkeys=nxt5, sn=8)
        assert serder8.ked["i"] == pre
        assert serder8.ked["s"] == '8'
        assert serder8.ked["p"] == serder7.said

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
        nexter1 = coring.Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [nexter1.qb64]  # transferable so nxt is not empty
        cnfg = [TraitDex.EstOnly]  # EstOnly
        serder0 = incept(keys=keys0, nkeys=nxt1, cnfg=cnfg)
        event_digs.append(serder0.said)
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
        assert kever.serder.saider.qb64 == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.nexter.digs == nxt1
        assert kever.estOnly is True
        assert kever.transferable is True

        # Event 1 Interaction. Because EstOnly, this event not included in KEL
        serder1 = interact(pre=pre, dig=serder0.said, sn=1)
        assert serder1.ked["i"] == pre
        assert serder1.ked["s"] == '1'
        assert serder1.ked["p"] == serder0.said
        # sign serialization and verify signature
        sig1 = signers[0].sign(serder1.raw, index=0)
        assert signers[0].verfer.verify(sig1.raw, serder1.raw)
        # update key event verifier state
        with pytest.raises(ValidationError):  # attempt ixn with estOnly
            kever.update(serder=serder1, sigers=[sig1])

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2  but from event0
        nexter2 = coring.Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [nexter2.qb64]  # transferable so nxt is not empty
        assert nxt2 == ['EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF-S7t9aeZMERXU']
        serder2 = rotate(pre=pre, keys=keys1, dig=serder0.said, nkeys=nxt2, sn=1)
        event_digs.append(serder2.said)
        assert serder2.ked["i"] == pre
        assert serder2.ked["s"] == '1'
        assert serder2.ked["kt"] == '1'
        assert serder2.ked["k"] == keys1
        assert serder2.ked["n"] == nxt2
        assert serder2.ked["p"] == serder0.said

        # sign serialization and verify signature
        sig2 = signers[1].sign(serder2.raw, index=0)
        assert signers[1].verfer.verify(sig2.raw, serder2.raw)
        # update key event verifier state
        kever.update(serder=serder2, sigers=[sig2])
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 1
        assert kever.serder.saider.qb64 == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.nexter.digs == nxt2

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

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
        nxtkeys = [signers[3].verfer.qb64b, signers[4].verfer.qb64b, signers[5].verfer.qb64b]
        sith = "2"
        code = MtrDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        sith=sith,
                        nkeys=[coring.Diger(ser=sig).qb64 for sig in nxtkeys])

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

        assert msgs == bytearray(b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EZrJQSdhdiyXNpEzHo-dR0EE'
                                 b'bLfcIopBSImdLnQGOKkg","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdL'
                                 b'nQGOKkg","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_Z'
                                 b'OoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT'
                                 b'1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nt":"2","n":["E_Ik'
                                 b'dcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQ'
                                 b'Z0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZh'
                                 b'dRaZY8"],"bt":"0","b":[],"c":[],"a":[]}-AADAAzclB26m4VWp5R8ANlTU'
                                 b'2qhqE6GA9siAK_vhtqtNNR6qhVed-xEoXRadnL5Jc0kxPZi8XUqSk5KSaOnke_Sx'
                                 b'XDAABX--x4JGI0Dp0Ran-t1LMg3NEgizu1Jb85LTImofYqD6jz9w5TTPNAmj7rfI'
                                 b'Fvd4mfJ_ioH0Z0mzLWuIvTIFCBAACQTiHacY3flY9y_Wup66bNzcyQvJUT-WGkv4'
                                 b'CPgqkMwq5mOEFf2ps74bur1AE9OSGgrEBlcOQ9HWuTcr80FMKCg')

        # Event 1 Rotation Transferable
        keys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = "2"
        nxtkeys = [signers[5].verfer.qb64b, signers[6].verfer.qb64b, signers[7].verfer.qb64b]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith=sith,
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=sig).qb64 for sig in nxtkeys],
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
                          dig=kever.serder.saider.qb64,
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
                          dig=kever.serder.saider.qb64,
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
        keys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith="2",
                        dig=kever.serder.saider.qb64,
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

        assert len(msgs) == 3173

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
                        nkeys=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64])

        assert sn == int(serder.ked["s"], 16) == 0

        event_digs.append(serder.said)
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
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn)

        event_digs.append(serder.said)
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
                          dig=kever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn)
        event_digs.append(serder.said)
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
                          dig=kever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                          dig=kever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                          dig=kever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                        nkeys=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
                        sn=sn)
        event_digs.append(serder.said)
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
                          dig=kever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                        nkeys=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64])

        assert sn == int(serder.ked["s"], 16) == 0
        coepre = serder.ked["i"]
        assert coepre == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'

        event_digs.append(serder.said)
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
                           said=coeKever.serder.saider.qb64)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64 == \
               '0BEaTtTANB15o8ekvghBiJXAqIPRP-fpZtSwmjTZCH89FE1zg6OaLz9llY6_yUpXIXTBcTjHEUHCul9kOf-9rRBw'
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
        assert recnt.qb64 == '-CAB'

        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)
        assert res == bytearray(b'{"v":"KERI10JSON000091_","t":"rct","d":"ELeMG3OOxWi5n1Zud603_Bn6'
                                b'Hzm3hIRZXlQnSgC5lU7A","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKt'
                                b'WTOunRA","s":"0"}-CABB8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiM'
                                b'c0BEaTtTANB15o8ekvghBiJXAqIPRP-fpZtSwmjTZCH89FE1zg6OaLz9llY6_yUp'
                                b'XIXTBcTjHEUHCul9kOf-9rRBw')

        parsing.Parser().parse(ims=res, kvy=coeKevery)
        # coeKevery.process(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == valPrefixer.qb64b + valCigar.qb64b
        assert len(result) == 1

        # create invalid receipt to escrow use invalid dig and sn so not in db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=2,
                           said=fake)
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
        fake = coring.Diger(qb64="E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI").qb64
        reserder = receipt(pre=coeKever.prefixer.qb64,
                           sn=coeKever.sn,
                           said=fake)
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
                                                dig=coeKever.serder.saider.qb64))
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
                        dig=coeKever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
                        sn=sn)

        event_digs.append(serder.said)
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
                          dig=coeKever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                        dig=coeKever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
                        sn=sn)
        event_digs.append(serder.said)
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
                          dig=coeKever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                          dig=coeKever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                          dig=coeKever.serder.saider.qb64,
                          sn=sn)
        event_digs.append(serder.said)
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
                           nkeys=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == 'EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw'

        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON00012b_","t":"icp","d":"EdwS_D6wppLqfIp5LSgly8GT'
                                 b'Scg5OWBaa7thzEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                                 b'EnBqHvw","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_Z'
                                 b'OoeKtWTOunRA"],"nt":"1","n":["E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK'
                                 b'1kRXSYeMiI"],"bt":"0","b":[],"c":[],"a":[]}-AABAAEtmk7qXsdCpK8Uh'
                                 b'ruVzPpIITUg4UPodQuzNsR29tUIT1sCWnjXOEVUC_mlYrgquYSZSE1Xq8r9OOlI3'
                                 b'ELJEMAw')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           nkeys=[coring.Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == 'E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo'

        val_event_digs.append(valSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'{"v":"KERI10JSON00012b_","t":"icp","d":"E0VtKUgXnnXq9EtfgKAd_l5l'
                                 b'hyhx_Rlf0Uj1XejaNNoo","i":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1X'
                                 b'ejaNNoo","s":"0","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9'
                                 b'yzhDNZlEKiMc"],"nt":"1","n":["E71sZjtEedBeNrGYRXmeTdmgbCJUTpXX5T'
                                 b'W-VpNxxRXk"],"bt":"0","b":[],"c":[],"a":[]}-AABAAxXn_f_GuWg9ON12'
                                 b'x59DXir636vEsdwAozFRDcLgx_TmTY8WuhRbW_zWAEFX7d_YYMtYNNVk7uoxp7s5'
                                 b'U8m4FDA')

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
                           said=coeK.serder.saider.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.saider.qb64b == b'EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw'
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7th'
                             b'zEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","s":"0","kt":"1'
                             b'","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nt":"1","n":["E67B6W'
                             b'kwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiI"],"bt":"0","b":[],"c":[],"a":[]}')
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAhqa4qdyKUYl0gphqZp9511p3NfDecpUMvedi7pPxIVnufTeg3NpQ77GD9FNHTTtXZnQkZ2r8j_1-Iqi7ZMPlBg'
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EdwS_D6wppLqfIp5LSgly8GT'
                        b'Scg5OWBaa7thzEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                        b'EnBqHvw","s":"0"}-FABE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNo'
                        b'o0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1Xej'
                        b'aNNoo-AABAAhqa4qdyKUYl0gphqZp9511p3NfDecpUMvedi7pPxIVnufTeg3NpQ7'
                        b'7GD9FNHTTtXZnQkZ2r8j_1-Iqi7ZMPlBg')

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
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgX'
                                    b'nnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNooAAhqa4qdyKUYl0gphqZp9511p3NfDecpUMvedi7p'
                                    b'PxIVnufTeg3NpQ77GD9FNHTTtXZnQkZ2r8j_1-Iqi7ZMPlBg')

        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EdwS_D6wppLqfIp5LSgly8GT'
                        b'Scg5OWBaa7thzEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                        b'EnBqHvw","s":"a"}-FABE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNo'
                        b'o0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1Xej'
                        b'aNNoo-AABAAhqa4qdyKUYl0gphqZp9511p3NfDecpUMvedi7pPxIVnufTeg3NpQ7'
                        b'7GD9FNHTTtXZnQkZ2r8j_1-Iqi7ZMPlBg')
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
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
                           said=valK.serder.saider.qb64)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.saider.qb64b == b'E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo'
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1'
                             b'XejaNNoo","i":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo","s":"0","kt":"1'
                             b'","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nt":"1","n":["E71sZj'
                             b'tEedBeNrGYRXmeTdmgbCJUTpXX5TW-VpNxxRXk"],"bt":"0","b":[],"c":[],"a":[]}')

        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AAwRTBCuNLZdEpmDQcTBzNpUlvX7P7ihE9Hh5A_USAbT-8ILfEBvqfUEdbbdR5WrYCJvQQbQui63Kx-5z1z5uDBw'
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"E0VtKUgXnnXq9EtfgKAd_l5l'
                        b'hyhx_Rlf0Uj1XejaNNoo","i":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1X'
                        b'ejaNNoo","s":"0"}-FABEdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHv'
                        b'w0AAAAAAAAAAAAAAAAAAAAAAAEdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEn'
                        b'BqHvw-AABAAwRTBCuNLZdEpmDQcTBzNpUlvX7P7ihE9Hh5A_USAbT-8ILfEBvqfU'
                        b'EdbbdR5WrYCJvQQbQui63Kx-5z1z5uDBw')

        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.saider.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.saider.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw0AAAAAAAAAAAAAAAAAAAAAAAEdwS_D6w'
                                    b'ppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvwAAwRTBCuNLZdEpmDQcTBzNpUlvX7P7ihE9Hh5A_U'
                                    b'SAbT-8ILfEBvqfUEdbbdR5WrYCJvQQbQui63Kx-5z1z5uDBw')

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.saider.qb64,
                           nkeys=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           sn=csn)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000160_","t":"rot","d":"EPGhF0L32Ay6HAD0qLtM7Crr'
                                 b'1UVTp3D2pH2TdJ_8sG8Y","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                                 b'EnBqHvw","s":"1","p":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqH'
                                 b'vw","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"'
                                 b'],"nt":"1","n":["EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF-S7t9aeZMERXU"],'
                                 b'"bt":"0","br":[],"ba":[],"a":[]}-AABAARP1SU3CTLKkLhubMeFQbpe3wgL'
                                 b'qOTWyy3rojOhtzPrnzxpy1_MSKhnWAWSkfPF4Pp5elleoLrKfZvaswXbNcDQ')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.saider.qb64 == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.saider.qb64 == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.saider.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.saider.qb64b == b'EPGhF0L32Ay6HAD0qLtM7Crr1UVTp3D2pH2TdJ_8sG8Y'
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EPGhF0L32Ay6HAD0qLtM7Crr1UVTp3D2pH2T'
                             b'dJ_8sG8Y","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","s":"1","p":"Ed'
                             b'wS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","kt":"1","k":["DVcuJOOJF1IE8svqE'
                             b'trSuyQjGTd2HhfAkt9y2QkUtFJI"],"nt":"1","n":["EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF'
                             b'-S7t9aeZMERXU"],"bt":"0","br":[],"ba":[],"a":[]}')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AACKy97UIP4Bgh267LhWTXvrHXXQjsh8nJ5xwvwE_r-guPZdzjQZUqCbs3C6fVKU5sXLdDEa5fNkJ1wzoWu6CgBQ'
        # val create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EPGhF0L32Ay6HAD0qLtM7Crr'
                        b'1UVTp3D2pH2TdJ_8sG8Y","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                        b'EnBqHvw","s":"1"}-FABE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNo'
                        b'o0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1Xej'
                        b'aNNoo-AABAACKy97UIP4Bgh267LhWTXvrHXXQjsh8nJ5xwvwE_r-guPZdzjQZUqC'
                        b'bs3C6fVKU5sXLdDEa5fNkJ1wzoWu6CgBQ')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgX'
                                    b'nnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNooAACKy97UIP4Bgh267LhWTXvrHXXQjsh8nJ5xwvwE'
                                    b'_r-guPZdzjQZUqCbs3C6fVKU5sXLdDEa5fNkJ1wzoWu6CgBQ')

        # Next Event 2 Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.saider.qb64,
                             sn=csn)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKK-xQ6k-JyAkg40UNtFCv2C'
                                 b'7HAhXY-fKUYG2GPG6Q08","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                                 b'EnBqHvw","s":"2","p":"EPGhF0L32Ay6HAD0qLtM7Crr1UVTp3D2pH2TdJ_8sG'
                                 b'8Y","a":[]}-AABAAdS2iIv6OtwlulpyF0DI9pqvLh90iazJWCcFDF1jXidQcWrw'
                                 b'Ttr0LNWHB5AlZ-3DLtVYR0Yp7P58gAO5CYnGSDA')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.saider.qb64 == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.saider.qb64 == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.saider.qb64)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.saider.qb64b == b'EKK-xQ6k-JyAkg40UNtFCv2C7HAhXY-fKUYG2GPG6Q08'
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKK-xQ6k-JyAkg40UNtFCv2C7HAhXY-fKUYG'
                             b'2GPG6Q08","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","s":"2","p":"EP'
                             b'GhF0L32Ay6HAD0qLtM7Crr1UVTp3D2pH2TdJ_8sG8Y","a":[]}')
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == 'AA7hc9eseXL2v5STGffKtukn_s27XmNG_KfxeuH1nMxePeOWuE2ObVyAoPT-hgV-Kag9zl3MVigPyYPe0goWQMBw'
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EKK-xQ6k-JyAkg40UNtFCv2C'
                        b'7HAhXY-fKUYG2GPG6Q08","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thz'
                        b'EnBqHvw","s":"2"}-FABE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNo'
                        b'o0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1Xej'
                        b'aNNoo-AABAA7hc9eseXL2v5STGffKtukn_s27XmNG_KfxeuH1nMxePeOWuE2ObVy'
                        b'AoPT-hgV-Kag9zl3MVigPyYPe0goWQMBw')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgX'
                                    b'nnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNooAA7hc9eseXL2v5STGffKtukn_s27XmNG_KfxeuH1'
                                    b'nMxePeOWuE2ObVyAoPT-hgV-Kag9zl3MVigPyYPe0goWQMBw')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw',
                                             'EPGhF0L32Ay6HAD0qLtM7Crr1UVTp3D2pH2TdJ_8sG8Y',
                                             'EKK-xQ6k-JyAkg40UNtFCv2C7HAhXY-fKUYG2GPG6Q08']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo']

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
                           nkeys=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256,
                           kind=Serials.cbor)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]

        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xadavqKERI10CBOR0000f9_atcicpadx,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQ'
                                 b'lavnq3JpKZwaix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa0b'
                                 b'kta1ak\x81x,DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRAbnta1an'
                                 b'\x81x,E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiIbbta0ab\x80a'
                                 b'c\x80aa\x80-AABAA4j4IbpmAYY3eHUlN2pOn2og3JOs_vJ_KkCfK08tOsyFnHClFj'
                                 b'7xzRwiTam3uauPwE-_9EwgcCIsBQB4-8nXwAQ')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           nkeys=[coring.Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256,
                           kind=Serials.mgpk)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]

        val_event_digs.append(valSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == bytearray(b'\x8d\xa1v\xb1KERI10MGPK0000f9_\xa1t\xa3icp\xa1d\xd9,EAICGQrxtqsZw'
                                 b'l6s4D1jzCepnScs7j35Lt5-wX-bjd_Q\xa1i\xd9,EAICGQrxtqsZwl6s4D1jzCepn'
                                 b'Scs7j35Lt5-wX-bjd_Q\xa1s\xa10\xa2kt\xa11\xa1k\x91\xd9,D8KY1sKmgyj'
                                 b'AiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc\xa2nt\xa11\xa1n\x91\xd9,E71sZjtEe'
                                 b'dBeNrGYRXmeTdmgbCJUTpXX5TW-VpNxxRXk\xa2bt\xa10\xa1b\x90\xa1'
                                 b'c\x90\xa1a\x90-AABAA8EF2RDzaaXZSqMUUhtr8tl31iVg2F1EmamOkbwGW4EQBR'
                                 b'AYT7Tk9mWcQtHJlOggrDJNZELaihAgBcDws248OAQ')

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
                           said=coeK.serder.saider.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.saider.qb64b
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'\xadavqKERI10CBOR0000f9_atcicpadx,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3Jp'
                             b'KZwaix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa0bkta1ak\x81x,DSuhyBc'
                             b'PZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRAbnta1an\x81x,E67B6WkwQrEfSA2MylxmF28HJ'
                             b'c_HxfHRyK1kRXSYeMiIbbta0ab\x80ac\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,Eq51AFQINHs4Q'
                        b'63X7hk-MQwQojnPA0QbQlavnq3JpKZw\xa1i\xd9,Eq51AFQINHs4Q63X7hk-MQwQo'
                        b'jnPA0QbQlavnq3JpKZw\xa1s\xa10-FABEAICGQrxtqsZwl6s4D1jzCepnScs7j35L'
                        b't5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrxtqsZwl6s4D1jzCepnScs7'
                        b'j35Lt5-wX-bjd_Q-AABAAK_mb99LNCFTOo2euzvNlVuxbXis0FTIfXUqaSmKV-7G'
                        b'4BaHcKWS6T__vOfTpuohAosPPLqJiUjvX0_wGO54XCQ')

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
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrx'
                                    b'tqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_QAAK_mb99LNCFTOo2euzvNlVuxbXis0FTIfXUqaSm'
                                    b'KV-7G4BaHcKWS6T__vOfTpuohAosPPLqJiUjvX0_wGO54XCQ')

        # create receipt to escrow use invalid dig so not in coe's db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake,
                           kind=Serials.mgpk)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg ==(b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,Eq51AFQINHs4Q'
                       b'63X7hk-MQwQojnPA0QbQlavnq3JpKZw\xa1i\xd9,Eq51AFQINHs4Q63X7hk-MQwQo'
                       b'jnPA0QbQlavnq3JpKZw\xa1s\xa1a-FABEAICGQrxtqsZwl6s4D1jzCepnScs7j35L'
                       b't5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrxtqsZwl6s4D1jzCepnScs7'
                       b'j35Lt5-wX-bjd_Q-AABAAK_mb99LNCFTOo2euzvNlVuxbXis0FTIfXUqaSmKV-7G'
                       b'4BaHcKWS6T__vOfTpuohAosPPLqJiUjvX0_wGO54XCQ')

        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
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
                           said=valK.serder.saider.qb64,
                           kind=Serials.cbor)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.saider.qb64b
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'\x8d\xa1v\xb1KERI10MGPK0000f9_\xa1t\xa3icp\xa1d\xd9,EAICGQrxtqsZwl6s4D1jz'
                             b'CepnScs7j35Lt5-wX-bjd_Q\xa1i\xd9,EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bj'
                             b'd_Q\xa1s\xa10\xa2kt\xa11\xa1k\x91\xd9,D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzh'
                             b'DNZlEKiMc\xa2nt\xa11\xa1n\x91\xd9,E71sZjtEedBeNrGYRXmeTdmgbCJUTpXX5TW-VpNxx'
                             b'RXk\xa2bt\xa10\xa1b\x90\xa1c\x90\xa1a\x90')

        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'\xa5avqKERI10CBOR00007f_atcrctadx,EAICGQrxtqsZwl6s4D1jzCepnScs7j35L'
                        b't5-wX-bjd_Qaix,EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_Qasa0-'
                        b'FABEq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZw0AAAAAAAAAAAAAAAA'
                        b'AAAAAAAEq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZw-AABAAC0FNeUL'
                        b'OkyGqfKiiUSRxeU6lCaGKqAKc44wysmSshNabIhDis0lc-X8Y-IYGTG3SFrvGuBl'
                        b'rzfa8NFqLRHqzAA')

        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.saider.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.saider.qb64b +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZw0AAAAAAAAAAAAAAAAAAAAAAAEq51AFQI'
                                    b'NHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwAAC0FNeULOkyGqfKiiUSRxeU6lCaGKqAKc44wysm'
                                    b'SshNabIhDis0lc-X8Y-IYGTG3SFrvGuBlrzfa8NFqLRHqzAA')

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.saider.qb64,
                           nkeys=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           sn=csn,
                           kind=Serials.cbor)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # returns siger

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xaeavqKERI10CBOR00012b_atcrotadx,E5UktJ1jLc5V3nsh80g3kRA7CA_-3tumM'
                                 b'Pte77QniEM4aix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa1a'
                                 b'px,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwbkta1ak\x81x,DVcuJOO'
                                 b'JF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJIbnta1an\x81x,EL-1w3eYVzNy0-RQV'
                                 b'6r2ZORG-Y4gmOF-S7t9aeZMERXUbbta0bbr\x80bba\x80aa\x80-AABAABK8wth4'
                                 b'fMaOPfA7bRcN61uar_zqBrZQ2x2X5eWyhYZvcE3A52eralD1xfZnzGBwdilbhW7f'
                                 b'ACoDe0-DEHNxOBg')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.saider.qb64 == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.saider.qb64 == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.saider.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.saider.qb64b
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'\xaeavqKERI10CBOR00012b_atcrotadx,E5UktJ1jLc5V3nsh80g3kRA7CA_-3tumMPte77Qni'
                             b'EM4aix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa1apx,Eq51AFQINHs4Q63X7'
                             b'hk-MQwQojnPA0QbQlavnq3JpKZwbkta1ak\x81x,DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9'
                             b'y2QkUtFJIbnta1an\x81x,EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF-S7t9aeZMERXUbbta0'
                             b'bbr\x80bba\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,E5UktJ1jLc5V3'
                        b'nsh80g3kRA7CA_-3tumMPte77QniEM4\xa1i\xd9,Eq51AFQINHs4Q63X7hk-MQwQo'
                        b'jnPA0QbQlavnq3JpKZw\xa1s\xa11-FABEAICGQrxtqsZwl6s4D1jzCepnScs7j35L'
                        b't5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrxtqsZwl6s4D1jzCepnScs7'
                        b'j35Lt5-wX-bjd_Q-AABAAVlFzvafwR5JKq-EhF90pEUDOqQBQL-FSxOBza4IygFk'
                        b'4lV1GIErW8aZ_TRa9jN_bbFLnk6gQgnfqxRJUWkD1DA')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrx'
                                    b'tqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_QAAVlFzvafwR5JKq-EhF90pEUDOqQBQL-FSxOBza4'
                                    b'IygFk4lV1GIErW8aZ_TRa9jN_bbFLnk6gQgnfqxRJUWkD1DA')

        # Next Event Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.saider.qb64,
                             sn=csn,
                             kind=Serials.cbor)
        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)

        # create msg
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == bytearray(b'\xa7avqKERI10CBOR0000b2_atcixnadx,EpU_Dr1beH3JWNBV3LEvoH3hjeYgJRbwN'
                                 b'J2sQEUEN4HEaix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa2a'
                                 b'px,E5UktJ1jLc5V3nsh80g3kRA7CA_-3tumMPte77QniEM4aa\x80-AABAAPexu7tgA'
                                 b'NhixOSKM_ROtuOyxqpaSoZoqzGWxOGRIQDvCVC5vwdK0zVQTq28Q5MVeRhIWlYbb'
                                 b'cvjERWbqUJFsBw')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.saider.qb64 == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.saider.qb64 == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.saider.qb64,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.saider.qb64b
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'\xa7avqKERI10CBOR0000b2_atcixnadx,EpU_Dr1beH3JWNBV3LEvoH3hjeYgJRbwNJ2sQEUEN'
                             b'4HEaix,Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZwasa2apx,E5UktJ1jLc5V3nsh8'
                             b'0g3kRA7CA_-3tumMPte77QniEM4aa\x80')

        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,EpU_Dr1beH3JW'
                        b'NBV3LEvoH3hjeYgJRbwNJ2sQEUEN4HE\xa1i\xd9,Eq51AFQINHs4Q63X7hk-MQwQo'
                        b'jnPA0QbQlavnq3JpKZw\xa1s\xa12-FABEAICGQrxtqsZwl6s4D1jzCepnScs7j35L'
                        b't5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrxtqsZwl6s4D1jzCepnScs7'
                        b'j35Lt5-wX-bjd_Q-AABAArq12oDvsHfjELzwRo8M0kt4_EhNO7qF9FYLgMU3X5qp'
                        b'77sjZZa71blAGGYm-Of23QFsynB3UZHPDzlvXM_mtAA')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.saider.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saider.qb64b +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_Q0AAAAAAAAAAAAAAAAAAAAAAAEAICGQrx'
                                    b'tqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_QAArq12oDvsHfjELzwRo8M0kt4_EhNO7qF9FYLgMU'
                                    b'3X5qp77sjZZa71blAGGYm-Of23QFsynB3UZHPDzlvXM_mtAA')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['Eq51AFQINHs4Q63X7hk-MQwQojnPA0QbQlavnq3JpKZw',
                                             'E5UktJ1jLc5V3nsh80g3kRA7CA_-3tumMPte77QniEM4',
                                             'EpU_Dr1beH3JWNBV3LEvoH3hjeYgJRbwNJ2sQEUEN4HE']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['EAICGQrxtqsZwl6s4D1jzCepnScs7j35Lt5-wX-bjd_Q']

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

    ked0 = dict(v=versify(kind=Serials.json, size=0),
                t=Ilks.icp,
                d="",
                i=aid0.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                k=[aid0.qb64],  # list of signing keys each qual Base64
                n=nxt,  # hash qual Base64
                wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                w=[],  # list of qual Base64 may be empty
                c=[],  # list of config ordered mappings may be empty
                )
    _, ked0 = coring.Saider.saidify(sad=ked0)

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
    nxt = nexter.digs  # transferable so next is not empty

    sn = 0  # inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  # one attached signature unspecified index

    ked0 = dict(v=versify(kind=Serials.json, size=0),
                t=Ilks.icp,
                d="",
                i="",  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
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
    _, ked0 = coring.Saider.saidify(sad=ked0)

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
    rnxt1 = Nexter(digs=rser0.ked["n"])
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
    ked0 = dict(v=versify(kind=Serials.json, size=0),
                t=Ilks.icp,
                d="",
                i=aidmat.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                k=[aidmat.qb64],  # list of signing keys each qual Base64
                n=nxtdigmat.qb64,  # hash qual Base64
                wt="{:x}".format(toad),  # hex string no leading zeros lowercase
                w=[],  # list of qual Base64 may be empty
                c=[],  # list of config ordered mappings may be empty
                )
    _, ked0 = coring.Saider.saidify(sad=ked0)

    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"v":"KERI10JSON000119_","t":"icp","d":"Ehh5mZwnWswxUiQS1rIIrEgM6eFYpsk9AXWZ'
                          b'oynyqrrc","i":"Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s","s":"0","kt":"1'
                          b'","k":["Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s"],"n":"E3ld50z3LYM7pmQx'
                          b'G3bJDNgOnRg1T1v5tmYmsYDyqiNI","wt":"0","w":[],"c":[]}')

    assert txsrdr.size == 281

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = coring.Saider(sad=ked0, code=MtrDex.Blake3_256)
    assert txdigmat.qb64 == 'Ehh5mZwnWswxUiQS1rIIrEgM6eFYpsk9AXWZoynyqrrc'

    assert txsrdr.said == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  # sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = Indexer(raw=sig0raw, code=IdrDex.Ed25519_Sig, index=index)
    assert txsigmat.qb64 == 'AAPXCeDIOQtggPdzKgAcBGT5Vhr8js6N-o8TVod9_NheNTzuZJdkDagFVb90MTG0yK1VXwuZe3cVxIi9w-8JlOAA'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 369  # 281 + 88

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

    with habbing.openHby(name="nat", base="test") as natHby:
        # setup Nat's habitat using default salt multisig already incepts
        natHab = natHby.makeHab(name="nat", isith='2', icount=3)
        assert natHab.name == 'nat'
        assert natHab.ks == natHby.ks
        assert natHab.db == natHby.db
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.pre in natHab.prefixes
        assert natHab.db.path.endswith("/keri/db/test/nat")
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
        assert natHab.kever.serder.said == 'EbjxjMV9atsoyxBVAnoe3B22Gprbu1dvYTpubyxrOfSk'
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.saidb
        serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre, ldig))))
        assert serder.said == natHab.kever.serder.said
        nstate = natHab.kever.state()

        state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
        assert state.raw == (
             b'{"v":"KERI10JSON00029e_","i":"EXB_8Qm1dNl-0kXq1c5H8wsT4bzKjuvduJPY0fn6blMM",'
             b'"s":"6","p":"EDsxS0J2wVS7h1xLeeF0EgPDLWk-NCBDMtLmGuuP-9ys","d":"EbjxjMV9atso'
             b'yxBVAnoe3B22Gprbu1dvYTpubyxrOfSk","f":"6","dt":"2021-01-01T00:00:00.000000+0'
             b'0:00","et":"ixn","kt":"2","k":["DI5E8Zqgy0j9HIkVRMjOTTF3Nr_PqwFDZ7bDNi0QCzew'
             b'","D2NIcFtglppQom493fiftJFiJkeKvC9b5CIdG19G8GHg","D36Ev0IqfpZ2wg0QbbTtPilJ2N'
             b'owjFT1IqF954cLB-9M"],"nt":"2","n":["EBoVvSj1Y_Lm1nvIP-wGSlAv-O2Xfy6uNZEHiceA'
             b'o5s0","EjnuygssSKA4D6cX1O6KPrroQv0EBLZ6W9X6TH2z1FzU","EwUwluAAcCqy2FsV9Vuh5u'
             b'zrJ0tWrPz0h32DvFEXAC70"],"bt":"0","b":[],"c":[],"ee":{"s":"2","d":"EKqCJJbQL'
             b'utszUHQO2TxDRFFLwnFLAjhDklXWCtEQgmY","br":[],"ba":[]},"di":""}')
        assert state.sn == 6
        assert state.ked["f"] == '6'
        assert state.ked == nstate.ked

        # now create new Kever with state
        kever = eventing.Kever(state=state, db=natHby.db)
        assert kever.sn == 6
        assert kever.fn == 6
        assert kever.serder.ked == natHab.kever.serder.ked
        assert kever.serder.said == natHab.kever.serder.said

        kstate = kever.state()
        assert kstate.ked == state.ked
        assert state.raw == (
            b'{"v":"KERI10JSON00029e_","i":"EXB_8Qm1dNl-0kXq1c5H8wsT4bzKjuvduJPY0fn6blMM",'
            b'"s":"6","p":"EDsxS0J2wVS7h1xLeeF0EgPDLWk-NCBDMtLmGuuP-9ys","d":"EbjxjMV9atso'
            b'yxBVAnoe3B22Gprbu1dvYTpubyxrOfSk","f":"6","dt":"2021-01-01T00:00:00.000000+0'
            b'0:00","et":"ixn","kt":"2","k":["DI5E8Zqgy0j9HIkVRMjOTTF3Nr_PqwFDZ7bDNi0QCzew'
            b'","D2NIcFtglppQom493fiftJFiJkeKvC9b5CIdG19G8GHg","D36Ev0IqfpZ2wg0QbbTtPilJ2N'
            b'owjFT1IqF954cLB-9M"],"nt":"2","n":["EBoVvSj1Y_Lm1nvIP-wGSlAv-O2Xfy6uNZEHiceA'
            b'o5s0","EjnuygssSKA4D6cX1O6KPrroQv0EBLZ6W9X6TH2z1FzU","EwUwluAAcCqy2FsV9Vuh5u'
            b'zrJ0tWrPz0h32DvFEXAC70"],"bt":"0","b":[],"c":[],"ee":{"s":"2","d":"EKqCJJbQL'
            b'utszUHQO2TxDRFFLwnFLAjhDklXWCtEQgmY","br":[],"ba":[]},"di":""}')

    assert not os.path.exists(natHby.ks.path)
    assert not os.path.exists(natHby.db.path)

    """End Test"""


if __name__ == "__main__":
    # pytest.main(['-vv', 'test_eventing.py::test_keyeventfuncs'])
    test_messagize()
