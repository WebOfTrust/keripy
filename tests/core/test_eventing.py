# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import blake3
import pysodium
import pytest

from keri import kering
from keri.app import habbing, keeping
from keri.app.keeping import openKS, Manager
from keri.core import coring, eventing, parsing, serdering
from keri.core.coring import (Diger, MtrDex, Matter, IdrDex, Indexer,
                              CtrDex, Counter, Salter, Siger, Cigar,
                              Seqner, Verfer, Signer, Prefixer,
                              generateSigners, IdxSigDex, DigDex)
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
from keri.core import serdering

from keri.db import dbing, basing
from keri.db.basing import openDB
from keri.db.dbing import dgKey, snKey
from keri.kering import (ValidationError, DerivationError, Ilks)

from keri import help
from keri.help import helping

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
    dig = 'EK2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    wig = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    # str
    couple = dig + wig
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64 == dig
    assert wiger.qb64 == wig
    assert len(couple) == 132  # not strip delete

    # bytes
    couple = couple.encode("utf-8")
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == dig.encode("utf-8")
    assert wiger.qb64b == wig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == dig.encode("utf-8")
    assert wiger.qb64b == wig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 132
    diger, wiger = deWitnessCouple(couple)
    assert diger.qb64b == dig.encode("utf-8")
    assert wiger.qb64b == wig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # test strip delete
    # str
    couple = dig + wig
    assert len(couple) == 132
    with pytest.raises(TypeError):  # immutable str so no delete
        diger, wiger = deWitnessCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytes
    couple = couple.encode("utf-8")
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
    assert diger.qb64b == dig.encode("utf-8")
    assert wiger.qb64b == wig.encode("utf-8")
    assert len(couple) == 0  # bytearray mutable so strip delete succeeds

    """end test"""


def test_dereceiptcouple():
    """
    test deReceiptCouple function
    """
    pre = 'DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cig = '0BAszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'

    # str
    couple = pre + cig
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64 == pre
    assert cigar.qb64 == cig
    assert len(couple) == 132  # not strip delete

    # bytes
    couple = couple.encode("utf-8")
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 132
    prefixer, cigar = deReceiptCouple(couple)
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(couple) == 132  # not strip delete

    # test strip delete
    # str
    couple = pre + cig
    assert len(couple) == 132
    with pytest.raises(TypeError):  # immutable str so no delete
        prefixer, cigar = deReceiptCouple(couple, strip=True)
    assert len(couple) == 132  # immutable so no delete

    # bytes
    couple = couple.encode("utf-8")
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
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(couple) == 0  # bytearray mutable so strip delete succeeds

    """end test"""


def test_desourcecouple():
    """
    test deSourceCouple function
    """
    snu = '0AAAAAAAAAAAAAAAAAAAAAAC'
    dig = 'EMLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'

    # str
    couple = snu + dig
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64 == snu
    assert diger.qb64 == dig
    assert len(couple) == 68  # not strip delete

    # bytes
    couple = couple.encode("utf-8")
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snu.encode("utf-8")
    assert diger.qb64b == dig.encode("utf-8")
    assert len(couple) == 68  # not strip delete

    # memoryview
    couple = memoryview(couple)
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snu.encode("utf-8")
    assert diger.qb64b == dig.encode("utf-8")
    assert len(couple) == 68  # not strip delete

    # bytearray
    couple = bytearray(couple)
    assert len(couple) == 68
    seqner, diger = deSourceCouple(couple)
    assert seqner.qb64b == snu.encode("utf-8")
    assert diger.qb64b == dig.encode("utf-8")
    assert len(couple) == 68  # not strip delete

    # test strip delete
    # str
    couple = snu + dig
    assert len(couple) == 68
    with pytest.raises(TypeError):  # immutable str so no delete
        seqner, diger = deSourceCouple(couple, strip=True)
    assert len(couple) == 68  # immutable so no delete

    # bytes
    couple = couple.encode("utf-8")
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
    assert seqner.qb64b == snu.encode("utf-8")
    assert diger.qb64b == dig.encode("utf-8")
    assert len(couple) == 0  # bytearray mutable so strip delete succeeds

    """end test"""


def test_dereceipttriple():
    """
    test deReceiptTriple function
    """
    dig = 'EMLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    pre = 'DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    cig = '0BAszieX0cpTOWZwa2I2LfeFAi9lrDjc1-Ip9ywl1KCNqie4ds_3mrZxHFboMC8Fu_5asnM7m67KlGC9EYaw0KDQ'

    # str
    triple = dig + pre + cig
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64 == dig
    assert prefixer.qb64 == pre
    assert cigar.qb64 == cig
    assert len(triple) == 176

    # bytes
    triple = triple.encode("utf-8")
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == dig.encode("utf-8")
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(triple) == 176

    # memoryview
    triple = memoryview(triple)
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == dig.encode("utf-8")
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(triple) == 176

    # bytearray
    triple = bytearray(triple)
    diger, prefixer, cigar = deReceiptTriple(triple)
    assert diger.qb64b == dig.encode("utf-8")
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(triple) == 176

    # test strip delete
    # str converts to bytes
    triple = dig + pre + cig
    assert len(triple) == 176
    with pytest.raises(TypeError):
        diger, prefixer, cigar = deReceiptTriple(triple, strip=True)
    assert len(triple) == 176  # immutable so no strip delete

    # bytes
    triple = triple.encode("utf-8")
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
    assert diger.qb64b == dig.encode("utf-8")
    assert prefixer.qb64b == pre.encode("utf-8")
    assert cigar.qb64b == cig.encode("utf-8")
    assert len(triple) == 0  # mutable so strip delete

    """end test"""


def test_dequadruple():
    """
    test test_dequadruple function
    """
    spre = 'DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnu = '0AAAAAAAAAAAAAAAAAAAAAAC'
    sdig = 'EMLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sig = 'AFCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    # str
    quadruple = spre + ssnu + sdig + sig
    sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64 == spre
    assert sseqner.qb64 == ssnu
    assert sdiger.qb64 == sdig
    assert siger.qb64 == sig
    assert len(quadruple) == 200

    # bytes
    quadruple = (spre + ssnu + sdig + sig).encode("utf-8")
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quadruple) == 200

    # memoryview
    quadruple = memoryview(quadruple)
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quadruple) == 200

    # bytearray
    quadruple = bytearray(quadruple)
    sprefixer, sseqner, sdiger, sigar = deTransReceiptQuadruple(quadruple)
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quadruple) == 200

    # test strip delete
    # str converts to bytes
    quadruple = spre + ssnu + sdig + sig
    assert len(quadruple) == 200
    with pytest.raises(TypeError):  # immutable so no strip delete
        sprefixer, sseqner, sdiger, siger = deTransReceiptQuadruple(quadruple, strip=True)
    assert len(quadruple) == 200  # immutable so no strip delete

    # bytes
    quadruple = quadruple.encode("utf-8")
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
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quadruple) == 0  # mutable so strip delete

    """end test"""


def test_dequintuple():
    """
    test dequintuple function
    """
    edig = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    spre = 'DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    ssnu = '0AAAAAAAAAAAAAAAAAAAAAAC'
    sdig = 'EMLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    sig = 'AFCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

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
    quintuple = quintuple.encode("utf-8")
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edig.encode("utf-8")
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quintuple) == 244

    # memoryview
    quintuple = memoryview(quintuple)
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edig.encode("utf-8")
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
    assert len(quintuple) == 244

    # bytearray
    quintuple = bytearray(quintuple)
    ediger, sprefixer, sseqner, sdiger, sigar = deTransReceiptQuintuple(quintuple)
    assert ediger.qb64b == edig.encode("utf-8")
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
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
    quintuple = quintuple.encode("utf-8")
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
    assert ediger.qb64b == edig.encode("utf-8")
    assert sprefixer.qb64b == spre.encode("utf-8")
    assert sseqner.qb64b == ssnu.encode("utf-8")
    assert sdiger.qb64b == sdig.encode("utf-8")
    assert siger.qb64b == sig.encode("utf-8")
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
    assert serder.ked["i"] == 'BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4X'
                        b'eq9W8_As","i":"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1'
                        b'","k":["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":'
                        b'"0","b":[],"c":[],"a":[]}')
    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    with pytest.raises(ValidationError):
        # non-empty ndigs with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, ndigs=["ABCDE"])

    with pytest.raises(ValidationError):
        # non-empty backers with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, wits=["ABCDE"])

    with pytest.raises(ValidationError):
        # non-empty seals with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.Ed25519N, data=[{"i": "ABCDE"}])

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.Ed25519_Seed
    assert signer0.verfer.code == MtrDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1'
                    b'vhtNTd4n","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1'
                    b'","k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":'
                    b'"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str
    assert serder0.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2'
                           b'QtV8BB0C","i":"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C","s":"0","kt":"1'
                           b'","k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"1","n":["EIf-EN'
                           b'w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[]}')


    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5u'
                        b'k-WxvhsL","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,'
                        b'"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"n":["EIf-ENw7Pr'
                        b'M52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}')


    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.Ed25519_Seed
    assert signer1.verfer.code == MtrDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'{"v":"KERI10JSON000125_","t":"icp","d":"EFSJqZE0K0WU95dmccrg_8EKSuVSrt4kGIZN'
                        b'jqWFA_HL","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":1,'
                        b'"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"n":["EIf-ENw7Pr'
                        b'M52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}')

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
    assert nxt1 == ['EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W']
    serder0 = incept(keys=keys0, ndigs=nxt1)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == 'DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EJQUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEK'
                        b'TwIiTBPj","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1'
                        b'","k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"1","n":["EIf-EN'
                        b'w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder0.ked, code=MtrDex.Blake3_256)
    #assert saider.qb64 == serder0.said

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1)
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EFl8nvRCbN2xQJI75nBXp-gaXuHJw8zheVjw'
                        b'MN_rB-pb","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"1","p":"EJ'
                        b'QUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEKTwIiTBPj","kt":"1","k":["DB4GWvru73jWZKpNg'
                        b'MQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSb'
                        b'LJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}')

    #saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    #assert serder1.said == saider.qb64



    # Rotation: Transferable not abandoned i.e. next not empty  Intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.Ed25519_Seed
    assert signer2.verfer.code == MtrDex.Ed25519
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1, intive=True)  # intive
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == 1
    assert serder1.ked["nt"] == 1
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == 0
    assert serder1.raw == (b'{"v":"KERI10JSON00015a_","t":"rot","d":"ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Eb'
                        b'dzm4E-kQ","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"1","p":"EJ'
                        b'QUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEKTwIiTBPj","kt":1,"k":["DB4GWvru73jWZKpNgMQ'
                        b'p8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":1,"n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrE'
                        b'n21c2zVaU"],"bt":0,"br":[],"ba":[],"a":[]}')

    #saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    #assert serder1.said == saider.qb64

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.said, sn=2)
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["p"] == serder1.said
    assert serder2.raw == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T'
                           b'6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"2","p":"EC'
                           b'auhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ","a":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, said=serder2.said)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.said
    assert serder3.raw == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T'
                           b'6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0"}')



    serder4 = receipt(pre=pre, sn=2, said=serder2.said)

    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.said
    assert serder4.raw == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T'
                           b'6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"2"}')


    # Receipt  transferable identifier
    serderA = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
    assert serderA.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2'
                        b'QtV8BB0C","i":"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C","s":"0","kt":"1'
                        b'","k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"1","n":["EIf-EN'
                        b'w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[]}')
    seal = SealEvent(i=serderA.ked["i"], s=serderA.ked["s"], d=serderA.said)
    assert seal.i == serderA.ked["i"]
    assert seal.d == serderA.said

    siger = signer0.sign(ser=serderA.raw, index=0)
    msg = messagize(serder=serder4, sigers=[siger], seal=seal)
    assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjm'
                b'S28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpN'
                b'ceHo4XH","s":"2"}-FABEAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0'
                b'C0AAAAAAAAAAAAAAAAAAAAAAAEAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV'
                b'8BB0C-AABAAAPitVKfl6dG9dY4-7Ppg5tAANHsqEUptTfR05wLb0fbmKFt4DbZdB'
                b'NjJaCDrEc7kAIqbLsCMCKf26-Onxz-DoP')

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
    nxtD = [Diger(ser=key.encode("utf-8")).qb64 for key in keysD]  # default sith is 1
    # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, ndigs=nxtD)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'{"v":"KERI10JSON00015f_","t":"dip","d":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYU'
                        b'bUztxaiH","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"0","kt":"1'
                        b'","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIf-EN'
                        b'w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[],"di":'
                        b'"EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}')
    assert serderD.said == 'EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR)  # next signing keypair transferable is default
    assert signerR.code == MtrDex.Ed25519_Seed
    assert signerR.verfer.code == MtrDex.Ed25519
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    # default sith is 1
    nxtR = [Diger(ser=signerR.verfer.qb64b).qb64]  # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      ndigs=nxtR)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'{"v":"KERI10JSON000160_","t":"drt","d":"EMBBBkaLV7i6wNgfz3giib2ItrHsr548mtIf'
                        b'lW0Hrbuv","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"4","p":"EA'
                        b'Nkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1","k":["DPLt4YqQsWZ5DPztI'
                        b'32mSyTJPRESONvE9KbETtCVYIeH"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSb'
                        b'LJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}')
    assert serderR.said == 'EMBBBkaLV7i6wNgfz3giib2ItrHsr548mtIflW0Hrbuv'


    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    #  Secp256r1 Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False, code=MtrDex.ECDSA_256r1_Seed)  # original signing keypair non transferable
    assert signer0.code == MtrDex.ECDSA_256r1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256r1N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON000105_","t":"icp","d":"ELIz2CFNp4vCTJkCKYzqkv1tJeqaPiwhHkNuWA0tKfxo",'
                          b'"i":"1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ","s":"0","kt":"1",'
                          b'"k":["1AAIA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')
    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    with pytest.raises(ValidationError):
        # non-empty nxt with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N, ndigs=["ABCDE"])

    with pytest.raises(ValidationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N, wits=["ABCDE"])

    with pytest.raises(ValidationError):
        # non-empty witnesses with non-transferable code
        serder = incept(keys=keys0, code=MtrDex.ECDSA_256r1N, data=[{"i": "ABCDE"}])

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed, code=MtrDex.ECDSA_256r1_Seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.ECDSA_256r1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256r1
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON000105_","t":"icp","d":"EPqQeDE6eoawHEwQjyB4kwLTwZ2VV6jDz_TXWFV7sE8T",'
                          b'"i":"1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ","s":"0","kt":"1",'
                          b'"k":["1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],"nt":"0","n":[],'
                          b'"bt":"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == 'EFEscYZrbSsAPJq_OhGt19qb-ci1AtZTqwGqZ5FypKVd'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str

    assert serder0.raw == (b'{"v":"KERI10JSON00012f_","t":"icp","d":"EFEscYZrbSsAPJq_OhGt19qb-ci1AtZTqwGqZ5FypKVd",'
                          b'"i":"EFEscYZrbSsAPJq_OhGt19qb-ci1AtZTqwGqZ5FypKVd","s":"0",'
                          b'"kt":"1","k":["1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],'
                          b'"nt":"1","n":["EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4"],'
                          b'"bt":"0","b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'EJcQxvzMr3xaxa6rlXvPguII45JMmoRENnKFAsUS9Mx0'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'{"v":"KERI10JSON000129_","t":"icp","d":"EJcQxvzMr3xaxa6rlXvPguII45JMmoRENnKFAsUS9Mx0",'
                           b'"i":"EJcQxvzMr3xaxa6rlXvPguII45JMmoRENnKFAsUS9Mx0","s":"0",'
                           b'"kt":1,"k":["1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],'
                           b'"nt":1,"n":["EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4"],'
                           b'"bt":0,"b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'{"v":"KERI10JSON00012d_","t":"icp","d":"ECMsDN8WUWcKGe7X0GNrecOgtrTkuHTfoo7YoQ4TIOLS",'
                           b'"i":"1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ","s":"0",'
                           b'"kt":1,"k":["1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],'
                           b'"nt":1,"n":["EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4"],'
                           b'"bt":0,"b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256r1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256r1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4']
    serder0 = incept(keys=keys0, ndigs=nxt1)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'{"v":"KERI10JSON000133_","t":"icp","d":"EF8tNYXNKPjByUNg2s7zEhEKKl39COxwOYA1CpqvxB_J",'
                           b'"i":"1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ","s":"0",'
                           b'"kt":"1","k":["1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"],'
                           b'"nt":"1","n":["EDCWQzPSj3zZBKMZ-_FAckxIMFM25ITsEwD72psBYak4"],'
                           b'"bt":"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder0.ked, code=MtrDex.Blake3_256)
    #assert saider.qb64 == serder0.said


    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256r1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256r1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256r1
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1)
    print(f'evnt {serder1.raw}')
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'{"v":"KERI10JSON000168_","t":"rot","d":"ENsyn8FRcmd9N3Dhi_kRdWcnI_AIa7yhDNsHXycclSXQ",'
                           b'"i":"1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ","s":"1","p":"EF8tNYXNKPjByUNg2s7zEhEKKl39COxwOYA1CpqvxB_J",'
                           b'"kt":"1","k":["1AAJAtrK9Q8IqgO3B4IKY4m8Dl7dp1fC77dNCsHP2aWctria"],'
                           b'"nt":"1","n":["EIkmr0Ne3wbNvTKRU-A9NLmCL-RYgu2SZuzIb3n-9xFH"],'
                           b'"bt":"0","br":[],"ba":[],"a":[]}')

    #saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    #assert serder1.said == saider.qb64


    #  Secp256k1 Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False, code=MtrDex.ECDSA_256k1_Seed)  # original signing keypair non transferable
    assert signer0.code == MtrDex.ECDSA_256k1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256k1N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AAAAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON000105_","t":"icp","d":"EGEP0h6tTUUOeIK4ApGlnLl2lwD0lbaQGBfL9'
                         b'pM2v0J0","i":"1AAAAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"0","kt":"1"'
                         b',"k":["1AAAAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')
    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)  # original signing keypair transferable default
    assert signer0.code == MtrDex.ECDSA_256k1_Seed
    assert signer0.verfer.code == MtrDex.ECDSA_256k1
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  # default nxt is empty so abandoned
    assert serder.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder.ked["n"] == []
    assert serder.raw == (b'{"v":"KERI10JSON000105_","t":"icp","d":"EO3M4d4pvQu2SXFLaXEy05ey80d71gbEakA2TgCTnJtN",'
                          b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"0","kt":"1",'
                          b'"k":["1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],"nt":"0","n":[],'
                          b'"bt":"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder.ked, code=MtrDex.Blake3_256)
    #assert saider.verify(serder.ked) is True

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)  # intive false
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == serder0.ked["i"] == 'EBTJs_972Mh0Q2raFOINbmgtdtT0Od4VJm6aNd4xVW9u'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == '0'  # hex str
    assert serder0.raw == (b'{"v":"KERI10JSON00012f_","t":"icp","d":"EBTJs_972Mh0Q2raFOINbmgtdtT0Od4VJm6aNd4xVW9u",'
                           b'"i":"EBTJs_972Mh0Q2raFOINbmgtdtT0Od4VJm6aNd4xVW9u","s":"0","kt":"1",'
                           b'"k":["1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],'
                           b'"nt":"1","n":["EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO"],'
                           b'"bt":"0","b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty,Self-Addressing, intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked['d'] == pre == 'ECzQWBHMIRJpUhrIB2sn4YUsb0HL-wE1wErVcQnkme5z'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0
    assert serder0.raw == (b'{"v":"KERI10JSON000129_","t":"icp","d":"ECzQWBHMIRJpUhrIB2sn4YUsb0HL-wE1wErVcQnkme5z",'
                           b'"i":"ECzQWBHMIRJpUhrIB2sn4YUsb0HL-wE1wErVcQnkme5z","s":"0","kt":1,'
                           b'"k":["1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],'
                           b'"nt":1,"n":["EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO"],'
                           b'"bt":0,"b":[],"c":[],"a":[]}')

    # Inception: Transferable not abandoned i.e. next not empty, Intive True
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1, intive=True)  # intive true
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == 1
    assert serder0.ked["nt"] == 1
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == 0  # int not hex str
    assert serder0.raw == (b'{"v":"KERI10JSON00012d_","t":"icp","d":"EJR4ywPEpo08A10s8Eq8MGIRtmQx_D6szqYKGOl7jSpY",'
                          b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"0","kt":1,'
                          b'"k":["1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],'
                          b'"nt":1,"n":["EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO"],'
                          b'"bt":0,"b":[],"c":[],"a":[]}')


    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer1.code == MtrDex.ECDSA_256k1_Seed
    assert signer1.verfer.code == MtrDex.ECDSA_256k1
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    assert nxt1 == ['EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO']
    serder0 = incept(keys=keys0, ndigs=nxt1)
    pre = serder0.ked["i"]
    assert serder0.ked["t"] == Ilks.icp
    assert serder0.ked["i"] == '1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk'
    assert serder0.ked["s"] == '0'
    assert serder0.ked["kt"] == "1"
    assert serder0.ked["nt"] == "1"
    assert serder0.ked["n"] == nxt1
    assert serder0.ked["bt"] == "0"  # hex str
    assert serder0.raw == (b'{"v":"KERI10JSON000133_","t":"icp","d":"EJZHJo2S1oESDhtadHN-RUV4J3DM9xlWHdsi2TI8ztZ6",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"0","kt":"1",'
                           b'"k":["1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"],'
                           b'"nt":"1","n":["EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO"],'
                           b'"bt":"0","b":[],"c":[],"a":[]}')

    #saider = coring.Saider(sad=serder0.ked, code=MtrDex.Blake3_256)
    #assert saider.qb64 == serder0.said

    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256k1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256k1
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1)
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == "1"
    assert serder1.ked["nt"] == "1"
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == '0'  # hex str
    assert serder1.raw == (b'{"v":"KERI10JSON000168_","t":"rot","d":"EKpAPAgfGLxzXuusVQJ4uTuSOzt1mm3a8K1VPRnJOufJ",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"1","p":"EJZHJo2S1oESDhtadHN-RUV4J3DM9xlWHdsi2TI8ztZ6",'
                           b'"kt":"1","k":["1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQKgHfa6eKyLcZpEn26"],'
                           b'"nt":"1","n":["EDn6z-KqmwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07"],'
                           b'"bt":"0","br":[],"ba":[],"a":[]}')

    #saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    #assert serder1.said == saider.qb64


    # Rotation: Transferable not abandoned i.e. next not empty  Intive
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signer2.code == MtrDex.ECDSA_256k1_Seed
    assert signer2.verfer.code == MtrDex.ECDSA_256k1
    keys2 = [coring.Diger(ser=signer2.verfer.qb64b).qb64]
    # compute nxt digest
    serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=keys2, sn=1, intive=True)  # intive
    assert serder1.ked["t"] == Ilks.rot
    assert serder1.ked["i"] == pre
    assert serder1.ked["s"] == '1'
    assert serder1.ked["p"] == serder0.said
    assert serder1.ked["kt"] == 1
    assert serder1.ked["nt"] == 1
    assert serder1.ked["n"] == keys2
    assert serder1.ked["bt"] == 0
    assert serder1.raw == (b'{"v":"KERI10JSON000162_","t":"rot","d":"EHc84kDs5EsLQYVLkP7fe-7DUfCQ7jFY69Zqq2UfmvTe",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"1","p":"EJZHJo2S1oESDhtadHN-RUV4J3DM9xlWHdsi2TI8ztZ6",'
                           b'"kt":1,"k":["1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQKgHfa6eKyLcZpEn26"],'
                           b'"nt":1,"n":["EDn6z-KqmwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07"],'
                           b'"bt":0,"br":[],"ba":[],"a":[]}')

    #saider = coring.Saider(sad=serder1.ked, code=MtrDex.Blake3_256)
    #assert serder1.said == saider.qb64

    # Interaction:
    serder2 = interact(pre=pre, dig=serder1.said, sn=2)
    assert serder2.ked["t"] == Ilks.ixn
    assert serder2.ked["i"] == pre
    assert serder2.ked["s"] == '2'
    assert serder2.ked["p"] == serder1.said
    assert serder2.raw == (b'{"v":"KERI10JSON0000cf_","t":"ixn","d":"EGa_yUkSwFvJTbFnEBosvpIkJ_AkyY5E3XdU7fqhtErf",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"2","p":"EHc84kDs5EsLQYVLkP7fe-7DUfCQ7jFY69Zqq2UfmvTe","a":[]}')

    # Receipt
    serder3 = receipt(pre=pre, sn=0, said=serder2.said)
    assert serder3.ked["i"] == pre
    assert serder3.ked["s"] == "0"
    assert serder3.ked["t"] == Ilks.rct
    assert serder3.ked["d"] == serder2.said
    assert serder3.raw == (b'{"v":"KERI10JSON000095_","t":"rct","d":"EGa_yUkSwFvJTbFnEBosvpIkJ_AkyY5E3XdU7fqhtErf",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"0"}')


    serder4 = receipt(pre=pre, sn=2, said=serder2.said)
    assert serder4.ked["i"] == pre
    assert serder4.ked["s"] == "2"
    assert serder4.ked["t"] == Ilks.rct
    assert serder4.ked["d"] == serder2.said
    assert serder4.raw == (b'{"v":"KERI10JSON000095_","t":"rct","d":"EGa_yUkSwFvJTbFnEBosvpIkJ_AkyY5E3XdU7fqhtErf",'
                           b'"i":"1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk","s":"2"}')


    # Delegated Inception:
    # Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedD = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')
    signerD = Signer(raw=seedD, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signerD.code == MtrDex.ECDSA_256k1_Seed
    assert signerD.verfer.code == MtrDex.ECDSA_256k1
    keysD = [signerD.verfer.qb64]
    # compute nxt digest
    nxtD = [Diger(ser=key.encode("utf-8")).qb64 for key in keysD]  # default sith is 1
    # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderD = delcept(keys=keysD, delpre=delpre, ndigs=nxtD)
    pre = serderD.ked["i"]
    assert serderD.ked["i"] == 'EFVACrfsy2Ke_tjqq-wroc-TE0IFZ-QNwQwuMVzl0rgj'
    assert serderD.ked["s"] == '0'
    assert serderD.ked["t"] == Ilks.dip
    assert serderD.ked["n"] == nxtD
    assert serderD.raw == (b'{"v":"KERI10JSON000163_","t":"dip","d":"EFVACrfsy2Ke_tjqq-wroc-TE0IFZ-QNwQwuMVzl0rgj",'
                           b'"i":"EFVACrfsy2Ke_tjqq-wroc-TE0IFZ-QNwQwuMVzl0rgj","s":"0",'
                           b'"kt":"1","k":["1AABA7KZA_wxPCXJ5BgZ9jjdrMIy3OQKgHfa6eKyLcZpEn26"],'
                           b'"nt":"1","n":["EJ6Ycs7kho8XRxiq3DK37jiJ8mU9RP9HpSYnARm26EnO"],'
                           b'"bt":"0","b":[],"c":[],"a":[],"di":"EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}')

    assert serderD.said == 'EFVACrfsy2Ke_tjqq-wroc-TE0IFZ-QNwQwuMVzl0rgj'

    # Delegated Rotation:
    # Transferable not abandoned i.e. next not empty
    seedR = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
             b'e\xf9AL\x1aeK\xafj\xa1pB')
    signerR = Signer(raw=seedR, code=MtrDex.ECDSA_256k1_Seed)  # next signing keypair transferable is default
    assert signerR.code == MtrDex.ECDSA_256k1_Seed
    assert signerR.verfer.code == MtrDex.ECDSA_256k1
    keysR = [signerR.verfer.qb64]
    # compute nxt digest
    # default sith is 1
    nxtR = [Diger(ser=signerR.verfer.qb64b).qb64]  # transferable so nxt is not empty

    delpre = 'EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd'
    serderR = deltate(pre=pre,
                      keys=keysR,
                      dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                      sn=4,
                      ndigs=nxtR)

    assert serderR.ked["i"] == pre
    assert serderR.ked["s"] == '4'
    assert serderR.ked["t"] == Ilks.drt
    assert serderR.ked["n"] == nxtR
    assert serderR.raw == (b'{"v":"KERI10JSON000164_","t":"drt","d":"EMN4ZdZEZzB0FyHzAOKehHTa6WvvBfK3xwylPuxoJ4sO",'
                           b'"i":"EFVACrfsy2Ke_tjqq-wroc-TE0IFZ-QNwQwuMVzl0rgj","s":"4","p":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30",'
                           b'"kt":"1","k":["1AABAh-zxZOUdAZwXBhbtZQgzD3LLPMYxF7HgsPbd2mILaPc"],'
                           b'"nt":"1","n":["EDn6z-KqmwcDVCql1CkMkvSNbNghhMF2TwsdllyP4a07"],'
                           b'"bt":"0","br":[],"ba":[],"a":[]}')

    assert serderR.said == 'EMN4ZdZEZzB0FyHzAOKehHTa6WvvBfK3xwylPuxoJ4sO'

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
        "c": ["EO"],
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
    # raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=raw)

    # State NonDelegated (key state notification)
    # create transferable key pair for controller of KEL
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 trans pre
    assert preC == 'DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN'
    sith = '1'
    keys = [signerC.verfer.qb64]
    # compute nxt digest (dummy reuse keys)
    nxt = [Diger(ser=signerC.verfer.qb64b).qb64]
    assert nxt == ['EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg']

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BDU5LLVHxQSb9EdSKDTYyqViusxGT8Y4DHOyktkOv5Rt'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'BO7x6ctSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqwRc_9W'

    wits = [preW1, preW2, preW3]
    toad = 2

    # create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         br=[preW0],
                         ba=[preW3])

    ksr = state(pre=preC,
                    sn=4,
                    pig='EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                    dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                    fn=4,
                    eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    ndigs=nxt,
                    toad=toad,
                    wits=wits,
                    )

    raw = ksr._asjson()
    assert raw == (b'{"vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN","s":"4","p":"'
                    b'EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI'
                    b'462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"i'
                    b'xn","kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"nt":"1","'
                    b'n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt":"2","b":["BGhCNcrRB'
                    b'R6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6ctSA7FllJx39hlObnetizGFjuZT1jq0ge'
                    b'no0NRK","BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3"'
                    b',"d":"EUskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSK'
                    b'DTYyqViusxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqw'
                    b'Rc_9W"]},"di":""}')

    assert ksr.d == 'EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30'
    assert ksr.i == preC == 'DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN'
    assert ksr.s == '4'

    # create endorsed ksn with nontrans endorser
    # create nontrans key pair for endorder of KSN
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'BMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    cigarE = signerE.sign(ser=raw)
    assert signerE.verfer.verify(sig=cigarE.raw, ser=raw)
    #msg = messagize(serderK, cigars=[cigarE])
    #assert msg == (b'{"v":"KERI10JSON0002d5_","vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFY'
          #b'TaUgrasnqz6llSvWQTWZN","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRS'
          #b'KH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132'
          #b'Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn",'
          #b'"kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"n'
          #b't":"1","n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt"'
          #b':"2","b":["BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6c'
          #b'tSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK","BK7isi_2-A-RE6Pbtdg7S1N'
          #b'SeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS'
          #b'_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSKDTYyqViu'
          #b'sxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCF'
          #b'ASqwRc_9W"]},"di":""}-CABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aN'
          #b'UL64y0BAxhIlDV7ZlsV2OoDi1ltOQOFA7Z7NnjdoEL_rKdO2mn2q3LEtbPPYgJ9t'
          #b'UOIE3F0BABStJ5RMOrqnrwntbZesG')

    # create endorsed ksn with trans endorser
    # create trans key pair for endorder of KSN
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    # create endorsed ksn
    sigerE = signerE.sign(ser=raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=raw)
    #msg = messagize(serderK, sigers=[sigerE], seal=seal)
    #assert msg == (b'{"v":"KERI10JSON0002d5_","vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFY'
          #b'TaUgrasnqz6llSvWQTWZN","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRS'
          #b'KH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132'
          #b'Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn",'
          #b'"kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"n'
          #b't":"1","n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt"'
          #b':"2","b":["BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6c'
          #b'tSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK","BK7isi_2-A-RE6Pbtdg7S1N'
          #b'SeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3","d":"EUskHI462CuIMS'
          #b'_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSKDTYyqViu'
          #b'sxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCF'
          #b'ASqwRc_9W"]},"di":""}-FABDMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aN'
          #b'UL64y0AAAAAAAAAAAAAAAAAAAAAAAEAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhq'
          #b'TEhkeDZ2z-AABAAAxhIlDV7ZlsV2OoDi1ltOQOFA7Z7NnjdoEL_rKdO2mn2q3LEt'
          #b'bPPYgJ9tUOIE3F0BABStJ5RMOrqnrwntbZesG')


    # State Delegated (key state notification)
    # create transferable key pair for controller of KEL
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preC == 'DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN'
    sith = '1'
    keys = [signerC.verfer.qb64]
    # compute nxt digest (dummy reuse keys)
    nxt = [Diger(ser=signerC.verfer.qb64b).qb64]
    assert nxt == ['EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg']

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BDU5LLVHxQSb9EdSKDTYyqViusxGT8Y4DHOyktkOv5Rt'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'BO7x6ctSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqwRc_9W'

    wits = [preW1, preW2, preW3]
    toad = 2

    # create namedtuple of latest est event
    eevt = StateEstEvent(s='3',
                         d='EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                         br=[preW0],
                         ba=[preW3])

    # create transferable key pair for delegator of KEL
    signerD = salter.signer(path="D", temp=True)
    assert signerD.code == MtrDex.Ed25519_Seed
    assert signerD.verfer.code == MtrDex.Ed25519  # transferable
    preD = signerD.verfer.qb64  # use public key verfer.qb64 as trans pre
    assert preD == 'DBs-gd3nJGtF0Ch2jn7NLaUKsCKB7l3nLs-993_s5Ie1'

    ksr = state(pre=preC,
                    sn=4,
                    pig='EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30',
                    dig='EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30',
                    fn=4,
                    eilk=Ilks.ixn,
                    keys=keys,
                    eevt=eevt,
                    sith=sith,
                    ndigs=nxt,
                    toad=toad,
                    wits=wits,
                    dpre=preD
                    )

    raw = ksr._asjson()
    assert raw == (b'{"vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN","s":"4","p":"'
                b'EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI'
                b'462CuIMS_HQIO132Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"i'
                b'xn","kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"nt":"1","'
                b'n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt":"2","b":["BGhCNcrRB'
                b'R6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6ctSA7FllJx39hlObnetizGFjuZT1jq0ge'
                b'no0NRK","BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3"'
                b',"d":"EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSK'
                b'DTYyqViusxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqw'
                b'Rc_9W"]},"di":"DBs-gd3nJGtF0Ch2jn7NLaUKsCKB7l3nLs-993_s5Ie1"}')

    assert ksr.d == 'EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30'
    assert ksr.i == preC == 'DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN'
    assert ksr.s == '4'

    # create endorsed ksn with nontrans endorser
    # create nontrans key pair for endorder of KSN
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'BMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    # create endorsed ksn
    cigarE = signerE.sign(ser=raw)
    assert signerE.verfer.verify(sig=cigarE.raw, ser=raw)
    #msg = messagize(serderK, cigars=[cigarE])
    #assert msg == (b'{"v":"KERI10JSON000301_","vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFY'
          #b'TaUgrasnqz6llSvWQTWZN","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRS'
          #b'KH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132'
          #b'Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn",'
          #b'"kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"n'
          #b't":"1","n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt"'
          #b':"2","b":["BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6c'
          #b'tSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK","BK7isi_2-A-RE6Pbtdg7S1N'
          #b'SeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3","d":"EAskHI462CuIMS'
          #b'_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSKDTYyqViu'
          #b'sxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCF'
          #b'ASqwRc_9W"]},"di":"DBs-gd3nJGtF0Ch2jn7NLaUKsCKB7l3nLs-993_s5Ie1"'
          #b'}-CABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BBTNCmYMYJNNQd'
          #b'QN9irkUaL_RBdztUlykS6P-fxDUofmfWuTL7Hb0XHjtcT-wJMCYO7G1i5IbuhSHf'
          #b'o-maDh4EG')

    # create endorsed ksn with trans endorser
    # create trans key pair for endorder of KSN
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

    # create endorsed ksn
    sigerE = signerE.sign(ser=raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=raw)
    #msg = messagize(serderK, sigers=[sigerE], seal=seal)
    #assert msg == (b'{"v":"KERI10JSON000301_","vn":[1,0],"i":"DN6WBhWqp6wC08no2iWhgFY'
          #b'TaUgrasnqz6llSvWQTWZN","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRS'
          #b'KH2p9zHQIO132Z30","d":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132'
          #b'Z30","f":"4","dt":"2021-01-01T00:00:00.000000+00:00","et":"ixn",'
          #b'"kt":"1","k":["DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN"],"n'
          #b't":"1","n":["EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg"],"bt"'
          #b':"2","b":["BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F","BO7x6c'
          #b'tSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK","BK7isi_2-A-RE6Pbtdg7S1N'
          #b'SeinNQkJ4oCFASqwRc_9W"],"c":[],"ee":{"s":"3","d":"EAskHI462CuIMS'
          #b'_gNkcl_QewzrRSKH2p9zHQIO132Z30","br":["BDU5LLVHxQSb9EdSKDTYyqViu'
          #b'sxGT8Y4DHOyktkOv5Rt"],"ba":["BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCF'
          #b'ASqwRc_9W"]},"di":"DBs-gd3nJGtF0Ch2jn7NLaUKsCKB7l3nLs-993_s5Ie1"'
          #b'}-FABDMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0AAAAAAAAAAAAAA'
          #b'AAAAAAAAAEAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAABTNCm'
          #b'YMYJNNQdQN9irkUaL_RBdztUlykS6P-fxDUofmfWuTL7Hb0XHjtcT-wJMCYO7G1i'
          #b'5IbuhSHfo-maDh4EG')

    """Done Test"""


def test_messagize():
    """
    Test messagize utility function
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256)

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)
        msg = messagize(serder, sigers=sigers)
        assert isinstance(msg, bytearray)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')

        # Test with pipelined
        msg = messagize(serder, sigers=sigers, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'X-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with seal
        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, sigers=sigers, seal=seal)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-FA'
                    b'BDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAA'
                    b'AAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuEfnZZ'
                    b'6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_X'
                    b'jyZLHyClVTLoD')

        # Test with pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                b'0-FABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA'
                b'AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuE'
                b'fnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI8'
                b'62_XjyZLHyClVTLoD')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with wigers and pipelined
        msg = messagize(serder, wigers=wigers, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'X-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'BBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFi'
                    b'DF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVw'
                    b'g_TwF')

        # Test with cigars and pipelined
        msg = messagize(serder, cigars=cigars, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'i-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgG'
                    b'FtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko'
                    b'5EVwg_TwF')


        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')


        # Test with wigers and cigars and pipelined
        msg = messagize(serder, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'5-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47'
                    b'513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa'
                    b'0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')


        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_J'
                    b'uO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MC'
                    b'DssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas'
                    b'-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and wigers and cigars and pipelines
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                    b'Q-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyx'
                    b's7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJj'
                    b'H1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7Q'
                    b'oVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with receipt message
        ked = serder.ked
        reserder = receipt(pre=ked["i"],
                           sn=int(ked["s"], 16),
                           said=serder.said)

        # Test with wigers
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1'
                    b'US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with cigars
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt
        msg = messagize(reserder, cigars=cigars)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QK'
                    b'z0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1'
                    b'US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, )
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1'
                    b'US2fBWe7FNpn6xko5EVwg_TwF-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars and pipelined
        msg = messagize(serder, wigers=wigers, cigars=cigars, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'5-BABAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xs'
                    b'yyH1US2fBWe7FNpn6xko5EVwg_TwF-CABBJjH1MCDssEZMnORskF34AwOFDgDL47'
                    b'513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa'
                    b'0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and seal and wigers and cigars and pipelined
        msg = messagize(serder, sigers=sigers, seal=seal, wigers=wigers,
                        cigars=cigars, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                    b't-FABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA'
                    b'AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuE'
                    b'fnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI8'
                    b'62_XjyZLHyClVTLoD-BABAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31'
                    b'jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-CABBJjH1MCDssEZMnO'
                    b'RskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0x'
                    b'tOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with query message
        ked = serder.ked
        qserder = query(route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=help.helping.DTS_BASE_0)

        # create SealEvent for endorsers est evt whose keys use to sign
        seal = SealLast(i=ked["i"])
        msg = messagize(qserder, sigers=sigers, seal=seal)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AABAAB'
                    b'1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQ'
                    b'kxI862_XjyZLHyClVTLoD')

        # create SealEvent for endorsers est evt whose keys use to sign
        msg = messagize(qserder, sigers=sigers, seal=seal, pipelined=True)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-VAj-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')

        """ Done Test """


def test_messagize_with_prior_next():
    """
    Test messagize utility function with prior next modifier on indexed signatures
    """
    pass

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
        raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
        salter = Salter(raw=raw)
        # create current key
        sith = 1  # one signer
        #  original signing keypair transferable default
        skp0 = salter.signer(path="A", temp=True, transferable=True)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519
        assert skp0.verfer.qb64 == 'DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        keys = [skp0.verfer.qb64]

        # create next key
        #  next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        # compute nxt digest
        # transferable so nxt is not empty
        ndiger = Diger(ser=skp1.verfer.qb64b)
        nxt = [ndiger.qb64]
        assert nxt == ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj']

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        # make with defaults with non-digestive prefix
        serder = serdering.SerderKERI(makify=True,
                                      ilk=kering.Ilks.icp,
                                      saids = {'i': coring.PreDex.Ed25519},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 1
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)

        serder = serdering.SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EBTCANzIfUThxmM1z1SFxQuwooGdF4QwtotRS01vZGqi'
        assert serder.pre == 'DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        aid0 = serder.pre

        # Assign first serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # no error
        assert kever.db == db
        assert kever.cues == None
        assert kever.prefixer.qb64 == aid0
        assert kever.sner.num == 0
        assert kever.sn == kever.sner.num  # sn property
        assert [verfer.qb64 for verfer in kever.verfers] == [skp0.verfer.qb64]
        assert kever.ndigs == nxt
        state = kever.db.states.get(keys=kever.prefixer.qb64)
        assert state.s == kever.sner.numh == '0'
        feqner = kever.db.fons.get(keys=(kever.prefixer.qb64, kever.serder.said))
        assert feqner.sn == kever.sn

        ksr = kever.state()  # key state record
        assert ksr == state
        assert ksr.i == kever.prefixer.qb64
        assert ksr.s == kever.sner.numh
        assert ([key for key in ksr.k] ==
                [verfer.qb64 for verfer in kever.verfers])
        assert ksr._asjson() == (b'{"vn":[1,0],"i":"DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e","s":"0","p":"'
                        b'","d":"EBTCANzIfUThxmM1z1SFxQuwooGdF4QwtotRS01vZGqi","f":"0","dt":"2021-01-0'
                        b'1T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DAUDqkmn-hqlQKD8W-FAEa5JU'
                        b'vJC2I9yarEem-AAEg3e"],"nt":"1","n":["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7'
                        b'hOrWj"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EBTCANzIfUThxmM1z1SFxQuwoo'
                        b'GdF4QwtotRS01vZGqi","br":[],"ba":[]},"di":""}')

        # test exposeds
        raw = b"raw salt to test"
        #  create signers with verfers
        signers = coring.Salter(raw=raw).signers(count=3, path="next", temp=True)

        # create something to sign
        ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

        # test different index and ondex
        sigers = []
        digers = []
        for i, signer in enumerate(signers):
            o = len(signers) - 1 - i
            siger = signer.sign(ser=ser, index=i, ondex=o)
            diger = Diger(ser=siger.verfer.qb64b)
            sigers.append(siger)
            digers.append(diger)

        digers.reverse()

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[2, 1, 0]

        # test partial mix
        siger0 = signers[0].sign(ser=ser, index=0)  # both same
        assert siger0.code == IdxSigDex.Ed25519_Sig  # both same
        diger0 = Diger(ser=siger0.verfer.qb64b)

        siger1 = signers[1].sign(ser=ser, index=1, only=True)  # current only
        assert siger1.code == IdxSigDex.Ed25519_Crt_Sig  # current only

        siger2 = signers[2].sign(ser=ser, index=2, ondex=1)  # both different
        assert siger2.code == IdxSigDex.Ed25519_Big_Sig  # both different
        diger1 = Diger(ser=siger2.verfer.qb64b)

        sigers = [siger0, siger1, siger2]
        digers = [diger0, diger1]

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[0, 1]


        # test Bad digest
        siger0 = signers[0].sign(ser=ser, index=0)  # both same
        assert siger0.code == IdxSigDex.Ed25519_Sig  # both same
        diger0 = Diger(ser=b"Bad Digest")  # bad digest

        siger1 = signers[1].sign(ser=ser, index=1, only=True)  # current only
        assert siger1.code == IdxSigDex.Ed25519_Crt_Sig  # current only

        siger2 = signers[2].sign(ser=ser, index=2, ondex=1)  # both different
        assert siger2.code == IdxSigDex.Ed25519_Big_Sig  # both different
        diger1 = Diger(ser=siger2.verfer.qb64b, code=DigDex.Blake2b_256)

        sigers = [siger0, siger1, siger2]
        digers = [diger0, diger1]

        kever.ndigers = digers  # Monkey patch for test
        ondices = kever.exposeds(sigers=sigers)
        assert ondices ==[1]


    with openDB() as db:  # Non-Transferable case Error nxt not empty
        # test  Error case Transferable incept event but with nontrans aid
        # Setup inception key event dict
        # create current key
        sith = 1  # one signer
        # original signing keypair non-transferable
        skp0 = salter.signer(path="A", temp=True, transferable=False)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        assert skp0.verfer.qb64 == 'BAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e'
        keys = [skp0.verfer.qb64]

        # create next key
        # next signing keypair transferable is default
        skp1 = salter.signer(path="N", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest
        nxt = [Diger(ser=skp1.verfer.qb64b).qb64]  # nxt is not empty so will error

        sn = 0  # inception event so 0
        toad = 0  # no witnesses
        nsigs = 1  # one attached signature unspecified index

        # make with defaults with non-transferable prefix
        serder = serdering.SerderKERI(makify=True,
                                      ilk=kering.Ilks.icp,
                                      saids = {'i': coring.PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 1
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)

        serder = serdering.SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EFsuiA86Q5gGuVOO3tou8KSU6LORSExIUxzWNrlnW7WP'
        assert serder.pre == skp0.verfer.qb64
        aid0 = serder.pre

        # assign serialization
        tser0 = serder

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


        # make with defaults with non-transferable prefix
        serder = serdering.SerderKERI(makify=True,
                                      ilk=kering.Ilks.icp,
                                      saids = {'i': coring.PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 0
        sad['n'] = nxt  # empty nxt
        sad['bt'] = "{:x}".format(toad)

        serder = serdering.SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EHXNdcXZzJnRIdaNk30W5h4yD5sZ2Y_n3u_ReE65X9w-'
        assert serder.pre == skp0.verfer.qb64
        aid0 = serder.pre

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

    with openDB() as db:  # Non-Transferable case baks not empty
        # Setup inception key event dict
        # create current key

        # original signing keypair non-transferable
        skp0 = salter.signer(path="B", temp=True, transferable=False)
        assert skp0.code == MtrDex.Ed25519_Seed
        assert skp0.verfer.code == MtrDex.Ed25519N
        assert skp0.verfer.qb64 == 'BEe36N1fb59sXaHIUBOlfSCf4J_H5xajMuMr5u_isjs4'
        sith = 1  # one signer
        keys = [skp0.verfer.qb64]

        # create next key
        # next signing keypair transferable is default
        skp1 = salter.signer(path="O", temp=True, transferable=True)
        assert skp1.code == MtrDex.Ed25519_Seed
        assert skp1.verfer.code == MtrDex.Ed25519
        nxtkeys = [skp1.verfer.qb64]
        # compute nxt digest must be empty
        nxt = ""

        sn = 0  # inception event so 0
        toad = 0  # no witnesses

        # error case if baks not empty
        baks = ["BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"]

        # make with defaults with non-transferable prefix
        serder = serdering.SerderKERI(makify=True,
                                      ilk=kering.Ilks.icp,
                                      saids = {'i': coring.PreDex.Ed25519N},
                                      verify=False)

        sad = serder.sad
        sad['i'] = skp0.verfer.qb64  # non-digestive aid
        sad['s'] = "{:x}".format(sn)  # hex string
        sad['kt'] = "{:x}".format(sith)  # hex string
        sad['k'] = keys
        sad['nt'] = 0
        sad['n'] = nxt
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks

        serder = serdering.SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EKcREpfNupJ8oOqdnqDIyJVr1-GgIMBrVOtBUR9Gm6lO'
        assert serder.pre == skp0.verfer.qb64


        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)


        # retry with toad =1 and baks not empty
        toad = 1
        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)

        serder = serdering.SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EBKhptvqccp0KNBaS45bNPdTE4m19U1IvweHJW2PIEDI'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)


        # retry with valid empty baks
        baks = []
        # use some data, also invalid
        a = [dict(i="EAz8Wqqom6eeIFsng3cGQiUJ1uiNelCrR9VgFlk_8QAM")]
        sn = 0  # inception event so 0
        toad = 0  # no witnesses

        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks
        sad['a'] = a

        serder = serdering.SerderKERI(makify=True, verify=False, sad=sad)
        assert serder.said == 'EEu-cdj_9b_66XRJ5UuhgEvJxAPpn4RjyaHvRgDU3iyA'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder

        # sign serialization
        tsig0 = skp0.sign(tser0.raw, index=0)

        # verify signature
        assert skp0.verfer.verify(tsig0.raw, tser0.raw)

        with pytest.raises(ValidationError):
            kever = Kever(serder=tser0, sigers=[tsig0], db=db)  # valid so no error

        # retry with valid empty baks and empty a

        a = []
        toad = 0  # no witnesses
        baks = []

        sad =serder.sad  # makes copy
        sad['bt'] = "{:x}".format(toad)
        sad['b'] = baks
        sad['a'] = a


        serder = serdering.SerderKERI(makify=True, verify=True, sad=sad)
        assert serder.said == 'EOyd2ZALXBm5k9lEpmvakO6RYPDgX1zWSFNd3MfOXL-e'
        assert serder.pre == skp0.verfer.qb64

        # assign serialization
        tser0 = serder


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
    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = generateSigners(raw=salt, count=8, transferable=True)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    with openDB(name="controller") as conlgr:
        event_digs = []  # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        ndiger1 = coring.Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [ndiger1.qb64]  # transferable so nxt is not empty
        assert nxt1 == ['EIQsSW4KMrLzY1HQI9H_XxY6MyzhaFFXhG6fdBb5Wxta']
        serder0 = incept(keys=keys0, ndigs=nxt1)
        pre = serder0.ked["i"]
        event_digs.append(serder0.said)
        assert serder0.ked["i"] == signers[0].verfer.qb64
        assert serder0.ked["s"] == '0'
        assert serder0.ked["kt"] == '1'
        assert serder0.ked["k"] == keys0
        assert serder0.ked["n"] == nxt1
        assert serder0.said == 'ECLgCt_5bprUe0SF1XCR94Zo5ShSEZO8cLf0dH3pwZxU'

        # sign serialization and verify signature
        sig0 = signers[0].sign(serder0.raw, index=0)
        assert signers[0].verfer.verify(sig0.raw, serder0.raw)
        # create key event verifier state
        kever = Kever(serder=serder0, sigers=[sig0], db=conlgr)
        assert kever.prefixer.qb64 == pre
        assert kever.sn == 0
        assert kever.serder.said == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.ndigs == nxt1
        assert kever.estOnly is False
        assert kever.transferable is True

        pigers = kever.fetchPriorDigers()
        assert pigers is None

        # Event 1 Rotation Transferable
        # compute nxt digest from keys2
        keys2 = [signers[2].verfer.qb64]
        ndiger2 = coring.Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [ndiger2.qb64]  # transferable so nxt is not empty
        assert nxt2 == ['EHuvLs1hmwxo4ImDoCpaAermYVQhiPsPDNaZsz4bcgko']
        serder1 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=nxt2, sn=1)
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
        assert kever.serder.said == serder1.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.ndigs  == nxt2

        pigers = kever.fetchPriorDigers()  # digs from inception before rotation
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt1


        # Event 2 Rotation Transferable
        # compute nxt digest from keys3
        keys3 = [signers[3].verfer.qb64]
        ndiger3 = coring.Diger(ser=signers[3].verfer.qb64b)
        nxt3 = [ndiger3.qb64]  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys2, dig=serder1.said, ndigs=nxt3, sn=2)
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
        assert kever.serder.said == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys2
        assert kever.ndigs  == nxt3

        pigers = kever.fetchPriorDigers()  # digs from rotation before rotation
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2

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
        assert kever.serder.said == serder3.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.ndigs  == nxt3  # no change

        pigers = kever.fetchPriorDigers()
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2  # digs from rot before rot before ixn

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
        assert kever.serder.said == serder4.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
        assert kever.ndigs  == nxt3  # no change

        pigers = kever.fetchPriorDigers()  # digs from rot before rot before ixn ixn
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt2

        # Event 5 Rotation Transferable
        # compute nxt digest from keys4
        keys4 = [signers[4].verfer.qb64]
        ndiger4 = coring.Diger(ser=signers[4].verfer.qb64b)
        nxt4 = [ndiger4.qb64]  # transferable so nxt is not empty
        serder5 = rotate(pre=pre, keys=keys3, dig=serder4.said, ndigs=nxt4, sn=5)
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
        assert kever.serder.said == serder5.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys3
        assert kever.ndigs  == nxt4

        pigers = kever.fetchPriorDigers()  # digs from rot before ixn ixn before rot
        assert pigers is not None
        assert [diger.qb64 for diger in pigers] == nxt3

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
        assert kever.serder.said == serder6.said
        assert kever.ilk == Ilks.ixn
        assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
        assert kever.ndigs  == nxt4  # no change

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
        assert kever.serder.said == serder7.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys4
        assert kever.ndigs  == []
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
        nxt5 = [ndiger4.qb64]  # transferable so nxt is not empty
        serder8 = rotate(pre=pre, keys=keys5, dig=serder7.said, ndigs=nxt5, sn=8)
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

    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = generateSigners(raw=salt, count=8, transferable=True)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    # New Sequence establishment only
    with openDB(name="controller") as conlgr:
        event_digs = []  # list of event digs in sequence

        # Event 0  Inception Transferable (nxt digest not empty)
        keys0 = [signers[0].verfer.qb64]
        # compute nxt digest from keys1
        keys1 = [signers[1].verfer.qb64]
        ndiger1 = coring.Diger(ser=signers[1].verfer.qb64b)
        nxt1 = [ndiger1.qb64]  # transferable so nxt is not empty
        cnfg = [TraitDex.EstOnly]  # EstOnly
        serder0 = incept(keys=keys0, ndigs=nxt1, cnfg=cnfg)
        event_digs.append(serder0.said)
        pre = serder0.ked["i"]
        assert serder0.ked["i"] == signers[0].verfer.qb64
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
        assert kever.serder.said == serder0.said
        assert kever.ilk == Ilks.icp
        assert kever.tholder.thold == 1
        assert [verfer.qb64 for verfer in kever.verfers] == keys0
        assert kever.ndigs  == nxt1
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
        ndiger2 = coring.Diger(ser=signers[2].verfer.qb64b)
        nxt2 = [ndiger2.qb64]  # transferable so nxt is not empty
        serder2 = rotate(pre=pre, keys=keys1, dig=serder0.said, ndigs=nxt2, sn=1)
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
        assert kever.serder.said == serder2.said
        assert kever.ilk == Ilks.rot
        assert [verfer.qb64 for verfer in kever.verfers] == keys1
        assert kever.ndigs  == nxt2

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

    """ Done Test """


def test_multisig_digprefix():
    """
    Test multisig with self-addressing (digest) pre
    """

    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = generateSigners(raw=salt, count=8, transferable=True)

    pubkeys = [signer.verfer.qb64 for signer in signers]
    assert pubkeys == ['DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q',
                    'DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS',
                    'DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f',
                    'DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE',
                    'DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV',
                    'DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED',
                    'DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-',
                    'DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY']

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        #  2 0f 3 multisig

        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        nxtkeys = [signers[3].verfer.qb64b, signers[4].verfer.qb64b, signers[5].verfer.qb64b]
        sith = "2"
        code = MtrDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        isith=sith,
                        ndigs=[coring.Diger(ser=sig).qb64 for sig in nxtkeys])

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

        assert msgs == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1'
                    b'FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88Ukb'
                    b'nOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2'
                    b'TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE'
                    b'9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk'
                    b'5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-'
                    b'Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV'
                    b'3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRG'
                    b'z2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW'
                    b'8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5'
                    b'm7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1D'
                    b'glezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC')

        # Event 1 Rotation Transferable
        keys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = "2"
        nxtkeys = [signers[5].verfer.qb64b, signers[6].verfer.qb64b, signers[7].verfer.qb64b]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        isith=sith,
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=sig).qb64 for sig in nxtkeys],
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
                          dig=kever.serder.said,
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
                          dig=kever.serder.said,
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
                        isith="2",
                        dig=kever.serder.said,
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
    #  create signers
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    signers = generateSigners(raw=salt, count=8, transferable=True)

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        event_digs = []  # list of event digs in sequence to verify against database

        # create event stream
        kes = bytearray()
        sn = esn = 0  # sn and last establishment sn = esn

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[esn].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64])

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
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
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
                          dig=kever.serder.said,
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
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
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
                          dig=kever.serder.said,
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
                          dig=kever.serder.said,
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
                          dig=kever.serder.said,
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
                        ndigs=[coring.Diger(ser=signers[esn + 1].verfer.qb64b).qb64],
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
                          dig=kever.serder.said,
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

        db_est_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelLastIter(pre)]
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
        y_db_est_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelLastIter(pre)]
        assert db_est_digs == y_db_est_digs

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_receipt():
    """
    Test event receipt message and attached couplets
    """

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigner = salter.signers(count=1, path='val', transferable=False, temp=True)[0]
    assert valSigner.verfer.qb64 != coeSigners[0].verfer.qb64


    # create receipt signer prefixer  default code is non-transferable
    valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
    assert valPrefixer.code == MtrDex.Ed25519N
    valpre = valPrefixer.qb64
    assert valpre == 'BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4p'

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
                        ndigs=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64])

        assert sn == int(serder.ked["s"], 16) == 0
        coepre = serder.ked["i"]
        assert coepre == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

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
                           said=coeKever.serder.said)
        # sign event not receipt
        valCigar = valSigner.sign(ser=serder.raw)  # returns Cigar cause no index
        assert valCigar.qb64 == ('0BADE2aOlwLi6OCF-jzRWSPuaOo916ADjwhA92hBQ1km'
                                 'LSSYdzDiZIpJNFf0uislNR8uhCbB6x2Y1I6rqbNeBXwF')
        recnt = Counter(code=CtrDex.NonTransReceiptCouples, count=1)
        assert recnt.qb64 == '-CAB'

        res.extend(reserder.raw)
        res.extend(recnt.qb64b)
        res.extend(valPrefixer.qb64b)
        res.extend(valCigar.qb64b)
        assert res == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EK5yV6IiXCZ-EXkFrBDhrf0I'
                    b'cXLjkixyMeV2cji1po1O","i":"DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqR'
                    b'wFuyq4i","s":"0"}-CABBF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4'
                    b'p0BADE2aOlwLi6OCF-jzRWSPuaOo916ADjwhA92hBQ1kmLSSYdzDiZIpJNFf0uis'
                    b'lNR8uhCbB6x2Y1I6rqbNeBXwF')


        parsing.Parser().parse(ims=res, kvy=coeKevery)
        # coeKevery.process(ims=res)  #  coe process the receipt from val
        #  check if in receipt database
        result = coeKevery.db.getRcts(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
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

        #  coe process the escrow receipt from val
        parsing.Parser().parse(ims=res, kvy=coeKevery)
        #  check if in escrow database
        result = coeKevery.db.getUres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=2))
        assert bytes(result[0]) == fake.encode("utf-8") + valPrefixer.qb64b + valCigar.qb64b

        # create invalid receipt stale use valid sn so in database but invalid dig
        # so bad receipt
        fake = coring.Diger(qb64="EAdapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI").qb64
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
                                                dig=coeKever.serder.said))
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
                        dig=coeKever.serder.said,
                        ndigs=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
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
                          dig=coeKever.serder.said,
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
                        dig=coeKever.serder.said,
                        ndigs=[coring.Diger(ser=coeSigners[esn + 1].verfer.qb64b).qb64],
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
                          dig=coeKever.serder.said,
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
                          dig=coeKever.serder.said,
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
                          dig=coeKever.serder.said,
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
    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigners = salter.signers(count=8, path='val', transferable=False, temp=True)
    assert valSigners[0].verfer.qb64 != coeSigners[0].verfer.qb64

    with (openDB(name="controller") as coeLogger,
          openDB(name="validator") as valLogger):
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
                           ndigs=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == 'EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL'

        coe_event_digs.append(coeSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = coeSigners[cesn].sign(coeSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        cmsg = bytearray(coeSerder.raw)
        cmsg.extend(counter.qb64b)
        cmsg.extend(siger.qb64b)
        assert cmsg == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EJe_sKQb1otKrz6COIL8VFvB'
                    b'v3DEFvtKaVFGn1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"0","kt":"1","k":["DC8kCMHKrYZewclvG9vj1R1nSspiRwPi'
                    b'-ByqRwFuyq4i"],"nt":"1","n":["EBPlMwLJ5rSKWCaZq4bczEHLQvYX3P7cIL'
                    b'mBzy0Pp4O4"],"bt":"0","b":[],"c":[],"a":[]}-AABAAAWQ0yBzzzVsOJPD'
                    b'kKzbDPzfYXEF5xmQgJSEKXcDO3XMVSL2DmDRYZV73huYX5BAsfzIhBXggKKAcGcE'
                    b'fT38R8L')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           ndigs=[coring.Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
                           code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == 'EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz'

        val_event_digs.append(valSerder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = valSigners[vesn].sign(valSerder.raw, index=0)  # return Siger if index

        #  create serialized message
        vmsg = bytearray(valSerder.raw)
        vmsg.extend(counter.qb64b)
        vmsg.extend(siger.qb64b)
        assert vmsg == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EAzjKx3hSVJArKpIOVt2KfTR'
                    b'jq8st22hL25Ho9vnNodz","i":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho'
                    b'9vnNodz","s":"0","kt":"1","k":["BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx'
                    b'25Drp5Jj2j4p"],"nt":"1","n":["ECoxJfQH0GUrlDKoC3U-neGY1CJib7VyZG'
                    b'h6QhdJtWoT"],"bt":"0","b":[],"c":[],"a":[]}-AABAACOKLyxKvQyy_Tvk'
                    b'fQffGnk-p0cc1H11dpxV8gbxvYGm5kfvqPerlorqD21hGRAqvyFQJ967Y8lFl_dx'
                    b'Taal2cA')

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
                           said=coeK.serder.said)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.saidb == b'EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL'
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFG'
                        b'n1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"0","kt":"1'
                        b'","k":["DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i"],"nt":"1","n":["EBPlMw'
                        b'LJ5rSKWCaZq4bczEHLQvYX3P7cILmBzy0Pp4O4"],"bt":"0","b":[],"c":[],"a":[]}')
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == ('AAD-iI61odpZQjzm0fN9ZATjHx-KjQ9W3-CIlvhowwUaPC5K'
                              'nQAIGYFuWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF')
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EJe_sKQb1otKrz6COIL8VFvB'
                    b'v3DEFvtKaVFGn1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"0"}-FABEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNod'
                    b'z0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9v'
                    b'nNodz-AABAAD-iI61odpZQjzm0fN9ZATjHx-KjQ9W3-CIlvhowwUaPC5KnQAIGYF'
                    b'uWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF')

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
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vn'
                                    b'Nodz0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3h'
                                    b'SVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodzAAD'
                                    b'-iI61odpZQjzm0fN9ZATjHx-KjQ9W3-CIlvho'
                                    b'wwUaPC5KnQAIGYFuWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF')

        # create receipt to escrow use invalid dig and sn so not in coe's db
        fake = reserder.said  # some other dig
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake)
        # sign event not receipt
        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index

        # create message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000091_","t":"rct","d":"EJe_sKQb1otKrz6COIL8VFvB'
                            b'v3DEFvtKaVFGn1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                            b'1vm0IlL","s":"a"}-FABEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNod'
                            b'z0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9v'
                            b'nNodz-AABAAD-iI61odpZQjzm0fN9ZATjHx-KjQ9W3-CIlvhowwUaPC5KnQAIGYF'
                            b'uWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF')

        #bytearray(b'{"v":"KERI10JSON000067_","t":"rct","d":null,"i":"EJe_sKQb1otKrz6'
                                 #b'COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"a"}-FABEAzjKx3hSVJArKpIOVt2K'
                                 #b'fTRjq8st22hL25Ho9vnNodz0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIO'
                                 #b'Vt2KfTRjq8st22hL25Ho9vnNodz-AABAAD-iI61odpZQjzm0fN9ZATjHx-KjQ9W3'
                                 #b'-CIlvhowwUaPC5KnQAIGYFuWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF')
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
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
                           said=valK.serder.said)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.saidb == b'EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz'
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25H'
                        b'o9vnNodz","i":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz","s":"0","kt":"1'
                        b'","k":["BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4p"],"nt":"1","n":["ECoxJf'
                        b'QH0GUrlDKoC3U-neGY1CJib7VyZGh6QhdJtWoT"],"bt":"0","b":[],"c":[],"a":[]}')


        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        assert siger.qb64 == ('AACRmy9_dCMi45BSI89fGeM_ktOTWQctSGrVsZtQMm1RtJZY'
                              '31xaNoEN-GJ0c5UrNbNuSyT-wkeit0AeYsPWLEYG')
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EAzjKx3hSVJArKpIOVt2KfTR'
                    b'jq8st22hL25Ho9vnNodz","i":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho'
                    b'9vnNodz","s":"0"}-FABEJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0Il'
                    b'L0AAAAAAAAAAAAAAAAAAAAAAAEJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1v'
                    b'm0IlL-AABAACRmy9_dCMi45BSI89fGeM_ktOTWQctSGrVsZtQMm1RtJZY31xaNoE'
                    b'N-GJ0c5UrNbNuSyT-wkeit0AeYsPWLEYG')

        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.said))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.saidb +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0'
                                    b'IlL0AAAAAAAAAAAAAAAAAAAAAAAEJe_sKQb'
                                    b'1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlLAACRm'
                                    b'y9_dCMi45BSI89fGeM_ktOTWQctSGrVsZtQ'
                                    b'Mm1RtJZY31xaNoEN-GJ0c5UrNbNuSyT-wkeit0AeYsPWLEYG')

        # Coe Event 1 RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.said,
                           ndigs=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
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
        assert cmsg == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EKlC013XEpwYuCQ84aVnEAqz'
                    b'NurjAJDN6ayK-9NxggAr","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"1","p":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0I'
                    b'lL","kt":"1","k":["DIR7b_v2seXd-1PMMQn2j4atO2B1YiRQwKUQNgKBLUSV"'
                    b'],"nt":"1","n":["ED9O5NCpb7MABWrOY82keABUCkUrljKBds1mHStvG3RR"],'
                    b'"bt":"0","br":[],"ba":[],"a":[]}-AABAAC06yqOCGcpJJ5RiqzCpvMreYag'
                    b'oZbZoZGlgzbAYh01fjdhacBg2S5Bya48tyo9uvTVz-OQNHP52_ZgEYjbQn4C')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.saidb == b'EKlC013XEpwYuCQ84aVnEAqzNurjAJDN6ayK-9NxggAr'
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EKlC013XEpwYuCQ84aVnEAqzNurjAJDN6ayK'
                             b'-9NxggAr","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"1","p":"EJ'
                             b'e_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","kt":"1","k":["DIR7b_v2seXd-1PMM'
                             b'Qn2j4atO2B1YiRQwKUQNgKBLUSV"],"nt":"1","n":["ED9O5NCpb7MABWrOY82keABUCkUrljK'
                             b'Bds1mHStvG3RR"],"bt":"0","br":[],"ba":[],"a":[]}')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        assert siger.qb64 == ('AAANSIICz13kvy4hk2bvTCr2b2uePn4uTf4_nwdolkI77Voq'
                              'sm5QFtF6z6sjJK7_oTLY36k2VigSExx0UgGQV7YL')
        # val create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EKlC013XEpwYuCQ84aVnEAqz'
                    b'NurjAJDN6ayK-9NxggAr","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"1"}-FABEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNod'
                    b'z0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9v'
                    b'nNodz-AABAAANSIICz13kvy4hk2bvTCr2b2uePn4uTf4_nwdolkI77Voqsm5QFtF'
                    b'6z6sjJK7_oTLY36k2VigSExx0UgGQV7YL')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnN'
                                    b'odz0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3h'
                                    b'SVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodzAAANS'
                                    b'IICz13kvy4hk2bvTCr2b2uePn4uTf4_nwdo'
                                    b'lkI77Voqsm5QFtF6z6sjJK7_oTLY36k2VigSExx0UgGQV7YL')


        # Next Event 2 Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.said,
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
        assert cmsg == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EG3O9AV3lhySOadwTn810vHO'
                    b'ZDc6B8TZY_u_4_iy_ono","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"2","p":"EKlC013XEpwYuCQ84aVnEAqzNurjAJDN6ayK-9Nxgg'
                    b'Ar","a":[]}-AABAABmeJqf2j87kAvvqqIxmLI9IU3CGuigruWent6i4iml9n61d'
                    b'U4ah0NHsJgl-7KtapI72aMxDY6BZ9EvU2c8YHQP')
        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.saidb == b'EG3O9AV3lhySOadwTn810vHOZDc6B8TZY_u_4_iy_ono'
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EG3O9AV3lhySOadwTn810vHOZDc6B8TZY_u_'
                             b'4_iy_ono","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"2","p":"EK'
                             b'lC013XEpwYuCQ84aVnEAqzNurjAJDN6ayK-9NxggAr","a":[]}')
        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        assert siger.qb64 == ('AABP_iABSPKxN2_pcedeIu1qb9rIj5nLaGaiPOW2BFSUQQ7C'
                              'SL9IW1s9_wVAxv2idySMjiGuLOZk8qI2thqMZ3ED')
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EG3O9AV3lhySOadwTn810vHO'
                    b'ZDc6B8TZY_u_4_iy_ono","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn'
                    b'1vm0IlL","s":"2"}-FABEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNod'
                    b'z0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9v'
                    b'nNodz-AABAABP_iABSPKxN2_pcedeIu1qb9rIj5nLaGaiPOW2BFSUQQ7CSL9IW1s'
                    b'9_wVAxv2idySMjiGuLOZk8qI2thqMZ3ED')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt quadruple from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNo'
                                    b'dz0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3h'
                                    b'SVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodzAABP_'
                                    b'iABSPKxN2_pcedeIu1qb9rIj5nLaGaiPOW2'
                                    b'BFSUQQ7CSL9IW1s9_wVAxv2idySMjiGuLOZk8qI2thqMZ3ED')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL',
                                             'EKlC013XEpwYuCQ84aVnEAqzNurjAJDN6ayK-9NxggAr',
                                             'EG3O9AV3lhySOadwTn810vHOZDc6B8TZY_u_4_iy_ono']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz']

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

    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    coeSigners = salter.signers(count=8, path='coe', temp=True)
    assert coeSigners[0].verfer.qb64 == 'DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i'

    #  create val signer
    valSigners = salter.signers(count=8, path='val', transferable=False, temp=True)
    assert valSigners[0].verfer.qb64 != coeSigners[0].verfer.qb64

    with (openDB(name="controller") as coeLogger,
          openDB(name="validator") as valLogger):
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
                           ndigs=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
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
        assert cmsg == (b'\xadavqKERI10CBOR0000f9_atcicpadx,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO'
                    b'-luqqsp5mK-aix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-asa0b'
                    b'kta1ak\x81x,DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4ibnta1an'
                    b'\x81x,EBPlMwLJ5rSKWCaZq4bczEHLQvYX3P7cILmBzy0Pp4O4bbta0ab\x80a'
                    b'c\x80aa\x80-AABAABufNTcYP8KtnykukjpAa3mwg8ozQlD8tTwI6GwQAceuDbr2kx'
                    b'Jv-6YGLedGHvi0FcT6twCzM8g2-TA4JRqcbwL')

        # create own Coe Kever in  Coe's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Val Event 0  Inception Transferable (nxt digest not empty)
        valSerder = incept(keys=[valSigners[vesn].verfer.qb64],
                           ndigs=[coring.Diger(ser=valSigners[vesn + 1].verfer.qb64b).qb64],
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
        assert vmsg == (b'\x8d\xa1v\xb1KERI10MGPK0000f9_\xa1t\xa3icp\xa1d\xd9,EFBYcX4vOeL7Y'
                    b'5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZX\xa1i\xd9,EFBYcX4vOeL7Y5pz0iQ5yCfxd'
                    b'19R1dgA_r9i1nVdqMZX\xa1s\xa10\xa2kt\xa11\xa1k\x91\xd9,BF5b1hKlY38'
                    b'RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4p\xa2nt\xa11\xa1n\x91\xd9,ECoxJfQH0'
                    b'GUrlDKoC3U-neGY1CJib7VyZGh6QhdJtWoT\xa2bt\xa10\xa1b\x90\xa1'
                    b'c\x90\xa1a\x90-AABAAAex67GqWdlDRQN7UdUfe4_20ynqa8WIL16OBNIECJEpKN'
                    b'E3RRzeWWLPNxwxodjK0dJk4u1zb2ZiIU_ci37BYUN')

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
                           said=coeK.serder.said,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.saidb
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'\xadavqKERI10CBOR0000f9_atcicpadx,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5'
                             b'mK-aix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-asa0bkta1ak\x81x,DC8kCMH'
                             b'KrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4ibnta1an\x81x,EBPlMwLJ5rSKWCaZq4bczEHLQ'
                             b'vYX3P7cILmBzy0Pp4O4bbta0ab\x80ac\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeIcpRaw, index=0)  # return Siger if index
        # process own Val receipt in Val's Kevery so have copy in own log
        rmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert rmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,EDTOWE_oHAO7j'
                    b'6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-\xa1i\xd9,EDTOWE_oHAO7j6rhUMGfQ_kX8'
                    b'GJbpaAhO-luqqsp5mK-\xa1s\xa10-FABEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_'
                    b'r9i1nVdqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1'
                    b'dgA_r9i1nVdqMZX-AABAADk55HF23ePK4g9Mmxxi4o7Pfn3VsPrtpWR3l5wGNQT3'
                    b'cJ7LrFYTE-Xjt72WVu2cbKjVLf9GAIGixpzh11tlCUD')

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
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdq'
                                    b'MZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4v'
                                    b'OeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZXAADk5'
                                    b'5HF23ePK4g9Mmxxi4o7Pfn3VsPrtpWR3l5w'
                                    b'GNQT3cJ7LrFYTE-Xjt72WVu2cbKjVLf9GAIGixpzh11tlCUD')

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
        assert vmsg ==(b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,EDTOWE_oHAO7j'
                    b'6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-\xa1i\xd9,EDTOWE_oHAO7j6rhUMGfQ_kX8'
                    b'GJbpaAhO-luqqsp5mK-\xa1s\xa1a-FABEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_'
                    b'r9i1nVdqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1'
                    b'dgA_r9i1nVdqMZX-AABAADk55HF23ePK4g9Mmxxi4o7Pfn3VsPrtpWR3l5wGNQT3'
                    b'cJ7LrFYTE-Xjt72WVu2cbKjVLf9GAIGixpzh11tlCUD')

        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process the escrow receipt from val
        #  check if in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
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
                           said=valK.serder.said,
                           kind=Serials.cbor)
        # sign vals's event not receipt
        # look up event to sign from coe's kever for val
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.saidb
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'\x8d\xa1v\xb1KERI10MGPK0000f9_\xa1t\xa3icp\xa1d\xd9,EFBYcX4vOeL7Y5pz0iQ5y'
                            b'Cfxd19R1dgA_r9i1nVdqMZX\xa1i\xd9,EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdq'
                            b'MZX\xa1s\xa10\xa2kt\xa11\xa1k\x91\xd9,BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25D'
                            b'rp5Jj2j4p\xa2nt\xa11\xa1n\x91\xd9,ECoxJfQH0GUrlDKoC3U-neGY1CJib7VyZGh6QhdJt'
                            b'WoT\xa2bt\xa10\xa1b\x90\xa1c\x90\xa1a\x90')

        siger = coeSigners[vesn].sign(ser=valIcpRaw, index=0)  # return Siger if index
        # create receipt message
        cmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert cmsg == (b'\xa5avqKERI10CBOR00007f_atcrctadx,EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_'
                        b'r9i1nVdqMZXaix,EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZXasa0-'
                        b'FABEDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-0AAAAAAAAAAAAAAAA'
                        b'AAAAAAAEDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK--AABAABZtKLct'
                        b'VcqHwMjVhYwdwQphN0HqilToRc-fE1YDDWlxXWa7Q-GAzpFBLYYdfCLuruDzDC0t'
                        b'EG3wSGDDj-GKfgB')


        # coe process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate send to val of coe's receipt of val's inception message
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  #  coe process val's incept and receipt

        #  check if receipt from coe in val's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.said))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.saidb +
                                    siger.qb64b)
        assert bytes(result[0]) == (b'EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5'
                                    b'mK-0AAAAAAAAAAAAAAAAAAAAAAAEDTOWE_o'
                                    b'HAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-AABZt'
                                    b'KLctVcqHwMjVhYwdwQphN0HqilToRc-fE1Y'
                                    b'DDWlxXWa7Q-GAzpFBLYYdfCLuruDzDC0tEG3wSGDDj-GKfgB')

        # Coe RotationTransferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeSigners[cesn].verfer.qb64],
                           dig=coeKever.serder.said,
                           ndigs=[coring.Diger(ser=coeSigners[cesn + 1].verfer.qb64b).qb64],
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
        assert cmsg == (b'\xaeavqKERI10CBOR00012b_atcrotadx,EN4m9YLkeBgWVIvwmj45_qdnBBBY61NVZ'
                        b'bwOe__MAsYMaix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-asa1a'
                        b'px,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-bkta1ak\x81x,DIR7b_v'
                        b'2seXd-1PMMQn2j4atO2B1YiRQwKUQNgKBLUSVbnta1an\x81x,ED9O5NCpb7MABWrOY'
                        b'82keABUCkUrljKBds1mHStvG3RRbbta0bbr\x80bba\x80aa\x80-AABAADXi2zNQ'
                        b'KISm5WPAA-FrfnFwu5xEN8gTseUnurqPV8AKpOkbzPxGMU5tEcXcLwv8wp57QkYw'
                        b'WkkWaz67kBxBaIN')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's rotation
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.saidb
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'\xaeavqKERI10CBOR00012b_atcrotadx,EN4m9YLkeBgWVIvwmj45_qdnBBBY61NVZbwOe__MA'
                             b'sYMaix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-asa1apx,EDTOWE_oHAO7j6rhU'
                             b'MGfQ_kX8GJbpaAhO-luqqsp5mK-bkta1ak\x81x,DIR7b_v2seXd-1PMMQn2j4atO2B1YiRQwKU'
                             b'QNgKBLUSVbnta1an\x81x,ED9O5NCpb7MABWrOY82keABUCkUrljKBds1mHStvG3RRbbta0'
                             b'bbr\x80bba\x80aa\x80')

        siger = valSigners[vesn].sign(ser=coeRotRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,EN4m9YLkeBgWV'
                    b'Ivwmj45_qdnBBBY61NVZbwOe__MAsYM\xa1i\xd9,EDTOWE_oHAO7j6rhUMGfQ_kX8'
                    b'GJbpaAhO-luqqsp5mK-\xa1s\xa11-FABEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_'
                    b'r9i1nVdqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1'
                    b'dgA_r9i1nVdqMZX-AABAABgKgla6y-DWqKIuSzV5iqPacG_ckEQOO7w2osmn1YYx'
                    b'TIq0aVELDNwXt1mnqWJw73-UVekqTtrU1jWgekCx0cF')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)

        assert bytes(result[0])  == (b'EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nV'
                                     b'dqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4v'
                                     b'OeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZXAABg'
                                     b'Kgla6y-DWqKIuSzV5iqPacG_ckEQOO7w2osm'
                                     b'n1YYxTIq0aVELDNwXt1mnqWJw73-UVekqTtrU1jWgekCx0cF')


        # Next Event Coe Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.said,
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
        assert cmsg == (b'\xa7avqKERI10CBOR0000b2_atcixnadx,EEobyRfni6TAnEROE5yL9sC6lhKEbpbmX'
                        b'yeqSZ1QjAKMaix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-asa2a'
                        b'px,EN4m9YLkeBgWVIvwmj45_qdnBBBY61NVZbwOe__MAsYMaa\x80-AABAABAUXnpXj'
                        b'nd55zb2DDInf7mgqBo1QtYjqSbmCw6-5QPlG9iK8IH6B2ijrpG2SkgH9Lk0oYQbY'
                        b'tWd4gRXNT5i54O')

        # update coe's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify coe's copy of coe's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from coe to val
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify val's copy of coe's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of coe's interaction
        # create seal of val's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said,
                           kind=Serials.mgpk)
        # sign coe's event not receipt
        # look up event to sign from val's kever for coe
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.saidb
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'\xa7avqKERI10CBOR0000b2_atcixnadx,EEobyRfni6TAn'
                              b'EROE5yL9sC6lhKEbpbmXyeqSZ1Qj'
                              b'AKMaix,EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp'
                              b'5mK-asa2apx,EN4m9YLkeBgWVIvwm'
                              b'j45_qdnBBBY61NVZbwOe__MAsYMaa\x80')

        siger = valSigners[vesn].sign(ser=coeIxnRaw, index=0)  # return Siger if index
        # create receipt message
        vmsg = messagize(serder=reserder, sigers=[siger], seal=seal)
        assert vmsg == (b'\x85\xa1v\xb1KERI10MGPK00007f_\xa1t\xa3rct\xa1d\xd9,EEobyRfni6TAn'
                    b'EROE5yL9sC6lhKEbpbmXyeqSZ1QjAKM\xa1i\xd9,EDTOWE_oHAO7j6rhUMGfQ_kX8'
                    b'GJbpaAhO-luqqsp5mK-\xa1s\xa12-FABEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_'
                    b'r9i1nVdqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4vOeL7Y5pz0iQ5yCfxd19R1'
                    b'dgA_r9i1nVdqMZX-AABAADxJgKTEqP-yWJrKuEB9X8ZBkozW_t0v1alMYouOPQn6'
                    b'Fp2IT_ZSwWmk26Bxj5PPB4qiJmJ7LwbfQvJZLxgMUQC')

        # val process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to coe of val's receipt of coe's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  #  coe process val's incept and receipt

        #  check if receipt from val in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    siger.qb64b)

        assert bytes(result[0]) == (b'EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nV'
                                     b'dqMZX0AAAAAAAAAAAAAAAAAAAAAAAEFBYcX4v'
                                     b'OeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZXAADx'
                                     b'JgKTEqP-yWJrKuEB9X8ZBkozW_t0v1alMYou'
                                     b'OPQn6Fp2IT_ZSwWmk26Bxj5PPB4qiJmJ7LwbfQvJZLxgMUQC')

        #  verify final coe event state
        assert coeKever.verfers[0].qb64 == coeSigners[cesn].verfer.qb64
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['EDTOWE_oHAO7j6rhUMGfQ_kX8GJbpaAhO-luqqsp5mK-',
 'EN4m9YLkeBgWVIvwmj45_qdnBBBY61NVZbwOe__MAsYM',
 'EEobyRfni6TAnEROE5yL9sC6lhKEbpbmXyeqSZ1QjAKM']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final val event state
        assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['EFBYcX4vOeL7Y5pz0iQ5yCfxd19R1dgA_r9i1nVdqMZX']

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
    nxt = []  # non-transferable so nxt is empty
    toad = 0  # no witnesses
    nsigs = 1  # one attached signature unspecified index

    #["v", "t", "d", "i", "s",  "kt", "k", "nt", "n","bt", "b", "c", "a"]
    ked0 = dict(v=versify(kind=Serials.json, size=0),
                t=Ilks.icp,
                d="",
                i=aid0.qb64,  # qual base 64 prefix
                s="{:x}".format(sn),  # hex string no leading zeros lowercase
                kt="{:x}".format(sith),  # hex string no leading zeros lowercase
                k=[aid0.qb64],  # list of signing keys each qual Base64
                nt=0,
                n=nxt,  # hash qual Base64
                bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                b=[],  # list of qual Base64 may be empty
                c=[],  # list of config ordered mappings may be empty
                a=[],
                )
    _, ked0 = coring.Saider.saidify(sad=ked0)

    # verify derivation of aid0 from ked0
    assert aid0.verify(ked=ked0)

    # Serialize ked0
    tser0 = serdering.SerderKERI(sad=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create attached sig counter
    cnt0 = Counter(CtrDex.ControllerIdxSigs)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = serdering.SerderKERI(raw=msgb0)
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
        rsig = Siger(qb64=msgb0)
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
    nxt = [Diger(ser=skp1.verfer.qb64b).qb64]  # transferable so next is not empty

    sn = 0  # inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  # one attached signature unspecified index


    ked0 = dict(v=versify(kind=Serials.json, size=0),  # version string
               t=Ilks.icp,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt="{:x}".format(sith),  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=1,
               n=nxt,  # hash qual Base64
               bt=0,  # hex string no leading zeros lowercase
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )


    # Use non digestive AID
    aid0 = Prefixer(ked=ked0, code=MtrDex.Ed25519)
    assert aid0.code == MtrDex.Ed25519
    assert aid0.qb64 == skp0.verfer.qb64
    # update ked with pre
    ked0["i"] = aid0.qb64
    _, ked0 = coring.Saider.saidify(sad=ked0)

    # Serialize ked0
    tser0 = serdering.SerderKERI(sad=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create attached sig counter
    cnt0 = Counter(CtrDex.ControllerIdxSigs)

    # create packet
    msgb0 = bytearray(tser0.raw + cnt0.qb64b + tsig0.qb64b)

    # deserialize packet
    rser0 = serdering.SerderKERI(raw=msgb0)
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
        rsig = Siger(qb64=msgb0)
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
    digers=rser0.ndigers
    #assert rnxt1.includes(keys=nxtkeys)
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
    assert aidmat.qb64 == 'DK-WsHD7MKfQpBjJ3B2GwjqY9z90G94uzMs7irCiT-dL'
    # 'Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'

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

    # create nxt digest
    nxtsith = "{:x}".format(1)  # lowecase hex no leading zeros
    assert nxtsith == "1"

    # create qualified nxt key in basic format
    nxtkeymat = Matter(raw=verkey, code=MtrDex.Ed25519)
    assert nxtkeymat.qb64 == 'DPVET0I6PM0WGJuDTKUMmFiQQxqzME-lD-M5bKbfWBg1'
    #'D9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'
    nxtdig = blake3.blake3(verkey).digest()
    assert nxtdig == (b"7\x16$m\xb0oA\x171\x94\xf3\xb3\x80\xe03\x00\x167\xf4'\xd8N\xa82D\xed_`"
                      b'\xbc\x13\xfe\x11')
    nxtdigmat = Matter(raw=nxtdig, code=MtrDex.Blake3_256)
    assert nxtdigmat.qb64 == 'EDcWJG2wb0EXMZTzs4DgMwAWN_Qn2E6oMkTtX2C8E_4R'
    nxts = [nxtdigmat.qb64]

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
                nt=nxtsith,
                n=nxts,
                bt="{:x}".format(toad),  # hex string no leading zeros lowercase
                b=[],  # list of qual Base64 may be empty
                c=[],  # list of config traits may be empty
                a=[],  # list of seals ordered mappings may be empty
                )
    _, ked0 = coring.Saider.saidify(sad=ked0)

    txsrdr = serdering.SerderKERI(sad=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EKYHED-wvkYDZv4tNUF9qiC1kgnnGLS9YUU8'
                        b'PCWig_n4","i":"DK-WsHD7MKfQpBjJ3B2GwjqY9z90G94uzMs7irCiT-dL","s":"0","kt":"1'
                        b'","k":["DK-WsHD7MKfQpBjJ3B2GwjqY9z90G94uzMs7irCiT-dL"],"nt":"1","n":["EDcWJG'
                        b'2wb0EXMZTzs4DgMwAWN_Qn2E6oMkTtX2C8E_4R"],"bt":"0","b":[],"c":[],"a":[]}')

    assert txsrdr.size == 299

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = coring.Saider(sad=ked0, code=MtrDex.Blake3_256)
    assert txdigmat.qb64 == 'EKYHED-wvkYDZv4tNUF9qiC1kgnnGLS9YUU8PCWig_n4'

    assert txsrdr.said == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  # sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = Siger(raw=sig0raw, code=IdrDex.Ed25519_Sig, index=index)
    assert txsigmat.qb64 == 'AAAbwxAS2DuLS4HLaiv9hHd6YEolpPjMKYRdXY3VwmWKh5gW5J2QBsZ1cMmdrlyIlgvqTQEViicNv9mHHOvj9ZAB'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 387  # 299 + 88

    #  Recieve side
    rxsrdr = serdering.SerderKERI(raw=msgb)
    assert rxsrdr.size == txsrdr.size
    assert rxsrdr.ked == ked0

    rxsigqb64 = msgb[rxsrdr.size:].decode("utf-8")
    assert len(rxsigqb64) == len(txsigmat.qb64)
    rxsigmat = Siger(qb64=rxsigqb64)
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

    with habbing.openHby(name="nat", base="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as natHby:
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
        assert natHab.kever.serder.said == 'EA3QbTpV15MvLSXHSedm4lRYdQhmYXqXafsD4i75B_yo'
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.saidb
        serder = serdering.SerderKERI(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre, ldig))))
        assert serder.said == natHab.kever.serder.said
        nstate = natHab.kever.state()

        state =natHab.db.states.get(keys=natHab.pre)  # key state record
        assert state._asjson() == (b'{"vn":[1,0],"i":"EBm9JqQKS4a3EYv5I7BmAPiwhdSQvFAOpqe0dgk3kgH_","s":"6","p":"'
                            b'ED_HpKSCQJoeGxHYjPRD2tgUhbIrLf6fH3e3xJFSq2dL","d":"EA3QbTpV15MvLSXHSedm4lRYd'
                            b'QhmYXqXafsD4i75B_yo","f":"6","dt":"2021-01-01T00:00:00.000000+00:00","et":"i'
                            b'xn","kt":"2","k":["DCORPGaoMtI_RyJFUTIzk0xdza_z6sBQ2e2wzYtEAs3s","DNjSHBbYJa'
                            b'aUKJuPd34n7SRYiZHirwvW-QiHRtfRvBh4","DN-hL9CKn6WdsINEG207T4pSdjaMIxU9SKhfeeH'
                            b'CwfvT"],"nt":"2","n":["EGZ9WHJPgrvDpe08gJpEZ8Gz-rcy72ZG7Tey0PS2CrXY","EO_z0O'
                            b'FTUZ1pmfxj-VnQJcsYFdIVq2tWkN9nUWRxQab_","EMeWMAZpVy7IX6yl4F2t-WoUCaRFZ-0g5dx'
                            b'_LLoEywhx"],"bt":"0","b":[],"c":[],"ee":{"s":"2","d":"EJ7s1vk30hWK_l-exQtzj4'
                            b'P5u_wIzki1drVR4FAKDbEW","br":[],"ba":[]},"di":""}')
        assert state.f == '6'
        assert state == nstate

        # now create new Kever with state
        kever = eventing.Kever(state=state, db=natHby.db)
        assert kever.sn == 6
        assert kever.fn == 6
        assert kever.serder.ked == natHab.kever.serder.ked
        assert kever.serder.said == natHab.kever.serder.said

        kstate = kever.state()
        assert kstate == state
        assert state._asjson() == (b'{"vn":[1,0],"i":"EBm9JqQKS4a3EYv5I7BmAPiwhdSQvFAOpqe0dgk3kgH_","s":"6","p":"'
                            b'ED_HpKSCQJoeGxHYjPRD2tgUhbIrLf6fH3e3xJFSq2dL","d":"EA3QbTpV15MvLSXHSedm4lRYd'
                            b'QhmYXqXafsD4i75B_yo","f":"6","dt":"2021-01-01T00:00:00.000000+00:00","et":"i'
                            b'xn","kt":"2","k":["DCORPGaoMtI_RyJFUTIzk0xdza_z6sBQ2e2wzYtEAs3s","DNjSHBbYJa'
                            b'aUKJuPd34n7SRYiZHirwvW-QiHRtfRvBh4","DN-hL9CKn6WdsINEG207T4pSdjaMIxU9SKhfeeH'
                            b'CwfvT"],"nt":"2","n":["EGZ9WHJPgrvDpe08gJpEZ8Gz-rcy72ZG7Tey0PS2CrXY","EO_z0O'
                            b'FTUZ1pmfxj-VnQJcsYFdIVq2tWkN9nUWRxQab_","EMeWMAZpVy7IX6yl4F2t-WoUCaRFZ-0g5dx'
                            b'_LLoEywhx"],"bt":"0","b":[],"c":[],"ee":{"s":"2","d":"EJ7s1vk30hWK_l-exQtzj4'
                            b'P5u_wIzki1drVR4FAKDbEW","br":[],"ba":[]},"di":""}')

    assert not os.path.exists(natHby.ks.path)
    assert not os.path.exists(natHby.db.path)

    """End Test"""


def test_load_event(mockHelpingNowUTC):
    with habbing.openHby(name="tor", base="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as torHby, \
         habbing.openHby(name="wil", base="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as wilHby, \
         habbing.openHby(name="wan", base="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as wanHby, \
         habbing.openHby(name="tee", base="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as teeHby:

        wanKvy = Kevery(db=wanHby.db, lax=False, local=False)
        torKvy = Kevery(db=torHby.db, lax=False, local=False)

        # Create Wan the witness
        wanHab = wanHby.makeHab(name="wan", transferable=False)
        assert wanHab.pre == "BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP"
        msg = wanHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=msg, kvy=torKvy)
        assert wanHab.pre in torKvy.kevers

        # Create Wil the witness, we'll use him later
        wilHab = wilHby.makeHab(name="wil", transferable=False)

        # Create Tor the delegaTOR and pass to witness Wan
        torHab = torHby.makeHab(name="tor", icount=1, isith='1', ncount=1, nsith='1', wits=[wanHab.pre], toad=1)
        assert torHab.pre == "EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP"
        torIcp = torHab.makeOwnEvent(sn=0)
        assert torHab.pre in torHab.kvy.kevers

        # Try to load event before Wan has seen it
        with pytest.raises(ValueError):
            _ = eventing.loadEvent(wanHab.db, torHab.pre, torHab.pre)

        # tor events are locallyWitnessed by wan so must process as local
        parsing.Parser().parse(ims=bytearray(torIcp), kvy=wanHab.kvy, local=True) # process as local

        wanHab.processCues(wanHab.kvy.cues)  # process cue returns rct msg
        evt = eventing.loadEvent(wanHab.db, torHab.pre, torHab.pre)
        assert evt == {'ked': {'a': [],
                               'b': ['BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP'],
                               'bt': '1',
                               'c': [],
                               'd': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                               'i': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                               'k': ['DDgZRj4y6XmkeCsjxLQ-WeAU_U0D3ttTBHW-yicX9hjT'],
                               'kt': '1',
                               'n': ['ED9aiBH7JDgWIgPU1bEXDx8XDFPCWKQilDNyw9W1sCl_'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON000159_'},
                       'receipts': {},
                       'signatures': [{'index': 0,
                                       'signature': 'AAAa36fZASpQeSPn6cEcDMuXRCpDqjXbQ0Q6PqOXB_uktcuANR8rsRdpgB3A87XWeU'
                                                    'QMB0MrWxUE-2bcjq5JJtMP'}],
                       'stored': True,
                       'timestamp': '2021-01-01T00:00:00.000000+00:00',
                       'witness_signatures': [{'index': 0,
                                               'signature': 'AAAU3Kk_Sgd_r4NX4MyE33-eAxM5fUS0WxIyId8YJ-wphNxMT5wI1Mz540'
                                                            'EjYZRkrnty3VfkYhMv-XkGJuY-JWQI'}],
                       'witnesses': ['BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP']}

        # Create Tee the delegaTEE and pass to witness Wan
        teeHab = teeHby.makeHab(name="tee", delpre=torHab.pre, icount=1, isith='1', ncount=1, nsith='1',
                                wits=[wanHab.pre], toad=1)
        assert teeHab.pre == "EDnrWpxagMvr5BBCwCOh3q5M9lvurboZ66vxR-GnIgQo"
        teeIcp = teeHab.makeOwnEvent(sn=0)

        # Anchor Tee's inception event in Tor's KEL
        ixn = torHab.interact(data=[dict(i=teeHab.pre, s='0', d=teeHab.kever.serder.said)])
        parsing.Parser().parse(ims=bytearray(ixn), kvy=wanHab.kvy, local=True)  # give to wan must be local
        wanHab.processCues(wanHab.kvy.cues)  # process cue returns rct msg

        evt = eventing.loadEvent(wanHab.db, torHab.pre, torHab.kever.serder.said)
        assert evt == {'ked': {'a': [{'d': 'EDnrWpxagMvr5BBCwCOh3q5M9lvurboZ66vxR-GnIgQo',
                                      'i': 'EDnrWpxagMvr5BBCwCOh3q5M9lvurboZ66vxR-GnIgQo',
                                      's': '0'}],
                               'd': 'EF7pHYN6XABC9znRdzprt5frW-MMry9rfrCI-_t5Y8VD',
                               'i': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                               'p': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                               's': '1',
                               't': 'ixn',
                               'v': 'KERI10JSON00013a_'},
                       'receipts': {},
                       'signatures': [{'index': 0,
                                       'signature': 'AABw4jnfadT8aCwyGX2rDtOV8ojW4w4kVehFoJu_p6TzRpsayZ-cibTM_2iZfHVjWx'
                                                    'zcIUbP2ibq6cVbVcOcNHsF'}],
                       'stored': True,
                       'timestamp': '2021-01-01T00:00:00.000000+00:00',
                       'witness_signatures': [{'index': 0,
                                               'signature': 'AABBQIanzXTUfATO36Q_ZzXSE4x2OlxC0MnOuyaUBE4bJhdHhV0f7qPIu5'
                                                            'xClEH2C5AgWgLRPlQ-qo98qJHhIr0B'}],
                       'witnesses': []}

        # Add seal source couple to Tee's inception before sending to Wan
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                 count=1)
        teeIcp.extend(counter.qb64b)
        seqner = coring.Seqner(sn=torHab.kever.sn)
        teeIcp.extend(seqner.qb64b)
        teeIcp.extend(torHab.kever.serder.saidb)

        # Endorse Tee's inception event with Tor's Hab just so we have trans receipts
        rct = torHab.receipt(serder=teeHab.kever.serder)
        nrct = wilHab.receipt(serder=teeHab.kever.serder)

        # Now Wan should be ready for Tee's inception
        parsing.Parser().parse(ims=bytearray(teeIcp), kvy=wanKvy, local=True)  # local
        parsing.Parser().parse(ims=bytearray(rct), kvy=wanHab.kvy, local=True) # local
        parsing.Parser().parse(ims=bytearray(nrct), kvy=wanHab.kvy, local=True)  # local
        # ToDo XXXX fix it so cues are durable in db so can process cues from
        # both and remote sources
        wanHab.processCues(wanHab.kvy.cues)  # process cue returns rct msg
        wanHab.processCues(wanKvy.cues)  # process cue returns rct msg

        # Endorse Tee's inception event with Wan's Hab just so we have non-trans receipts

        evt = eventing.loadEvent(wanHab.db, teeHab.pre, teeHab.pre)
        assert evt == {'ked': {'a': [],
                               'b': ['BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP'],
                               'bt': '1',
                               'c': [],
                               'd': 'EDnrWpxagMvr5BBCwCOh3q5M9lvurboZ66vxR-GnIgQo',
                               'di': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                               'i': 'EDnrWpxagMvr5BBCwCOh3q5M9lvurboZ66vxR-GnIgQo',
                               'k': ['DLDlVl1H2Q138A5tftVRpyy834ejsY33BB71kXLRNP2h'],
                               'kt': '1',
                               'n': ['EBTtZqMkJOO4nf3cCt6SdezwkoCKtx2fGUKHeFApj_Yx'],
                               'nt': '1',
                               's': '0',
                               't': 'dip',
                               'v': 'KERI10JSON00018d_'},
                       'receipts': {'nontransferable': [{'prefix': 'BEXrSXVksXpnfno_Di6RBX2Lsr9VWRAihjLhowfjNOQQ',
                                                         'signature': '0BCQOeNT3mwAHxh6mYU9K_B2VmbtjJh7_8115k4JrBPR3c4'
                                                                      '3jUSO197H2J73vWMi61qzOovNkSWQbnRx3NFnrk8I'}],
                                    'transferable': [{'prefix': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                                                      'said': 'EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP',
                                                      'sequence': '0AAAAAAAAAAAAAAAAAAAAAAA',
                                                      'signature': 'AADGbcmUNw_SX7OVNX-PQYl41UZx_pgJXHOoMWrcfmCDGgkc1-'
                                                                   'MqXJjMD9S9moJ-lpPL9-AiXgITemMZL_QYGzIA'}]},
                       'signatures': [{'index': 0,
                                       'signature': 'AAC1-NTntZ0xkgHwooNcKxe9G4XC-rgkSryVz0B_QrZR2kkv4IKi7DMkfMBd4Eck-'
                                                    '2NAi0DMuZeXnlvch6ZP0coO'}],
                       'source_seal': {'said': 'EF7pHYN6XABC9znRdzprt5frW-MMry9rfrCI-_t5Y8VD',
                                       'sequence': 1},
                       'stored': True,
                       'timestamp': '2021-01-01T00:00:00.000000+00:00',
                       'witness_signatures': [{'index': 0,
                                               'signature': 'AABPMW3J1iZyMC-elPOkdIhddhZB_BJYHTdYv5SxcrOfJL_5igDVB6zKD'
                                                            'AQiTj_cNa7oP-l6xSRRxwlHDwqgSwcB'}],
                       'witnesses': ['BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP']}

    """End Test"""


if __name__ == "__main__":
    # pytest.main(['-vv', 'test_eventing.py::test_keyeventfuncs'])
    #test_process_manual()
    #test_keyeventsequence_0()
    #test_process_transferable()
    #test_messagize()
    test_direct_mode()
