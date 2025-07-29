# -*- encoding: utf-8 -*-
"""
tests.spac.essr.test_tsping module

"""

import pytest
from base64 import urlsafe_b64decode as decodeB64

from keri.kering import EmptyMaterialError, InvalidSoftError, InvalidCodeError
from keri.core.coring import MtrDex
from keri.spac.essr.tsping import Tspage, Tsper, Tsps


def test_tsps():
    """
    Test Tsps namedtuple instance Tsps
    """
    Tsps = Tspage(HOP='HOP', RFI='RFI', RFA='RFA', RFD='RFD', SCS='SCS')

    assert isinstance(Tsps, Tspage)

    for fld in Tsps._fields:
        assert fld == getattr(Tsps, fld)

    assert 'HOP' in Tsps
    assert Tsps.HOP == 'HOP'
    assert 'RFI' in Tsps
    assert Tsps.RFI == 'RFI'
    assert 'RFA' in Tsps
    assert Tsps.RFA == 'RFA'
    assert 'RFD' in Tsps
    assert Tsps.RFD == 'RFD'
    assert 'SCS' in Tsps
    assert Tsps.SCS == 'SCS'

    """End Test """


def test_tsper():
    """
    Test Tsper message type subclass of Tagger
    """
    with pytest.raises(EmptyMaterialError):
        tsper = Tsper()  # defaults

    tsp = Tsps.SCS
    tag = tsp
    code = MtrDex.Tag3
    soft = 'SCS'
    qb64 = 'XSCS'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)
    raw = b''

    tsper = Tsper(tsp=tsp)  # defaults
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    tsper = Tsper(qb2=qb2)
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    tsper = Tsper(qb64=qb64)
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    tsper = Tsper(qb64b=qb64b)
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    tsper = Tsper(tag=tag)
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    # test error condition
    with pytest.raises(InvalidSoftError):
        tsper = Tsper(tsp='bad')

    # ignores code
    tsper = Tsper(tsp=tsp, code=MtrDex.Tag4)
    assert tsper.code == tsper.hard == code
    assert tsper.soft == soft
    assert tsper.raw == raw
    assert tsper.qb64 == qb64
    assert tsper.qb2 == qb2
    assert tsper.special
    assert tsper.composable
    assert tsper.tag == tag
    assert tsper.tsp == tsp

    # test error using soft and code
    with pytest.raises(InvalidCodeError):
        tsper = Tsper(soft='bady', code=MtrDex.Tag4)

    """End Test"""
