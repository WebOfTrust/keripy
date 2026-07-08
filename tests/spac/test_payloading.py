# -*- encoding: utf-8 -*-
"""
tests.spac.test_payloading module

"""

import pytest
from base64 import urlsafe_b64decode as decodeB64

from keri.kering import EmptyMaterialError, InvalidSoftError, InvalidCodeError
from keri.core.coring import MtrDex
from keri.spac.payloading import PayloadTypage, PayloadTyper, PayloadTypes


def test_payloadtypes():
    """
    Test PayloadTypage namedtuple instance PayloadTypes
    """
    PayloadTypes = PayloadTypage(HOP='HOP', RFI='RFI', RFA='RFA', RFD='RFD', SCS='SCS')

    assert isinstance(PayloadTypes, PayloadTypage)

    for fld in PayloadTypes._fields:
        assert fld == getattr(PayloadTypes, fld)

    assert 'HOP' in PayloadTypes
    assert PayloadTypes.HOP == 'HOP'
    assert 'RFI' in PayloadTypes
    assert PayloadTypes.RFI == 'RFI'
    assert 'RFA' in PayloadTypes
    assert PayloadTypes.RFA == 'RFA'
    assert 'RFD' in PayloadTypes
    assert PayloadTypes.RFD == 'RFD'
    assert 'SCS' in PayloadTypes
    assert PayloadTypes.SCS == 'SCS'

    """End Test """


def test_payloadtyper():
    """
    Test PayloadTyper message type subclass of Tagger
    """
    with pytest.raises(EmptyMaterialError):
        typer = PayloadTyper()  # defaults

    type = PayloadTypes.SCS
    tag = type
    code = MtrDex.Tag3
    soft = 'SCS'
    qb64 = 'XSCS'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)
    raw = b''

    typer = PayloadTyper(type=type)  # defaults
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    typer = PayloadTyper(qb2=qb2)
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    typer = PayloadTyper(qb64=qb64)
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    typer = PayloadTyper(qb64b=qb64b)
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    typer = PayloadTyper(tag=tag)
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    # test error condition
    with pytest.raises(InvalidSoftError):
        typer = PayloadTyper(type='bad')

    # ignores code
    typer = PayloadTyper(type=type, code=MtrDex.Tag4)
    assert typer.code == typer.hard == code
    assert typer.soft == soft
    assert typer.raw == raw
    assert typer.qb64 == qb64
    assert typer.qb2 == qb2
    assert typer.special
    assert typer.composable
    assert typer.tag == tag
    assert typer.type == type

    # test error using soft and code
    with pytest.raises(InvalidCodeError):
        typer = PayloadTyper(soft='bady', code=MtrDex.Tag4)

    """End Test"""
