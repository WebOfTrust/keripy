# -*- coding: utf-8 -*-
"""
tests.core.test_serdering module

"""
import dataclasses
import json
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import cbor2 as cbor
import msgpack

import pytest
from  ordered_set import OrderedSet as oset

from keri import kering
from keri.kering import (Protocols, Versionage, Version, Vrsn_1_0, Vrsn_2_0,
                      VERRAWSIZE, VERFMT,
                      MAXVERFULLSPAN, VER1FULLSPAN,  VER2FULLSPAN,)

from keri.help import helping

from keri import core

from keri.core.structing import Sealer, SealEvent, SealTrans

from keri.core.serdering import (FieldDom, FieldDom, Serdery, Serder,
                                 SerderKERI, SerderACDC, )

from keri.core.eventing import (incept, interact, rotate, delcept, deltate)

from keri.app import habbing


def test_fielddom():
    """Test FieldDom dataclass"""
    with pytest.raises(TypeError):  # alls required positional init arg
        fdom = FieldDom()

    alls = dict(v='', t='')
    fdom = FieldDom(alls=alls)
    assert fdom.alls == alls
    assert fdom.opts == {}
    assert not fdom.opts
    assert fdom.alts == {}
    assert not fdom.alts
    assert fdom.saids == {}
    assert not fdom.saids
    assert fdom.strict
    assert fdom.strict == True

    """End Test"""

def test_spans():
    """
    Test Spans dict of version string sizes by version
    """
    assert Serder.Spans
    assert isinstance(Serder.Spans, dict)

    assert Serder.Spans[kering.Vrsn_1_0] == kering.VER1FULLSPAN == 17
    assert Serder.Spans[kering.Vrsn_2_0] == kering.VER2FULLSPAN == 16

    """End Test"""


def test_serder_class():
    """Test Serder class"""

    assert Serder.ClanCodes
    assert Serder.ClanCodes == \
    {
        'SealDigest': '-V',
        'SealRoot': '-W',
        'SealBacker': '-X',
        'SealLast': '-Y',
        'SealTrans': '-Q',
        'SealEvent': '-R'
    }

    assert Serder.CodeClans
    assert Serder.CodeClans == \
    {
        '-V': 'SealDigest',
        '-W': 'SealRoot',
        '-X': 'SealBacker',
        '-Y': 'SealLast',
        '-Q': 'SealTrans',
        '-R': 'SealEvent'
    }


    assert Serder.Fields

    # Ensure all Serder.Fields all and opts and alts and saids are correct subsets
    # iterate through all FieldDoms

    for kp, kv in Serder.Fields.items():  # iterate through protocols
        for kv, vv in kv.items():  # iterate through versions for each protocol
            for kf, vf in vv.items():  # iterate through fields for each version
                assert oset(vf.opts) <= oset(vf.alls)
                assert oset(vf.alts) <= oset(vf.opts)
                assert oset(vf.saids) <= oset(vf.alls)


    assert Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].saids == {'d': 'E'}
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].alls ==
            {'v': '', 'd': '', 'u': '', 'i': '', 'ri': '', 's': '', 'a': '', 'A': '', 'e': '', 'r': ''})
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].opts ==
            {'u': '', 'ri': '', 'a': '', 'A': '', 'e': '', 'r': ''})
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].alts ==
            {'a': 'A', 'A': 'a'})
    assert Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].strict

    # said field labels must be subset of all field labels
    assert (set(Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].saids) <=
            set(Serder.Fields[Protocols.acdc][kering.Vrsn_1_0][None].alls))


    for proto, vrsns in Serder.Fields.items():
        for vrsn, ilks in vrsns.items():
            for ilk, fields in ilks.items():
                assert set(fields.saids) <= set(fields.alls)


    """End Test"""


def test_serder():
    """Test Serder instances"""

    # Test Serder



    with pytest.raises(kering.InvalidValueError):
        serder = Serder()

    #Test Serder bare makify bootstrap for ACDC JSON
    serder = Serder(makify=True, proto=Protocols.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                            'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                            'i': '',
                            's': ''}
    assert serder.raw == (b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjpI_-'
                          b'BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}')
    assert serder.verify()
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')
    assert serder.pretty() == ('{\n'
                                ' "v": "ACDC10JSON00005a_",\n'
                                ' "d": "EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT",\n'
                                ' "i": "",\n'
                                ' "s": ""\n'
                                '}')

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))

    serder = Serder(sad=sad, makify=True)  # test makify with sad
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)



    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)

    serder = Serder(raw=raw, verify=False)  # test not verify
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)



    # Test ignores strip if raw is bytes not bytearray
    serder = Serder(raw=raw, strip=True)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)

    # Test strip of bytearray
    extra = bytearray(b'Not a serder.')
    stream = bytearray(raw) + extra
    assert stream == bytearray(b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjp'
                               b'I_-BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}'
                               b'Not a serder.')
    serder = Serder(raw=stream, strip=True)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert stream == extra
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None

    # test verify bad digest value
    badraw = (b'{"v":"ACDC10JSON00005a_",'
              b'"d":"EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE",'
              b'"i":"","s":""}')
    with pytest.raises(kering.ValidationError):
        serder = Serder(raw=badraw, verify=True)



    #Test makify bootstrap for ACDC with CBOR
    serder = Serder(makify=True, proto=Protocols.acdc, kind=kering.Serials.cbor)
    assert serder.sad == {'v': 'ACDC10CBOR00004b_',
                            'd': 'EGahYhEMb_Sz0L1UwhrUvbyxyzoi_G85-pD9jRjhnqgU',
                            'i': '',
                            's': ''}
    assert serder.raw == (b'\xa4avqACDC10CBOR00004b_adx,EGahYhEMb_Sz0L1UwhrU'
                          b'vbyxyzoi_G85-pD9jRjhnqgUai`as`')
    assert serder.verify()
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.cbor
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')
    assert serder.pretty() == ('{\n'
                                ' "v": "ACDC10CBOR00004b_",\n'
                                ' "d": "EGahYhEMb_Sz0L1UwhrUvbyxyzoi_G85-pD9jRjhnqgU",\n'
                                ' "i": "",\n'
                                ' "s": ""\n'
                                '}')

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.cbor
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))

    serder = Serder(sad=sad, makify=True)  # test makify with sad
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.cbor
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)


    #Test makify bootstrap for ACDC with MGPK
    serder = Serder(makify=True, proto=Protocols.acdc, kind=kering.Serials.mgpk)
    assert serder.sad == {'v': 'ACDC10MGPK00004b_',
                        'd': 'EGV5wdF1nRbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC',
                        'i': '',
                        's': ''}
    assert serder.raw == (b'\x84\xa1v\xb1ACDC10MGPK00004b_\xa1d\xd9,EGV5wdF1'
                          b'nRbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC\xa1i\xa0\xa1s\xa0')
    assert serder.verify()
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')
    assert serder.pretty() == ('{\n'
                                ' "v": "ACDC10MGPK00004b_",\n'
                                ' "d": "EGV5wdF1nRbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC",\n'
                                ' "i": "",\n'
                                ' "s": ""\n'
                                '}')

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))

    serder = Serder(sad=sad, makify=True)  # test makify with sad
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)


    # Test KERI JSON with makify defaults for self bootstrap which is state msg
    serder = Serder(makify=True)  # make with all defaults is state message
    assert serder.sad == {'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        'i': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}
    assert serder.raw == (b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEd'
                          b'jON07Rwv","i":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv","s":"0","kt":"0'
                          b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')

    assert serder.verify()
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk == kering.Ilks.icp

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk == kering.Ilks.icp


    # Test KERI JSON with makify defaults for self bootstrap with ilk icp
    serder = Serder(makify=True, ilk=kering.Ilks.icp)  # make with defaults
    assert serder.sad =={'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        'i': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEd'
                        b'jON07Rwv","i":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv","s":"0","kt":"0'
                        b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.icp
    assert serder.sad['i'] == serder.said  # default prefix is saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk


    # Test with non-digestive code for 'i' saidive field no sad
    serder = Serder(makify=True,
                    ilk=kering.Ilks.icp,
                    saids = {'i': core.PreDex.Ed25519},
                    verify=False)

    assert serder.sad == {'v': 'KERI10JSON0000a3_',
                        't': 'icp',
                        'd': 'EEeXbwybn8tv2Wo_YNBpaqP3PobjvzUs6tH0XNRmfOTx',
                        'i': '',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000a3_","t":"icp","d":"EEeXbwybn8tv2Wo_YNBpaqP3PobjvzUs6tH0'
                            b'XNRmfOTx","i":"","s":"0","kt":"0","k":[],"nt":"0","n":[],"bt":"0","b":[],"c"'
                            b':[],"a":[]}')

    assert not serder.verify()  # because of empty 'i' field saidive
    assert serder.ilk == kering.Ilks.icp
    assert serder.sad['i'] == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = Serder(sad=sad, makify=True)
    assert serder.sad == {'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FAHDvAqO_R',
                        'i': 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw ==(b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FA'
                        b'HDvAqO_R","i":"DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx","s":"0","kt":"0'
                        b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')

    assert serder.verify()
    assert serder.ilk == kering.Ilks.icp
    assert serder.sad['i'] == pre != said  # prefix is not saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    # Test KERI JSON with makify defaults for self bootstrap with ilk rot
    serder = Serder(makify=True, ilk=kering.Ilks.rot)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000ac_',
                            't': 'rot',
                            'd': 'EMgauZPVfh6807jO9QO8A4Iauq1xhYTZnKX2doVd_UDl',
                            'i': '',
                            's': '0',
                            'p': '',
                            'kt': '0',
                            'k': [],
                            'nt': '0',
                            'n': [],
                            'bt': '0',
                            'br': [],
                            'ba': [],
                            'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000ac_","t":"rot","d":"EMgauZPVfh6807jO9QO8A4Iauq1xhYTZnKX2'
                          b'doVd_UDl","i":"","s":"0","p":"","kt":"0","k":[],"nt":"0","n":[],"bt":"0","br'
                          b'":[],"ba":[],"a":[]}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.rot
    assert serder.sad['i'] == '' != serder.said  # prefix is not saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    # test opts
    serder = Serder(makify=True, proto=Protocols.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                            'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                            'i': '',
                            's': ''}
    assert serder.raw == (b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjpI_-'
                          b'BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}')
    assert serder.verify()
    sad = serder.sad

    sad['a'] = ""
    sad['e'] = ""
    sad['r'] = ""

    serder = Serder(makify=True, sad=sad)  # make using sad
    assert serder.raw == (b'{"v":"ACDC10JSON00006f_","d":"EBE7-v1veGz54DF2PIYmUoSG2BCLsEcIQSDSIYFsn9uw",'
                          b'"i":"","s":"","a":"","e":"","r":""}')
    assert serder.verify()

    # out of order field
    sad = serder.sad
    sad["ri"] = ""

    serder = Serder(makify=True, sad=sad)  # make using sad fixes order

    # extra field with strict
    sad = serder.sad
    sad["x"] = ""

    with pytest.raises(kering.SerializeError):
        serder = Serder(makify=True, sad=sad)  # make using sad

    # test alts
    serder = Serder(makify=True, proto=Protocols.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                            'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                            'i': '',
                            's': ''}
    assert serder.verify()
    sad = serder.sad

    sad['a'] = ""
    sad['A'] = ""  # both alts
    sad['e'] = ""
    sad['r'] = ""

    with pytest.raises(kering.SerializeError):
        serder = Serder(makify=True, sad=sad)  # make using sad

    # test not strict
    # test opts
    serder = Serder(makify=True, proto=Protocols.acdc, ilk=kering.Ilks.ace)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON000064_',
                            't': 'ace',
                            'd': 'EKFsN95K2h5I6pJC6eTrNKiX8uHyn5o-SYHy6IelbPK8',
                            'i': '',
                            's': ''}
    assert serder.verify()

    sad = serder.sad
    sad["x"] = ""
    serder = Serder(makify=True, sad=sad)  # make using sad
    assert serder.sad == {'v': 'ACDC10JSON00006b_',
                        't': 'ace',
                        'd': 'ECmOYyE7X5TVvBiM7PtApT-w9wsj7ZYI0jQt1TTcTa-1',
                        'i': '',
                        's': '',
                        'x': ''}
    assert serder.verify()

    # out of order with extra
    sad = serder.sad
    sad["ri"] = ""
    serder = Serder(makify=True, sad=sad)  # makify fixes order with extra

    # ToDo: create malicious raw values to test verify more thoroughly
    # ToDo: create bad sad values to test makify more thoroughly
    # unhappy paths




    """End Test"""

def test_serderkeri():
    """Test SerderKERI default"""

    # Test KERI JSON with makify defaults for bootstrap which is state (ksn) msg
    # ksn msg has no ilk field for itself because is is embedded in exn or other
    serder = SerderKERI(makify=True)  # make with all defaults is state message
    assert serder.sad == {'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        'i': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEd'
                          b'jON07Rwv","i":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv","s":"0","kt":"0'
                          b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')

    assert serder.verify()  # because empty prefix 'i' field
    assert serder.ilk == kering.Ilks.icp
    assert serder.said == 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv'
    assert serder.pre == serder.said  # prefix is not saidive

    sad = serder.sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre
    said = serder.said

    serder = SerderKERI(sad=sad, makify=True)

    assert serder.verify()
    assert serder.ilk == kering.Ilks.icp
    assert serder.said == 'EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FAHDvAqO_R'
    assert serder.pre == pre  # prefix is not saidive

    sad = serder.sad
    raw = serder.raw
    size = serder.size
    said = serder.said
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.pre == pre
    assert serder.ilk == kering.Ilks.icp

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None


    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.icp

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None


def test_serderkeri_icp():
    """Test SerderKERI icp msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk icp
    serder = SerderKERI(makify=True, ilk=kering.Ilks.icp)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        'i': 'EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}


    assert serder.raw == (b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEd'
                        b'jON07Rwv","i":"EF6LmlLkfoNVY25RcGTsqKLW5uHq36FbnNEdjON07Rwv","s":"0","kt":"0'
                        b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.icp
    assert serder.pre == serder.said  # default prefix is saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None


    # Test with non-digestive code for 'i' saidive field no sad
    serder = SerderKERI(makify=True,
                    ilk=kering.Ilks.icp,
                    saids = {'i': core.PreDex.Ed25519},
                    verify=False)

    assert serder.sad == {'v': 'KERI10JSON0000a3_',
                        't': 'icp',
                        'd': 'EEeXbwybn8tv2Wo_YNBpaqP3PobjvzUs6tH0XNRmfOTx',
                        'i': '',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000a3_","t":"icp","d":"EEeXbwybn8tv2Wo_YNBpaqP3PobjvzUs6tH0'
                        b'XNRmfOTx","i":"","s":"0","kt":"0","k":[],"nt":"0","n":[],"bt":"0","b":[],"c"'
                        b':[],"a":[]}')

    assert not serder.verify()  # because of empty 'i' field saidive
    assert serder.ilk == kering.Ilks.icp
    assert serder.pre == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)
    assert serder.sad == {'v': 'KERI10JSON0000cf_',
                        't': 'icp',
                        'd': 'EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FAHDvAqO_R',
                        'i': 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': []}

    assert serder.raw ==(b'{"v":"KERI10JSON0000cf_","t":"icp","d":"EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FA'
                         b'HDvAqO_R","i":"DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx","s":"0","kt":"0'
                         b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')

    assert serder.verify()
    assert serder.ilk == kering.Ilks.icp
    assert serder.pre == pre != said  # prefix is not saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_rot():
    """Test SerderKERI rot msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk rot
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rot, verify=False)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000ac_',
                        't': 'rot',
                        'd': 'EMgauZPVfh6807jO9QO8A4Iauq1xhYTZnKX2doVd_UDl',
                        'i': '',
                        's': '0',
                        'p': '',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'br': [],
                        'ba': [],
                        'a': []}


    assert serder.raw == (b'{"v":"KERI10JSON0000ac_","t":"rot","d":"EMgauZPVfh6807jO9QO8A4Iauq1xhYTZnKX2'
                          b'doVd_UDl","i":"","s":"0","p":"","kt":"0","k":[],"nt":"0","n":[],"bt":"0","br'
                          b'":[],"ba":[],"a":[]}')

    assert not serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.rot
    assert serder.pre == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)

    assert serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.rot
    assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.prior == ""
    assert serder.priorb == b""
    assert serder.cuts == []
    assert serder.adds == []
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_ixn():
    """Test SerderKERI ixn msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk ixn
    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn, verify=False)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON000073_',
                        't': 'ixn',
                        'd': 'ELI1jUxlJky6RvRieoO20H7_YikKnQMthnWM38etba3r',
                        'i': '',
                        's': '0',
                        'p': '',
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON000073_","t":"ixn","d":"ELI1jUxlJky6RvRieoO20H7_YikKnQMthnWM'
                          b'38etba3r","i":"","s":"0","p":"","a":[]}')

    assert not serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.ixn
    assert serder.pre == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)

    assert serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.ixn
    assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.keys == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.prior == ""
    assert serder.priorb == b""
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.keys == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.prior == ""
    assert serder.priorb == b""
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None
    """End Test"""

def test_serderkeri_dip():
    """Test SerderKERI dip msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk dip
    serder = SerderKERI(makify=True, ilk=kering.Ilks.dip, verify=False)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000d7_',
                        't': 'dip',
                        'd': 'EPyzEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a9ZcKfC',
                        'i': 'EPyzEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a9ZcKfC',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': [],
                        'di': ''}

    assert serder.raw == (b'{"v":"KERI10JSON0000d7_","t":"dip","d":"EPyzEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP'
                          b'2a9ZcKfC","i":"EPyzEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a9ZcKfC","s":"0","kt":"0'
                          b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[],"di":""}')


    assert not serder.verify()  # serder.delpre empty so not valid PreDex code
    assert serder.ilk == kering.Ilks.dip
    assert serder.pre == serder.said  # default prefix is saidive

    delpre = 'EPyz9ZcKfCEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a'
    sad = serder.sad
    sad["di"] = delpre

    serder = SerderKERI(makify=True, sad=sad)
    assert serder.sad == {'v': 'KERI10JSON000103_',
                        't': 'dip',
                        'd': 'EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa',
                        'i': 'EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': [],
                        'di': 'EPyz9ZcKfCEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a'}

    assert serder.raw == (b'{"v":"KERI10JSON000103_","t":"dip","d":"EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZ'
                          b'p_OZUUJa","i":"EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa","s":"0","kt":"0'
                          b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[],"di":"EPyz9ZcKfCEgwg6'
                          b'ls8iY4jViniM15rAFWaaVbsZ4eP2a"}')

    assert serder.verify()

    raw = serder.raw
    sad = serder.sad
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == delpre
    assert serder.delpreb == delpre.encode("utf-8")
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == delpre
    assert serder.delpreb == delpre.encode("utf-8")
    #assert serder.fner == None
    #assert serder.fn == None


    # Test with non-digestive code for 'i' saidive field no sad
    serder = SerderKERI(makify=True,
                    ilk=kering.Ilks.dip,
                    saids = {'i': core.PreDex.Ed25519},
                    verify=False)

    assert serder.sad == {'v': 'KERI10JSON0000ab_',
                        't': 'dip',
                        'd': 'EEPX5NpQed1laFb8VZPES3zAoMcEuMq796KnN33GwWqF',
                        'i': '',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': [],
                        'di': ''}


    assert serder.raw == (b'{"v":"KERI10JSON0000ab_","t":"dip","d":"EEPX5NpQed1laFb8VZPES3zAoMcEuMq796Kn'
                          b'N33GwWqF","i":"","s":"0","kt":"0","k":[],"nt":"0","n":[],"bt":"0","b":[],"c"'
                          b':[],"a":[],"di":""}')


    assert not serder.verify()  # because of empty 'i' field and 'di' field
    assert serder.ilk == kering.Ilks.dip
    assert serder.pre == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'  # non digest so raise error
    sad['i'] = pre
    sad['di'] = delpre

    serder = SerderKERI(sad=sad, makify=True, verify=False)

    assert not serder.verify()
    pre = 'EF78YGUYCWXptoVVel1TN1F9-KShPHAtEqvf-TEiGvv9'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)
    assert serder.verify()

    assert serder.ilk == kering.Ilks.dip
    assert serder.pre == said  != pre # prefix is computed
    assert serder.delpre == delpre

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre


    serder = SerderKERI(sad=sad,
                        makify=True,
                        saids = {'i': core.PreDex.Blake3_256})

    assert serder.sad == {'v': 'KERI10JSON000103_',
                        't': 'dip',
                        'd': 'EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa',
                        'i': 'EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa',
                        's': '0',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'b': [],
                        'c': [],
                        'a': [],
                        'di': 'EPyz9ZcKfCEgwg6ls8iY4jViniM15rAFWaaVbsZ4eP2a'}

    assert serder.raw == (b'{"v":"KERI10JSON000103_","t":"dip","d":"EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZ'
                          b'p_OZUUJa","i":"EJrgptxlZU7ue_WQkZb5wwSyv-LE0B-eOhRZp_OZUUJa","s":"0","kt":"0'
                          b'","k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[],"di":"EPyz9ZcKfCEgwg6'
                          b'ls8iY4jViniM15rAFWaaVbsZ4eP2a"}')

    assert serder.verify()
    assert serder.ilk == kering.Ilks.dip
    assert serder.pre == said  == pre  # prefix is computed same as before
    assert serder.delpre == delpre
    assert serder.said == said


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == delpre
    assert serder.delpreb == delpre.encode("utf-8")
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '0'
    assert serder.keys == []
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == []
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.prior == None
    assert serder.priorb == None
    assert serder.cuts == None
    assert serder.adds == None
    assert serder.delpre == delpre
    assert serder.delpreb == delpre.encode("utf-8")
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_drt():
    """Test SerderKERI drt msg"""
    # Test KERI JSON with makify defaults for self bootstrap with ilk drt
    serder = SerderKERI(makify=True, ilk=kering.Ilks.drt, verify=False)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000ac_',
                        't': 'drt',
                        'd': 'EMiEhgKRsD559TX6b03AT5P2GfKPPqoNk5COHZxU2TkR',
                        'i': '',
                        's': '0',
                        'p': '',
                        'kt': '0',
                        'k': [],
                        'nt': '0',
                        'n': [],
                        'bt': '0',
                        'br': [],
                        'ba': [],
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON0000ac_","t":"drt","d":"EMiEhgKRsD559TX6b03AT5P2GfKPPqoNk5CO'
                          b'HZxU2TkR","i":"","s":"0","p":"","kt":"0","k":[],"nt":"0","n":[],"bt":"0","br'
                          b'":[],"ba":[],"a":[]}')


    assert not serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.drt
    assert serder.pre == '' != serder.said  # prefix is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True, verify=False)

    assert not serder.verify()  # because pre is not digest and delpre is empty
    sad = serder.sad
    pre = 'EF78YGUYCWXptoVVel1TN1F9-KShPHAtEqvf-TEiGvv9'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)

    assert serder.verify()
    assert serder.ilk == kering.Ilks.drt
    assert serder.pre == pre != serder.said  # prefix is not computed
    assert serder.delpre == None


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '0'
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.prior == ""
    assert serder.priorb == b""
    assert serder.cuts == []
    assert serder.adds == []
    assert serder.delpre == None
    assert serder.delpreb == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '0'
    assert [verfer.qb64 for verfer in serder.verfers] == []
    assert serder.ntholder.sith == '0'
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.prior == ""
    assert serder.priorb == b""
    assert serder.cuts == []
    assert serder.adds == []
    assert serder.delpre == None
    assert serder.delpreb == None

    """End Test"""

def test_serderkeri_rct():
    """Test SerderKERI rct msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk ixn
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rct, verify=False)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON000039_', 't': 'rct', 'd': '', 'i': '', 's': '0'}

    assert serder.raw == b'{"v":"KERI10JSON000039_","t":"rct","d":"","i":"","s":"0"}'

    assert not serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.rct
    assert serder._said == None  # no saidive fields
    assert serder.pre == ''  # prefix is not saidive
    assert serder.said == ''  # d field is not saidive

    sad = serder.sad

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)

    assert serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.rct
    assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None
    """End Test"""

def test_serderkeri_qry():
    """Test SerderKERI qry query msg"""
    # Test KERI JSON with makify defaults for self bootstrap with ilk qry
    serder = SerderKERI(makify=True, ilk=kering.Ilks.qry)  # make with defaults
    assert serder.sad =={'v': 'KERI10JSON000074_',
                        't': 'qry',
                        'd': 'EHVP7GS9B8PFKDogN3WD93NcSg6hShBXiolOqwnO3Vfm',
                        'dt': '',
                        'r': '',
                        'rr': '',
                        'q': {}}

    assert serder.raw == (b'{"v":"KERI10JSON000074_","t":"qry","d":"EHVP7GS9B8PFKDogN3WD93NcSg6hShBXiolO'
                          b'qwnO3Vfm","dt":"","r":"","rr":"","q":{}}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.qry
    assert serder.pre == None != serder.said  # prefix is not saidive

    #sad = serder.sad
    # test makify with preloaded non-digestive 'i' value in sad
    #pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #sad['i'] = pre

    #serder = SerderKERI(sad=sad, makify=True)

    #assert serder.verify()  # because pre is empty
    #assert serder.ilk == kering.Ilks.qry
    #assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""


def test_serderkeri_rpy():
    """Test SerderKERI rpy reply msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk rpy
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rpy)  # make with defaults
    assert serder.sad =={'v': 'KERI10JSON00006c_',
                        't': 'rpy',
                        'd': 'EFnZ6ER7GXDjNpcn-QgXWqW4IZVAp73cCKC_zW_48Nu-',
                        'dt': '',
                        'r': '',
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON00006c_","t":"rpy","d":"EFnZ6ER7GXDjNpcn-QgXWqW4IZVAp73cCKC_'
                          b'zW_48Nu-","dt":"","r":"","a":[]}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.rpy
    assert serder.pre == None != serder.said  # prefix is not saidive

    #sad = serder.sad
    # test makify with preloaded non-digestive 'i' value in sad
    #pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #sad['i'] = pre

    #serder = SerderKERI(sad=sad, makify=True)

    #assert serder.verify()  # because pre is empty
    #assert serder.ilk == kering.Ilks.qry
    #assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_pro():
    """Test SerderKERI pro prod msg"""
    # Test KERI JSON with makify defaults for self bootstrap with ilk qry
    serder = SerderKERI(makify=True, ilk=kering.Ilks.pro)  # make with defaults
    assert serder.sad =={'v': 'KERI10JSON000074_',
                        't': 'pro',
                        'd': 'EP5pwF1ioQjnY1J0Gu12f_ZZEaoAntM3bng52tzZAvrM',
                        'dt': '',
                        'r': '',
                        'rr': '',
                        'q': {}}

    assert serder.raw == (b'{"v":"KERI10JSON000074_","t":"pro","d":"EP5pwF1ioQjnY1J0Gu12f_ZZEaoAntM3bng5'
                          b'2tzZAvrM","dt":"","r":"","rr":"","q":{}}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.pro
    assert serder.pre == None != serder.said  # prefix is not saidive

    #sad = serder.sad
    # test makify with preloaded non-digestive 'i' value in sad
    #pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #sad['i'] = pre

    #serder = SerderKERI(sad=sad, makify=True)

    #assert serder.verify()  # because pre is empty
    #assert serder.ilk == kering.Ilks.qry
    #assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == None
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_bar():
    """Test SerderKERI bar alls msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk bar
    serder = SerderKERI(makify=True, ilk=kering.Ilks.bar)  # make with defaults
    assert serder.sad =={'v': 'KERI10JSON00006c_',
                        't': 'bar',
                        'd': 'EAGe-dBuaN1l1LFK8MrBS60BiFhSbxrf_l6dZBkd8JNR',
                        'dt': '',
                        'r': '',
                        'a': []}

    assert serder.raw == (b'{"v":"KERI10JSON00006c_","t":"bar","d":"EAGe-dBuaN1l1LFK8MrBS60BiFhSbxrf_l6d'
                          b'ZBkd8JNR","dt":"","r":"","a":[]}')


    assert serder.verify()
    assert serder.ilk == kering.Ilks.bar
    assert serder.pre == None != serder.said  # prefix is not saidive

    #sad = serder.sad
    # test makify with preloaded non-digestive 'i' value in sad
    #pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #sad['i'] = pre

    #serder = SerderKERI(sad=sad, makify=True)

    #assert serder.verify()  # because pre is empty
    #assert serder.ilk == kering.Ilks.qry
    #assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == None
    assert serder.preb == None
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    """End Test"""

def test_serderkeri_exn():
    """Test SerderKERI exn msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk ixn
    serder = SerderKERI(makify=True, ilk=kering.Ilks.exn)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON000088_',
                            't': 'exn',
                            'd': 'EMuAoRSE4zREKKYyvuNeYCDM9_MwPQIh1WL0cFC4e-bU',
                            'i': '',
                            'p': '',
                            'dt': '',
                            'r': '',
                            'q': {},
                            'a': [],
                            'e': {}}

    assert serder.raw == (b'{"v":"KERI10JSON000088_","t":"exn",'
                           b'"d":"EMuAoRSE4zREKKYyvuNeYCDM9_MwPQIh1WL0'
                           b'cFC4e-bU","i":"","p":"","dt":"","r":"","q":{},"a":[],"e":{}}')



    assert serder.verify()  # because pre is empty
    assert serder.ilk == kering.Ilks.exn
    assert serder.pre == ''
    assert serder.prior == ''

    #sad = serder.sad
    ## test makify with preloaded non-digestive 'i' value in sad
    #pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #sad['i'] = pre

    #serder = SerderKERI(sad=sad, makify=True)
    #assert serder.verify()  # because pre is empty
    #assert serder.ilk == kering.Ilks.exn
    ## need to fix this, since exn does not include prefix field which should be
    ## required
    #assert serder.pre == pre != serder.said  # prefix is not saidive


    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == ''
    assert serder.preb == b''
    assert serder.prior == ''
    assert serder.priorb == b''
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == ''  # serder.sad['i'] == pre
    assert serder.preb == b''  # serder.pre.encode("utf-8")
    assert serder.prior == ''
    assert serder.priorb == b''
    assert serder.sner == None
    assert serder.sn == None
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner == None
    assert serder.bn == None
    assert serder.backs == None
    assert serder.berfers == None
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None


    """End Test"""

def test_serderkeri_vcp():
    """Test SerderKERI vcp msg"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk vcp
    serder = SerderKERI(makify=True, ilk=kering.Ilks.vcp)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000b7_',
                        't': 'vcp',
                        'd': 'ELJmaZ1Cq3JoXDmNNtTpL-oNTpo4936wx4YAvXMK5tLU',
                        'i': 'ELJmaZ1Cq3JoXDmNNtTpL-oNTpo4936wx4YAvXMK5tLU',
                        'ii': '',
                        's': '0',
                        'c': [],
                        'bt': '0',
                        'b': [],
                        'n': ''}


    assert serder.raw == (b'{"v":"KERI10JSON0000b7_","t":"vcp","d":"ELJmaZ1Cq3JoXDmNNtTpL-oNTpo4936wx4YA'
                          b'vXMK5tLU","i":"ELJmaZ1Cq3JoXDmNNtTpL-oNTpo4936wx4YAvXMK5tLU","ii":"","s":"0"'
                          b',"c":[],"bt":"0","b":[],"n":""}')

    assert serder.verify()
    assert serder.ilk == kering.Ilks.vcp
    assert serder.pre == serder.said  # default prefix is saidive

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == None
    assert serder.traits == []
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.berfers == []
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None
    assert serder.uuid == None
    assert serder.nonce == ''

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == None
    assert serder.traits == []
    assert serder.tholder == None
    assert serder.verfers == None
    assert serder.ntholder == None
    assert serder.ndigers == None
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert serder.berfers == []
    assert serder.delpre == None
    assert serder.delpreb == None
    #assert serder.fner == None
    #assert serder.fn == None
    assert serder.uuid == None
    assert serder.nonce == ''


    """End Test"""


def test_serderacdc():
    """Test SerderACDC"""

    with pytest.raises(kering.InvalidValueError):
        serder = SerderACDC()

    serder = SerderACDC(makify=True, proto=Protocols.acdc, verify=False)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                          'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                          'i': '',
                          's': ''}
    assert serder.raw == (b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjpI_'
                          b'-BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}')

    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT'
    assert serder.ilk == None

    assert serder.issuer == serder.sad['i'] == ''
    assert serder.issuerb == serder.issuer.encode("utf-8")

    sad = serder.sad
    raw = serder.raw

    with pytest.raises(kering.ValidationError):
        serder = SerderACDC(sad=sad)

    with pytest.raises(kering.ValidationError):
        serder = SerderACDC(sad=sad)

    isr = 'EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2'
    sad['i'] = isr

    serder = SerderACDC(sad=sad, makify=True)
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size


    serder = SerderACDC(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None
    assert serder.issuer ==  isr


    serder = SerderACDC(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None
    assert serder.issuer ==  isr



    """End Test"""

def test_serder_v2():
    """
    Test Serder with version 2.00 of protocols
    """


    assert Serder.Fields[Protocols.acdc][kering.Vrsn_2_0][None].saids == {'d': 'E'}
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_2_0][None].alls ==
            {'v': '', 'd': '', 'u': '', 'i': '', 'rd': '', 's': '', 'a': '', 'A': '', 'e': '', 'r': ''})
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_2_0][None].opts ==
            {'u': '', 'rd': '', 'a': '', 'A': '', 'e': '', 'r': ''})
    assert (Serder.Fields[Protocols.acdc][kering.Vrsn_2_0][None].alts ==
            {'a': 'A', 'A': 'a'})
    assert Serder.Fields[Protocols.acdc][kering.Vrsn_2_0][None].strict



    with pytest.raises(kering.InvalidValueError):
        serder = Serder()

    #Test Serder bare makify bootstrap for ACDC JSON
    serder = Serder(makify=True,
                    proto=Protocols.acdc,
                    vrsn=kering.Vrsn_2_0)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDCCAAJSONAABZ.',
                            'd': 'EN-uBXL6rsJpJvDSsyOAnttQiI9gka4qLbe3MlIoYwYy',
                            'i': '',
                            's': ''}
    assert serder.raw == (b'{"v":"ACDCCAAJSONAABZ.","d":"EN-uBXL6rsJpJvDSsyOAnttQiI9gka4qLbe3MlIoYwYy","'
                          b'i":"","s":""}')
    assert serder.verify()
    assert serder.vrsn == serder.version == kering.Vrsn_2_0
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_2_0 == serder.version
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')
    assert serder.pretty() == ('{\n'
                ' "v": "ACDCCAAJSONAABZ.",\n'
                ' "d": "EN-uBXL6rsJpJvDSsyOAnttQiI9gka4qLbe3MlIoYwYy",\n'
                ' "i": "",\n'
                ' "s": ""\n'
                '}')

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_2_0 == serder.version
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)
    assert serder.compare(said=said.encode("utf-8"))

    serder = Serder(sad=sad, makify=True)  # test makify with sad
    assert serder.raw == raw
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == Protocols.acdc
    assert serder.vrsn == kering.Vrsn_2_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)

    # test default
    serder = Serder(makify=True,
                    vrsn=kering.Vrsn_2_0)  # make defaults for default proto


    assert serder.sad == {'v': 'KERICAAJSONAADO.',
                            't': 'icp',
                            'd': 'EGqrN042jSUT5bjUuQqGALW4inJMJA6BBlVKf21VH3bn',
                            'i': 'EGqrN042jSUT5bjUuQqGALW4inJMJA6BBlVKf21VH3bn',
                            's': '0',
                            'kt': '0',
                            'k': [],
                            'nt': '0',
                            'n': [],
                            'bt': '0',
                            'b': [],
                            'c': [],
                            'a': []}
    assert serder.raw == (b'{"v":"KERICAAJSONAADO.","t":"icp","d":"EGqrN042jSUT5bjUuQqGALW4inJMJA6BBlVKf'
                        b'21VH3bn","i":"EGqrN042jSUT5bjUuQqGALW4inJMJA6BBlVKf21VH3bn","s":"0","kt":"0"'
                        b',"k":[],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}')
    assert serder.verify()
    assert serder.proto == Protocols.keri == Serder.Proto  # default
    assert serder.vrsn == kering.Vrsn_2_0
    assert serder.kind == kering.Serials.json == Serder.Kind  # default
    assert serder.ilk == kering.Ilks.icp  # default first one


    """End Test"""



def test_serdery():
    """Test Serdery"""
    #Create incoming message stream for Serdery to reap

    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn, verify=False)  # make with defaults
    sad = serder.sad
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 2
    sad['a'] = []
    serderKeri = SerderKERI(sad=sad, makify=True)
    assert serderKeri.verify()

    ims = bytearray(serderKeri.raw)

    serder = SerderACDC(makify=True, proto=Protocols.acdc, verify=False)  # make defaults for ACDC
    sad = serder.sad
    isr = 'EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2'
    sad['i'] = isr
    serderAcdc = SerderACDC(sad=sad, makify=True)
    assert serderAcdc.verify()

    ims.extend(serderAcdc.raw)

    ims.extend(b"Not a Serder here or there or anywhere.")

    assert ims == bytearray(b'{"v":"KERI10JSON00009d_","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYML'
                            b'Od2eYjmclndQN4bArjSf","i":"EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf'
                            b'87Bc70J","s":2,"p":"","a":[]}{"v":"ACDC10JSON000086_","d":"EJxJ1'
                            b'GB8oGD4JAH7YpiMCSWKDV3ulpt37zg9vq1QnOh_","i":"EO8CE5RH1X8QJwHHhP'
                            b'kj_S6LJQDRNOiGohW327FMA6D2","s":""}Not a Serder here or there or'
                            b' anywhere.')

    serdery = Serdery()

    serder = serdery.reap(ims)
    assert isinstance(serder, SerderKERI)
    assert serder.raw == serderKeri.raw

    serder = serdery.reap(ims)
    assert isinstance(serder, SerderACDC)
    assert serder.raw == serderAcdc.raw

    assert ims == bytearray(b'Not a Serder here or there or anywhere.')

    with pytest.raises(kering.VersionError):
        serder = serdery.reap(ims)

    assert ims == bytearray(b'Not a Serder here or there or anywhere.')


    """End Test"""


def test_cesr_native_dumps():
    """Test Serder._dumps"""

    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    rawsalt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = core.Salter(raw=rawsalt)

    csigners = salter.signers(count=12, transferable=True, temp=True)
    wsigners = salter.signers(count=12, transferable=False, temp=True)


    # simple inception event

    keys = [csigners[0].verfer.qb64]
    assert keys == ['DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ']
    serder = incept(keys, version=Vrsn_2_0, kind=kering.Serials.cesr)

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'icp',
        'd': 'EO6lMLcTbUhdpbQVXCh78MShuT_69th6tiZhEbAfPCj4',
        'i': 'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
        's': '0',
        'kt': '1',
        'k': ['DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ'],
        'nt': '0',
        'n': [],
        'bt': '0',
        'b': [],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FAtYKERICAAXicpEO6lMLcTbUhdpbQVXCh78MShuT_69th6tiZhEbAfPCj4DG9X'
                          b'hvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAMAAB-LALDG9XhvcVryHj'
                          b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAA-LAAMAAA-LAA-LAA-LAA')
    assert len(serder.raw) == serder.size == 184
    sizeh = serder.raw[2:4]
    assert sizeh == b"At"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 184

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw
    assert len(rawqb64) == 184

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 138
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 252

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 202

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 202

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.46, 1.46, 1.83]

    # more complex inception event

    keys = [signer.verfer.qb64 for signer in csigners][:3]
    ndigs = [core.Diger(ser=key.encode()).qb64 for key in keys][:3]
    wits = [signer.verfer.qb64 for signer in wsigners][:3]
    data = [dict(i=keys[0], s=core.Number(num=0).numh, d=ndigs[0]),
            dict(i=keys[1], s=core.Number(num=1).numh, d=ndigs[1]),
            dict(s=core.Number(num=15).numh, d=ndigs[2])]

    assert data == \
    [
        {
            'i': 'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
            's': '0',
            'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
        },
        {
            'i': 'DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
            's': '1',
            'd': 'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG'
        },
        {
            's': 'f',
            'd': 'EEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZpZEyP'
        }
    ]


    serder = incept(keys,
                    ndigs=ndigs,
                    wits=wits,
                    cnfg=['DND'],
                    data=data,
                    code=core.MtrDex.Blake3_256,
                    version=Vrsn_2_0,
                    kind=kering.Serials.cesr)

    pre = serder.pre
    assert pre == 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6'
    said = serder.said
    assert said == pre

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'icp',
        'd': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6',
        'i': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6',
        's': '0',
        'kt': '2',
        'k':
        [
            'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
            'DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
            'DMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0'
        ],
        'nt': '2',
        'n':
        [
            'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_',
            'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG',
            'EEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZpZEyP'
        ],
        'bt': '3',
        'b':
        [
            'BG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
            'BK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
            'BMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0'
        ],
        'c': ['DND'],
        'a':
        [
            {
                'i': 'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
                's': '0',
                'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
            },
            {
                'i': 'DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
                's': '1',
                'd': 'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG'
            },
            {
                's': 'f',
                'd': 'EEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZpZEyP'
            }
        ]
    }

    assert serder.raw == (b'-FDCYKERICAAXicpEMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6EMEv'
          b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAAAMAAC-LAhDG9XhvcVryHj'
          b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQDK58m521o6nwgcluK8Mu2ULvScXM9kB1'
          b'bSORrxNSS9cnDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MAAC-LAh'
          b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_EMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUGEEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZp'
          b'ZEyPMAAD-LAhBG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQBK58m521'
          b'o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnBMOmBoddcrRHShSajb4d60S6RK34'
          b'gXZ2WYbr3AiPY1M0-LABXDND-LA8-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
          b'4fBJre3NGwTQMAAAEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
          b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAABEMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMAAPEEbufBpvagqe9kijKISOoQPYFEOpy22C'
          b'ZJGJqQZpZEyP')

    assert len(serder.raw) == serder.size == 780
    sizeh = serder.raw[2:4]
    assert sizeh == b"DC"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 780

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw
    assert rawqb64 == (b'-FDCYKERICAAXicpEMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6EMEv'
          b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAAAMAAC-LAhDG9XhvcVryHj'
          b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQDK58m521o6nwgcluK8Mu2ULvScXM9kB1'
          b'bSORrxNSS9cnDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MAAC-LAh'
          b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_EMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUGEEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZp'
          b'ZEyPMAAD-LAhBG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQBK58m521'
          b'o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnBMOmBoddcrRHShSajb4d60S6RK34'
          b'gXZ2WYbr3AiPY1M0-LABXDND-LA8-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
          b'4fBJre3NGwTQMAAAEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
          b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAABEMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMAAPEEbufBpvagqe9kijKISOoQPYFEOpy22C'
          b'ZJGJqQZpZEyP')


    assert len(rawqb64) == 780

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 585
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 915

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 829

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 829

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.42, 1.42, 1.56]

    # complex interaction event

    prior = said

    data = \
        [
            dict(i=keys[0], s=core.Number(num=2).numh, d=ndigs[0]),
            dict(i=keys[1], s=core.Number(num=34).numh, d=ndigs[1]),
            dict(s=core.Number(num=67).numh, d=ndigs[2]),
            dict(i=keys[2], s=core.Number(num=128).numh, d=ndigs[0])
        ]

    assert data == \
    [
        {
            'i': 'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
            's': '2',
            'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
        },
        {
            'i': 'DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
            's': '22',
            'd': 'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG'
        },
        {
            's': '43',
            'd': 'EEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZpZEyP'
        },
        {
            'i': 'DMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0',
            's': '80',
            'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
        },
    ]


    serder = interact(pre=pre,
                      dig=prior,
                      sn=1,
                      data=data,
                      version=Vrsn_2_0,
                      kind=kering.Serials.cesr)

    said = serder.said
    assert said == 'EHeLJVa4LLNRRYVkLQsXHIDvllcmhDaahe5a_oMvXKeP'

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'ixn',
        'd': 'EHeLJVa4LLNRRYVkLQsXHIDvllcmhDaahe5a_oMvXKeP',
        'i': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6',
        's': '1',
        'p': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6',
        'a':
        [
            {
                'i': 'DG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ',
                's': '2',
                'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
            },
            {
                'i': 'DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn',
                's': '22',
                'd': 'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG'
            },
            {
                's': '43',
                'd': 'EEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZpZEyP'
            },
            {
                'i': 'DMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0',
                's': '80',
                'd': 'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
            }
        ]
    }

    assert serder.raw == (b'-FB6YKERICAAXixnEHeLJVa4LLNRRYVkLQsXHIDvllcmhDaahe5a_oMvXKePEMEv'
          b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAABEMEvSn0o6Iv2-3gInTDM'
          b'MDTV0qQEfooM-yTzkj6Kynn6-LBU-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
          b'4fBJre3NGwTQMAACEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
          b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAAiEMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMABDEEbufBpvagqe9kijKISOoQPYFEOpy22C'
          b'ZJGJqQZpZEyP-RAXDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MACA'
          b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_')

    assert len(serder.raw) == serder.size == 492
    sizeh = serder.raw[2:4]
    assert sizeh == b"B6"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 492

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw
    assert len(rawqb64) == 492

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 369
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 601

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 536

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 536

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.45, 1.45, 1.63]

    # complex rotation event

    prior = said

    keys = [signer.verfer.qb64 for signer in csigners][3:6]
    ndigs = [core.Diger(ser=key.encode()).qb64 for key in keys]
    cuts = [wits[0]]
    adds = [signer.verfer.qb64 for signer in wsigners][3:4]
    data = {}  # no anchors


    serder = rotate(pre=pre,
                    keys=keys,
                      dig=prior,
                      sn=2,
                      ndigs=ndigs,
                      wits=wits, #prior
                      cuts=cuts,
                      adds=adds,
                      data=data,
                      version=Vrsn_2_0,
                      kind=kering.Serials.cesr)

    said = serder.said
    assert said == 'EDtBwgOB0uGrSMBJhOmnkRoCupjg-4sJApvOx04ujhKs'

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'rot',
        'd': 'EDtBwgOB0uGrSMBJhOmnkRoCupjg-4sJApvOx04ujhKs',
        'i': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6',
        's': '2',
        'p': 'EHeLJVa4LLNRRYVkLQsXHIDvllcmhDaahe5a_oMvXKeP',
        'kt': '2',
        'k': ['DH7p14xo09rob5cEupmo8jSDi35ZOGt1k4t2nm1C1A68',
              'DIAdqJzLWEwQbhXEMOFjvFVZ7oMCJP4XXDP_ILaTEBAQ',
              'DKhYdMBeP6FoH3ajGJTf_4fH229rm_lTZXfYkfwGTMER'],
        'nt': '2',
        'n':
        [
            'EBvDSpcj3y0y9W2-1GzYJ85KEkDIPxu4y_TxAK49k7ci',
            'EEb97lh2oOd_yM3meBaRX5xSs8mIeBoPdhOTgVkd31jb',
            'ECQTrhKHgrOXJS4kdvifvOqoJ7RjfJSsN3nshclYStga'
        ],
        'bt': '3',
        'br': ['BG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ'],
        'ba': ['BH7p14xo09rob5cEupmo8jSDi35ZOGt1k4t2nm1C1A68'],
        'c': [],
        'a': {}
    }


    assert serder.raw == (b'-FCGYKERICAAXrotEDtBwgOB0uGrSMBJhOmnkRoCupjg-4sJApvOx04ujhKsEMEv'
          b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAACEHeLJVa4LLNRRYVkLQsX'
          b'HIDvllcmhDaahe5a_oMvXKePMAAC-LAhDH7p14xo09rob5cEupmo8jSDi35ZOGt1'
          b'k4t2nm1C1A68DIAdqJzLWEwQbhXEMOFjvFVZ7oMCJP4XXDP_ILaTEBAQDKhYdMBe'
          b'P6FoH3ajGJTf_4fH229rm_lTZXfYkfwGTMERMAAC-LAhEBvDSpcj3y0y9W2-1GzY'
          b'J85KEkDIPxu4y_TxAK49k7ciEEb97lh2oOd_yM3meBaRX5xSs8mIeBoPdhOTgVkd'
          b'31jbECQTrhKHgrOXJS4kdvifvOqoJ7RjfJSsN3nshclYStgaMAAD-LALBG9XhvcV'
          b'ryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ-LALBH7p14xo09rob5cEupmo8jSD'
          b'i35ZOGt1k4t2nm1C1A68-LAA-LAA')

    assert len(serder.raw) == serder.size == 540
    sizeh = serder.raw[2:4]
    assert sizeh == b"CG"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 540

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw
    assert len(rawqb64) == 540

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 405
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 638

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 577

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 577

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.42, 1.42, 1.58]


    # Test delcept
    delpre = pre
    keys = [signer.verfer.qb64 for signer in csigners][6:9]
    ndigs = [core.Diger(ser=key.encode()).qb64 for key in keys][:3]
    wits = [signer.verfer.qb64 for signer in wsigners][6:9]
    data = [dict(i=keys[0], s=core.Number(num=3).numh, d=ndigs[0]),
            dict(i=keys[1], s=core.Number(num=4).numh, d=ndigs[1]),
            dict(s=core.Number(num=21).numh, d=ndigs[2]),
            dict(s=core.Number(num=15890).numh, d=ndigs[0])]

    assert data == \
    [
        {
            'i': 'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV',
            's': '3',
            'd': 'EKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DS'
        },
        {
            'i': 'DN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUti',
            's': '4',
            'd': 'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ'
        },
        {
            's': '15',
            'd': 'EHgewy_ymPxtSFwuX2KaI_mPmoIUkxClviX3f-M38kCD'
        },
        {
            's': '3e12',
            'd': 'EKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DS'
        }
    ]



    serder = delcept(keys,
                    isith=["1/2", "1/2", "1/2"],
                    ndigs=ndigs,
                    nsith=["1/2", "1/2", "1/2"],
                    wits=wits,
                    data=data,
                    delpre=delpre,
                    code=core.MtrDex.Blake3_256,
                    version=Vrsn_2_0,
                    kind=kering.Serials.cesr)

    pre = serder.pre
    assert pre == 'ECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8T'
    said = serder.said
    assert said == pre

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'dip',
        'd': 'ECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8T',
        'i': 'ECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8T',
        's': '0',
        'kt': ['1/2', '1/2', '1/2'],
        'k':
        [
            'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV',
            'DN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUti',
            'DOE5jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY'
        ],
        'nt': ['1/2', '1/2', '1/2'],
        'n':
        [
            'EKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DS',
            'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ',
            'EHgewy_ymPxtSFwuX2KaI_mPmoIUkxClviX3f-M38kCD'
        ],
        'bt': '3',
        'b':
        [
            'BIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV',
            'BN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUti',
            'BOE5jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY'
        ],
        'c': [],
        'a':
        [
            {
                'i': 'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV',
                's': '3',
                'd': 'EKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DS'
            },
            {
                'i': 'DN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUti',
                's': '4',
                'd': 'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ'
            },
            {
                's': '15',
                'd': 'EHgewy_ymPxtSFwuX2KaI_mPmoIUkxClviX3f-M38kCD'
            },
            {
                's': '3e12',
                'd': 'EKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DS'
            }
        ],
        'di': 'EMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6'
    }


    assert serder.raw == (b'-FDeYKERICAAXdipECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TECQs'
          b'0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TMAAA4AADA1s2c1s2c1s2-LAh'
          b'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uVDN7WiKyjLLBTK92xayCu'
          b'ddZsBuwPmD2BKrl83h1xEUtiDOE5jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl'
          b'5nfY4AADA1s2c1s2c1s2-LAhEKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ'
          b'44DSEC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZEHgewy_ymPxtSFwu'
          b'X2KaI_mPmoIUkxClviX3f-M38kCDMAAD-LAhBIR8GACw4z2GC5_XoReU4DMKbqi6'
          b'-EdbgDZUAobRb8uVBN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiBOE5'
          b'jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY-LAA-LBI-RAuDIR8GACw4z2G'
          b'C5_XoReU4DMKbqi6-EdbgDZUAobRb8uVMAADEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
          b'iD1D9Qx0MagJ44DSDN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiMAAE'
          b'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ-QAYMAAVEHgewy_ymPxt'
          b'SFwuX2KaI_mPmoIUkxClviX3f-M38kCDMD4SEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
          b'iD1D9Qx0MagJ44DSEMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6')

    assert len(serder.raw) == serder.size == 892
    sizeh = serder.raw[2:4]
    assert sizeh == b"De"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 892

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw

    assert len(rawqb64) == 892

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 669
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 1059

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 953

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 953

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.42, 1.42, 1.58]


    # Test deltate

    prior = said

    keys = [signer.verfer.qb64 for signer in csigners][9:10]
    ndigs = [core.Diger(ser=key.encode()).qb64 for key in keys]
    cuts = [wits[0]]
    adds = [signer.verfer.qb64 for signer in wsigners][9:10]
    data = {}  # no anchors


    serder = deltate(pre=pre,
                    keys=keys,
                    dig=prior,
                      sn=1,
                      ndigs=ndigs,
                      wits=wits, #prior
                      cuts=cuts,
                      adds=adds,
                      data=data,
                      version=Vrsn_2_0,
                      kind=kering.Serials.cesr)

    said = serder.said
    assert said == 'EKwDKG0L9pAMbzV2e31-I5ObiEfkptfs8VqXYiHGCL1v'

    assert serder.sad == \
    {
        'v': 'KERICAACESRAAAA.',
        't': 'drt',
        'd': 'EKwDKG0L9pAMbzV2e31-I5ObiEfkptfs8VqXYiHGCL1v',
        'i': 'ECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8T',
        's': '1',
        'p': 'ECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8T',
        'kt': '1',
        'k': ['DJ0pLe3f2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f'],
        'nt': '1',
        'n': ['ENX_LTL97uOSOkA1PEzam9vtmCLPprnbcpi71wXpmhFF'],
        'bt': '3',
        'br': ['BIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV'],
        'ba': ['BJ0pLe3f2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f'],
        'c': [],
        'a': {}
    }


    assert serder.raw == (b'-FBaYKERICAAXdrtEKwDKG0L9pAMbzV2e31-I5ObiEfkptfs8VqXYiHGCL1vECQs'
                        b'0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TMAABECQs0t3_GL7-B3q4kMU-'
                        b'qLeRCugTFjrxR15mxUwYWp8TMAAB-LALDJ0pLe3f2zGus0Va1dqWAnukWdZHGNWl'
                        b'K9NciJop9N4fMAAB-LALENX_LTL97uOSOkA1PEzam9vtmCLPprnbcpi71wXpmhFF'
                        b'MAAD-LALBIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV-LALBJ0pLe3f'
                        b'2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f-LAA-LAA')

    assert len(serder.raw) == serder.size == 364
    sizeh = serder.raw[2:4]
    assert sizeh == b"Ba"
    assert helping.b64ToInt(sizeh) * 4 + 4 == serder.size == 364

    rawqb64 = serder._dumps()  # default is it dumps self.sad
    assert rawqb64 == serder.raw
    assert len(rawqb64) == 364

    rawqb2 = decodeB64(rawqb64)
    assert len(rawqb2) == 273
    assert rawqb64 == encodeB64(rawqb2)  # round trips

    rawjson = serder.dumps(serder.sad)
    assert len(rawjson) == 450

    rawcbor = serder.dumps(serder.sad, kind=kering.Serials.cbor)
    assert len(rawcbor) == 393

    rawmgpk = serder.dumps(serder.sad, kind=kering.Serials.mgpk)
    assert len(rawmgpk) == 393

    raws = [rawqb2, rawqb64, rawcbor, rawmgpk, rawjson]
    ratios = [ round(len(raw) / len(rawqb2), 2) for raw in raws]

    assert ratios == [1.0, 1.33, 1.44, 1.44, 1.65]


    """End Test"""

def test_cesr_native_dumps_hby():
    """Test Serder._dumps with habery"""

    rawsalt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = core.Salter(raw=rawsalt)
    salt = salter.qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    # need to fix this so it uses different Kind and different Version
    # makHab uses stem=name to make different names have differnt AID pre
    with (habbing.openHby(name="wes", base="test", salt=salt) as wesHby,
         habbing.openHby(name="wok", base="test", salt=salt) as wokHby,
         habbing.openHby(name="wam", base="test", salt=salt) as wamHby,
         habbing.openHby(name="cam", base="test", salt=salt) as camHby):

        # witnesses first so can setup inception event for tam
        wsith = '1'
        wesHab = wesHby.makeHab(name='wes', isith=wsith, icount=1, transferable=False)
        wokHab = wokHby.makeHab(name='wok', isith=wsith, icount=1, transferable=False)
        wamHab = wamHby.makeHab(name='wam', isith=wsith, icount=1, transferable=False)

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        tsith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name='cam', isith=tsith, icount=3, toad=2, wits=wits,)

        assert camHab.kever.prefixer.transferable
        assert len(camHab.iserder.berfers) == len(wits)
        for werfer in camHab.iserder.berfers:
            assert werfer.qb64 in wits
        assert camHab.kever.wits == wits
        assert camHab.kever.toader.num == 2
        assert camHab.kever.sn == 0
        assert camHab.kever.tholder.thold == 2 == int(tsith, 16)

        serder, _, _ = camHab.getOwnEvent(sn=0)

        assert serder.sad == \
        {
            'v': 'KERI10JSON000273_',
             't': 'icp',
             'd': 'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
             'i': 'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
             's': '0',
             'kt': '2',
             'k': ['DJV4r5kpA-DuQGmDr3owzHvcWreg9fWetlS_hoznje4Q',
                   'DHjp2Ewj88Url6d23i6myE-c3bSjOuNgjkZKnF8LkH7C',
                   'DDjY_8DygjZg6F5-qWfZahKwPHjs1gSjzGU6nqikn1g0'],
             'nt': '2',
             'n': ['EHY_zOKIFva_iS1bGuu2etyuQOuq3tOrjaRIYHknRSSz',
                   'ENlS_9WEDDgjpVRmux37ITU4O6UW8hOif-Gwa3Ch0I6t',
                   'EJ67YtK72WQBmGSLS1ibDIVGM4hHtf2HrTPd1Mn51iWV'],
             'bt': '2',
             'b': ['BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom',
                   'BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX',
                   'BByq5Nfi0KgohEaJ8h9JrLqbhX_waySFSXKsgumxEYQp'],
             'c': [],
             'a': []
        }

    """End Test"""

if __name__ == "__main__":
    test_fielddom()
    test_spans()
    test_serder_class()
    test_serder()
    test_serderkeri()
    test_serderkeri_icp()
    test_serderkeri_rot()
    test_serderkeri_ixn()
    test_serderkeri_dip()
    test_serderkeri_drt()
    test_serderkeri_rct()
    test_serderkeri_qry()
    test_serderkeri_rpy()
    test_serderkeri_pro()
    test_serderkeri_bar()
    test_serderkeri_exn()
    test_serderkeri_vcp()
    test_serderacdc()
    test_serder_v2()
    test_serdery()
    test_cesr_native_dumps()
    test_cesr_native_dumps_hby()

