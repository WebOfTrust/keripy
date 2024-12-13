# -*- encoding: utf-8 -*-
"""
tests.core.test_serdering module

"""
import dataclasses
import json
from collections import namedtuple

import cbor2 as cbor
import msgpack

import pytest

from keri import kering
from keri.kering import Versionage, Version

from keri.core import coring

from keri.core.serdering import (Fieldage, Serdery, Serder,
                                 SerderKERI, SerderACDC, )



def test_serder():
    """
    Test Serder
    """

    # Test Serder

    assert Serder.Fields == {'KERI': {Versionage(major=1, minor=0): {'icp': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': []}),
                                         'rot': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'br': [], 'ba': [], 'a': []}),
                                         'ixn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'a': []}),
                                         'dip': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': [], 'di': ''}),
                                         'drt': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'br': [], 'ba': [], 'a': []}),
                                         'rct': Fieldage(saids={}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0'}),
                                         'qry': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'rpy': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'a': []}),
                                         'pro': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'bar': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'a': []}),
                                         'exn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'rp': '', 'p': '', 'dt': '', 'r': '', 'q': {}, 'a': [], 'e': {}}),
                                         'vcp': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'ii': '', 's': '0', 'c': [], 'bt': '0', 'b': [], 'n': ''}),
                                         'vrt': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'p': '', 's': '0', 'bt': '0', 'br': [], 'ba': []}),
                                         'iss': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'ri': '', 'dt': ''}),
                                         'rev': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'ri': '', 'p': '', 'dt': ''}),
                                         'bis': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'ii': '', 's': '0', 'ra': {}, 'dt': ''}),
                                         'brv': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'ra': {}, 'dt': ''})},
                                      Versionage(major=1, minor=1): {'icp': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': []}),
                                         'rot': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'br': [], 'ba': [], 'c': [], 'a': []}),
                                         'ixn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'a': []}),
                                         'dip': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': [], 'di': ''}),
                                         'drt': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '0', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'br': [], 'ba': [], 'c': [], 'a': []}),
                                         'rct': Fieldage(saids={}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0'}),
                                         'qry': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'rpy': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'dt': '', 'r': '', 'a': []}),
                                         'pro': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'bar': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'dt': '', 'r': '', 'a': []}),
                                         'exn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'rp': '', 'p': '', 'dt': '', 'r': '', 'q': {}, 'a': [], 'e': {}})}},
                             'CREL': {Versionage(major=1, minor=1): {'vcp': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'ii': '', 's': '0', 'c': [], 'bt': '0', 'b': [], 'u': ''}),
                                         'vrt': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'p': '', 's': '0', 'bt': '0', 'br': [], 'ba': []}),
                                         'iss': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'ri': '', 'dt': ''}),
                                         'rev': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'ri': '', 'p': '', 'dt': ''}),
                                         'bis': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 'ii': '', 's': '0', 'ra': {}, 'dt': ''}),
                                         'brv': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'ra': {}, 'dt': ''})}},
                             'ACDC': {Versionage(major=1, minor=0): {None: Fieldage(saids={'d': 'E'}, alls={'v': '', 'd': '', 'i': '', 's': ''})}}}


    assert Serder.Ilks == {'KERI': 'icp', 'CREL': 'vcp', 'ACDC': None}

    assert Serder.Fields[kering.Protos.acdc][kering.Vrsn_1_0][None].saids == {'d': 'E'}
    assert Serder.Fields[kering.Protos.acdc][kering.Vrsn_1_0][None].alls == {'v': '', 'd': '', 'i': '', 's': ''}

    # said field labels must be subset of all field labels
    assert (set(Serder.Fields[kering.Protos.acdc][kering.Vrsn_1_0][None].saids.keys()) <=
            set(Serder.Fields[kering.Protos.acdc][kering.Vrsn_1_0][None].alls.keys()))


    for proto, vrsns in Serder.Fields.items():
        for vrsn, ilks in vrsns.items():
            for ilk, fields in ilks.items():
                assert set(fields.saids.keys()) <= set(fields.alls.keys())


    with pytest.raises(ValueError):
        serder = Serder()

    #Test Serder bare makify bootstrap for ACDC JSON
    serder = Serder(makify=True, proto=kering.Protos.acdc)  # make defaults for ACDC
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    serder = Serder(makify=True, proto=kering.Protos.acdc, kind=kering.Serials.cbor)
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.cbor
    assert serder.said == said
    assert serder.saidb == said.encode("utf-8")
    assert serder.ilk == None
    assert serder.compare(said=said)


    #Test makify bootstrap for ACDC with MGPK
    serder = Serder(makify=True, proto=kering.Protos.acdc, kind=kering.Serials.mgpk)
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk


    # Test with non-digestive code for 'i' saidive field no sad
    serder = Serder(makify=True,
                    ilk=kering.Ilks.icp,
                    saids = {'i': coring.PreDex.Ed25519})

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
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == ilk



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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
                    saids = {'i': coring.PreDex.Ed25519})

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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rot)  # make with defaults
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn)  # make with defaults
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    serder = SerderKERI(makify=True, ilk=kering.Ilks.dip)  # make with defaults
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
    said = serder.said
    size = serder.size
    ilk = serder.ilk
    pre = serder.pre

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
                    saids = {'i': coring.PreDex.Ed25519})

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

    serder = SerderKERI(sad=sad, makify=True)

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
                        saids = {'i': coring.PreDex.Blake3_256})

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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    serder = SerderKERI(makify=True, ilk=kering.Ilks.drt)  # make with defaults
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

    serder = SerderKERI(sad=sad, makify=True)

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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rct)  # make with defaults
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.sad == {'v': 'KERI10JSON000090_',
                            't': 'exn',
                            'd': 'EPx9pShQTfv2FoISZJAZ4dlUcekG8-CSkgJh0i0q_iJn',
                            'i': '',
                            'rp': '',
                            'p': '',
                            'dt': '',
                            'r': '',
                            'q': {},
                            'a': [],
                            'e': {}}

    assert serder.raw == (b'{"v":"KERI10JSON000090_","t":"exn","d":"EPx9pShQTfv2FoISZJAZ4dlUcekG8-CSkgJh0i0q_iJn",'
                          b'"i":"","rp":"","p":"","dt":"","r":"","q":{},"a":[],"e":{}}')

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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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
    assert serder.proto == kering.Protos.keri
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

    with pytest.raises(ValueError):
        serder = SerderACDC()

    serder = SerderACDC(makify=True, proto=kering.Protos.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                          'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                          'i': '',
                          's': ''}
    assert serder.raw == (b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjpI_'
                          b'-BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}')

    assert serder.proto == kering.Protos.acdc
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
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None
    assert serder.issuer ==  isr


    serder = SerderACDC(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None
    assert serder.issuer ==  isr



    """End Test"""


def test_serdery():
    """Test Serdery"""
    #Create incoming message stream for Serdery to reap

    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn)  # make with defaults
    sad = serder.sad
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 2
    sad['a'] = []
    serderKeri = SerderKERI(sad=sad, makify=True)
    assert serderKeri.verify()

    ims = bytearray(serderKeri.raw)

    serder = SerderACDC(makify=True, proto=kering.Protos.acdc)  # make defaults for ACDC
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

    serdery = Serdery(version=Version)

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

def test_serdery_noversion():
    """Test Serdery unsupported version"""
    #Create incoming message stream for Serdery to reap

    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn)  # make with defaults
    sad = serder.sad
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 2
    sad['a'] = []
    serderKeri = SerderKERI(sad=sad, makify=True)
    assert serderKeri.verify()

    ims = bytearray(serderKeri.raw)

    serder = SerderACDC(makify=True, proto=kering.Protos.acdc)  # make defaults for ACDC
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

    serdery = Serdery()  # effective version is None

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


if __name__ == "__main__":
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
    test_serdery()
    test_serdery_noversion()
