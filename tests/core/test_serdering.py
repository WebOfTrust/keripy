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
from keri.kering import Versionage

from keri.core import coring

from keri.core.serdering import (Fieldage, Serdery, Serder,
                                 SerderKERI, SerderACDC, )



def test_serder():
    """
    Test Serder
    """

    # Test Serder

    assert Serder.Fields == {'KERI': {Versionage(major=1, minor=0):
                                        {None: Fieldage(saids={}, alls={'v': '', 'i': '', 's': '0', 'p': '', 'd': '', 'f': '0', 'dt': '', 'et': '', 'kt': '1', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'ee': {}, 'di': ''}),
                                         'icp': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '1', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': []}),
                                         'rot': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '1', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'br': [], 'ba': [], 'a': []}),
                                         'ixn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'a': []}),
                                         'dip': Fieldage(saids={'d': 'E', 'i': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'kt': '1', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'c': [], 'a': [], 'di': ''}),
                                         'drt': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0', 'p': '', 'kt': '1', 'k': [], 'nt': '0', 'n': [], 'bt': '0', 'b': [], 'br': [], 'ba': [], 'a': [], 'di': ''}),
                                         'rct': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'i': '', 's': '0'}),
                                         'qry': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'rpy': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'a': []}),
                                         'pro': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'rr': '', 'q': {}}),
                                         'bar': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'a': []}),
                                         'exn': Fieldage(saids={'d': 'E'}, alls={'v': '', 't': '', 'd': '', 'dt': '', 'r': '', 'q': {}, 'a': []})}},
                             'ACDC': {Versionage(major=1, minor=0):
                                        {None: Fieldage(saids={'d': 'E'}, alls={'v': '', 'd': '', 'i': '', 's': ''})}}}

    assert Serder.Ilks == {'KERI': None, 'ACDC': None}

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

    # Test ACDC JSON bootstrap with Saider.saidify
    sad = dict(v=kering.versify(proto=kering.Protos.acdc,
                                version=kering.Version,
                                kind=kering.Serials.json),
               d="",
               i="",
               s="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'ACDC10JSON00005a_',
                   'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                   'i': '',
                   's': ''}

    assert saider.qb64 == sad["d"]
    saidAcdcJson = sad["d"]  # save for later

    serder = Serder(sad=sad)
    assert serder.raw == (b'{"v":"ACDC10JSON00005a_",'
                          b'"d":"EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT",'
                          b'"i":"","s":""}')
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                               ' "v": "ACDC10JSON00005a_",\n'
                               ' "d": "EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT",\n'
                               ' "i": "",\n'
                               ' "s": ""\n'
                               '}')

    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')

    rawJSON = serder.raw  # save for later tests
    assert rawJSON == (b'{"v":"ACDC10JSON00005a_",'
                       b'"d":"EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT",'
                       b'"i":"","s":""}')

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True, codes=[coring.DigDex.Blake3_256])  # test makify
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON)
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON, verify=False)  # test without verify
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # Test ignores strip if raw is bytes not bytearray
    serder = Serder(raw=rawJSON, strip=True)
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    # Test strip of bytearray
    extra = bytearray(b'Not a serder.')
    stream = bytearray(rawJSON) + extra
    assert stream == bytearray(b'{"v":"ACDC10JSON00005a_","d":"EMk7BvrqO_2sYjp'
                               b'I_-BmSELOFNie-muw4XTi3iYCz6pT","i":"","s":""}'
                               b'Not a serder.')
    serder = Serder(raw=stream, strip=True)
    assert serder.raw == rawJSON
    assert isinstance(serder.raw, bytes)
    assert stream == extra
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # test verify bad digest value
    badraw = (b'{"v":"ACDC10JSON00005a_",'
              b'"d":"EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE",'
              b'"i":"","s":""}')
    with pytest.raises(kering.ValidationError):
        serder = Serder(raw=badraw, verify=True)

    # Test ACDC CBOR bootstrap with Saider.saidify
    sad = dict(v=kering.versify(proto=kering.Protos.acdc,
                                version=kering.Version,
                                kind=kering.Serials.cbor),
               d="",
               i="",
               s="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'ACDC10CBOR00004b_',
                    'd': 'EGahYhEMb_Sz0L1UwhrUvbyxyzoi_G85-pD9jRjhnqgU',
                    'i': '',
                    's': ''}

    assert saider.qb64 == sad["d"]

    serder = Serder(sad=sad)
    assert serder.raw == (b'\xa4avqACDC10CBOR00004b_adx,EGahYhEMb_Sz0L1UwhrUv'
                          b'byxyzoi_G85-pD9jRjhnqgUai`as`')
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                                ' "v": "ACDC10CBOR00004b_",\n'
                                ' "d": "EGahYhEMb_Sz0L1UwhrUvbyxyzoi_G85-pD9jRjhnqgU",\n'
                                ' "i": "",\n'
                                ' "s": ""\n'
                                '}')
    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8e')

    rawCBOR = serder.raw  # save for later tests
    assert rawCBOR == (b'\xa4avqACDC10CBOR00004b_adx,EGahYhEMb_Sz0L1UwhrUv'
                          b'byxyzoi_G85-pD9jRjhnqgUai`as`')

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawCBOR)
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawCBOR, verify=False)  # test without verify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None


    # Test ACDC MGPK bootstrap with Saider.saidify
    sad = dict(v=kering.versify(proto=kering.Protos.acdc,
                                version=kering.Version,
                                kind=kering.Serials.mgpk),
               d="",
               i="",
               s="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'ACDC10MGPK00004b_',
                    'd': 'EGV5wdF1nRbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC',
                    'i': '',
                    's': ''}

    assert saider.qb64 == sad["d"]

    serder = Serder(sad=sad)
    assert serder.raw == (b'\x84\xa1v\xb1ACDC10MGPK00004b_\xa1d\xd9,EGV5wdF1n'
                          b'RbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC\xa1i\xa0\xa1s\xa0')
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                                ' "v": "ACDC10MGPK00004b_",\n'
                                ' "d": "EGV5wdF1nRbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC",\n'
                                ' "i": "",\n'
                                ' "s": ""\n'
                                '}')
    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8e')

    rawMGPK = serder.raw  # save for later tests
    assert rawMGPK == (b'\x84\xa1v\xb1ACDC10MGPK00004b_\xa1d\xd9,EGV5wdF1n'
                          b'RbSXatBgZDpAxlGL6BuATjpUYBuk0AQW7GC\xa1i\xa0\xa1s\xa0')

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawMGPK)
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawMGPK, verify=False)  # test not verify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 75
    assert serder.kind == kering.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # test ACDC JSON with makify defaults for self bootstrap of ACDC
    serder = Serder(makify=True, proto=kering.Protos.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                          'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                          'i': '',
                          's': ''}
    assert serder.raw == rawJSON
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 90
    assert serder.kind == kering.Serials.json
    assert serder.said == saidAcdcJson
    assert serder.ilk == None

    # Test KERI JSON with makify defaults for self bootstrap which is state msg
    serder = Serder(makify=True)  # make with all defaults is state message
    assert serder.sad == {'v': 'KERI10JSON000090_',
                        'i': '',
                        's': '',
                        'p': '',
                        'd': '',
                        'f': '',
                        'dt': '',
                        'et': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'ee': '',
                        'di': ''}
    assert serder.raw == (b'{"v":"KERI10JSON000090_","i":"","s":"","p":"","d":"","f":"","dt":"","et":"",'
                          b'"kt":"","k":"","nt":"","n":"","bt":"","b":"","c":"","ee":"","di":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 144
    assert serder.kind == kering.Serials.json
    assert serder.said == None
    assert serder.ilk == None

    sad = serder.sad
    raw = serder.raw

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 144
    assert serder.kind == kering.Serials.json
    assert serder.said == None
    assert serder.ilk == None

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 144
    assert serder.kind == kering.Serials.json
    assert serder.said == None
    assert serder.ilk == None


    # Test KERI JSON with makify defaults for self bootstrap with ilk icp
    serder = Serder(makify=True, ilk=kering.Ilks.icp)  # make with defaults
    assert serder.sad == {
                            'v': 'KERI10JSON0000cb_',
                            't': 'icp',
                            'd': 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J',
                            'i': 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J',
                            's': '',
                            'kt': '',
                            'k': '',
                            'nt': '',
                            'n': '',
                            'bt': '',
                            'b': '',
                            'c': '',
                            'a': ''
                         }
    assert serder.raw == (b'{"v":"KERI10JSON0000cb_","t":"icp","d":"EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KG'
                          b'f87Bc70J","i":"EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J","s":"","kt":"",'
                          b'"k":"","nt":"","n":"","bt":"","b":"","c":"","a":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 203
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.sad['i'] == serder.said
    assert serder.ilk == kering.Ilks.icp
    assert serder.pretty() == ('{\n'
                        ' "v": "KERI10JSON0000cb_",\n'
                        ' "t": "icp",\n'
                        ' "d": "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J",\n'
                        ' "i": "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J",\n'
                        ' "s": "",\n'
                        ' "kt": "",\n'
                        ' "k": "",\n'
                        ' "nt": "",\n'
                        ' "n": "",\n'
                        ' "bt": "",\n'
                        ' "b": "",\n'
                        ' "c": "",\n'
                        ' "a": ""\n'
                        '}')
    assert serder.compare(said=serder.said)
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')

    sad = serder.sad  # save for later
    raw = serder.raw  # save for later
    size = serder.size # save for later
    said = serder.said  # save for later


    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.icp


    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.icp

    # Test with non-digestive code for 'i' saidive field no sad
    serder = Serder(makify=True, ilk=kering.Ilks.icp, codes=[None, coring.PreDex.Ed25519])
    assert serder.sad == {'v': 'KERI10JSON00009f_',
                        't': 'icp',
                        'd': 'EFmPBVkCqAbAOO8JHr4WJDvR-lcb14SzW1tQ5C53S3-T',
                        'i': '',
                        's': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'a': ''}

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad = serder.sad
    sad['i'] = pre

    serder = Serder(sad=sad, makify=True)
    assert serder.sad == {'v': 'KERI10JSON0000cb_',
                        't': 'icp',
                        'd': 'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL',
                        'i': 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx',
                        's': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'a': ''}
    assert serder.sad['i'] == pre
    sad = serder.sad  # save for later

    serder = Serder(sad=sad)  # test verify
    assert serder.sad == sad


    # Test KERI JSON with makify defaults for self bootstrap with ilk icp
    serder = Serder(makify=True, ilk=kering.Ilks.rot)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000af_',
                            't': 'rot',
                            'd': 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx',
                            'i': '',
                            's': '',
                            'p': '',
                            'kt': '',
                            'k': '',
                            'nt': '',
                            'n': '',
                            'bt': '',
                            'b': '',
                            'br': '',
                            'ba': '',
                            'a': ''}
    assert serder.raw == (b'{"v":"KERI10JSON0000af_","t":"rot","d":"EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF'
                          b'9TuM2smx","i":"","s":"","p":"","kt":"","k":"","nt":"","n":"","bt":"","b":"",'
                          b'"br":"","ba":"","a":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot

    sad = serder.sad
    raw = serder.raw

    serder = Serder(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot

    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot


    # ToDo: create malicious raw values to test verify more thoroughly
    # ToDo: create bad sad values to test makify more thoroughly
    # unhappy paths


    """End Test"""

def test_serderkeri():
    """Test SerderKERI"""

    # Test KERI JSON with makify defaults for self bootstrap with ilk icp
    serder = SerderKERI(makify=True, ilk=kering.Ilks.icp)  # make with defaults
    assert serder.sad == {
                            'v': 'KERI10JSON0000cb_',
                            't': 'icp',
                            'd': 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J',
                            'i': 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J',
                            's': '',
                            'kt': '',
                            'k': '',
                            'nt': '',
                            'n': '',
                            'bt': '',
                            'b': '',
                            'c': '',
                            'a': ''
                         }
    assert serder.raw == (b'{"v":"KERI10JSON0000cb_","t":"icp","d":"EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KG'
                          b'f87Bc70J","i":"EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J","s":"","kt":"",'
                          b'"k":"","nt":"","n":"","bt":"","b":"","c":"","a":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 203
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.sad['i'] == serder.said
    assert serder.ilk == kering.Ilks.icp
    assert serder.pretty() == ('{\n'
                        ' "v": "KERI10JSON0000cb_",\n'
                        ' "t": "icp",\n'
                        ' "d": "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J",\n'
                        ' "i": "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J",\n'
                        ' "s": "",\n'
                        ' "kt": "",\n'
                        ' "k": "",\n'
                        ' "nt": "",\n'
                        ' "n": "",\n'
                        ' "bt": "",\n'
                        ' "b": "",\n'
                        ' "c": "",\n'
                        ' "a": ""\n'
                        '}')
    assert serder.compare(said=serder.said)
    assert not serder.compare(said='EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pE')

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None


    sad = serder.sad  # save for later
    raw = serder.raw  # save for later
    size = serder.size # save for later
    said = serder.said  # save for later


    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.icp

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None


    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.icp

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    # Test with non-digestive code for 'i' saidive field no sad
    serder = SerderKERI(makify=True, ilk=kering.Ilks.icp, codes=[None, coring.PreDex.Ed25519])
    assert serder.sad == {'v': 'KERI10JSON00009f_',
                        't': 'icp',
                        'd': 'EFmPBVkCqAbAOO8JHr4WJDvR-lcb14SzW1tQ5C53S3-T',
                        'i': '',
                        's': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'a': ''}

    # test makify with preloaded non-digestive 'i' value in sad
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    sad = serder.sad
    sad['i'] = pre

    serder = SerderKERI(sad=sad, makify=True)
    assert serder.sad == {'v': 'KERI10JSON0000cb_',
                        't': 'icp',
                        'd': 'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL',
                        'i': 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx',
                        's': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'a': ''}
    assert serder.sad['i'] == pre
    sad = serder.sad  # save for later

    serder = SerderKERI(sad=sad)  # test verify
    assert serder.sad == sad


    # Test KERI JSON with makify defaults for self bootstrap with ilk rot
    serder = SerderKERI(makify=True, ilk=kering.Ilks.rot)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000af_',
                            't': 'rot',
                            'd': 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx',
                            'i': '',
                            's': '',
                            'p': '',
                            'kt': '',
                            'k': '',
                            'nt': '',
                            'n': '',
                            'bt': '',
                            'b': '',
                            'br': '',
                            'ba': '',
                            'a': ''}
    assert serder.raw == (b'{"v":"KERI10JSON0000af_","t":"rot","d":"EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF'
                          b'9TuM2smx","i":"","s":"","p":"","kt":"","k":"","nt":"","n":"","bt":"","b":"",'
                          b'"br":"","ba":"","a":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == None
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    sad = serder.sad
    raw = serder.raw

    with pytest.raises(kering.ValidationError):
        serder = SerderKERI(sad=sad)

    serder = SerderKERI(sad=sad, verify=False)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == None
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    with pytest.raises(kering.ValidationError):
        serder = SerderKERI(raw=raw)

    serder = SerderKERI(raw=raw, verify=False)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 175
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx'
    assert serder.ilk == kering.Ilks.rot

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == None
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    # fix empty pre so verify works and add values to other fields
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 1
    sad['kt'] = 1
    sad['k'] = ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    sad['nt'] = 1
    sad['n'] = ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    sad['bt'] = 0
    sad['b'] = []
    sad['a'] = []

    # first makify to get said correct
    serder = SerderKERI(sad=sad, makify=True)
    sad = serder.sad
    raw = serder.raw
    said = serder.said

    # Now test verify
    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 307
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.rot

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 1
    assert serder.sn == 1
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '1'
    assert [verfer.qb64 for verfer in serder.verfers] == ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    assert serder.ntholder.sith == '1'
    assert [diger.qb64 for diger in serder.ndigers] == ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 307
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.rot

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 1
    assert serder.sn == 1
    assert serder.seals == []
    assert serder.traits == None
    assert serder.tholder.sith == '1'
    assert [verfer.qb64 for verfer in serder.verfers] == ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    assert serder.ntholder.sith == '1'
    assert [diger.qb64 for diger in serder.ndigers] == ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == None
    assert serder.delpreb == None
    assert serder.fner == None
    assert serder.fn == None

    # Test KERI JSON with makify defaults for self bootstrap with ilk ixn
    serder = SerderKERI(makify=True, ilk=kering.Ilks.ixn)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON000072_',
                        't': 'ixn',
                        'd': 'EKb6MbjiEAo_xmyDOeeOdRcPU7myPt0USWdTtKybS1ri',
                        'i': '',
                        's': '',
                        'p': '',
                        'a': ''}

    assert serder.raw == (b'{"v":"KERI10JSON000072_","t":"ixn","d":"EKb6MbjiEAo_xmyDOeeOdRcPU7myPt0USWdT'
                          b'tKybS1ri","i":"","s":"","p":"","a":""}')

    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 114
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EKb6MbjiEAo_xmyDOeeOdRcPU7myPt0USWdTtKybS1ri'
    assert serder.ilk == kering.Ilks.ixn

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
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
    assert serder.fner == None
    assert serder.fn == None

    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    with pytest.raises(kering.ValidationError):
        serder = SerderKERI(sad=sad)

    serder = SerderKERI(sad=sad, verify=False)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.ixn

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
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
    assert serder.fner == None
    assert serder.fn == None


    with pytest.raises(kering.ValidationError):
        serder = SerderKERI(raw=raw)

    serder = SerderKERI(raw=raw, verify=False)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.ixn

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == ''
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
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
    assert serder.fner == None
    assert serder.fn == None


    # fix empty pre so verify works and add values to other fields
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 2
    sad['a'] = []

    # first makify to get said correct
    serder = SerderKERI(sad=sad, makify=True)
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    # Now test verify
    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.ixn

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 2
    assert serder.sn == 2
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
    assert serder.fner == None
    assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.ixn

    assert not serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 2
    assert serder.sn == 2
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
    assert serder.fner == None
    assert serder.fn == None

    # Test KERI JSON with makify defaults for self bootstrap with ilk dip
    serder = SerderKERI(makify=True, ilk=kering.Ilks.dip)  # make with defaults
    assert serder.sad == {'v': 'KERI10JSON0000d3_',
                        't': 'dip',
                        'd': 'EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2',
                        'i': 'EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2',
                        's': '',
                        'kt': '',
                        'k': '',
                        'nt': '',
                        'n': '',
                        'bt': '',
                        'b': '',
                        'c': '',
                        'a': '',
                        'di': ''}
    assert serder.raw == (b'{"v":"KERI10JSON0000d3_","t":"dip","d":"EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW3'
                          b'27FMA6D2","i":"EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2","s":"","kt":"",'
                          b'"k":"","nt":"","n":"","bt":"","b":"","c":"","a":"","di":""}')
    assert serder.proto == kering.Protos.keri
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == 211
    assert serder.kind == kering.Serials.json
    assert serder.said == 'EO8CE5RH1X8QJwHHhPkj_S6LJQDRNOiGohW327FMA6D2'
    assert serder.ilk == kering.Ilks.dip

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == serder.said
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == ''
    assert serder.delpreb == b''
    assert serder.fner == None
    assert serder.fn == None

    sad = serder.sad
    raw = serder.raw
    size = serder.size
    said = serder.said

    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.dip

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == serder.said
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == ''
    assert serder.delpreb == b''
    assert serder.fner == None
    assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.dip

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == serder.said
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 0
    assert serder.sn == 0
    assert serder.seals == ""
    assert serder.traits == ""
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.tholder.sith == ''
    assert [verfer.qb64 for verfer in serder.verfers] == []
    with pytest.raises(kering.EmptyMaterialError):
        assert serder.ntholder.sith == ''
    assert [diger.qb64 for diger in serder.ndigers] == []
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == ''
    assert serder.delpreb == b''
    assert serder.fner == None
    assert serder.fn == None

    # fix empty pre so verify works and add values to other fields
    pre = "EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J"
    sad['i'] = pre
    sad['s'] = 1
    sad['kt'] = 1
    sad['k'] = ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    sad['nt'] = 1
    sad['n'] = ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    sad['bt'] = 0
    sad['b'] = []
    sad['c'] = []
    sad['a'] = []
    sad['di'] =  'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL'

    # first makify to get said correct
    serder = SerderKERI(sad=sad, makify=True)
    pre = serder.pre
    sad = serder.sad
    raw = serder.raw
    said = serder.said
    size = serder.size

    # Now test verify
    serder = SerderKERI(sad=sad)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.dip

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 1
    assert serder.sn == 1
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '1'
    assert [verfer.qb64 for verfer in serder.verfers] == ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    assert serder.ntholder.sith == '1'
    assert [diger.qb64 for diger in serder.ndigers] == ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == 'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL'
    assert serder.delpreb == b'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL'
    assert serder.fner == None
    assert serder.fn == None

    serder = SerderKERI(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == kering.Ilks.dip

    assert serder.estive
    assert serder.ked == serder.sad
    assert serder.pre == serder.sad['i'] == pre
    assert serder.preb == serder.pre.encode("utf-8")
    assert serder.sner.num == 1
    assert serder.sn == 1
    assert serder.seals == []
    assert serder.traits == []
    assert serder.tholder.sith == '1'
    assert [verfer.qb64 for verfer in serder.verfers] == ['DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx']
    assert serder.ntholder.sith == '1'
    assert [diger.qb64 for diger in serder.ndigers] == ['EIg9cWt662gJKnn4FRuKAvxOOKAATCt_THBF9TuM2smx']
    assert serder.bner.num == 0
    assert serder.bn == 0
    assert [verfer.qb64 for verfer in serder.berfers] == []
    assert serder.delpre == 'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL'
    assert serder.delpreb == b'EDnHYttCtZK1pWFax-VfqLoCB-hEMeo11Wg14r0Qy4AL'
    assert serder.fner == None
    assert serder.fn == None

    """End Test"""

def test_serderacdc():
    """Test SerderACDC"""

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

    assert serder.isr == serder.sad['i'] == ''
    assert serder.isrb == serder.isr.encode("utf-8")

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
    assert serder.isr ==  isr


    serder = SerderACDC(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == kering.Protos.acdc
    assert serder.vrsn == kering.Vrsn_1_0
    assert serder.size == size
    assert serder.kind == kering.Serials.json
    assert serder.said == said
    assert serder.ilk == None
    assert serder.isr ==  isr



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

if __name__ == "__main__":
    test_serder()
    test_serderkeri()
    test_serderacdc()
    test_serdery()
