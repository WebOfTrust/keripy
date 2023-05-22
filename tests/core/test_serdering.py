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

from keri.core.serdering import Labelage, Serder, Serdery



def test_serder():
    """
    Test Serder
    """

    # Test Serder

    assert Serder.Labels == {'KERI': {Versionage(major=1, minor=0): {None: Labelage(saids=[], codes=[], fields=['v', 'i', 's', 'p', 'd', 'f', 'dt', 'et', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'ee', 'di']),
                                         'icp': Labelage(saids=['d', 'i'], codes=['E', 'E'], fields=['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a']),
                                         'rot': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'br', 'ba', 'a']),
                                         'ixn': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'i', 's', 'p', 'a']),
                                         'dip': Labelage(saids=['d', 'i'], codes=['E', 'E'], fields=['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a', 'di']),
                                         'drt': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'br', 'ba', 'a', 'di']),
                                         'rct': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'i', 's']),
                                         'qry': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'dt', 'r', 'rr', 'q']),
                                         'rpy': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'dt', 'r', 'a']),
                                         'pro': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'dt', 'r', 'rr', 'q']),
                                         'bar': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'dt', 'r', 'a']),
                                         'exn': Labelage(saids=['d'], codes=['E'], fields=['v', 't', 'd', 'dt', 'r', 'q', 'a'])}},
                             'ACDC': {Versionage(major=1, minor=0): {None: Labelage(saids=['d'], codes=['E'], fields=['v', 'd', 'i', 's'])}}}

    assert Serder.Ilks == {'KERI': None, 'ACDC': None}

    assert Serder.Labels[kering.Protos.acdc][kering.Vrsn_1_0][None].saids == ['d']
    assert Serder.Labels[kering.Protos.acdc][kering.Vrsn_1_0][None].codes == [coring.DigDex.Blake3_256]
    assert Serder.Labels[kering.Protos.acdc][kering.Vrsn_1_0][None].fields == ['v', 'd', 'i', 's']

    # said field labels must be subset of all field labels
    assert (set(Serder.Labels[kering.Protos.acdc][kering.Vrsn_1_0][None].saids) <=
            set(Serder.Labels[kering.Protos.acdc][kering.Vrsn_1_0][None].fields))


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



if __name__ == "__main__":
    test_serder()
