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
from keri.core import coring
from keri.core.serdering import Labelage, Serder, Serdery



def test_serder():
    """
    Test Serder
    """

    # Test Serder

    assert Serder.Labels == {'KERI':
                             {'icp': Labelage(saids=['d', 'i'],
                                              codes=['E', 'E'],
                                              fields=['v', 't', 'd', 'i', 's',
                                                      'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'])},
                            'ACDC':
                              {None: Labelage(saids=['d'],
                                              codes=['E'],
                                              fields=['v', 'd', 'i', 's'])}}

    assert Serder.Ilks == {'KERI': 'icp', 'ACDC': None}

    assert Serder.Labels[coring.Protos.acdc][None].saids == ['d']
    assert Serder.Labels[coring.Protos.acdc][None].codes == [coring.DigDex.Blake3_256]
    assert Serder.Labels[coring.Protos.acdc][None].fields == ['v', 'd', 'i', 's']

    # said field labels must be subset of all field labels
    assert (set(Serder.Labels[coring.Protos.acdc][None].saids) <=
            set(Serder.Labels[coring.Protos.acdc][None].fields))


    with pytest.raises(ValueError):
        serder = Serder()

    # Test ACDC JSON bootstrap with Saider.saidify
    sad = dict(v=coring.versify(proto=coring.Protos.acdc,
                                version=coring.Version,
                                kind=coring.Serials.json),
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
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
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
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True, codes=[coring.DigDex.Blake3_256])  # test makify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON)
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON, verify=False)  # test without verify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
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
    sad = dict(v=coring.versify(proto=coring.Protos.acdc,
                                version=coring.Version,
                                kind=coring.Serials.cbor),
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
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.cbor
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
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawCBOR)
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawCBOR, verify=False)  # test without verify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None


    # Test ACDC MGPK bootstrap with Saider.saidify
    sad = dict(v=coring.versify(proto=coring.Protos.acdc,
                                version=coring.Version,
                                kind=coring.Serials.mgpk),
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
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.mgpk
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
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawMGPK)
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawMGPK, verify=False)  # test not verify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 75
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # test ACDC JSON with makify defaults for self bootstrap of ACDC
    serder = Serder(makify=True, proto=coring.Protos.acdc)  # make defaults for ACDC
    assert serder.sad == {'v': 'ACDC10JSON00005a_',
                          'd': 'EMk7BvrqO_2sYjpI_-BmSELOFNie-muw4XTi3iYCz6pT',
                          'i': '',
                          's': ''}
    assert serder.raw == rawJSON
    assert serder.proto == coring.Protos.acdc
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 90
    assert serder.kind == coring.Serials.json
    assert serder.said == saidAcdcJson
    assert serder.ilk == None

    # Test KERI JSON with makify defaults for self bootstrap
    serder = Serder(makify=True)  # make with defaults
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
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 203
    assert serder.kind == coring.Serials.json
    assert serder.said == 'EDGnGYIa5obfFUhxcAuUmM4fJyeRYj2ti3KGf87Bc70J'
    assert serder.sad['i'] == serder.said
    assert serder.ilk == coring.Ilks.icp
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
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == size
    assert serder.kind == coring.Serials.json
    assert serder.said == said
    assert serder.ilk == coring.Ilks.icp



    serder = Serder(raw=raw)
    assert serder.raw == raw
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == size
    assert serder.kind == coring.Serials.json
    assert serder.said == said
    assert serder.ilk == coring.Ilks.icp

    serder = Serder(makify=True, codes=[None, coring.PreDex.Ed25519])  # test makify
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




    # ToDo: create malicious raw values to test verify more thoroughly
    # ToDo: create bad sad values to test makify more thoroughly
    # unhappy paths






    """End Test"""



if __name__ == "__main__":
    test_serder()
