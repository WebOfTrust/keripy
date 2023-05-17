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
from keri.core.serdering import Serder, Serdery



def test_serder():
    """
    Test Serder
    """

    # Test Serder

    assert Serder.Labels[coring.Protos.acdc][None].saids == ['d']
    assert Serder.Labels[coring.Protos.acdc][None].codes == [coring.DigDex.Blake3_256]
    assert Serder.Labels[coring.Protos.acdc][None].fields == ['v', 'd', 'i', 's']

    # said field labels must be subset of all field labels
    assert (set(Serder.Labels[coring.Protos.acdc][None].saids) <=
            set(Serder.Labels[coring.Protos.acdc][None].fields))


    with pytest.raises(ValueError):
        serder = Serder()


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

    # Test CBOR
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


    # Test MGPK
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


    # ToDo: create malicious raw values to test verify more thoroughly
    # ToDo: create bad sad values to test makify more thoroughly
    # unhappy paths






    """End Test"""



if __name__ == "__main__":
    test_serder()
