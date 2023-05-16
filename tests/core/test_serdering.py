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

    assert Serder.Labels[None].saids == ['d']
    assert Serder.Labels[None].fields == ['v', 'd']

    # said field labels must be subset of all field labels
    assert set(Serder.Labels[None].saids) <= set(Serder.Labels[None].fields)


    with pytest.raises(ValueError):
        serder = Serder()

    sad = dict(v=coring.Vstrings.json, #
               d="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'KERI10JSON00004c_',
                   'd': 'EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8d'}

    assert saider.qb64 == sad["d"]

    serder = Serder(sad=sad)
    assert serder.raw == (b'{"v":"KERI10JSON00004c_",'
                          b'"d":"EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8d"}')
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 76
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                                ' "v": "KERI10JSON00004c_",\n'
                                ' "d": "EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8d"\n'
                                '}')

    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8e')

    rawJSON = serder.raw  # save for later tests
    assert rawJSON == (b'{"v":"KERI10JSON00004c_",'
                              b'"d":"EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8d"}')

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 76
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(sad=sad, makify=True)  # test makify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 76
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON)
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 76
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawJSON, verify=False)  # test without verify
    assert serder.raw == rawJSON
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 76
    assert serder.kind == coring.Serials.json
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # test verify bad digest value
    badraw = (b'{"v":"KERI10JSON00004c_",'
                          b'"d":"EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8g"}')
    with pytest.raises(kering.ValidationError):
        serder = Serder(raw=badraw, verify=True)

    # Test CBOR
    sad = dict(v=coring.Vstrings.cbor, #
               d="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'KERI10CBOR000045_',
                   'd': 'EK2_0ouKrN9hXmQvtfenA455EYZ4QENydBdrwtbPZuxa'}

    assert saider.qb64 == sad["d"]

    serder = Serder(sad=sad)
    assert serder.raw == b'\xa2avqKERI10CBOR000045_adx,EK2_0ouKrN9hXmQvtfenA455EYZ4QENydBdrwtbPZuxa'
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                                ' "v": "KERI10CBOR000045_",\n'
                                ' "d": "EK2_0ouKrN9hXmQvtfenA455EYZ4QENydBdrwtbPZuxa"\n'
                                '}')
    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8e')

    rawCBOR = serder.raw  # save for later tests
    assert rawCBOR == b'\xa2avqKERI10CBOR000045_adx,EK2_0ouKrN9hXmQvtfenA455EYZ4QENydBdrwtbPZuxa'

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    #serder = Serder(sad=sad, makify=True)  # test makify
    #assert serder.raw == rawCBOR
    #assert serder.sad == sad
    #assert serder.proto == coring.Protos.keri
    #assert serder.version == coring.Versionage(major=1, minor=0)
    #assert serder.size == 69
    #assert serder.kind == coring.Serials.cbor
    #assert serder.said == saider.qb64
    #assert serder.saidb == saider.qb64b
    #assert serder.ilk == None

    serder = Serder(raw=rawCBOR)
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawCBOR, verify=False)  # test without verify
    assert serder.raw == rawCBOR
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.cbor
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None


    # Test MGPK
    sad = dict(v=coring.Vstrings.mgpk, #
               d="")
    saider, sad = coring.Saider.saidify(sad=sad)
    assert sad == {'v': 'KERI10MGPK000045_',
                   'd': 'EHORCaFv9ThskIBG0qSr3edk7oQ9x-xT8-FgsUIADb5E'}

    assert saider.qb64 == sad["d"]

    serder = Serder(sad=sad)
    assert serder.raw == (b'\x82\xa1v\xb1KERI10MGPK000045_\xa1d\xd9,EHORCaFv9'
                          b'ThskIBG0qSr3edk7oQ9x-xT8-FgsUIADb5E')
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None
    assert serder.pretty() == ('{\n'
                               ' "v": "KERI10MGPK000045_",\n'
                               ' "d": "EHORCaFv9ThskIBG0qSr3edk7oQ9x-xT8-FgsUIADb5E"\n'
                               '}')
    assert serder.compare(said=saider.qb64)
    assert serder.compare(said=saider.qb64b)
    assert not serder.compare(said='EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8e')

    rawMGPK = serder.raw  # save for later tests
    assert rawMGPK == (b'\x82\xa1v\xb1KERI10MGPK000045_\xa1d\xd9,EHORCaFv9'
                          b'ThskIBG0qSr3edk7oQ9x-xT8-FgsUIADb5E')

    serder = Serder(sad=sad, verify=False)  # test not verify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    #serder = Serder(sad=sad, makify=True)  # test makify
    #assert serder.raw == rawMGPK
    #assert serder.sad == sad
    #assert serder.proto == coring.Protos.keri
    #assert serder.version == coring.Versionage(major=1, minor=0)
    #assert serder.size == 69
    #assert serder.kind == coring.Serials.mgpk
    #assert serder.said == saider.qb64
    #assert serder.saidb == saider.qb64b
    #assert serder.ilk == None

    serder = Serder(raw=rawMGPK)
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    serder = Serder(raw=rawMGPK, verify=False)  # test not verify
    assert serder.raw == rawMGPK
    assert serder.sad == sad
    assert serder.proto == coring.Protos.keri
    assert serder.version == coring.Versionage(major=1, minor=0)
    assert serder.size == 69
    assert serder.kind == coring.Serials.mgpk
    assert serder.said == saider.qb64
    assert serder.saidb == saider.qb64b
    assert serder.ilk == None

    # ToDo
    # test cbor and msgpack versions of Serder
    # make .saidify for real and test
    # ToDo: create malicious raw values to test verify more thoroughly





    """End Test"""



if __name__ == "__main__":
    test_serder()
