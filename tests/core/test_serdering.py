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

    raw = serder.raw  # save for later tests

    serder = Serder(sad=sad, saidify=True)  # test saidify
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



    serder = Serder(raw=raw)
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


    serder = Serder(raw=raw, verify=True)  # test verify
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

    raw = serder.raw  # save for later tests

    serder = Serder(sad=sad, saidify=True)  # test saidify
    assert serder.raw ==  b'\xa2avqKERI10CBOR000045_adx,EK2_0ouKrN9hXmQvtfenA455EYZ4QENydBdrwtbPZuxa'
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


    # ToDo
    # test cbor and msgpack versions of Serder

    # make .saidify for real and test
    # ToDo: create malicious raw values to test verify more thouroughly





    """End Test"""



if __name__ == "__main__":
    test_serder()
