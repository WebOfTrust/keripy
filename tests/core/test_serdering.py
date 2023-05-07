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

from keri.core.serdering import Serder, Serdery

from keri.core import coring



def test_serder():
    """
    Test Serder
    """

    # Test Serder

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

    raw = serder.raw
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


    # test cbor and msgpack versions of Serder
    # make .verify() for real and test
    # make .saidify for real and test
    # make PreDex PrefixCodex of valid identifier prefix codes


    """End Test"""



if __name__ == "__main__":
    test_serder()
