# -*- encoding: utf-8 -*-
"""
tests.vdr.test_reger_mapsize module

"""
import os
import pytest


def test_reger_specific_env_var():
    from keri.vdr import viring

    os.environ['KERI_REGER_MAP_SIZE'] = '150000000'

    try:
        reger = viring.Reger(name='test_reger', temp=True)
        assert reger.MapSize == 150000000
        reger.close()
    finally:
        os.environ.pop('KERI_REGER_MAP_SIZE', None)


def test_reger_general_env_var_fallback():
    from keri.vdr import viring

    os.environ['KERI_LMDB_MAP_SIZE'] = '250000000'

    try:
        reger = viring.Reger(name='test_reger_general', temp=True)
        assert reger.MapSize == 250000000
        reger.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)


def test_reger_specific_takes_precedence():
    from keri.vdr import viring

    os.environ['KERI_LMDB_MAP_SIZE'] = '100000000'
    os.environ['KERI_REGER_MAP_SIZE'] = '200000000'

    try:
        reger = viring.Reger(name='test_reger_precedence', temp=True)
        assert reger.MapSize == 200000000
        reger.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)
        os.environ.pop('KERI_REGER_MAP_SIZE', None)


if __name__ == '__main__':
    test_reger_specific_env_var()
    test_reger_general_env_var_fallback()
    test_reger_specific_takes_precedence()
