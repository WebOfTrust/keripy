# -*- encoding: utf-8 -*-
"""
tests.db.test_baser_mapsize module

"""
import os
import pytest


def test_baser_specific_env_var():
    from keri.db import basing

    os.environ['KERI_BASER_MAP_SIZE'] = '150000000'

    try:
        baser = basing.Baser(name='test_baser', temp=True)
        assert baser.MapSize == 150000000
        baser.close()
    finally:
        os.environ.pop('KERI_BASER_MAP_SIZE', None)


def test_baser_general_env_var_fallback():
    from keri.db import basing

    os.environ['KERI_LMDB_MAP_SIZE'] = '250000000'

    try:
        baser = basing.Baser(name='test_baser_general', temp=True)
        assert baser.MapSize == 250000000
        baser.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)


def test_baser_specific_takes_precedence():
    from keri.db import basing

    os.environ['KERI_LMDB_MAP_SIZE'] = '100000000'
    os.environ['KERI_BASER_MAP_SIZE'] = '200000000'

    try:
        baser = basing.Baser(name='test_baser_precedence', temp=True)
        assert baser.MapSize == 200000000
        baser.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)
        os.environ.pop('KERI_BASER_MAP_SIZE', None)


if __name__ == '__main__':
    test_baser_specific_env_var()
    test_baser_general_env_var_fallback()
    test_baser_specific_takes_precedence()
