# -*- encoding: utf-8 -*-
"""
tests.app.test_keeper_mapsize module

"""
import os
import pytest


def test_keeper_specific_env_var():
    from keri.app import keeping

    os.environ['KERI_KEEPER_MAP_SIZE'] = '150000000'

    try:
        keeper = keeping.Keeper(name='test_keeper', temp=True)
        assert keeper.MapSize == 150000000
        keeper.close()
    finally:
        os.environ.pop('KERI_KEEPER_MAP_SIZE', None)


def test_keeper_general_env_var_fallback():
    from keri.app import keeping

    os.environ['KERI_LMDB_MAP_SIZE'] = '250000000'

    try:
        keeper = keeping.Keeper(name='test_keeper_general', temp=True)
        assert keeper.MapSize == 250000000
        keeper.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)


def test_keeper_specific_takes_precedence():
    from keri.app import keeping

    os.environ['KERI_LMDB_MAP_SIZE'] = '100000000'
    os.environ['KERI_KEEPER_MAP_SIZE'] = '200000000'

    try:
        keeper = keeping.Keeper(name='test_keeper_precedence', temp=True)
        assert keeper.MapSize == 200000000
        keeper.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)
        os.environ.pop('KERI_KEEPER_MAP_SIZE', None)


if __name__ == '__main__':
    test_keeper_specific_env_var()
    test_keeper_general_env_var_fallback()
    test_keeper_specific_takes_precedence()
