# -*- encoding: utf-8 -*-
"""
tests.app.test_noter_mapsize module

"""
import os
import pytest


def test_noter_specific_env_var():
    from keri.app import notifying

    os.environ['KERI_NOTER_MAP_SIZE'] = '150000000'

    try:
        noter = notifying.Noter(name='test_noter', temp=True)
        assert noter.MapSize == 150000000
        noter.close()
    finally:
        os.environ.pop('KERI_NOTER_MAP_SIZE', None)


def test_noter_general_env_var_fallback():
    from keri.app import notifying

    os.environ['KERI_LMDB_MAP_SIZE'] = '250000000'

    try:
        noter = notifying.Noter(name='test_noter_general', temp=True)
        assert noter.MapSize == 250000000
        noter.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)


def test_noter_specific_takes_precedence():
    from keri.app import notifying

    os.environ['KERI_LMDB_MAP_SIZE'] = '100000000'
    os.environ['KERI_NOTER_MAP_SIZE'] = '200000000'

    try:
        noter = notifying.Noter(name='test_noter_precedence', temp=True)
        assert noter.MapSize == 200000000
        noter.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)
        os.environ.pop('KERI_NOTER_MAP_SIZE', None)


if __name__ == '__main__':
    test_noter_specific_env_var()
    test_noter_general_env_var_fallback()
    test_noter_specific_takes_precedence()
