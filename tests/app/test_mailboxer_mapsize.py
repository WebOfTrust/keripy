# -*- encoding: utf-8 -*-
"""
tests.app.test_mailboxer_mapsize module

"""
import os
import pytest


def test_mailboxer_specific_env_var():
    from keri.app import storing

    os.environ['KERI_MAILBOXER_MAP_SIZE'] = '150000000'

    try:
        mbx = storing.Mailboxer(name='test_mailboxer', temp=True)
        assert mbx.MapSize == 150000000
        mbx.close()
    finally:
        os.environ.pop('KERI_MAILBOXER_MAP_SIZE', None)


def test_mailboxer_general_env_var_fallback():
    from keri.app import storing

    os.environ['KERI_LMDB_MAP_SIZE'] = '250000000'

    try:
        mbx = storing.Mailboxer(name='test_mailboxer_general', temp=True)
        assert mbx.MapSize == 250000000
        mbx.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)


def test_mailboxer_specific_takes_precedence():
    """Test that KERI_MAILBOXER_MAP_SIZE takes precedence over KERI_LMDB_MAP_SIZE"""
    from keri.app import storing

    os.environ['KERI_LMDB_MAP_SIZE'] = '100000000'
    os.environ['KERI_MAILBOXER_MAP_SIZE'] = '200000000'

    try:
        mbx = storing.Mailboxer(name='test_mailboxer_precedence', temp=True)
        assert mbx.MapSize == 200000000
        mbx.close()
    finally:
        os.environ.pop('KERI_LMDB_MAP_SIZE', None)
        os.environ.pop('KERI_MAILBOXER_MAP_SIZE', None)


if __name__ == '__main__':
    test_mailboxer_specific_env_var()
    test_mailboxer_general_env_var_fallback()
    test_mailboxer_specific_takes_precedence()
