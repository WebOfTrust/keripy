# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import os

import lmdb

from keri.db.dbing import clearDatabaserDir, openDatabaser
from keri.db.dbing import Databaser, Logger, Dupler

def test_opendatabaser():
    """
    test contextmanager decorator for test databases
    """
    with openDatabaser() as databaser:
        assert isinstance(databaser, Databaser)
        assert databaser.name == "test"
        assert isinstance(databaser.env, lmdb.Environment)
        assert databaser.path.startswith("/tmp/keri_lmdb_")
        assert databaser.path.endswith("_test/keri/db/test")
        assert databaser.env.path() == databaser.path
        assert os.path.exists(databaser.path)

    assert not os.path.exists(databaser.path)

    with openDatabaser(name="blue") as databaser:
        assert isinstance(databaser, Databaser)
        assert databaser.name == "blue"
        assert isinstance(databaser.env, lmdb.Environment)
        assert databaser.path.startswith("/tmp/keri_lmdb_")
        assert databaser.path.endswith("_test/keri/db/blue")
        assert databaser.env.path() == databaser.path
        assert os.path.exists(databaser.path)

    assert not os.path.exists(databaser.path)

    with openDatabaser(name="red") as redbaser,  openDatabaser(name="gray") as graybaser:
        assert isinstance(redbaser, Databaser)
        assert redbaser.name == "red"
        assert redbaser.env.path() == redbaser.path
        assert os.path.exists(redbaser.path)

        assert isinstance(graybaser, Databaser)
        assert graybaser.name == "gray"
        assert graybaser.env.path() == graybaser.path
        assert os.path.exists(graybaser.path)

    assert not os.path.exists(redbaser.path)
    assert not os.path.exists(graybaser.path)

    """ End Test """

def test_databaser():
    """
    Test Databaser creation
    """
    databaser = Databaser()
    assert isinstance(databaser, Databaser)
    assert databaser.name == "main"
    assert isinstance(databaser.env, lmdb.Environment)
    assert databaser.path.endswith("keri/db/main")
    assert databaser.env.path() == databaser.path
    assert os.path.exists(databaser.path)

    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert databaser.snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert databaser.dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    databaser.clearDirPath()
    assert not os.path.exists(databaser.path)

    """ End Test """


def test_logger():
    """
    Test Logger class
    """
    logger = Logger()
    assert isinstance(logger, Logger)
    assert logger.name == "main"
    assert isinstance(logger.env, lmdb.Environment)
    assert logger.path.endswith("keri/db/main")
    assert logger.env.path() == logger.path
    assert os.path.exists(logger.path)

    assert isinstance(logger.evts, lmdb._Database)
    assert isinstance(logger.sigs, lmdb._Database)
    assert isinstance(logger.rcts, lmdb._Database)
    assert isinstance(logger.kels, lmdb._Database)
    assert isinstance(logger.ooes, lmdb._Database)
    assert isinstance(logger.pses, lmdb._Database)
    assert isinstance(logger.dels, lmdb._Database)
    assert isinstance(logger.pdes, lmdb._Database)

    logger.clearDirPath()
    assert not os.path.exists(logger.path)

    # Test using context manager
    with openDatabaser(cls=Logger) as logger:
        assert isinstance(logger, Logger)
        assert logger.name == "test"
        assert isinstance(logger.env, lmdb.Environment)
        assert logger.path.startswith("/tmp/keri_lmdb_")
        assert logger.path.endswith("_test/keri/db/test")
        assert logger.env.path() == logger.path
        assert os.path.exists(logger.path)

        assert isinstance(logger.evts, lmdb._Database)
        assert isinstance(logger.sigs, lmdb._Database)
        assert isinstance(logger.rcts, lmdb._Database)
        assert isinstance(logger.kels, lmdb._Database)
        assert isinstance(logger.ooes, lmdb._Database)
        assert isinstance(logger.pses, lmdb._Database)
        assert isinstance(logger.dels, lmdb._Database)
        assert isinstance(logger.pdes, lmdb._Database)


    assert not os.path.exists(logger.path)


    """ End Test """


def test_dupler():
    """
    Test Dupler class

    """
    dupler = Dupler()
    assert isinstance(dupler, Dupler)
    assert dupler.name == "main"
    assert isinstance(dupler.env, lmdb.Environment)
    assert dupler.path.endswith("keri/db/main")
    assert dupler.env.path() == dupler.path
    assert os.path.exists(dupler.path)

    assert isinstance(dupler.evts, lmdb._Database)
    assert isinstance(dupler.dels, lmdb._Database)
    assert isinstance(dupler.pdes, lmdb._Database)

    dupler.clearDirPath()
    assert not os.path.exists(dupler.path)

    """ End Test """

def test_uselogger():
    """
    Test using logger to
    """
    with openDatabaser(cls=Logger) as logger:
        pass


    assert not os.path.exists(logger.path)

    """ End Test """

if __name__ == "__main__":
    test_databaser()
