# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import os

import lmdb

from keri.db.dbing import clearDatabaserDir, openDatabaser, Databaser

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
    Different tests.
    """
    databaser = Databaser()
    assert isinstance(databaser, Databaser)
    assert databaser.name == "main"
    assert isinstance(databaser.env, lmdb.Environment)
    assert databaser.path.endswith("keri/db/main")
    assert databaser.env.path() == databaser.path
    assert os.path.exists(databaser.path)

    assert isinstance(databaser.kels, lmdb._Database)
    assert isinstance(databaser.kelds, lmdb._Database)

    databaser.clearDirPath()
    assert not os.path.exists(databaser.path)



    """ End Test """

if __name__ == "__main__":
    test_databaser()
