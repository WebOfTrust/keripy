# -*- encoding: utf-8 -*-
"""
tests.vc.pocketer module

"""

import os

import lmdb

from keri.db.dbing import openLMDB
from keri.vc.walleting import Pocketer, openPocket


def test_pocketer():
    pocket = Pocketer()

    assert isinstance(pocket, Pocketer)
    assert pocket.name == "main"
    assert pocket.temp is False
    assert isinstance(pocket.env, lmdb.Environment)
    assert pocket.path.endswith("keri/pck/main")
    assert pocket.env.path() == pocket.path
    assert os.path.exists(pocket.path)

    assert isinstance(pocket.sers, lmdb._Database)

    pocket.close(clear=True)
    assert not os.path.exists(pocket.path)
    assert not pocket.opened

    # test not opened on init
    pocket = Pocketer(reopen=False)
    assert isinstance(pocket, Pocketer)
    assert pocket.name == "main"
    assert pocket.temp is False
    assert pocket.opened is False
    assert pocket.path is None
    assert pocket.env is None

    pocket.reopen()
    assert pocket.opened
    assert pocket.path is not None
    assert isinstance(pocket.env, lmdb.Environment)
    assert pocket.path.endswith("keri/pck/main")
    assert pocket.env.path() == pocket.path
    assert os.path.exists(pocket.path)

    pocket.close(clear=True)
    assert not os.path.exists(pocket.path)
    assert not pocket.opened

    assert isinstance(pocket.issus, lmdb._Database)

    with openLMDB(cls=Pocketer) as pocket:
        assert isinstance(pocket, Pocketer)
        assert pocket.name == "test"
        assert pocket.temp is True
        assert isinstance(pocket.env, lmdb.Environment)
        assert pocket.path.startswith("/tmp/keri_pck_")
        assert pocket.path.endswith("_test/keri/pck/test")
        assert pocket.env.path() == pocket.path
        assert os.path.exists(pocket.path)

        assert isinstance(pocket.subjs, lmdb._Database)

    assert not os.path.exists(pocket.path)

    with openPocket(name="test") as pocket:
        key = "Eb87ZrHEOxPShWXjrg2XjGXYKYf35IIA7XCJSc8eeuR0"
        issuer = b'EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc'
        subject = b'E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U'
        schema = b'EOWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0'

        key = key.encode("utf-8")
        assert pocket.getSigs(key) == []
        assert pocket.cntSigs(key) == 0
        assert pocket.delSigs(key) == False

        sig0b = 'AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'.encode("utf-8")
        sig1b = 'AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z'.encode("utf-8")

        # dup vals are lexocographic
        assert pocket.putSigs(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert pocket.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert pocket.cntSigs(key) == 4
        assert pocket.putSigs(key, vals=[b'a']) == True   # duplicate but True
        assert pocket.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert pocket.addSig(key, b'a') == False   # duplicate
        assert pocket.addSig(key, b'b') == True
        assert pocket.getSigs(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in pocket.getSigsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert pocket.delSigs(key) == True
        assert pocket.getSigs(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert pocket.putSigs(key, vals) == True
        for val in vals:
            assert pocket.delSigs(key, val) == True
        assert pocket.getSigs(key) == []
        assert pocket.putSigs(key, vals) == True
        for val in pocket.getSigsIter(key):
            assert pocket.delSigs(key, val) == True
        assert pocket.getSigs(key) == []

        assert pocket.putSigs(key, vals=[sig0b]) == True
        assert pocket.getSigs(key) == [sig0b]
        assert pocket.putSigs(key, vals=[sig1b]) == True
        assert pocket.getSigs(key) == [sig0b, sig1b]
        assert pocket.delSigs(key) == True
        assert pocket.putSigs(key, vals=[sig1b, sig0b]) == True
        assert pocket.getSigs(key) == [sig0b, sig1b]
        assert pocket.delSigs(key) == True
        assert pocket.getSigs(key) == []

        cred1 = b'EhUlGZJ_-xyYy__IMRS4vHRB27EU4tDdUB7swE3pUvXU'
        cred2 = b'EvcZT4uLfeHRJV48J-f4n3MNzwQ-GX0Ogw7DkkaSKkR4'
        cred3 = b'EmZZhv2sSzM7lyIEBmdseYkKbOvTV6dBSW_30heEqICE'
        cred4 = b'EyFSfdyHfPBs-lSHc7k7TqeAXotT5jcJ8Z-vj5h8tHRc'
        cred5 = b'EvYB417eijN1IrClN8KpzqTi4oWJUgtEUhSIy-_W2C4o'
        creds = [cred1, cred2, cred3, cred4]

        assert pocket.getIssus(issuer) == []
        assert pocket.cntIssus(issuer) == 0
        assert pocket.delIssus(issuer) is False
        assert pocket.putIssus(issuer, creds) is True
        assert pocket.getIssus(issuer) == creds
        assert pocket.cntIssus(issuer) == len(creds) == 4
        assert pocket.putIssus(issuer, vals=[cred2]) is False
        assert pocket.getIssus(issuer) == creds
        assert pocket.addIssu(issuer, b'EhUlGZJ_-xyYy__IMRS4vHRB27EU4tDdUB7swE3pUvXU') is False
        assert pocket.addIssu(issuer, cred5) is True
        assert pocket.getIssus(issuer) == [cred1, cred2, cred3, cred4, cred5] 
        assert [val for val in pocket.getIssusIter(issuer)] == [cred1, cred2, cred3, cred4, cred5]
        assert pocket.delIssus(issuer) is True
        assert pocket.getIssus(issuer) == []

        assert pocket.getSubjs(subject) == []
        assert pocket.cntSubjs(subject) == 0
        assert pocket.delSubjs(subject) is False
        assert pocket.putSubjs(subject, creds) is True
        assert pocket.getSubjs(subject) == creds
        assert pocket.cntSubjs(subject) == len(creds) == 4
        assert pocket.putSubjs(subject, vals=[cred2]) is False
        assert pocket.getSubjs(subject) == creds
        assert pocket.addSubj(subject, b'EhUlGZJ_-xyYy__IMRS4vHRB27EU4tDdUB7swE3pUvXU') is False
        assert pocket.addSubj(subject, cred5) is True
        assert pocket.getSubjs(subject) == [cred1, cred2, cred3, cred4, cred5]
        assert [val for val in pocket.getSubjsIter(subject)] == [cred1, cred2, cred3, cred4, cred5]
        assert pocket.delSubjs(subject) is True
        assert pocket.getSubjs(subject) == []

        assert pocket.getSchms(schema) == []
        assert pocket.cntSchms(schema) == 0
        assert pocket.delSchms(schema) is False
        assert pocket.putSchms(schema, creds) is True
        assert pocket.getSchms(schema) == creds
        assert pocket.cntSchms(schema) == len(creds) == 4
        assert pocket.putSchms(schema, vals=[cred2]) is False
        assert pocket.getSchms(schema) == creds
        assert pocket.addSchm(schema, b'EhUlGZJ_-xyYy__IMRS4vHRB27EU4tDdUB7swE3pUvXU') is False
        assert pocket.addSchm(schema, cred5) is True
        assert pocket.getSchms(schema) == [cred1, cred2, cred3, cred4, cred5]
        assert [val for val in pocket.getSchmsIter(schema)] == [cred1, cred2, cred3, cred4, cred5]
        assert pocket.delSchms(schema) is True
        assert pocket.getSchms(schema) == []


if __name__ == '__main__':
    test_pocketer()
