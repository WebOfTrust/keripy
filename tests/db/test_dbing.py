# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import os
import json

import lmdb

from keri.db.dbing import clearDatabaserDir, openDatabaser, openLogger
from keri.db.dbing import Databaser, Logger

from keri.core.coring import Signer, Nexter, Prefixer, Serder
from keri.core.coring import CryCntDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import Serials, Vstrings, Versify

from keri.core.eventing import incept, rotate, interact, Kever, Kevery

from keri.help.helping import nowIso8601, toIso8601, fromIso8601

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

    with openDatabaser() as dber:
        #test Val methods
        key = b'A'
        val = b'whatever'
        db = dber.env.open_db(key=b'beep.')

        assert dber.getVal(db, key) == None
        assert dber.delVal(db, key) == False
        assert dber.putVal(db, key, val) == True
        assert dber.putVal(db, key, val) == False
        assert dber.setVal(db, key, val) == True
        assert dber.getVal(db, key) == val
        assert dber.delVal(db, key) == True
        assert dber.getVal(db, key) == None

        # test Vals dup methods.  dup vals are lexocographic
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        db = dber.env.open_db(key=b'boop.', dupsort=True)

        assert dber.getVals(db, key) == []
        assert dber.delVals(db, key) == False
        assert dber.cntVals(db, key) == 0
        assert dber.putVals(db, key, vals) == True
        assert dber.getVals(db, key) == [b'a', b'm', b'x', b'z']  #  lexocographic order
        assert dber.cntVals(db, key) == len(vals) == 4
        assert dber.putVals(db, key, vals=[b'a']) == True   # duplicate
        assert dber.getVals(db, key) == [b'a', b'm', b'x', b'z']  #  no change
        assert dber.addVal(db, key, val=b'a') == False  # duplicate
        assert dber.addVal(db, key, val=b'b') == True
        assert dber.getVals(db, key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in dber.getIterVals(db, key)] == [b'a', b'b', b'm', b'x', b'z']
        assert dber.delVals(db, key) == True
        assert dber.getVals(db, key) == []


        # test IoVals insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        db = dber.env.open_db(key=b'peep.', dupsort=True)

        assert dber.getIoVals(db, key) == []
        assert dber.getIoValsLast(db, key) == None
        assert dber.cntIoVals(db, key) == 0
        assert dber.delIoVals(db, key) == False
        assert dber.putIoVals(db, key, vals) == True
        assert dber.getIoVals(db, key) == vals  # preserved insertion order
        assert dber.cntIoVals(db, key) == len(vals) == 4
        assert dber.getIoValsLast(db, key) == vals[-1]
        assert dber.putIoVals(db, key, vals=[b'a']) == False   # duplicate
        assert dber.getIoVals(db, key) == vals  #  no change
        assert dber.addIoVal(db, key, val=b'b') == True
        assert dber.addIoVal(db, key, val=b'a') == False
        assert dber.getIoVals(db, key) == [b"z", b"m", b"x", b"a", b'b']
        assert dber.delIoVals(db, key) == True
        assert dber.getIoVals(db, key) == []

    assert not os.path.exists(dber.path)

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
    assert isinstance(logger.dtss, lmdb._Database)
    assert isinstance(logger.rcts, lmdb._Database)
    assert isinstance(logger.kels, lmdb._Database)
    assert isinstance(logger.ooes, lmdb._Database)
    assert isinstance(logger.pses, lmdb._Database)
    assert isinstance(logger.dels, lmdb._Database)
    assert isinstance(logger.ldes, lmdb._Database)

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
        assert isinstance(logger.dtss, lmdb._Database)
        assert isinstance(logger.rcts, lmdb._Database)
        assert isinstance(logger.kels, lmdb._Database)
        assert isinstance(logger.ooes, lmdb._Database)
        assert isinstance(logger.pses, lmdb._Database)
        assert isinstance(logger.dels, lmdb._Database)
        assert isinstance(logger.ldes, lmdb._Database)


    assert not os.path.exists(logger.path)

    preb = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    vs = Versify(kind=Serials.json, size=20)
    assert vs == 'KERI10JSON000014_'

    ked = dict(vs=vs, pre=preb.decode("utf-8"),
               sn="{:x}".format(sn),
               ilk="rot",
               dig=digb.decode("utf-8"))
    skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert skedb == (b'{"vs":"KERI10JSON000014_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                     b'c","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"'
                     b'}')


    sig0b = 'AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'.encode("utf-8")
    sig1b = 'AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z'.encode("utf-8")

    wit0b = 'BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT'.encode("utf-8")
    wit1b = 'BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT'.encode("utf-8")
    wsig0b = '0A1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9'.encode("utf-8")
    wsig1b = '0A5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z'.encode("utf-8")

    with openLogger() as lgr:
        key = lgr.dgKey(preb, digb)
        assert key == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.'
                       b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

        #  test .evts sub db methods
        assert lgr.getEvt(key) == None
        assert lgr.delEvt(key) == False
        assert lgr.putEvt(key, val=skedb) == True
        assert lgr.getEvt(key) == skedb
        assert lgr.putEvt(key, val=skedb) == False
        assert lgr.setEvt(key, val=skedb) == True
        assert lgr.getEvt(key) == skedb
        assert lgr.delEvt(key) == True
        assert lgr.getEvt(key) == None

        # test .dtss sub db methods
        val1 = b'2020-08-22T17:50:09.988921+00:00'
        val2 = b'2020-08-22T17:50:09.988921+00:00'

        assert lgr.getDts(key) == None
        assert lgr.delDts(key) == False
        assert lgr.putDts(key, val1) == True
        assert lgr.getDts(key) == val1
        assert lgr.putDts(key, val2) == False
        assert lgr.getDts(key) == val1
        assert lgr.setDts(key, val2) == True
        assert lgr.getDts(key) == val2
        assert lgr.delDts(key) == True
        assert lgr.getDts(key) == None

        # test .sigs sub db methods
        assert lgr.getSigs(key) == []
        assert lgr.cntSigs(key) == 0
        assert lgr.delSigs(key) == False

        # dup vals are lexocographic
        assert lgr.putSigs(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert lgr.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert lgr.cntSigs(key) == 4
        assert lgr.putSigs(key, vals=[b'a']) == True   # duplicate but True
        assert lgr.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert lgr.addSig(key, b'a') == False   # duplicate
        assert lgr.addSig(key, b'b') == True
        assert lgr.getSigs(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in lgr.getIterSigs(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert lgr.delSigs(key) == True
        assert lgr.getSigs(key) == []

        assert lgr.putSigs(key, vals=[sig0b]) == True
        assert lgr.getSigs(key) == [sig0b]
        assert lgr.putSigs(key, vals=[sig1b]) == True
        assert lgr.getSigs(key) == [sig0b, sig1b]
        assert lgr.delSigs(key) == True
        assert lgr.putSigs(key, vals=[sig1b, sig0b]) == True
        assert lgr.getSigs(key) == [sig0b, sig1b]
        assert lgr.delSigs(key) == True
        assert lgr.getSigs(key) == []

        # test .rcts sub db methods
        assert lgr.getRcts(key) == []
        assert lgr.cntRcts(key) == 0
        assert lgr.delRcts(key) == False

        # dup vals are lexocographic
        assert lgr.putRcts(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert lgr.getRcts(key) == [b'a', b'm', b'x', b'z']
        assert lgr.cntRcts(key) == 4
        assert lgr.putRcts(key, vals=[b'a']) == True   # duplicate
        assert lgr.getRcts(key) == [b'a', b'm', b'x', b'z']
        assert lgr.addRct(key, b'a') == False   # duplicate
        assert lgr.addRct(key, b'b') == True
        assert lgr.getRcts(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in lgr.getIterRcts(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert lgr.delRcts(key) == True
        assert lgr.getRcts(key) == []

        assert lgr.putRcts(key, vals=[wit0b + wsig0b, wit1b + wsig1b]) == True
        assert lgr.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]
        assert lgr.putRcts(key, vals=[wit1b + wsig1b]) == True
        assert lgr.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]
        assert lgr.delRcts(key) == True
        assert lgr.putRcts(key, vals=[wit1b + wsig1b, wit0b + wsig0b]) == True
        assert lgr.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]
        assert lgr.delRcts(key) == True
        assert lgr.getRcts(key) == []

        # test .ures sub db methods
        key = lgr.dgKey(wit0b, digb)
        val1 = preb + sig0b
        val2 = preb + sig1b

        assert lgr.getUre(key) == None
        assert lgr.delUre(key) == False
        assert lgr.putUre(key, val1) == True
        assert lgr.getUre(key) == val1
        assert lgr.putUre(key, val2) == False
        assert lgr.getUre(key) == val1
        assert lgr.setUre(key, val2) == True
        assert lgr.getUre(key) == val2
        assert lgr.delUre(key) == True
        assert lgr.getUre(key) == None


        # test .kels insertion order dup methods.  dup vals are insertion order
        key = lgr.snKey(preb, 0)
        vals = [b"z", b"m", b"x", b"a"]

        assert lgr.getKes(key) == []
        assert lgr.getKesLast(key) == None
        assert lgr.cntKes(key) == 0
        assert lgr.delKes(key) == False
        assert lgr.putKes(key, vals) == True
        assert lgr.getKes(key) == vals  # preserved insertion order
        assert lgr.cntKes(key) == len(vals) == 4
        assert lgr.getKesLast(key) == vals[-1]
        assert lgr.putKes(key, vals=[b'a']) == False   # duplicate
        assert lgr.getKes(key) == vals  #  no change
        assert lgr.addKe(key, b'a') == False   # duplicate
        assert lgr.addKe(key, b'b') == True
        assert lgr.getKes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert lgr.delKes(key) == True
        assert lgr.getKes(key) == []

        # test .pses insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert lgr.getPses(key) == []
        assert lgr.getPsesLast(key) == None
        assert lgr.cntPses(key) == 0
        assert lgr.delPses(key) == False
        assert lgr.putPses(key, vals) == True
        assert lgr.getPses(key) == vals  # preserved insertion order
        assert lgr.cntPses(key) == len(vals) == 4
        assert lgr.getPsesLast(key) == vals[-1]
        assert lgr.putPses(key, vals=[b'a']) == False   # duplicate
        assert lgr.getPses(key) == vals  #  no change
        assert lgr.addPse(key, b'a') == False   # duplicate
        assert lgr.addPse(key, b'b') == True
        assert lgr.getPses(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert lgr.delPses(key) == True
        assert lgr.getPses(key) == []

        # test .ooes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert lgr.getOoes(key) == []
        assert lgr.getOoesLast(key) == None
        assert lgr.cntOoes(key) == 0
        assert lgr.delOoes(key) == False
        assert lgr.putOoes(key, vals) == True
        assert lgr.getOoes(key) == vals  # preserved insertion order
        assert lgr.cntOoes(key) == len(vals) == 4
        assert lgr.getOoesLast(key) == vals[-1]
        assert lgr.putOoes(key, vals=[b'a']) == False   # duplicate
        assert lgr.getOoes(key) == vals  #  no change
        assert lgr.addOoe(key, b'a') == False   # duplicate
        assert lgr.addOoe(key, b'b') == True
        assert lgr.getOoes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert lgr.delOoes(key) == True
        assert lgr.getOoes(key) == []

        # test .dels insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert lgr.getDes(key) == []
        assert lgr.getDesLast(key) == None
        assert lgr.cntDes(key) == 0
        assert lgr.delDes(key) == False
        assert lgr.putDes(key, vals) == True
        assert lgr.getDes(key) == vals  # preserved insertion order
        assert lgr.cntDes(key) == len(vals) == 4
        assert lgr.getDesLast(key) == vals[-1]
        assert lgr.putDes(key, vals=[b'a']) == False   # duplicate
        assert lgr.getDes(key) == vals  #  no change
        assert lgr.addDe(key, b'a') == False   # duplicate
        assert lgr.addDe(key, b'b') == True
        assert lgr.getDes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert lgr.delDes(key) == True
        assert lgr.getDes(key) == []

        # test .ldes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert lgr.getLdes(key) == []
        assert lgr.getLdesLast(key) == None
        assert lgr.cntLdes(key) == 0
        assert lgr.delLdes(key) == False
        assert lgr.putLdes(key, vals) == True
        assert lgr.getLdes(key) == vals  # preserved insertion order
        assert lgr.cntLdes(key) == len(vals) == 4
        assert lgr.getLdesLast(key) == vals[-1]
        assert lgr.putLdes(key, vals=[b'a']) == False   # duplicate
        assert lgr.getLdes(key) == vals  #  no change
        assert lgr.delLdes(key) == True
        assert lgr.getLdes(key) == []


    assert not os.path.exists(lgr.path)

    """ End Test """



def test_uselogger():
    """
    Test using logger to
    """
    # Some secrets to use on the events
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create signers from the secrets
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets



    with openLogger() as lgr:
        # Event 0  Inception Transferable (nxt digest not empty) 2 0f 3 multisig
        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        count = len(keys)
        nxtkeys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = 2
        code = CryOneDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        sith=sith,
                        nxt=Nexter(keys=nxtkeys).qb64)


        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers)

        # Event 1 Rotation Transferable
        keys = nxtkeys
        nxtkeys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith=sith,
                        dig=kever.diger.qb64,
                        nxt=Nexter(keys=nxtkeys).qb64,
                        sn=1)

        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)


        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.diger.qb64,
                          sn=2)

        # sign serialization  (keys don't change for signing)
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)

    assert not os.path.exists(lgr.path)

    """ End Test """

if __name__ == "__main__":
    test_logger()
