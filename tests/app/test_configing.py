# -*- encoding: utf-8 -*-
"""
tests.app.configin module
"""
import os
import platform
import shutil
import tempfile

import pytest

from hio.base import doing
from keri.app import configing
from keri.core import coring

def test_configer():
    """
    Test Configer class
    """
    # Test Filer with file not dir
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    filepath = os.path.join(os.path.sep, 'usr', 'local', 'var', 'keri', 'cf', 'main', 'conf.json')
    if os.path.exists(filepath):
        os.remove(filepath)

    cfr = configing.Configer()  # defaults
    # assert cfr.path == filepath
    # github runner does not allow /usr/local/var
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert cfr.opened
    assert os.path.exists(cfr.path)
    assert cfr.file
    assert not cfr.file.closed
    assert not cfr.file.read()
    assert cfr.human

    # plain json manually
    data = dict(name="habi", oobi="ABCDEFG")
    wmsg = coring.dumps(data)
    assert hasattr(wmsg, "decode")  # bytes
    assert len(wmsg) == cfr.file.write(wmsg)
    assert 0 == cfr.file.seek(0)
    rmsg = cfr.file.read()
    assert rmsg == wmsg
    assert data == coring.loads(rmsg)

     # default is hjson for .human == True
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata
    assert 0 == cfr.file.seek(0)
    rmsg = cfr.file.read()
    assert rmsg == b'{\n  name: hope\n  oobi: abc\n}'  # hjson

    cfr.close()
    assert not cfr.opened
    assert cfr.file.closed
    # assert cfr.path == filepath
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    with pytest.raises(ValueError):
        rdata = cfr.get()

    cfr.reopen(reuse=True)  # reuse True and clear False so don't remake
    assert cfr.opened
    assert not cfr.file.closed
    # assert cfr.path == filepath
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == wdata  # not empty

    cfr.reopen()  # reuse False so remake but not clear
    assert cfr.opened
    assert not cfr.file.closed
    # assert cfr.path == filepath
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == wdata  # not empty

    cfr.reopen(reuse=True, clear=True)  # clear True so remake even if reuse
    assert cfr.opened
    assert not cfr.file.closed
    # assert cfr.path == filepath
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == {}  # empty
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata

    cfr.reopen(clear=True)  # clear True so remake
    assert cfr.opened
    assert not cfr.file.closed
    # assert cfr.path == filepath
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == {}  # empty
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata

    cfr.close(clear=True)
    assert not os.path.exists(cfr.path)
    with pytest.raises(ValueError):
        rdata = cfr.get()

    # Test with plain json human==False
    cfr = configing.Configer(human=False)
    # assert cfr.path == filepath
    # github runner does not allow /usr/local/var
    assert cfr.path.endswith(os.path.join('keri', 'cf', 'main', 'conf.json'))
    assert cfr.opened
    assert os.path.exists(cfr.path)
    assert cfr.file
    assert not cfr.human
    assert not cfr.file.closed
    assert not cfr.file.read()

    #  .human == False
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata
    assert 0 == cfr.file.seek(0)
    rmsg = cfr.file.read()
    assert rmsg == b'{\n  "name": "hope",\n  "oobi": "abc"\n}'  # plain json
    cfr.close(clear=True)
    assert not os.path.exists(cfr.path)

    # Test with altPath by using not permitted headDirPath /opt/keri to force Alt
    filepath = os.path.join(os.path.sep, cfr.AltHeadDirPath, cfr.AltTailDirPath, "main", "conf.json")
    if os.path.exists(filepath):
        os.remove(filepath)

    headDirPath = "/root/keri"
    if platform.system() == "Windows":
        headDirPath="C:\\System Volume Information"
    cfr = configing.Configer(headDirPath=headDirPath)
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))
    assert cfr.opened
    assert os.path.exists(cfr.path)
    print(cfr.path)
    assert cfr.file
    assert not cfr.file.closed
    assert not cfr.file.read()

    data = dict(name="habi", oobi="ABCDEFG")
    wmsg = coring.dumps(data)
    assert hasattr(wmsg, "decode")  # bytes
    assert len(wmsg) == cfr.file.write(wmsg)
    assert 0 == cfr.file.seek(0)
    rmsg = cfr.file.read()
    assert rmsg == wmsg
    assert data == coring.loads(rmsg)

    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata

    cfr.close()
    assert not cfr.opened
    assert cfr.file.closed
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    with pytest.raises(ValueError):
        rdata = cfr.get()

    cfr.reopen(reuse=True)  # reuse True and clear False so don't remake
    assert cfr.opened
    assert not cfr.file.closed
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == wdata  # not empty

    cfr.reopen()  # reuse False so remake but not clear
    assert cfr.opened
    assert not cfr.file.closed
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == wdata  # not empty

    if platform.system() == "Windows":
        cfr.reopen(reuse=True, clear=True, headDirPath="C:\\System Volume Information")  # clear True so remake even if reuse
    else:
        cfr.reopen(reuse=True, clear=True)
    assert cfr.opened
    assert not cfr.file.closed
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))

    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == {}  # empty
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata

    cfr.reopen(clear=True)  # clear True so remake
    assert cfr.opened
    assert not cfr.file.closed
    assert cfr.path.endswith(os.path.join('.keri', 'cf', 'main', 'conf.json'))
    assert os.path.exists(cfr.path)
    assert (rdata := cfr.get()) == {}  # empty
    wdata = dict(name="hope", oobi="abc")
    assert cfr.put(wdata)
    rdata = cfr.get()
    assert rdata == wdata

    cfr.close(clear=True)
    assert not os.path.exists(cfr.path)
    with pytest.raises(ValueError):
        rdata = cfr.get()

    #test openCF hjson
    with configing.openCF() as cfr:  # default uses json and temp==True
        filepath = os.path.join(tempDirPath, 'keri_cf_2_zu01lb_test', 'keri', 'cf', 'main', 'test.json')
        assert cfr.path.startswith(os.path.join(tempDirPath, 'keri_'))
        assert cfr.path.endswith(os.path.join('_test', 'keri', 'cf', 'main', 'test.json'))
        assert cfr.opened
        assert cfr.human
        assert os.path.exists(cfr.path)
        assert cfr.file
        assert not cfr.file.closed
        wdata = dict(name="hope", oobi="abc")
        assert cfr.put(wdata)
        rdata = cfr.get()
        assert rdata == wdata
    assert not os.path.exists(cfr.path)  # if temp cleans

    #test openCF json
    with configing.openCF(human=False) as cfr:  # default uses json and temp==True
        filepath = os.path.join(tempDirPath,'keri_cf_2_zu01lb_test/keri/cf/main/test.json')
        assert cfr.path.startswith(os.path.join(tempDirPath, 'keri_'))
        assert cfr.path.endswith(os.path.join('_test', 'keri', 'cf', 'main', 'test.json'))
        assert cfr.opened
        assert not cfr.human
        assert os.path.exists(cfr.path)
        assert cfr.file
        assert not cfr.file.closed
        wdata = dict(name="hope", oobi="abc")
        assert cfr.put(wdata)
        rdata = cfr.get()
        assert rdata == wdata
    assert not os.path.exists(cfr.path)  # if temp cleans

    #test openCF mgpk
    with configing.openCF(fext='mgpk') as cfr:  # default uses temp==True
        assert cfr.path.startswith(os.path.join(tempDirPath, 'keri_'))
        assert cfr.path.endswith(os.path.join('_test', 'keri', 'cf', 'main', 'test.mgpk'))
        assert cfr.opened
        assert os.path.exists(cfr.path)
        assert cfr.file
        assert not cfr.file.closed
        wdata = dict(name="hope", oobi="abc")
        assert cfr.put(wdata)
        rdata = cfr.get()
        assert rdata == wdata
    assert not os.path.exists(cfr.path)  # if temp cleans

    # test openCF cbor
    with configing.openCF(fext='cbor') as cfr:  # default uses temp==True
        assert cfr.path.startswith(os.path.join(tempDirPath, 'keri_'))
        assert cfr.path.endswith(os.path.join('_test', 'keri', 'cf', 'main', 'test.cbor'))
        assert cfr.opened
        assert os.path.exists(cfr.path)
        assert cfr.file
        assert not cfr.file.closed
        wdata = dict(name="hope", oobi="abc")
        assert cfr.put(wdata)
        rdata = cfr.get()
        assert rdata == wdata
    assert not os.path.exists(cfr.path)  # if temp cleans

    """Done Test"""


def test_configer_doer():
    """
    Test ConfigerDoer
    """
    cfr0 = configing.Configer(name='test0', temp=True, reopen=False)
    assert cfr0.opened == False
    assert cfr0.path == None
    assert cfr0.file == None

    cfrDoer0 = configing.ConfigerDoer(configer=cfr0)
    assert cfrDoer0.configer == cfr0
    assert cfrDoer0.configer.opened == False

    cfr1 = configing.Configer(name='test1', temp=True, reopen=False)
    assert cfr1.opened == False
    assert cfr1.path == None
    assert cfr0.file == None

    cfrDoer1 = configing.ConfigerDoer(configer=cfr1)
    assert cfrDoer1.configer == cfr1
    assert cfrDoer1.configer.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [cfrDoer0, cfrDoer1]

    doist.doers = doers
    doist.enter()
    assert len(doist.deeds) == 2
    assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer.configer.opened
        assert os.path.join('_test', 'keri', 'cf', 'main') in doer.configer.path

    doist.recur()
    assert doist.tyme == 0.03125  # on next cycle
    assert len(doist.deeds) == 2
    for doer in doers:
        assert doer.configer.opened == True

    for dog, retyme, index in doist.deeds:
        dog.close()

    for doer in doers:
        assert doer.configer.opened == False
        assert not os.path.exists(doer.configer.path)

    # start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.configer.opened == False
        assert not os.path.exists(doer.configer.path)

    # test with filed == True
    cfr0 = configing.Configer(name='test0', temp=True, reopen=False, filed=True)
    assert cfr0.opened == False
    assert cfr0.path == None
    assert cfr0.file == None

    cfrDoer0 = configing.ConfigerDoer(configer=cfr0)
    assert cfrDoer0.configer == cfr0
    assert cfrDoer0.configer.opened == False

    cfr1 = configing.Configer(name='test1', temp=True, reopen=False, filed=True)
    assert cfr1.opened == False
    assert cfr1.path == None
    assert cfr0.file == None

    cfrDoer1 = configing.ConfigerDoer(configer=cfr1)
    assert cfrDoer1.configer == cfr1
    assert cfrDoer1.configer.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [cfrDoer0, cfrDoer1]

    doist.doers = doers
    doist.enter()
    assert len(doist.deeds) == 2
    assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer.configer.opened
        assert os.path.join('_test', 'keri', 'cf', 'main') in doer.configer.path
        assert  doer.configer.path.endswith(".json")
        assert doer.configer.file is not None
        assert not doer.configer.file.closed

    doist.recur()
    assert doist.tyme == 0.03125  # on next cycle
    assert len(doist.deeds) == 2
    for doer in doers:
        assert doer.configer.opened
        assert doer.configer.file is not None
        assert not doer.configer.file.closed

    for dog, retyme, index in doist.deeds:
        dog.close()

    for doer in doers:
        assert doer.configer.opened == False
        assert not os.path.exists(doer.configer.path)
        assert doer.configer.file is None

    # start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.configer.opened == False
        assert not os.path.exists(doer.configer.path)
        assert doer.configer.file is None

    """End Test"""




if __name__ == "__main__":
    test_configer()
