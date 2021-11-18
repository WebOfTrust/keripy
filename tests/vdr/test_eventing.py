# -*- encoding: utf-8 -*-
"""
tests.vdr.eventing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core import coring
from keri.core import eventing as keventing
from keri.core.coring import Versify, Serials, Ilks, MtrDex, Prefixer, Serder, Signer, Seqner
from keri.db import basing
from keri.db.dbing import snKey, dgKey
from keri.kering import Version, EmptyMaterialError, DerivationError, MissingAnchorError, ValidationError, \
    MissingWitnessSignatureError, LikelyDuplicitousError
from keri.vdr import eventing, viring
from keri.vdr.eventing import rotate, issue, revoke, backerIssue, backerRevoke, Tever, Tevery
from keri.vdr.viring import nsKey


def test_incept():
    """
    Test incept utility function
    """

    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # no backers, allowed to add later
    serder = eventing.incept(pre, baks=[], code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON0000a9_","i":"EiLMklo_OJmbv8D58wPlv_fudfEzuqsIl3mFYq640Jzg",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"0","b":[]}')

    # no backers allowed
    serder = eventing.incept(pre, baks=[], cnfg=[keventing.TraitDex.NoBackers], code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON0000ad_","i":"EjD_sFljMHXJCC3rEFL93MwHNGguKdC11mcMuQnZitcs",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}')

    # no backers allows, one attempted
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[keventing.TraitDex.NoBackers],
                        baks=[bak1])

    # with backer dupes
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[],
                        baks=[bak1, bak1, bak2])

    # with oob toad
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[], toad=4,
                        baks=[bak1, bak2, bak3])

    # with oob toad
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[], toad=1,
                        baks=[])

    # one backer
    serder = eventing.incept(pre,
                             baks=[bak1],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON0000d7_","i":"EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"1",'
        b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    # 3 backers
    serder = eventing.incept(pre,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON000135_","i":"Ez5ncVo7zXjC9DJT8-DM-ZMqJ-WtgpEGGs8JUzXh_Tc0",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"3",'
        b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
        b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    # one backer, with threshold
    serder = eventing.incept(pre,
                             toad=1,
                             baks=[bak1],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON0000d7_","i":"EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"1",'
        b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    # 3 backers, with threshold
    serder = eventing.incept(pre,
                             toad=2,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (
        b'{"v":"KERI10JSON000135_","i":"E39gu2hSUBannC3st40r2d8Dy7T6JsyTk0JefYYPtDgE",'
        b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"2",'
        b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
        b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    """ End Test """


def test_rotate():
    """
    Test rotate functionality

    """
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON0000aa_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"1","t":"vrt","bt":"0","br":[],'
                          b'"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=3,
                    baks=[bak1])
    assert serder.raw == (
        b'{"v":"KERI10JSON0000aa_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"3","t":"vrt","bt":"1","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON0000aa_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"3","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2])
    assert serder.raw == (
        b'{"v":"KERI10JSON0000d8_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"2",'
        b'"br":["DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON000107_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"1",'
        b'"br":["DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],'
        b'"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak1, bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON000136_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"0",'
        b'"br":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
        b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"ba":[]}')

    # invalid cut
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak1, bak3],
               cuts=[bak2])

    # invalid cut
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak1, bak3],
               cuts=[bak2])

    # invalid toad
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               toad=2,
               baks=[bak1, bak3],
               cuts=[bak3])

    # invalid sn
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=0,
               baks=[])

    # adds
    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    adds=[bak1],
                    baks=[bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON0000d8_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"3","br":[],'
                          b'"ba":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=2,
                    adds=[bak1, bak2, bak3],
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON000136_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"2","br":[],'
                          b'"ba":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc",'
                          b'"DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
                          b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=3,
                    adds=[bak2, bak3],
                    baks=[bak1])
    assert serder.raw == (
        b'{"v":"KERI10JSON000107_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
        b'"p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","t":"vrt","bt":"3","br":[],'
        b'"ba":["DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    # invalid dupe add
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak2, bak3],
               adds=[bak2])

    # invalid dupe add
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak3],
               cuts=[bak2, bak3])

    # invalid toad
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=5,
               toad=3,
               adds=[bak2, bak3],
               baks=[])

    """ End Test """


def test_simple_issue_revoke(mockHelpingNowUTC):
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = issue(vcdig=vcdig, regk=regk)

    assert serder.raw == (b'{"v":"KERI10JSON0000ba_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",'
                          b'"s":"0","t":"iss","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"'
                          b'2021-01-01T00:00:00.000000+00:00"}')

    serder = revoke(vcdig=vcdig, regk=regk, dig=dig)

    assert serder.raw == (b'{"v":"KERI10JSON0000ed_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",'
                          b'"s":"1","t":"rev","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"E'
                          b'Y2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00.00000'
                          b'0+00:00"}')

    """ End Test """


def test_backer_issue_revoke(mockHelpingNowUTC):
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    sn = 3
    regd = "Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = backerIssue(vcdig=vcdig, regk=regk, regsn=sn, regd=regd)
    assert serder.raw == (b'{"v":"KERI10JSON00012d_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",'
                          b'"ii":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"0","t":"bis","ra":{'
                          b'"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":3,"d":"Ezpq06UecHwzy-'
                          b'K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')

    serder = backerRevoke(vcdig=vcdig, regk=regk, regsn=sn, regd=regd, dig=dig)
    assert serder.raw == (b'{"v":"KERI10JSON00012c_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",'
                          b'"s":"1","t":"brv","p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","ra":{"'
                          b'i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":3,"d":"Ezpq06UecHwzy-K'
                          b'9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')
    """ End Test """


def test_prefixer():
    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    vs = Versify(version=Version, kind=Serials.json, size=0)

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer()

    # vcp, backers allowed no backers
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[]
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "E_TB9WKVB4Zx-Wu3-u1_RQWy2ZrDccaOj2xUpHQcg0MA"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # Invalid event type
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.iss,
               c=[],
               b=[]
               )
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)

    # vcp, no backers allowed
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[keventing.TraitDex.NoBackers],
               b=[]
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "EEDVlhKzGXA6C7n1igQF8m4WfTAEuwuvitgoM4DI3iCs"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # vcp, one backer
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[bak1]
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "E_e9zbZI8WCMNoaY1b-3aEVB59M6dc2Br8EDJ1_ozK-8"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # vcp, many backers
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[bak1, bak2, bak3]
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "EEuFeIT3_0_IAaNg8D-5AxO6UtQCmD17n77iksL048Go"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    """ End Test """


def test_tever_escrow():
    with pytest.raises(ValueError):
        Tever()

    # registry with no backers, invalid anchor
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre
        assert regk == "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY"
        assert vcp.dig == "EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg"
        assert vcp.ked["ii"] == hab.pre

        # anchor to nothing, exception expected
        seqner = Seqner(sn=4)

        # invalid seal sn
        with pytest.raises(ValidationError):
            Tever(serder=vcp, seqner=seqner, diger=None, db=db, reger=reg)

    # registry with no backers
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # anchoring event not in db, exception and escrow
        seqner = Seqner(sn=1)

        with pytest.raises(MissingAnchorError):
            Tever(serder=vcp, seqner=seqner, db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.dig)
        assert reg.getTvt(dgkey) == (
            b'{"v":"KERI10JSON0000a9_","i":"EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"0","b":[]}')
        assert reg.getTae(snKey(pre=regk, sn=0)) == b'EvpB-_BWD7tOhLI0cDyEQbziBt6IMyQnkrh0booR4vhg'

    # registry with backers, no signatures.  should escrow
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=["BoOcciw30IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vcp.ked["s"], vcp.diger.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        with pytest.raises(MissingWitnessSignatureError):
            Tever(serder=vcp, seqner=seqner, diger=diger, db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.dig)
        assert reg.getTvt(dgkey) == (
            b'{"v":"KERI10JSON0000d7_","i":"E1cv04kvHvWPrfncYsq-lQ-QvyKmKz6-hlGj02B2QWbk",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],"bt":"1",'
            b'"b":["BoOcciw30IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"]}')

        assert reg.getAnc(dgkey) == (
            b'0AAAAAAAAAAAAAAAAAAAAAAQE1NdOqtN0HlhBPc7-MHvsA4vajMwFYp2eIturQQo0stM')
        assert reg.getTel(snKey(pre=regk, sn=0)) is None
        assert reg.getTwe(snKey(pre=regk, sn=0)) == b'EjhsbizNCwN_EFuOxbUt8CN0xOctGRIVOW8X-XqA3fSk'


def test_tever_no_backers(mockHelpingNowUTC):
    # registry with no backers
    # registry with backer and receipt
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.diger.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev = Tever(serder=vcp, seqner=seqner, diger=diger, db=db, reger=reg)

        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        dgkey = dgKey(pre=regk, dig=vcp.dig)
        assert reg.getTvt(dgkey) == (
            b'{"v":"KERI10JSON0000ad_","i":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw",'
            b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}')

        assert reg.getAnc(dgkey) == (
            b'0AAAAAAAAAAAAAAAAAAAAAAQE-yQ6BjCaJg-u2mNuE-ycVWVTq7IZ8TuN-Ew8soLijSA')
        assert reg.getTel(snKey(pre=regk, sn=0)) == b'ElYstqTocyQixLLz4zYCAs2unaFco_p6LqH0W01loIg4'
        assert reg.getTibs(dgkey) == []
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        # try to rotate a backerless registry
        vrt = eventing.rotate(regk, dig=vcp.dig)
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        # should raise validation err because rotation is not supported
        with pytest.raises(ValidationError):
            tev.update(serder=vrt, seqner=seqner, diger=diger)

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev.update(iss, seqner=seqner, diger=diger)

        vci = nsKey([regk, vcdig])
        dgkey = dgKey(pre=vci, dig=iss.dig)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON0000ba_","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",'
            b'"s":"0","t":"iss","ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw","dt":"'
            b'2021-01-01T00:00:00.000000+00:00"}')
        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAAwEJLLpuUKPSDIcoOAOArQBzceWc8MoShm-cDL-w81liIw'

        # revoke vc with no backers
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.dig)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev.update(rev, seqner=seqner, diger=diger)
        dgkey = dgKey(pre=vci, dig=rev.dig)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON0000ed_","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",'
            b'"s":"1","t":"rev","ri":"Ezm53Qww2LTJ1yksEL06Wtt-5D23QKdJEGI0egFyLehw","p":"E'
            b'C9PffPrvyaKzsn72SWTvgyvWCJ1FbDThvJhsQ9LWo9M","dt":"2021-01-01T00:00:00.00000'
            b'0+00:00"}')

        # assert reg.getAnc(dgkey) == b'0AAAAAAAAAAAAAAAAAAAAABAECgc6yHeTRhsKh1M7k65feWZGCf_MG0dWoei5Q6SwgqU'


def test_tever_backers(mockHelpingNowUTC):
    # registry with backer and receipt
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        valSecret = 'AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw'

        # create receipt signer prefixer default code is non-transferable
        valSigner = Signer(qb64=valSecret, transferable=False)
        valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
        valpre = valPrefixer.qb64
        assert valpre == 'B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'

        hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[valpre],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre
        valCigar = valSigner.sign(ser=vcp.raw, index=0)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.diger.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev = Tever(serder=vcp, seqner=seqner, diger=diger, bigers=[valCigar], db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.dig)
        assert reg.getTvt(dgkey) == (b'{"v":"KERI10JSON0000d7_","i":"EBZR8LxEozgFa6UXwtSAmiXsmdChrT7Hr-jcxc9NFfrU",'
                                     b'"ii":"EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","s":"0","t":"vcp","c":[],'
                                     b'"bt":"1",'
                                     b'"b":["B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"]}')
        assert reg.getAnc(dgkey) == b'0AAAAAAAAAAAAAAAAAAAAAAQEpWPsFsCcsu5SpVH0416qHx3gvG0CWlrP_i7BVdbmRBg'
        assert reg.getTel(snKey(pre=regk, sn=0)) == b'EJTWiS0ebp8VSyLr38x73dAHdUqivisUtAaGpEHt5HDc'
        assert [bytes(tib) for tib in reg.getTibs(dgkey)] == [
            b'AAGhpPxAoltsRAnqxf7NsBzWSxWYLZ_ALImVVBiTlzJSdlATxRp_hBK4AbOzu-a900hwRxa0RX-yVWbVJA6oxoBw']
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        debSecret = 'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ'

        # create receipt signer prefixer default code is non-transferable
        debSigner = Signer(qb64=debSecret, transferable=False)
        debPrefixer = Prefixer(qb64=debSigner.verfer.qb64)
        debpre = debPrefixer.qb64
        assert debpre == 'BbWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI'

        vrt = eventing.rotate(regk, dig=vcp.dig, baks=[valpre], adds=[debpre])
        valCigar = valSigner.sign(ser=vrt.raw, index=0)
        debCigar = debSigner.sign(ser=vrt.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev.update(serder=vrt, seqner=seqner, diger=diger, bigers=[valCigar, debCigar])

        assert tev.baks == ['B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc',
                            'BbWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI']

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        bis = eventing.backerIssue(vcdig=vcdig.decode("utf-8"), regk=regk, regsn=tev.sn, regd=tev.serder.dig)
        valCigar = valSigner.sign(ser=bis.raw, index=0)
        debCigar = debSigner.sign(ser=bis.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(bis.ked["i"], bis.ked["s"], bis.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tev.update(bis, seqner=seqner, diger=diger, bigers=[valCigar, debCigar])

        vci = nsKey([regk, vcdig])
        dgkey = dgKey(pre=vci, dig=bis.dig)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON00012d_","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",'
            b'"ii":"EBZR8LxEozgFa6UXwtSAmiXsmdChrT7Hr-jcxc9NFfrU","s":"0","t":"bis","ra":{'
            b'"i":"EBZR8LxEozgFa6UXwtSAmiXsmdChrT7Hr-jcxc9NFfrU","s":1,"d":"EZH2Cfw3nvcMRg'
            b'Y31Jyc2zHVh4a0LO_bVZ4EmL4V8Ol8"},"dt":"2021-01-01T00:00:00.000000+00:00"}')


def test_tevery():
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.diger.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tvy = Tevery(reger=reg, db=db)

        tvy.processEvent(serder=vcp, seqner=seqner, diger=diger)

        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        # send vcp again, get error
        with pytest.raises(LikelyDuplicitousError):
            tvy.processEvent(serder=vcp, seqner=seqner, diger=diger)

        # process issue vc event
        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tvy.processEvent(serder=iss, seqner=seqner, diger=diger)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.ked['et'] == Ilks.iss
        assert status.sn == 0

        # revoke the vc
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.dig)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.diger.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.diger

        tvy.processEvent(serder=rev, seqner=seqner, diger=diger)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.ked["et"] == Ilks.rev
        assert status.sn == 1


def test_tevery_process_escrow():
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReg() as reg:
        hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.diger.qb64)

        seqner = Seqner(sn=1)
        diger = coring.Diger(qb64b=b'E-yQ6BjCaJg-u2mNuE-ycVWVTq7IZ8TuN-Ew8soLijSA')

        tvy = Tevery(reger=reg, db=db)

        with pytest.raises(MissingAnchorError):  # Process before the Hab rotation event, will escrow
            tvy.processEvent(serder=vcp, seqner=seqner, diger=diger)

        assert regk not in tvy.tevers

        rot = hab.rotate(data=[rseal._asdict()])  # Now rotate so the achoring KEL event gets into the database
        rotser = coring.Serder(raw=rot)
        assert rotser.digb == diger.qb64b

        tvy.processEscrows()  # process escrows and now the Tever event is good.
        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0




def buildHab(db, kpr):
    secrets = [
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])
    # setup hab
    hab = habbing.Habitat(ks=kpr, db=db, secrecies=secrecies, temp=True)
    return hab


if __name__ == "__main__":
    test_tever_escrow()
    test_tevery_process_escrow()